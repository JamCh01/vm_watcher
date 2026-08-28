//! Long-running daemon: eBPF lifecycle, traffic collection, rolling-window threshold
//! evaluation, rate-limit enforcement with selectable algorithms, config hot reload and
//! the read-only IPC server.
//!
//! A single "engine" task owns every mutable piece of state (eBPF maps, TAP attachments,
//! the collector, the limiter). Everything else — the IPC server, the file watcher, signal
//! handling — talks to it through bounded channels, so there is exactly one writer and no
//! shared-mutable locking.

use std::collections::HashSet;
use std::fs::File;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use aya::maps::{
    lpm_trie::Key as TrieKey, HashMap as AyaHashMap, LpmTrie, MapData, MapError, PerCpuHashMap,
};
use futures::{SinkExt, StreamExt};
use notify::event::{AccessKind, AccessMode, CreateKind, EventKind, ModifyKind};
use notify::RecursiveMode;
use notify_debouncer_full::Debouncer;
use tokio::net::unix::OwnedWriteHalf;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use vm_bandwidth_common::{
    LimitKey, LimitPolicy, LimitState, OversizedStats, PolicerStats, SwlRing, TrafficKey,
    TrafficValue, ALGO_SLIDING_WINDOW_LOG, DIR_RX, DIR_TX,
};

use vm_bandwidth_core::config::{self, ValidatedConfig};
use vm_bandwidth_core::ip_range::Cidr;
use vm_bandwidth_core::ipc::{
    self, IpDetail, RangeDetail, RangeSummary, Request, Response, Status,
};
use vm_bandwidth_core::limiter::{LimitAction, Limiter};
use vm_bandwidth_core::timefmt::{format_unix_utc, now_unix};

use crate::collector::{Collector, PollResult};
use crate::interface::{self, Tap};
use crate::tc::AttachManager;

pub const SOCK_PATH: &str = "/run/vm-bandwidth-monitor.sock";
pub const PIN_MONITORED_IPS: &str = "/sys/fs/bpf/MONITORED_IPS";
pub const PIN_TRAFFIC: &str = "/sys/fs/bpf/TRAFFIC";
pub const PIN_LIMIT_POLICIES: &str = "/sys/fs/bpf/LIMIT_POLICIES";
pub const PIN_GCRA_STATE: &str = "/sys/fs/bpf/GCRA_STATE";
const LOCK_PATH: &str = "/run/vm-bandwidth-monitor.lock";

/// Bound on concurrent IPC clients: the socket is owner-only, but a slow or stuck
/// connection must not accumulate unbounded engine-side queues; new connections wait
/// in the listen backlog until a slot frees up.
const MAX_IPC_CONNECTIONS: usize = 16;
/// Debounce window for filesystem events (§29): one normal save ≈ one reload.
const RELOAD_DEBOUNCE_MS: u64 = 300;

type IpcReq = (Request, oneshot::Sender<Response>);

/// The applied configuration, shared as an atomic snapshot: the engine is the
/// sole writer (after a successful transactional reload), every read site loads
/// it lock-free and never observes a half-applied config.
type ConfigArc = Arc<ArcSwap<ValidatedConfig>>;

/// Messages the config watcher thread sends to the engine loop.
enum WatchMsg {
    Reload,
    /// Debouncer/inotify errors: without surfacing these the daemon keeps running but
    /// hot reload silently stops working.
    Error(String),
}

/// Whitelist-trie key for one prefix. The kernel LPM trie matches bits in MEMORY-byte
/// order, so the address goes in network byte order — a host-order u32 would reverse
/// the octets and only match by accident while all variance stays inside one octet.
fn trie_key(c: &Cidr) -> TrieKey<u32> {
    TrieKey::new(u32::from(c.prefix_len), c.network.to_be())
}

/// Treat "key absent" as success for cleanup removes; every other error propagates.
/// Absence surfaces two ways depending on the map op: `KeyNotFound` from lookup-based
/// paths, or a raw ENOENT (`io::ErrorKind::NotFound`) wrapped in `SyscallError` from
/// `bpf_map_delete_elem` — both mean the entry is already gone.
fn map_gone(r: Result<(), MapError>) -> Result<()> {
    match r {
        Ok(()) | Err(MapError::KeyNotFound) => Ok(()),
        Err(MapError::SyscallError(e)) if e.io_error.kind() == std::io::ErrorKind::NotFound => {
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// All the eBPF + runtime state the engine owns.
struct Engine {
    config: ConfigArc,
    generation: u64,
    /// Bumped on every successfully applied reload; the scheduler rebuilds its
    /// timers from it instead of waiting one stale interval out.
    config_watch: watch::Sender<u64>,
    config_loaded_at: String,
    last_reload_at: String,
    last_reload_ok: bool,
    last_reload_error: String,
    /// Raw bytes of the last successfully applied config (dedup spurious triggers).
    last_config_bytes: Vec<u8>,

    /// Config file watcher health (inotify failures are otherwise silent).
    config_watcher_healthy: bool,
    config_watcher_errors_total: u64,
    config_watcher_last_error: String,

    /// Dataplane health: set when a rollback could not fully restore the maps.
    /// The dataplane may then differ from the active configuration; each affected
    /// flow's exact state is carried by the per-step `RollbackFailure` logs. The
    /// flag stays on so operators can see the degradation instead of it being
    /// swallowed.
    dataplane_degraded: bool,
    rollback_failures_total: u64,

    bridge: String,
    manager: AttachManager,
    taps: Vec<Tap>,

    collector: Collector,
    limiter: Limiter,
    last_snapshot: Option<crate::collector::Snapshot>,
    /// Last poll's cumulative per-IP counters, for the VictoriaMetrics push.
    last_totals: std::collections::HashMap<u32, vm_bandwidth_core::limiter::IpTotals>,
    /// Last poll's cumulative policer verdict counters, for the VictoriaMetrics push.
    last_policer: std::collections::HashMap<u32, crate::collector::PolicerIpTotals>,
    /// Last poll's aggregate IPv6 counters, for the VictoriaMetrics push.
    last_ipv6: crate::collector::IpStats,
    /// Cumulative oversized (unpoliced) packet counters, (RX, TX) — observability for
    /// the fail-open path above MAX_POLICED_LEN while a policy is armed.
    oversized: (OversizedStats, OversizedStats),
    oversized_map: PerCpuHashMap<MapData, u8, OversizedStats>,

    /// Whitelist-trie capacity fixed at startup; hot reload must fit inside it.
    whitelist_capacity: u32,

    monitored: LpmTrie<MapData, u32, u8>,
    limit_policies: AyaHashMap<MapData, LimitKey, LimitPolicy>,
    limit_state: AyaHashMap<MapData, LimitKey, LimitState>,
    /// Bounded sliding-window-log rings; only populated for flows limited with
    /// the `sliding_window_log` algorithm.
    swl_log: AyaHashMap<MapData, LimitKey, SwlRing>,
    traffic: PerCpuHashMap<MapData, TrafficKey, TrafficValue>,
    /// Aggregate IPv6 counters per TAP ifindex (cardinality bounded by TAP count,
    /// not by address churn — see the eBPF TRAFFIC6 comment).
    traffic6: PerCpuHashMap<MapData, u32, TrafficValue>,
    policer_stats: PerCpuHashMap<MapData, LimitKey, PolicerStats>,
    /// Shared HTTP client for the VictoriaMetrics push.
    http: reqwest::Client,
    /// Single-flight flag plus process-lifetime push outcome counters
    /// (see push_metrics / PushCounters).
    push_counters: Arc<PushCounters>,
    /// TAP attach failures since daemon start (any attach class incl. backoff
    /// rejections); engine-owned, updated only by the engine task.
    tap_attach_failures_total: u64,

    epoch: std::time::Instant,
}

impl Engine {
    fn now_secs(&self) -> u64 {
        self.epoch.elapsed().as_secs()
    }

    fn collect_tick(&mut self) {
        let ranges = self.config.load().ip_ranges();
        let PollResult {
            snapshot,
            totals,
            ipv6,
            policer,
            stale_traffic,
            stale_traffic6,
        } = self
            .collector
            .poll(&self.traffic, &self.traffic6, &self.policer_stats, &ranges);
        // Idle eviction: drop counter-map entries frozen long enough; the data path
        // recreates them on the next packet (reset-safe deltas, see collector).
        let idle4 = remove_counter_keys(
            "TRAFFIC",
            "idle eviction",
            &stale_traffic,
            |k| std::net::Ipv4Addr::from(k.ipv4).to_string(),
            |k| self.traffic.remove(k),
        );
        let idle6 = remove_counter_keys(
            "TRAFFIC6",
            "idle eviction",
            &stale_traffic6,
            |k| format!("ifindex {k}"),
            |k| self.traffic6.remove(k),
        );
        if idle4.attempted + idle6.attempted > 0 {
            if idle4.failed + idle6.failed == 0 {
                log::debug!(
                    "evicted {} idle TRAFFIC / {} idle TRAFFIC6 key(s)",
                    idle4.removed,
                    idle6.removed
                );
            } else {
                log::warn!(
                    "idle eviction incomplete: TRAFFIC {}/{} + TRAFFIC6 {}/{} removed — see per-key failures",
                    idle4.removed,
                    idle4.attempted,
                    idle6.removed,
                    idle6.attempted
                );
            }
        }
        let now = self.now_secs();
        let actions = self.limiter.tick(now, &totals);
        if !actions.is_empty() {
            let mut journal = crate::txmaps::TxJournal::default();
            let applied = {
                let mut maps = EngineMaps {
                    policies: &mut self.limit_policies,
                    state: &mut self.limit_state,
                    swl: &mut self.swl_log,
                    policer: &mut self.policer_stats,
                };
                run_limit_actions(&mut maps, &actions, &mut journal)
            };
            if let Err(e) = applied {
                // A half-applied batch is worse than none: roll the dataplane back and
                // let the flows re-evaluate from NORMAL on their next threshold cross.
                let report = {
                    let mut maps = EngineMaps {
                        policies: &mut self.limit_policies,
                        state: &mut self.limit_state,
                        swl: &mut self.swl_log,
                        policer: &mut self.policer_stats,
                    };
                    let mut wl = EngineWhitelist(&mut self.monitored);
                    crate::txmaps::rollback_journal(&mut maps, &mut wl, &journal)
                };
                self.surface_rollback_report(&report);
                for action in &actions {
                    let (ipv4, direction) = match action {
                        LimitAction::Install {
                            ipv4, direction, ..
                        }
                        | LimitAction::Remove { ipv4, direction } => (*ipv4, *direction),
                    };
                    self.limiter.reset_flow(ipv4, direction);
                }
                log::error!("runtime limit actions failed and were rolled back: {e:#}");
            }
        }
        self.last_totals = totals;
        self.last_ipv6 = ipv6;
        self.last_policer = policer;
        self.last_snapshot = Some(snapshot);
        self.oversized = read_oversized(&self.oversized_map);
    }

    /// Push cumulative per-IP counters to VictoriaMetrics (no-op when disabled).
    /// Rendering happens here on the engine (current state, current config); only the
    /// network send runs in a spawned task, so a stalled endpoint delays at most
    /// itself — never the sampling tick. At most one push is in flight: if the
    /// previous one has not returned by the next interval this one is skipped and the
    /// interval after retries with fresh (cumulative) values.
    fn push_metrics(&self) {
        let cfg = self.config.load();
        if !cfg.metrics_enabled {
            return;
        }
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let mut lines =
            crate::metrics::render_prom_lines(&self.last_totals, |ip| self.range_name(ip), now_ms);
        lines.push_str(&crate::metrics::render_prom_lines_policer(
            &self.last_policer,
            |ip| self.range_name(ip),
            now_ms,
        ));
        lines.push_str(&crate::metrics::render_prom_lines_ipv6(
            &self.last_ipv6,
            now_ms,
        ));
        lines.push_str(&crate::metrics::render_prom_lines_oversized(
            &self.oversized,
            now_ms,
        ));
        lines.push_str(&crate::metrics::render_prom_lines_process(
            self.tap_attach_failures_total,
            self.push_counters.successes(),
            self.push_counters.failures(),
            self.push_counters.skipped(),
            now_ms,
        ));
        if lines.is_empty() {
            return;
        }
        let Some(guard) = self.push_counters.try_start() else {
            log::debug!("metrics push skipped: previous push still in flight");
            return;
        };
        let counters = self.push_counters.clone();
        let http = self.http.clone();
        let url = cfg.metrics_url.clone();
        tokio::spawn(async move {
            // The in-flight flag lives in an RAII guard: normal completion, HTTP
            // errors, cancellation and panic unwinding all drop it and release it.
            let _guard = guard;
            match crate::metrics::push(&http, &url, &lines).await {
                Ok(()) => {
                    counters.note_success();
                    log::debug!("metrics push: {} line(s)", lines.lines().count());
                }
                Err(e) => {
                    counters.note_failure();
                    log::warn!(
                        "metrics push to {} failed: {e:#}",
                        vm_bandwidth_core::config::safe_endpoint_display(&url)
                    );
                }
            }
        });
    }

    fn range_name(&self, ip: u32) -> String {
        self.config
            .load()
            .ranges
            .iter()
            .find(|r| r.inner.contains(ip))
            .map(|r| r.inner.name.clone())
            .unwrap_or_else(|| "unknown".to_string())
    }

    fn rescan_taps(&mut self) {
        match interface::discover_taps(&self.bridge) {
            Ok(found) => {
                let (added, failed) = self.manager.reconcile(&found);
                self.tap_attach_failures_total += failed as u64;
                if added > 0 || failed > 0 {
                    log::info!("scan: {added} attached, {failed} failed");
                }
                let new_taps = self.manager.taps();
                let new_ifindexes: std::collections::HashSet<u32> =
                    new_taps.iter().map(|t| t.ifindex).collect();
                let old_ifindexes: std::collections::HashSet<u32> =
                    self.taps.iter().map(|t| t.ifindex).collect();
                if new_ifindexes != old_ifindexes {
                    // Drop counters of vanished TAPs so the TRAFFIC map does not fill up
                    // with dead (ifindex, IP) keys as VMs churn (§33).
                    let mut stale = Vec::new();
                    for (key, _) in self.traffic.iter().flatten() {
                        if !new_ifindexes.contains(&key.ifindex) {
                            stale.push(key);
                        }
                    }
                    let pruned = remove_counter_keys(
                        "TRAFFIC",
                        "stale-TAP prune",
                        &stale,
                        |k| std::net::Ipv4Addr::from(k.ipv4).to_string(),
                        |k| self.traffic.remove(k),
                    );
                    if pruned.attempted > 0 {
                        if pruned.failed == 0 {
                            log::debug!("pruned {} stale TRAFFIC key(s)", pruned.removed);
                        } else {
                            log::warn!(
                                "stale-TAP prune incomplete: removed {}/{} TRAFFIC key(s) — see per-key failures",
                                pruned.removed,
                                pruned.attempted
                            );
                        }
                    }
                    self.collector.prune_ifindexes(&new_ifindexes);
                }
                self.taps = new_taps;
            }
            Err(e) => log::warn!("TAP scan failed: {e}"),
        }
    }

    /// Surface a rollback report: per-step failures at error severity, degraded
    /// flag plus counter when the dataplane could not be fully restored. Never
    /// silent. The exact post-rollback state varies per journal record (old policy
    /// re-armed, new limit kept armed, or unarmed with a bounded orphan); only the
    /// hard invariant `armed policy => matching state exists` is guaranteed.
    fn surface_rollback_report(&mut self, report: &crate::txmaps::RollbackReport) {
        for f in &report.failures {
            log::error!(
                "rollback failed at '{}' for {}: {}",
                f.op,
                std::net::Ipv4Addr::from(f.key.ipv4),
                f.error
            );
        }
        if !report.dataplane_consistent {
            self.dataplane_degraded = true;
            self.rollback_failures_total += report.failures.len() as u64;
            log::error!(
                "{}",
                degraded_summary(report.failures.len(), report.attempted)
            );
        }
    }

    fn record_watcher_error(&mut self, e: String) {
        self.config_watcher_healthy = false;
        self.config_watcher_errors_total += 1;
        self.config_watcher_last_error = e.clone();
        log::error!("config watcher error (hot reload may stop working): {e}");
    }

    /// Transactional config reload (§16): parse + validate fully, then apply once.
    /// A rejected config leaves the previous one fully in place (§28).
    fn reload(&mut self, path: &Path) {
        log::info!("config reload requested");

        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                self.last_reload_at = format_unix_utc(now_unix());
                self.last_reload_ok = false;
                self.last_reload_error = format!("cannot read {}: {e}", path.display());
                log::warn!("config reload rejected: {e}");
                return;
            }
        };
        let stamp = format_unix_utc(now_unix());
        self.last_reload_at = stamp.clone();
        // Spurious triggers (touch, identical re-save): nothing to apply. Refresh the
        // status so a previous FAILED does not linger after the file is back to normal.
        if bytes == self.last_config_bytes {
            self.last_reload_ok = true;
            self.last_reload_error.clear();
            log::info!("config unchanged; nothing to reload");
            return;
        }

        let new_cfg = match String::from_utf8(bytes.clone())
            .map_err(|e| format!("config is not valid UTF-8: {e}"))
            .and_then(|text| {
                config::parse(&text).map_err(|e| format!("{e} (in {})", path.display()))
            }) {
            Ok(cfg) => cfg,
            Err(e) => {
                self.last_reload_ok = false;
                self.last_reload_error = e.clone();
                log::warn!(
                    "config reload rejected (keeping generation {}): {e}",
                    self.generation
                );
                return;
            }
        };

        if let Err(e) = self.apply_config(new_cfg) {
            self.last_reload_ok = false;
            self.last_reload_error = format!("{e:#}");
            log::error!("config reload apply failed: {e:#}");
            return;
        }

        // apply_and_commit already incremented the generation on commit.
        let _ = self.config_watch.send_replace(self.generation);
        self.last_reload_ok = true;
        self.last_reload_error.clear();
        self.config_loaded_at = stamp;
        self.last_config_bytes = bytes;
        log::info!("config reload succeeded; generation {}", self.generation);

        // Rebuild the IPC snapshot immediately under the NEW config: build_status pairs
        // snapshot ranges with config ranges by index, so serving the old snapshot
        // against the new config would attach limited counts and policies to the wrong
        // ranges until the next scheduled collect. This also replaces last_totals, so
        // the metrics push cannot label stale IPs with the new config.
        self.collect_tick();
    }

    /// Transactional config apply: compute a pure plan, execute every map operation
    /// (whitelist additions, then limit actions removes-first/installs-last, then
    /// whitelist removals), and only if ALL of them succeed commit the limiter state,
    /// prune the collector and atomically switch the visible config. Any failure rolls
    /// the dataplane back and keeps the previous config and generation.
    fn apply_config(&mut self, new_cfg: ValidatedConfig) -> Result<()> {
        if new_cfg.bridge != self.bridge {
            anyhow::bail!(
                "changing network.bridge ({} -> {}) is not supported by hot reload; restart the daemon instead",
                self.bridge,
                new_cfg.bridge
            );
        }
        // Fields whose effects are baked into structures created at startup: the
        // limiter's windows are calibrated in whole tick seconds and the eBPF maps
        // have fixed capacities. Changing them needs a restart, not a reload.
        let cur = self.config.load();
        if new_cfg.refresh_interval_ms != cur.refresh_interval_ms {
            anyhow::bail!(
                "changing collector.refresh_interval_ms is not supported by hot reload \
                 (the limiter's windows are calibrated in whole tick seconds); \
                 restart the daemon instead"
            );
        }
        if new_cfg.map_max_entries != cur.map_max_entries {
            anyhow::bail!(
                "changing collector.map_max_entries is not supported by hot reload \
                 (the eBPF maps are sized once at startup); restart the daemon instead"
            );
        }
        if new_cfg.swl_map_max_entries != cur.swl_map_max_entries {
            anyhow::bail!(
                "changing collector.swl_map_max_entries is not supported by hot reload \
                 (the eBPF maps are sized once at startup); restart the daemon instead"
            );
        }

        let old_prefixes = prefix_set(&cur);
        let new_prefixes = prefix_set(&new_cfg);

        // The trie capacity is fixed at startup; refuse a reload that would overflow it
        // before touching any map, instead of failing halfway through the install phase.
        let new_count = u32::try_from(new_prefixes.len()).unwrap_or(u32::MAX);
        if new_count > self.whitelist_capacity {
            anyhow::bail!(
                "new config needs {new_count} whitelist prefixes but MONITORED_IPS capacity \
                 is {} (sized at startup); restart the daemon to resize it",
                self.whitelist_capacity
            );
        }

        let now = self.now_secs();
        let plan = self
            .limiter
            .plan_reload(&new_cfg, now)
            .map_err(anyhow::Error::msg)?;

        let result = {
            let mut maps = EngineMaps {
                policies: &mut self.limit_policies,
                state: &mut self.limit_state,
                swl: &mut self.swl_log,
                policer: &mut self.policer_stats,
            };
            let mut wl = EngineWhitelist(&mut self.monitored);
            apply_and_commit(
                &mut maps,
                &mut wl,
                &mut self.limiter,
                &mut self.collector,
                &self.config,
                &mut self.generation,
                &old_prefixes,
                plan,
                new_cfg,
            )
        };
        match result {
            Ok(()) => Ok(()),
            Err(rb) => {
                self.surface_rollback_report(&rb.report);
                Err(rb.message)
            }
        }
    }

    // ----- IPC response builders -----

    fn build_status(&self) -> Status {
        let mut ranges = Vec::new();
        let cfg = self.config.load();
        if let Some(snap) = &self.last_snapshot {
            for (i, rs) in snap.ranges.iter().enumerate() {
                let limited = cfg
                    .ranges
                    .get(i)
                    .map(|vr| self.limiter.limited_count(vr.start, vr.end))
                    .unwrap_or(0);
                ranges.push(RangeSummary {
                    name: rs.name.clone(),
                    range: rs.range.clone(),
                    rx_bps: rs.rx_bps,
                    tx_bps: rs.tx_bps,
                    rx_bytes: rs.rx_bytes,
                    tx_bytes: rs.tx_bytes,
                    ip_count: rs.ips.len(),
                    limited,
                    rx_dropped_bps: rs.rx_dropped_bps,
                    tx_dropped_bps: rs.tx_dropped_bps,
                    rx_dropped_bytes: rs.rx_dropped_bytes,
                    tx_dropped_bytes: rs.tx_dropped_bytes,
                });
            }
            // Aggregate IPv6 pseudo-range: counted but never policed, no per-IP
            // breakdown (the UI blocks Enter on it; `t` still trends it).
            let v6 = &self.last_ipv6;
            ranges.push(RangeSummary {
                name: ipc::IPV6_RANGE_NAME.to_string(),
                range: String::new(),
                rx_bps: v6.rx_bps,
                tx_bps: v6.tx_bps,
                rx_bytes: v6.rx_bytes,
                tx_bytes: v6.tx_bytes,
                ip_count: 0,
                limited: 0,
                rx_dropped_bps: 0.0,
                tx_dropped_bps: 0.0,
                rx_dropped_bytes: 0,
                tx_dropped_bytes: 0,
            });
        }
        Status {
            protocol_version: ipc::PROTOCOL_VERSION,
            generation: self.generation,
            config_loaded_at: self.config_loaded_at.clone(),
            last_reload_at: self.last_reload_at.clone(),
            last_reload_ok: self.last_reload_ok,
            last_reload_error: self.last_reload_error.clone(),
            bridge: self.bridge.clone(),
            tap_count: self.taps.len(),
            config_watcher_healthy: self.config_watcher_healthy,
            config_watcher_errors_total: self.config_watcher_errors_total,
            config_watcher_last_error: self.config_watcher_last_error.clone(),
            dataplane_degraded: self.dataplane_degraded,
            rollback_failures_total: self.rollback_failures_total,
            tap_attach_failures_total: self.tap_attach_failures_total,
            metrics_push_successes_total: self.push_counters.successes(),
            metrics_push_failures_total: self.push_counters.failures(),
            metrics_push_skipped_total: self.push_counters.skipped(),
            anti_spoof_mode: self.config.load().ip_ownership.clone(),
            anti_spoof_enforced_by_program: false,
            anti_spoof_acknowledged: true,
            oversized_rx_packets: self.oversized.0.packets,
            oversized_rx_bytes: self.oversized.0.bytes,
            oversized_tx_packets: self.oversized.1.packets,
            oversized_tx_bytes: self.oversized.1.bytes,
            swl_map_capacity: self.config.load().swl_map_max_entries,
            swl_map_used: self.swl_log.iter().filter_map(|i| i.ok()).count() as u32,
            ranges,
        }
    }

    fn build_range_detail(&self, index: usize) -> Option<RangeDetail> {
        let snap = self.last_snapshot.as_ref()?;
        let rs = snap.ranges.get(index)?;
        let now = self.now_secs();
        let ips = rs
            .ips
            .iter()
            .map(|(ip, stats)| {
                let eff = self.limiter.effective_policy(*ip);
                let rx_pol = eff.and_then(|p| p.rx);
                let tx_pol = eff.and_then(|p| p.tx);
                IpDetail {
                    ip: *ip,
                    rx_bps: stats.rx_bps,
                    tx_bps: stats.tx_bps,
                    rx_bytes: stats.rx_bytes,
                    tx_bytes: stats.tx_bytes,
                    rx_packets: stats.rx_packets,
                    tx_packets: stats.tx_packets,
                    rx_window_bps: self.limiter.window_avg_bps(*ip, DIR_RX),
                    tx_window_bps: self.limiter.window_avg_bps(*ip, DIR_TX),
                    rx_threshold: rx_pol.map(|d| d.threshold_bps).unwrap_or(0),
                    tx_threshold: tx_pol.map(|d| d.threshold_bps).unwrap_or(0),
                    rx_limit: rx_pol.map(|d| d.limit_bps).unwrap_or(0),
                    tx_limit: tx_pol.map(|d| d.limit_bps).unwrap_or(0),
                    rx_state: state_label(self.limiter.is_limited(*ip, DIR_RX)),
                    tx_state: state_label(self.limiter.is_limited(*ip, DIR_TX)),
                    rx_remaining: self.limiter.remaining_secs(*ip, DIR_RX, now),
                    tx_remaining: self.limiter.remaining_secs(*ip, DIR_TX, now),
                    rx_dropped_bytes: stats.rx_dropped_bytes,
                    tx_dropped_bytes: stats.tx_dropped_bytes,
                    rx_dropped_packets: stats.rx_dropped_packets,
                    tx_dropped_packets: stats.tx_dropped_packets,
                }
            })
            .collect();
        Some(RangeDetail {
            name: rs.name.clone(),
            range: rs.range.clone(),
            rx_bps: rs.rx_bps,
            tx_bps: rs.tx_bps,
            rx_bytes: rs.rx_bytes,
            tx_bytes: rs.tx_bytes,
            rx_dropped_bytes: rs.rx_dropped_bytes,
            tx_dropped_bytes: rs.tx_dropped_bytes,
            rx_dropped_packets: rs.rx_dropped_packets,
            tx_dropped_packets: rs.tx_dropped_packets,
            ips,
        })
    }

    fn handle_request(&self, req: Request) -> Response {
        match req {
            Request::Overview => Response::Status(Box::new(self.build_status())),
            Request::RangeDetail { index } => match self.build_range_detail(index) {
                Some(detail) => Response::RangeDetail(Box::new(detail)),
                None => Response::Error {
                    message: format!("range index {index} out of bounds"),
                },
            },
        }
    }
}

/// Aggregate the two-entry per-CPU OVERSIZED map into cumulative (RX, TX) counters.
/// Map read errors leave the previous numbers in place (observability must never
/// disturb the engine).
fn read_oversized(
    map: &PerCpuHashMap<MapData, u8, OversizedStats>,
) -> (OversizedStats, OversizedStats) {
    let mut acc = (OversizedStats::default(), OversizedStats::default());
    for item in map.iter() {
        let Ok((dir, values)) = item else { continue };
        let slot = match dir {
            DIR_RX => &mut acc.0,
            DIR_TX => &mut acc.1,
            _ => continue,
        };
        for v in values.iter() {
            slot.packets += v.packets;
            slot.bytes += v.bytes;
        }
    }
    acc
}

/// The engine's limit maps behind the [`crate::txmaps::LimitMaps`] trait. Absence-tolerant
/// cleanup ops go through [`map_gone`]; the policy read maps `KeyNotFound` to `None`.
struct EngineMaps<'a> {
    policies: &'a mut AyaHashMap<MapData, LimitKey, LimitPolicy>,
    state: &'a mut AyaHashMap<MapData, LimitKey, LimitState>,
    swl: &'a mut AyaHashMap<MapData, LimitKey, SwlRing>,
    policer: &'a mut PerCpuHashMap<MapData, LimitKey, PolicerStats>,
}

impl crate::txmaps::LimitMaps for EngineMaps<'_> {
    fn get_policy(&mut self, key: &LimitKey) -> Result<Option<LimitPolicy>> {
        match self.policies.get(key, 0) {
            Ok(p) => Ok(Some(p)),
            Err(MapError::KeyNotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn arm_policy(&mut self, key: &LimitKey, policy: LimitPolicy) -> Result<()> {
        self.policies.insert(*key, policy, 0).map_err(Into::into)
    }

    fn disarm_policy(&mut self, key: &LimitKey) -> Result<()> {
        map_gone(self.policies.remove(key))
    }

    fn write_fresh_state(&mut self, key: &LimitKey, algorithm: u32) -> Result<()> {
        // The data path never constructs lock-bearing values; userspace installs a
        // zeroed artifact of the shape the algorithm expects.
        if algorithm == ALGO_SLIDING_WINDOW_LOG {
            self.swl
                .insert(*key, SwlRing::default(), 0)
                .map_err(Into::into)
        } else {
            self.state
                .insert(*key, LimitState::default(), 0)
                .map_err(Into::into)
        }
    }

    fn clear_state(&mut self, key: &LimitKey, algorithm: u32) -> Result<()> {
        if algorithm == ALGO_SLIDING_WINDOW_LOG {
            map_gone(self.swl.remove(key))
        } else {
            map_gone(self.state.remove(key))
        }
    }

    fn clear_policer(&mut self, key: &LimitKey) -> Result<()> {
        map_gone(self.policer.remove(key))
    }
}

/// The whitelist trie behind [`crate::txmaps::WhitelistOps`].
struct EngineWhitelist<'a>(&'a mut LpmTrie<MapData, u32, u8>);

impl crate::txmaps::WhitelistOps for EngineWhitelist<'_> {
    fn wl_insert(&mut self, cidr: &Cidr) -> Result<()> {
        self.0.insert(&trie_key(cidr), 1u8, 0).map_err(Into::into)
    }

    fn wl_remove(&mut self, cidr: &Cidr) -> Result<()> {
        map_gone(self.0.remove(&trie_key(cidr)))
    }
}

fn state_label(limited: bool) -> String {
    if limited {
        "LIMITED".to_string()
    } else {
        "NORMAL".to_string()
    }
}

/// CIDR prefixes of all configured ranges — the whitelist's unit of install/removal.
/// Ranges are validated disjoint, so their prefix sets never overlap.
/// Summary line for the error log emitted when a rollback leaves the dataplane
/// inconsistent. Deliberately neutral about the outcome: after a failed rollback
/// a flow may be re-armed with its old policy, left armed on a new limit, or
/// unarmed with a bounded orphan artifact — per-record state differs, and only
/// the hard invariant `armed policy => matching state exists` holds. Any wording
/// that claims one outcome ("all flows unarmed", "all flows limited") for every
/// affected flow is wrong by construction; point at the per-step failures instead.
fn degraded_summary(failures: usize, attempted: usize) -> String {
    format!(
        "dataplane DEGRADED after rollback: {failures} of {attempted} step(s) failed; \
         dataplane state may differ from the active configuration — \
         inspect the per-step rollback failures above"
    )
}

/// Outcome of a bulk counter-map removal.
#[derive(Debug, PartialEq)]
struct RemovalStats {
    attempted: usize,
    removed: usize,
    failed: usize,
}

/// Remove keys from a counter map without stopping at individual failures.
/// One key failing never blocks the rest; the summary counts only keys whose
/// removal actually succeeded, never the input length.
///
/// Keys already absent count as removed — the goal (key not in map) is met.
/// aya 0.14 maps the kernel's ENOENT from `bpf_map_delete_elem` to
/// `MapError::SyscallError` with `io_error.kind() == NotFound` (see
/// `aya::maps::hash_map::remove`); the typed variants below are matched,
/// never the error string. Should a future aya return another variant for
/// absent keys, this degrades to a logged failure retried next cycle — never
/// to silent success. Real-kernel confirmation: docs/kernel-validation.md §6.
fn remove_counter_keys<K, D, F>(
    map_name: &str,
    op: &'static str,
    keys: &[K],
    display: D,
    mut remove: F,
) -> RemovalStats
where
    D: Fn(&K) -> String,
    F: FnMut(&K) -> Result<(), MapError>,
{
    let mut stats = RemovalStats {
        attempted: keys.len(),
        removed: 0,
        failed: 0,
    };
    for key in keys {
        match remove(key) {
            Ok(()) => stats.removed += 1,
            Err(e) if key_already_absent(&e) => stats.removed += 1,
            Err(e) => {
                stats.failed += 1;
                log::warn!(
                    "{map_name} remove failed during {op} for {}: {e}",
                    display(key)
                );
            }
        }
    }
    stats
}

/// Typed absent-key detection for `remove_counter_keys` — no string matching.
fn key_already_absent(e: &MapError) -> bool {
    use std::io::ErrorKind;
    match e {
        MapError::KeyNotFound | MapError::ElementNotFound => true,
        MapError::SyscallError(se) => se.io_error.kind() == ErrorKind::NotFound,
        MapError::IoError(io) => io.kind() == ErrorKind::NotFound,
        _ => false,
    }
}

/// Human-readable algorithm name for log lines.
fn algorithm_name(algorithm: u32) -> &'static str {
    use vm_bandwidth_common::*;
    match algorithm {
        ALGO_TOKEN_BUCKET => "token_bucket",
        ALGO_LEAKY_BUCKET => "leaky_bucket",
        ALGO_FIXED_WINDOW => "fixed_window",
        ALGO_SLIDING_WINDOW_COUNTER => "sliding_window_counter",
        ALGO_SLIDING_WINDOW_LOG => "sliding_window_log",
        ALGO_GCRA => "gcra",
        _ => "unknown",
    }
}

/// §27 ordering with journal bookkeeping: whitelist additions first, limit-map
/// actions second, whitelist removals last. Each successful operation is
/// journaled immediately, so any mid-way failure rolls back exactly what ran.
fn apply_reload_steps<M: crate::txmaps::LimitMaps, W: crate::txmaps::WhitelistOps>(
    maps: &mut M,
    wl: &mut W,
    actions: &[LimitAction],
    old_prefixes: &HashSet<Cidr>,
    new_prefixes: &HashSet<Cidr>,
    journal: &mut crate::txmaps::TxJournal,
) -> Result<()> {
    let additions: Vec<Cidr> = new_prefixes.difference(old_prefixes).copied().collect();
    crate::txmaps::apply_whitelist_additions(wl, journal, &additions)
        .context("whitelisting new prefixes")?;
    run_limit_actions(maps, actions, journal)?;
    let removals: Vec<Cidr> = old_prefixes.difference(new_prefixes).copied().collect();
    crate::txmaps::apply_whitelist_removals(wl, journal, &removals)
        .context("dropping removed whitelist prefixes")?;
    Ok(())
}

/// Two-pass limit-action execution against a [`crate::txmaps::LimitMaps`]:
/// removes first (they free capacity), installs after. For each flow the order
/// is disarm -> clear foreign artifacts -> fresh state -> arm LAST; the journal
/// exists before the first destructive write of every action.
fn run_limit_actions<M: crate::txmaps::LimitMaps>(
    maps: &mut M,
    actions: &[LimitAction],
    journal: &mut crate::txmaps::TxJournal,
) -> Result<()> {
    // Pass 1: removals.
    for action in actions {
        let LimitAction::Remove { ipv4, direction } = action else {
            continue;
        };
        let key = LimitKey::new(*ipv4, *direction);
        let addr = std::net::Ipv4Addr::from(*ipv4);
        crate::txmaps::remove_limit(maps, journal, key)
            .with_context(|| format!("removing limit policy for {addr} dir={direction}"))?;
        log::info!("back to NORMAL {addr} dir={direction}");
    }

    // Pass 2: installs.
    for action in actions {
        let LimitAction::Install {
            ipv4,
            direction,
            rate_bps,
            burst_bytes,
            algorithm,
            window_ns,
        } = action
        else {
            continue;
        };
        let key = LimitKey::new(*ipv4, *direction);
        let addr = std::net::Ipv4Addr::from(*ipv4);
        let policy = LimitPolicy {
            enabled: 1,
            _pad0: [0; 3],
            algorithm: *algorithm,
            rate_bps: *rate_bps,
            burst_bytes: *burst_bytes,
            window_ns: *window_ns,
        };
        crate::txmaps::install_limit(maps, journal, key, policy)
            .with_context(|| format!("installing limit policy for {addr} dir={direction}"))?;
        log::info!(
            "LIMITED {} dir={} algo={} at {} bps (burst {} B, window {} ns)",
            addr,
            direction,
            algorithm_name(*algorithm),
            rate_bps,
            burst_bytes,
            window_ns
        );
    }
    Ok(())
}

/// Error payload of a reload whose dataplane apply failed: the original error
/// plus the rollback report for surfacing.
#[derive(Debug)]
struct ReloadApplyError {
    message: anyhow::Error,
    report: crate::txmaps::RollbackReport,
}

/// Execute a validated reload plan against the dataplane and commit control-plane
/// state ONLY if every map operation succeeded. On any failure the journal is
/// played back in reverse and nothing commits: the limiter keeps its flows, the
/// collector keeps its pruning baseline, the visible config and generation stay
/// put. This free function is the single commit decision point for hot reloads;
/// the engine wires real aya maps into it, and tests drive it directly with
/// scripted maps.
// All nine parameters are live control-plane handles the single commit
// decision point needs; grouping them into a struct would only add a type.
#[allow(clippy::too_many_arguments)]
fn apply_and_commit<M: crate::txmaps::LimitMaps, W: crate::txmaps::WhitelistOps>(
    maps: &mut M,
    wl: &mut W,
    limiter: &mut Limiter,
    collector: &mut Collector,
    config: &ConfigArc,
    generation: &mut u64,
    old_prefixes: &HashSet<Cidr>,
    plan: vm_bandwidth_core::limiter::ReloadPlan,
    new_cfg: ValidatedConfig,
) -> Result<(), ReloadApplyError> {
    let mut journal = crate::txmaps::TxJournal::default();
    if let Err(e) = apply_reload_steps(
        maps,
        wl,
        &plan.actions,
        old_prefixes,
        &prefix_set(&new_cfg),
        &mut journal,
    ) {
        let report = crate::txmaps::rollback_journal(maps, wl, &journal);
        return Err(ReloadApplyError { message: e, report });
    }

    // Commit phase: limiter internals, then collector, then the visible switch.
    limiter.commit_reload(plan);
    collector.prune_ips(&new_cfg.ip_ranges());
    config.store(Arc::new(new_cfg));
    *generation += 1;
    Ok(())
}

fn prefix_set(cfg: &ValidatedConfig) -> HashSet<Cidr> {
    cfg.ranges.iter().flat_map(|r| r.inner.cidrs()).collect()
}

/// Entry point for daemon mode.
pub async fn run_daemon(config_path: PathBuf, object: &'static [u8]) -> Result<()> {
    // 1. Load and validate the initial config. Refuse to start on any problem.
    let cfg = config::load(&config_path).map_err(anyhow::Error::msg)?;
    let initial_config_bytes = std::fs::read(&config_path)?;
    log::info!(
        "loaded {} IP range(s) for bridge {}",
        cfg.ranges.len(),
        cfg.bridge
    );
    // The anti-spoofing contract is a security-relevant startup fact: say it loudly.
    log::warn!(
        "SECURITY: ip_ownership = \"{}\" — source-address anti-spoofing is enforced          EXTERNALLY (bridge/platform), NOT by this program; operator acknowledgement          recorded in [security]",
        cfg.ip_ownership
    );

    // 2. Single-instance lock. The file is created once and NEVER deleted: deleting
    //    it on shutdown opens an inode race (another process locks the old inode
    //    while a third creates and locks a fresh one). The flock dies with the fd.
    let lock_file = acquire_instance_lock(LOCK_PATH)?;

    // 3. Remove any pins left by older versions (v0.2.0 and earlier pinned the maps);
    //    the current maps are unpinned and live only as long as the daemon does.
    for pin in [
        PIN_MONITORED_IPS,
        PIN_TRAFFIC,
        PIN_LIMIT_POLICIES,
        PIN_GCRA_STATE,
    ] {
        let _ = std::fs::remove_file(pin);
    }

    let total_ips: u64 = cfg.ranges.iter().map(|r| r.len()).sum();
    let prefixes: Vec<Cidr> = cfg.ranges.iter().flat_map(|r| r.inner.cidrs()).collect();
    // The LPM trie holds one entry per CIDR prefix, not per address; keep headroom for
    // hot-reload additions.
    let whitelist_capacity = (prefixes.len().max(1) as u32)
        .saturating_mul(2)
        .next_power_of_two();

    let mut base = aya::EbpfLoader::new()
        .map_max_entries("TRAFFIC", cfg.map_max_entries)
        .map_max_entries("TRAFFIC6", cfg.map_max_entries)
        .map_max_entries("MONITORED_IPS", whitelist_capacity)
        .map_max_entries("LIMIT_POLICIES", cfg.map_max_entries)
        .map_max_entries("LIMIT_STATE", cfg.map_max_entries)
        // SWL rings are ~16.4 KiB each and preallocated; they get their own small
        // capacity (config::swl_map_max_entries) instead of the general map size.
        .map_max_entries("SWL_LOG", cfg.swl_map_max_entries)
        .map_max_entries("POLICER_STATS", cfg.map_max_entries)
        .map_max_entries("OVERSIZED", 4)
        .load(object)
        .context(
            "failed to load the eBPF object; this program needs root (CAP_BPF + CAP_NET_ADMIN), \
             a kernel with TC eBPF support, and bpffs mounted at /sys/fs/bpf",
        )?;

    let mut monitored = LpmTrie::<_, u32, u8>::try_from(
        base.take_map("MONITORED_IPS")
            .context("MONITORED_IPS map missing")?,
    )
    .context("MONITORED_IPS has the wrong type")?;
    for c in &prefixes {
        monitored
            .insert(&trie_key(c), 1u8, 0)
            .with_context(|| format!("inserting whitelist prefix {}", c.display()))?;
    }
    log::info!(
        "whitelisted {} CIDR prefix(es) covering {total_ips} IPv4 address(es)",
        prefixes.len()
    );

    let limit_policies = AyaHashMap::<_, LimitKey, LimitPolicy>::try_from(
        base.take_map("LIMIT_POLICIES")
            .context("LIMIT_POLICIES missing")?,
    )
    .context("LIMIT_POLICIES has the wrong type")?;
    let limit_state = AyaHashMap::<_, LimitKey, LimitState>::try_from(
        base.take_map("LIMIT_STATE")
            .context("LIMIT_STATE missing")?,
    )
    .context("LIMIT_STATE has the wrong type")?;
    let swl_log = AyaHashMap::<_, LimitKey, SwlRing>::try_from(
        base.take_map("SWL_LOG").context("SWL_LOG missing")?,
    )
    .context("SWL_LOG has the wrong type")?;
    let traffic = PerCpuHashMap::<MapData, TrafficKey, TrafficValue>::try_from(
        base.take_map("TRAFFIC").context("TRAFFIC missing")?,
    )
    .context("TRAFFIC has the wrong type")?;
    let traffic6 = PerCpuHashMap::<MapData, u32, TrafficValue>::try_from(
        base.take_map("TRAFFIC6").context("TRAFFIC6 missing")?,
    )
    .context("TRAFFIC6 has the wrong type")?;
    let policer_stats = PerCpuHashMap::<MapData, LimitKey, PolicerStats>::try_from(
        base.take_map("POLICER_STATS")
            .context("POLICER_STATS missing")?,
    )
    .context("POLICER_STATS has the wrong type")?;

    let oversized_map = PerCpuHashMap::<MapData, u8, OversizedStats>::try_from(
        base.take_map("OVERSIZED").context("OVERSIZED missing")?,
    )
    .context("OVERSIZED has the wrong type")?;

    // 4. Discover TAPs and attach (one loaded object, one link pair per TAP).
    let mut manager = AttachManager::new(base)?;
    let mut taps = Vec::new();
    let mut startup_attach_failures = 0usize;
    match interface::discover_taps(&cfg.bridge) {
        Ok(found) => {
            let (added, failed) = manager.reconcile(&found);
            startup_attach_failures = failed;
            log::info!("initial scan: {added} TAP(s) attached, {failed} failed");
            taps = manager.taps();
        }
        Err(e) => log::warn!("initial TAP discovery failed: {e}"),
    }

    // refresh_interval_ms is validated second-aligned, so this division is exact.
    let tick_secs = cfg.refresh_interval_ms / 1000;
    let config: ConfigArc = Arc::new(ArcSwap::from_pointee(cfg));
    let (config_watch, _) = watch::channel(1u64);
    let mut engine = Engine {
        config: config.clone(),
        config_watch: config_watch.clone(),
        generation: 1,
        config_loaded_at: format_unix_utc(now_unix()),
        last_reload_at: String::new(),
        last_reload_ok: true,
        last_reload_error: String::new(),
        last_config_bytes: initial_config_bytes,
        config_watcher_healthy: true,
        config_watcher_errors_total: 0,
        config_watcher_last_error: String::new(),
        dataplane_degraded: false,
        rollback_failures_total: 0,
        bridge: config.load().bridge.clone(),
        manager,
        taps,
        collector: Collector::new(),
        limiter: Limiter::new(tick_secs),
        last_snapshot: None,
        last_totals: std::collections::HashMap::new(),
        last_policer: std::collections::HashMap::new(),
        last_ipv6: crate::collector::IpStats::default(),
        oversized: (OversizedStats::default(), OversizedStats::default()),
        oversized_map,
        whitelist_capacity,
        monitored,
        limit_policies,
        limit_state,
        swl_log,
        traffic,
        traffic6,
        policer_stats,
        http: crate::metrics::client(),
        push_counters: Arc::new(PushCounters::new()),
        tap_attach_failures_total: startup_attach_failures as u64,
        epoch: std::time::Instant::now(),
    };
    // Apply the initial limiter policy index (no LIMITs yet; just builds lookups).
    let plan = engine
        .limiter
        .plan_reload(&engine.config.load(), engine.now_secs())
        .map_err(anyhow::Error::msg)?;
    engine.limiter.commit_reload(plan);

    // 5. IPC server.
    let _ = std::fs::remove_file(SOCK_PATH);
    let listener = UnixListener::bind(SOCK_PATH).with_context(|| format!("binding {SOCK_PATH}"))?;
    // The socket exposes per-customer bandwidth figures: owner-only.
    std::fs::set_permissions(SOCK_PATH, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("setting permissions on {SOCK_PATH}"))?;
    let (ipc_tx, mut ipc_rx) = mpsc::channel::<IpcReq>(32);
    let conn_permits = Arc::new(tokio::sync::Semaphore::new(MAX_IPC_CONNECTIONS));
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    // Backpressure: wait for a slot instead of spawning without bound;
                    // excess clients queue in the listen backlog.
                    let Ok(permit) = conn_permits.clone().acquire_owned().await else {
                        break; // semaphore closed: shutting down
                    };
                    let tx = ipc_tx.clone();
                    tokio::spawn(async move {
                        let _permit = permit; // held until the connection ends
                        handle_connection(stream, tx).await;
                    });
                }
                Err(e) => {
                    log::warn!("IPC accept error: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    });
    log::info!("IPC listening on {SOCK_PATH}");

    // 6. File watcher (hot reload) + SIGHUP.
    let (reload_tx, mut reload_rx) = mpsc::channel::<WatchMsg>(8);
    let _watcher = spawn_watcher(config_path.clone(), reload_tx.clone())?;

    // 7. Signals.
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sighup = signal(SignalKind::hangup())?;

    // 8. Engine loop. A config change reschedules all three timers immediately
    //    (the scheduler is the component that rebuilds on the watch signal).
    let mut config_rx = config_watch.subscribe();
    let (mut next_collect, mut next_scan, mut next_push) = schedules_from(&engine.config.load());

    log::info!("daemon running (generation {})", engine.generation);
    loop {
        tokio::select! {
            _ = sigint.recv() => {
                log::info!("SIGINT received; shutting down");
                break;
            }
            _ = sigterm.recv() => {
                log::info!("SIGTERM received; shutting down");
                break;
            }
            _ = sighup.recv() => {
                log::info!("SIGHUP received; reloading config");
                let _ = reload_tx.try_send(WatchMsg::Reload);
            }
            maybe = reload_rx.recv() => {
                match maybe {
                    Some(WatchMsg::Reload) => {
                        // File read + parse are blocking; block_in_place keeps the IPC
                        // tasks running on another worker while the engine works.
                        tokio::task::block_in_place(|| engine.reload(&config_path));
                    }
                    Some(WatchMsg::Error(e)) => engine.record_watcher_error(e),
                    None => {}
                }
            }
            r = config_rx.changed() => {
                if r.is_ok() {
                    // The reload applied above changed intervals; rebuild the
                    // schedule now rather than one stale cycle later.
                    (next_collect, next_scan, next_push) = schedules_from(&engine.config.load());
                    log::info!(
                        "config generation {}: timers rescheduled",
                        *config_rx.borrow_and_update()
                    );
                }
            }
            maybe = ipc_rx.recv() => {
                if let Some((req, reply)) = maybe {
                    let resp = engine.handle_request(req);
                    let _ = reply.send(resp);
                }
            }
            _ = tokio::time::sleep_until(next_collect) => {
                // Map iteration is a burst of syscalls; same reasoning as above.
                tokio::task::block_in_place(|| engine.collect_tick());
                next_collect = tokio::time::Instant::now()
                    + Duration::from_millis(engine.config.load().refresh_interval_ms.max(1));
            }
            _ = tokio::time::sleep_until(next_scan) => {
                tokio::task::block_in_place(|| engine.rescan_taps());
                next_scan = tokio::time::Instant::now()
                    + Duration::from_secs(engine.config.load().interface_scan_interval_secs.max(1));
            }
            _ = tokio::time::sleep_until(next_push) => {
                engine.push_metrics();
                next_push = tokio::time::Instant::now()
                    + Duration::from_secs(engine.config.load().metrics_push_interval_secs.max(5));
            }
        }
    }

    // 9. Cleanup: dropping `engine` drops the `AttachManager`, which detaches exactly
    //    the TC links this program created; the unpinned maps die with the process.
    drop(engine);
    let _ = std::fs::remove_file(SOCK_PATH);
    // Release the lock by dropping the fd; the lock file itself stays on disk
    // permanently (see the note at acquisition).
    drop(lock_file);
    log::info!("daemon stopped cleanly");
    Ok(())
}

/// Process-lifetime outcome counters for the metrics push path plus the
/// single-flight flag.
///
/// All counters are monotonic and purely observational: no decision reads them
/// with a happens-before dependency on other data, so `Ordering::Relaxed` is
/// correct for the increments and loads (each thread sees a coherent value
/// eventually; cross-thread freshness is irrelevant for diagnostics). The
/// inflight flag itself still uses an atomic swap/store pair for exclusion.
pub(crate) struct PushCounters {
    inflight: std::sync::atomic::AtomicBool,
    successes: std::sync::atomic::AtomicU64,
    failures: std::sync::atomic::AtomicU64,
    skipped: std::sync::atomic::AtomicU64,
}

impl PushCounters {
    pub(crate) fn new() -> Self {
        Self {
            inflight: std::sync::atomic::AtomicBool::new(false),
            successes: std::sync::atomic::AtomicU64::new(0),
            failures: std::sync::atomic::AtomicU64::new(0),
            skipped: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Take the single-flight slot, or count a skip when a push is already
    /// running. The returned guard releases the slot on every exit path
    /// (normal completion, HTTP error, cancellation, panic unwinding).
    pub(crate) fn try_start(self: &Arc<Self>) -> Option<PushGuard> {
        if self
            .inflight
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            self.skipped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return None;
        }
        Some(PushGuard(self.clone()))
    }

    pub(crate) fn note_success(&self) {
        self.successes
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn note_failure(&self) {
        self.failures
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn successes(&self) -> u64 {
        self.successes.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub(crate) fn failures(&self) -> u64 {
        self.failures.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub(crate) fn skipped(&self) -> u64 {
        self.skipped.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// RAII holder for the in-flight push slot; see `PushCounters::try_start`.
pub(crate) struct PushGuard(Arc<PushCounters>);

impl Drop for PushGuard {
    fn drop(&mut self) {
        self.0
            .inflight
            .store(false, std::sync::atomic::Ordering::Release);
    }
}

/// Open (creating if needed) the lock file at a fixed path and take an exclusive,
/// non-blocking flock. A second live holder fails with a clear error.
fn acquire_instance_lock(path: &str) -> Result<File> {
    let lock_file = File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)
        .with_context(|| format!("cannot create lock file {path}"))?;
    lock_file
        .try_lock()
        .context("another vm-bandwidth-monitor instance is already running")?;
    Ok(lock_file)
}

/// Serve one IPC client: length-delimited JSON request/response until it disconnects.
async fn handle_connection(stream: UnixStream, tx: mpsc::Sender<IpcReq>) {
    // The two directions carry asymmetric limits and get separate codecs: requests
    // are tiny documents (MAX_REQUEST_FRAME protects the engine from abusive
    // clients), while legitimate responses — a full RangeDetail — can reach several
    // MiB (MAX_RESPONSE_FRAME). One shared codec would either admit huge requests or
    // refuse our own large responses (LengthDelimitedCodec::encode enforces the same
    // ceiling on writes).
    let (read_half, write_half) = stream.into_split();
    let mut requests = FramedRead::new(
        read_half,
        LengthDelimitedCodec::builder()
            .length_field_type::<u32>()
            .max_frame_length(ipc::MAX_REQUEST_FRAME)
            .new_codec(),
    );
    let mut responses = FramedWrite::new(
        write_half,
        LengthDelimitedCodec::builder()
            .length_field_type::<u32>()
            .max_frame_length(ipc::MAX_RESPONSE_FRAME)
            .new_codec(),
    );
    while let Some(frame) = requests.next().await {
        let body = match frame {
            Ok(b) => b,
            Err(e) => {
                // Codec-level refusal: frame above MAX_REQUEST_FRAME or malformed
                // length framing. The payload never reached the engine channel. Tell
                // the client why, then drop the connection.
                log::warn!("IPC request rejected by frame limit: {e}");
                let resp = Response::Error {
                    message: format!("request rejected: {e}"),
                };
                if let Err(e) = send_response(&mut responses, &resp).await {
                    log::warn!("could not report IPC request rejection: {e}");
                }
                break;
            }
        };
        let req: Request = match ipc::decode(&body) {
            Ok(r) => r,
            Err(e) => {
                let resp = Response::Error { message: e };
                if let Err(e) = send_response(&mut responses, &resp).await {
                    log::warn!("IPC response failed: {e}");
                    break;
                }
                continue;
            }
        };
        let (reply_tx, reply_rx) = oneshot::channel();
        if tx.send((req, reply_tx)).await.is_err() {
            break;
        }
        let resp = match reply_rx.await {
            Ok(r) => r,
            Err(_) => break,
        };
        if let Err(e) = send_response(&mut responses, &resp).await {
            log::warn!("IPC response failed: {e}");
            break;
        }
    }
}

/// One failure class per way a response can fail to leave the daemon; callers log
/// the whole chain instead of a swallowed bool.
#[derive(Debug)]
enum SendFailure {
    Encode(String),
    TooLarge { body_len: usize, max: usize },
    Write(String),
}

impl std::fmt::Display for SendFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encode(e) => write!(f, "response serialization failed: {e}"),
            Self::TooLarge { body_len, max } => write!(
                f,
                "response body of {body_len} bytes exceeds the {max}-byte protocol limit"
            ),
            Self::Write(e) => write!(f, "socket write failed: {e}"),
        }
    }
}

/// Send one response under the response-side frame ceiling. When the serialized body
/// exceeds MAX_RESPONSE_FRAME the client gets a size-controlled Response::Error
/// instead of a silent disconnect (and the caller still sees TooLarge for its logs).
async fn send_response(
    sink: &mut FramedWrite<OwnedWriteHalf, LengthDelimitedCodec>,
    resp: &Response,
) -> Result<(), SendFailure> {
    let body = serde_json::to_vec(resp).map_err(|e| SendFailure::Encode(e.to_string()))?;
    if body.len() > ipc::MAX_RESPONSE_FRAME {
        let message = format!(
            "response body of {} bytes exceeds the {}-byte protocol limit; the range \
             detail is bounded by collector.map_max_entries — reduce it or query a \
             smaller range",
            body.len(),
            ipc::MAX_RESPONSE_FRAME
        );
        let err_resp = Response::Error { message };
        let err_body =
            serde_json::to_vec(&err_resp).map_err(|e| SendFailure::Encode(e.to_string()))?;
        if let Err(e) = sink.send(err_body.into()).await {
            return Err(SendFailure::Write(e.to_string()));
        }
        return Err(SendFailure::TooLarge {
            body_len: body.len(),
            max: ipc::MAX_RESPONSE_FRAME,
        });
    }
    sink.send(body.into())
        .await
        .map_err(|e| SendFailure::Write(e.to_string()))
}

/// (Re)build the three engine timers from a config snapshot.
fn schedules_from(
    cfg: &ValidatedConfig,
) -> (
    tokio::time::Instant,
    tokio::time::Instant,
    tokio::time::Instant,
) {
    let now = tokio::time::Instant::now();
    (
        now + Duration::from_millis(cfg.refresh_interval_ms.max(1)),
        now + Duration::from_secs(cfg.interface_scan_interval_secs.max(1)),
        now + Duration::from_secs(cfg.metrics_push_interval_secs.max(5)),
    )
}

/// Watch the config file's parent directory; debounce bursts and trigger one reload (§29).
/// Watching the directory (not the file) survives editors that save via atomic rename.
/// `notify-debouncer-full` merges event bursts and tracks renames; we keep the
/// "only real content changes count" semantics so the daemon's own reload reads
/// cannot re-trigger itself.
fn spawn_watcher(
    path: PathBuf,
    reload_tx: mpsc::Sender<WatchMsg>,
) -> Result<Debouncer<notify::RecommendedWatcher, notify_debouncer_full::RecommendedCache>> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let target_name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();

    let (tx, rx) = std::sync::mpsc::channel::<notify_debouncer_full::DebounceEventResult>();
    let mut debouncer =
        notify_debouncer_full::new_debouncer(Duration::from_millis(RELOAD_DEBOUNCE_MS), None, tx)
            .context("creating config debouncer")?;
    debouncer
        .watch(&dir, RecursiveMode::NonRecursive)
        .with_context(|| format!("watching {}", dir.display()))?;

    std::thread::spawn(move || {
        while let Ok(res) = rx.recv() {
            let events = match res {
                Ok(events) => events,
                Err(errs) => {
                    // Surface instead of swallowing: a dead inotify watch leaves the
                    // daemon healthy but permanently deaf to config changes.
                    let msg = errs
                        .iter()
                        .map(|e| e.to_string())
                        .collect::<Vec<_>>()
                        .join("; ");
                    if reload_tx.blocking_send(WatchMsg::Error(msg)).is_err() {
                        break; // engine loop is gone
                    }
                    continue;
                }
            };
            // Only real content changes count: in-place writes, atomic renames onto the
            // target, and (re)creation. Reads (OPEN/CLOSE-read — including this daemon's
            // own reload reads), metadata touches (ATTRIB) and deletions are ignored;
            // accepting them would make the daemon's reload re-trigger itself.
            let relevant = events.iter().any(|e| {
                let content_change = matches!(
                    e.event.kind,
                    EventKind::Modify(ModifyKind::Data(_) | ModifyKind::Name(_))
                ) || matches!(
                    e.event.kind,
                    EventKind::Create(CreateKind::File | CreateKind::Any)
                ) || matches!(
                    e.event.kind,
                    EventKind::Access(AccessKind::Close(AccessMode::Write))
                );
                content_change
                    && e.event
                        .paths
                        .iter()
                        .any(|p| p.file_name().map(|n| n == target_name).unwrap_or(false))
            });
            if relevant && reload_tx.blocking_send(WatchMsg::Reload).is_err() {
                break;
            }
        }
    });
    Ok(debouncer)
}

#[cfg(test)]
mod degraded_message_tests {
    use super::degraded_summary;

    /// The rollback state machine can leave different records in different states
    /// (old policy re-armed, new limit still armed, unarmed with a bounded orphan).
    /// The user-visible summary must not claim one outcome for all affected flows.
    #[test]
    fn summary_names_no_specific_outcome() {
        let msg = degraded_summary(2, 5);
        for banned in ["unarmed", "fail-open", "fail open", "limited"] {
            assert!(
                !msg.to_lowercase().contains(banned),
                "summary over-generalizes: contains {banned:?} in: {msg}"
            );
        }
    }

    #[test]
    fn summary_keeps_counts_and_points_at_details() {
        let msg = degraded_summary(2, 5);
        assert!(msg.contains("2 of 5"));
        assert!(msg.contains("per-step rollback failures"));
        assert!(msg.contains("DEGRADED"));
    }
}

#[cfg(test)]
mod removal_tests {
    use super::{remove_counter_keys, RemovalStats};
    use aya::maps::MapError;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn absent_syscall_error() -> MapError {
        // The variant aya 0.14 produces for ENOENT from bpf_map_delete_elem.
        MapError::SyscallError(aya::sys::SyscallError {
            call: "bpf_map_delete_elem",
            io_error: std::io::Error::from_raw_os_error(2), // ENOENT
        })
    }

    #[test]
    fn all_keys_removed() {
        let calls = AtomicUsize::new(0);
        let stats = remove_counter_keys(
            "TRAFFIC",
            "idle eviction",
            &[1u32, 2, 3],
            |k| k.to_string(),
            |_| {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );
        assert_eq!(
            stats,
            RemovalStats {
                attempted: 3,
                removed: 3,
                failed: 0
            }
        );
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn middle_failure_does_not_stop_the_rest() {
        let stats = remove_counter_keys(
            "TRAFFIC",
            "idle eviction",
            &[1u32, 2, 3],
            |k| k.to_string(),
            |k| {
                if *k == 2 {
                    Err(MapError::InvalidName {
                        name: "injected".to_string(),
                    })
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(
            stats,
            RemovalStats {
                attempted: 3,
                removed: 2,
                failed: 1
            }
        );
    }

    #[test]
    fn all_failures_counted_individually() {
        let stats = remove_counter_keys(
            "TRAFFIC6",
            "stale-TAP prune",
            &[7u32, 8],
            |k| k.to_string(),
            |_| {
                Err(MapError::InvalidName {
                    name: "injected".to_string(),
                })
            },
        );
        assert_eq!(
            stats,
            RemovalStats {
                attempted: 2,
                removed: 0,
                failed: 2
            }
        );
    }

    #[test]
    fn absent_key_counts_as_removed_via_typed_variants_only() {
        // Ok, KeyNotFound and the ENOENT syscall variant all mean "the key is
        // not in the map"; any other variant is a real failure.
        let stats = remove_counter_keys(
            "TRAFFIC",
            "idle eviction",
            &[1u32, 2, 3, 4, 5],
            |k| k.to_string(),
            |k| match *k {
                1 => Ok(()),
                2 => Err(MapError::KeyNotFound),
                3 => Err(MapError::ElementNotFound),
                4 => Err(absent_syscall_error()),
                _ => Err(MapError::InvalidName {
                    name: "injected".to_string(),
                }),
            },
        );
        assert_eq!(
            stats,
            RemovalStats {
                attempted: 5,
                removed: 4,
                failed: 1
            }
        );
    }

    #[test]
    fn failed_removals_never_enter_the_removed_total() {
        // The summary used for logs must be built from actual removal results,
        // not from the input length.
        let stats = remove_counter_keys(
            "TRAFFIC",
            "idle eviction",
            &[1u32, 2, 3, 4],
            |k| k.to_string(),
            |k| {
                if *k % 2 == 0 {
                    Err(MapError::InvalidName {
                        name: "injected".to_string(),
                    })
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(stats.removed + stats.failed, stats.attempted);
        assert_eq!(stats.removed, 2);
        assert_ne!(stats.removed, stats.attempted);
    }
}

#[cfg(test)]
mod reload_commit_tests {
    //! Engine-level (control-plane) tests of the reload commit decision: the
    //! production `apply_and_commit` is driven directly with scripted maps —
    //! no copy of its logic, no Engine construction (needs live aya maps).

    use super::{apply_and_commit, ConfigArc};
    use crate::collector::{Collector, IpStats};
    use crate::txmaps::testmaps::{policy, FakeMaps, FakeWhitelist};
    use arc_swap::ArcSwap;
    use std::collections::HashMap;
    use std::sync::Arc;
    use vm_bandwidth_common::{LimitKey, ALGO_GCRA, DIR_RX, DIR_TX};
    use vm_bandwidth_core::config::{self, ValidatedConfig};
    use vm_bandwidth_core::limiter::{IpTotals, LimitAction, Limiter};

    const IP1: u32 = u32::from_be_bytes([10, 0, 0, 1]); // dropped by the new config
    const IP2: u32 = u32::from_be_bytes([10, 0, 0, 2]); // kept, rate changed

    fn cfg(range: &str, rx_limit: &str, tx_limit: &str) -> ValidatedConfig {
        let text = format!(
            r#"
[network]
bridge = "br0"
[security]
ip_ownership = "external"
acknowledge_external_anti_spoofing = true
[[ip_ranges]]
name = "r1"
range = "{range}"
[ip_ranges.policy]
rx_threshold = "100Kbps"
tx_threshold = "100Kbps"
window = "2s"
trigger_ratio = "100%"
rx_limit = "{rx_limit}"
tx_limit = "{tx_limit}"
limit_duration = "30m"
burst = "1MiB"
"#
        );
        config::parse(&text).expect("test config must parse")
    }

    /// Limiter with two flows LIMITED in both directions, maps pre-armed with
    /// the old policies the way an earlier successful apply would have left them.
    /// The new config drops IP1 (-> Removes) and changes IP2's rates (-> Installs).
    fn setup() -> (Limiter, FakeMaps, Collector, ValidatedConfig) {
        let old_cfg = cfg("10.0.0.1-10.0.0.4", "100Kbps", "110Kbps");
        let mut limiter = Limiter::new(1);
        let plan = limiter.plan_reload(&old_cfg, 0).expect("initial plan");
        limiter.commit_reload(plan);

        let mut totals = HashMap::new();
        for ip in [IP1, IP2] {
            totals.insert(
                ip,
                IpTotals {
                    rx_bytes: 100_000,
                    tx_bytes: 100_000,
                    rx_packets: 10,
                    tx_packets: 10,
                },
            );
        }
        limiter.tick(10, &totals);
        for ip in [IP1, IP2] {
            totals.get_mut(&ip).unwrap().rx_bytes += 200_000;
            totals.get_mut(&ip).unwrap().tx_bytes += 200_000;
        }
        let actions = limiter.tick(11, &totals);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, LimitAction::Install { .. })),
            "flows must trigger LIMITED: {} action(s)",
            actions.len()
        );
        for ip in [IP1, IP2] {
            assert!(limiter.is_limited(ip, DIR_RX));
            assert!(limiter.is_limited(ip, DIR_TX));
        }

        // Dataplane as committed by the earlier successful apply.
        let mut maps = FakeMaps::default();
        let mut journal = crate::txmaps::TxJournal::default();
        for ip in [IP1, IP2] {
            for dir in [DIR_RX, DIR_TX] {
                crate::txmaps::install_limit(
                    &mut maps,
                    &mut journal,
                    LimitKey::new(ip, dir),
                    policy(ALGO_GCRA),
                )
                .unwrap();
            }
        }

        let mut collector = Collector::new();
        // IP1 is NOT covered by the new config: a commit would prune its
        // collector state; a rejected apply must not.
        collector.totals.insert(IP1, IpStats::default());
        (limiter, maps, collector, old_cfg)
    }

    #[test]
    fn failed_apply_commits_nothing_and_reports_rollback_failure() {
        let (mut limiter, mut maps, mut collector, old_cfg) = setup();
        let mut w = FakeWhitelist::default();
        let new_cfg = cfg("10.0.0.2-10.0.0.4", "120Kbps", "130Kbps");
        let plan = limiter.plan_reload(&new_cfg, 12).expect("reload plan");
        // 2 Removes (IP1) + 2 Installs (IP2), deterministic shape.
        assert_eq!(plan.actions.len(), 4);

        let config: ConfigArc = Arc::new(ArcSwap::from_pointee(old_cfg.clone()));
        let old_arc = config.load_full();
        let mut generation = 1u64;

        // Mid-apply failure: whichever IP2 direction installs first fails its
        // state write (both Removes already succeeded). Rollback failure: the
        // re-arm of the removed IP1/RX policy fails. Both injections are keyed
        // by (op, key), so the scenario is independent of map iteration order.
        maps.fail_next("write_fresh_state", LimitKey::new(IP2, DIR_RX));
        maps.fail_next("write_fresh_state", LimitKey::new(IP2, DIR_TX));
        maps.fail_next("arm_policy", LimitKey::new(IP1, DIR_RX));

        let rb = apply_and_commit(
            &mut maps,
            &mut w,
            &mut limiter,
            &mut collector,
            &config,
            &mut generation,
            &super::prefix_set(&old_cfg),
            plan,
            new_cfg.clone(),
        )
        .expect_err("apply must fail");

        // Nothing committed: visible config, generation, limiter and collector
        // all stay exactly where they were.
        assert_eq!(generation, 1, "generation must not advance on failure");
        assert!(
            Arc::ptr_eq(&config.load_full(), &old_arc),
            "visible config must not switch on failure"
        );
        assert!(
            limiter.is_limited(IP1, DIR_RX)
                && limiter.is_limited(IP1, DIR_TX)
                && limiter.is_limited(IP2, DIR_RX)
                && limiter.is_limited(IP2, DIR_TX),
            "limiter must not commit the new plan"
        );
        assert!(
            collector.totals.contains_key(&IP1),
            "collector must not be pruned with the new config"
        );
        // The rollback degraded: the removed IP1/RX policy could not be
        // re-armed. dataplane_degraded and rollback_failures_total in Status
        // are derived from exactly this report.
        assert!(!rb.report.dataplane_consistent);
        assert_eq!(rb.report.failures.len(), 1);
        assert_eq!(rb.report.failures[0].key, LimitKey::new(IP1, DIR_RX));
        assert_eq!(rb.report.failures[0].op, "re-arm removed policy");
        // Everything else rolled back cleanly on top of that one failure:
        // IP1/TX re-armed, both IP2 directions restored to the old policy.
        assert!(maps.policies.contains_key(&LimitKey::new(IP1, DIR_TX)));
        assert!(!maps.policies.contains_key(&LimitKey::new(IP1, DIR_RX)));
        assert_eq!(maps.policies.len(), 3);
        // IP1/RX state stays behind as a bounded orphan; hard invariant holds.
        assert!(maps.artifact(&LimitKey::new(IP1, DIR_RX), ALGO_GCRA));
        maps.assert_invariants();
    }

    #[test]
    fn successful_apply_commits_everything_exactly_once() {
        let (mut limiter, mut maps, mut collector, old_cfg) = setup();
        let mut w = FakeWhitelist::default();
        let new_cfg = cfg("10.0.0.2-10.0.0.4", "120Kbps", "130Kbps");
        let plan = limiter.plan_reload(&new_cfg, 12).expect("reload plan");

        let config: ConfigArc = Arc::new(ArcSwap::from_pointee(old_cfg.clone()));
        let old_arc = config.load_full();
        let mut generation = 1u64;

        apply_and_commit(
            &mut maps,
            &mut w,
            &mut limiter,
            &mut collector,
            &config,
            &mut generation,
            &super::prefix_set(&old_cfg),
            plan,
            new_cfg.clone(),
        )
        .expect("apply must succeed");

        assert_eq!(generation, 2, "generation advances exactly once");
        assert!(
            !Arc::ptr_eq(&config.load_full(), &old_arc),
            "visible config must switch on success"
        );
        assert!(
            !collector.totals.contains_key(&IP1),
            "collector pruned under the new config"
        );
        // Committed limiter state matches the new config: a re-plan against it
        // has nothing left to do (IP1 flows reset, IP2 policies up to date).
        let again = limiter.plan_reload(&new_cfg, 12).expect("re-plan");
        assert!(
            again.actions.is_empty(),
            "committed state must leave nothing to do: {} action(s)",
            again.actions.len()
        );
        // IP1 disarmed entirely, IP2 armed with the NEW rates.
        assert!(!maps.policies.contains_key(&LimitKey::new(IP1, DIR_RX)));
        assert!(!maps.policies.contains_key(&LimitKey::new(IP1, DIR_TX)));
        for (dir, rate) in [(DIR_RX, 120_000u64), (DIR_TX, 130_000)] {
            let p = maps
                .policies
                .get(&LimitKey::new(IP2, dir))
                .expect("armed after commit");
            assert_eq!(p.enabled, 1);
            assert_eq!(p.rate_bps, rate);
        }
        maps.assert_invariants();
        maps.assert_no_orphans();
    }
}

#[cfg(test)]
mod push_guard_tests {
    use crate::daemon::PushCounters;
    use std::sync::Arc;

    #[test]
    fn guard_releases_on_normal_drop() {
        let counters = Arc::new(PushCounters::new());
        {
            let _guard = counters.try_start().expect("slot free");
        }
        assert!(
            counters.try_start().is_some(),
            "slot must be free after the guard drops"
        );
    }

    #[test]
    fn guard_releases_on_panic_unwind() {
        let counters = Arc::new(PushCounters::new());
        let c = counters.clone();
        let result = std::panic::catch_unwind(move || {
            let _guard = c.try_start().expect("slot free");
            panic!("simulated push-task panic");
        });
        assert!(result.is_err());
        assert!(
            counters.try_start().is_some(),
            "slot stuck after panic unwinding"
        );
    }

    #[test]
    fn guard_releases_on_simulated_cancellation() {
        // A cancelled future drops its locals; model that by dropping the guard
        // mid-flight without ever reaching completion.
        let counters = Arc::new(PushCounters::new());
        let guard = counters.try_start().expect("slot free");
        drop(guard);
        assert!(counters.try_start().is_some(), "slot stuck after cancel");
    }

    #[test]
    fn concurrent_start_counts_a_skip_and_keeps_outcomes_separate() {
        let counters = Arc::new(PushCounters::new());
        let guard = counters.try_start().expect("slot free");
        assert!(counters.try_start().is_none(), "second start must skip");
        assert!(counters.try_start().is_none());
        counters.note_success();
        counters.note_failure();
        drop(guard);
        // Outcomes are independent of skips; all counters stay monotonic.
        assert_eq!(counters.successes(), 1);
        assert_eq!(counters.failures(), 1);
        assert_eq!(counters.skipped(), 2);
        assert!(counters.try_start().is_some(), "slot free after drop");
    }
}

#[cfg(test)]
mod lock_tests {
    use super::acquire_instance_lock;

    /// The lock lifecycle without the inode race: a second process/fd fails while the
    /// first holds the lock, succeeds after it is released, and two holders never
    /// coexist. Two separate open()s in one process contend exactly like two
    /// processes (flock is per open file description).
    #[test]
    fn instance_lock_serializes_holders() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("vmbw-lock-test-{}", std::process::id()));
        let path = path.to_str().unwrap();

        // A holds the lock.
        let a = acquire_instance_lock(path).expect("A acquires");
        // B must fail while A holds it.
        assert!(acquire_instance_lock(path).is_err());
        // A exits.
        drop(a);
        // B can now take it.
        let b = acquire_instance_lock(path).expect("B acquires after A exits");
        // And a third contender fails again — never two holders at once.
        assert!(acquire_instance_lock(path).is_err());
        drop(b);
        // The file stays behind on purpose; remove it only inside this test.
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(test)]
mod ipc_tests {
    use super::{handle_connection, IpcReq};
    use futures::StreamExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;
    use tokio::sync::mpsc;
    use tokio_util::codec::{FramedRead, LengthDelimitedCodec};
    use vm_bandwidth_core::ipc::{
        validate_frame_len, IpDetail, RangeDetail, Request, Response, MAX_REQUEST_FRAME,
        MAX_RESPONSE_FRAME,
    };

    /// Client-side framing exactly like the UI: 4-byte BE length + body.
    async fn write_raw(stream: &mut UnixStream, body: &[u8]) {
        stream
            .write_all(&(body.len() as u32).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(body).await.unwrap();
    }

    /// Read one frame, validating the untrusted length BEFORE allocating.
    async fn read_frame(stream: &mut UnixStream, max: usize) -> Vec<u8> {
        let mut lenbuf = [0u8; 4];
        stream.read_exact(&mut lenbuf).await.unwrap();
        let len = validate_frame_len(u32::from_be_bytes(lenbuf), max).unwrap();
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await.unwrap();
        body
    }

    /// One half of a socket pair behind handle_connection; the test side owns the
    /// engine-channel receiver and decides what (if anything) gets answered.
    fn pair() -> (UnixStream, mpsc::Receiver<IpcReq>) {
        let (client, server) = UnixStream::pair().unwrap();
        let (tx, rx) = mpsc::channel::<IpcReq>(8);
        tokio::spawn(handle_connection(server, tx));
        (client, rx)
    }

    fn big_range_detail(ips: u32) -> Response {
        Response::RangeDetail(Box::new(RangeDetail {
            name: "big".to_string(),
            range: "10.0.0.0/8".to_string(),
            ips: (0..ips)
                .map(|i| IpDetail {
                    ip: i,
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }))
    }

    // 1. Small request / small response round-trip.
    #[tokio::test]
    async fn small_roundtrip() {
        let (mut client, mut rx) = pair();
        write_raw(
            &mut client,
            &serde_json::to_vec(&Request::Overview).unwrap(),
        )
        .await;

        let (req, reply) = rx.recv().await.expect("request reached the engine");
        assert!(matches!(req, Request::Overview));
        let status = vm_bandwidth_core::ipc::Status {
            protocol_version: vm_bandwidth_core::ipc::PROTOCOL_VERSION,
            ..Default::default()
        };
        reply.send(Response::Status(Box::new(status))).unwrap();

        let body = read_frame(&mut client, MAX_RESPONSE_FRAME).await;
        match ipc_decode(&body) {
            Response::Status(s) => {
                assert_eq!(s.protocol_version, vm_bandwidth_core::ipc::PROTOCOL_VERSION)
            }
            other => panic!("expected status, got {other:?}"),
        }
    }

    // 2. A legitimate large response (64 KiB < size < 8 MiB) travels intact: the old
    //    single-codec design refused to encode it at all.
    #[tokio::test]
    async fn large_response_between_request_and_response_limits() {
        let (mut client, mut rx) = pair();
        write_raw(
            &mut client,
            &serde_json::to_vec(&Request::Overview).unwrap(),
        )
        .await;

        let (_, reply) = rx.recv().await.unwrap();
        let resp = big_range_detail(400);
        let size = serde_json::to_vec(&resp).unwrap().len();
        assert!(
            size > MAX_REQUEST_FRAME && size < MAX_RESPONSE_FRAME,
            "test payload must sit between the two limits, got {size}"
        );
        reply.send(resp).unwrap();

        let body = read_frame(&mut client, MAX_RESPONSE_FRAME).await;
        match ipc_decode(&body) {
            Response::RangeDetail(d) => assert_eq!(d.ips.len(), 400),
            other => panic!("expected range detail, got {other:?}"),
        }
    }

    // 3. An oversized request is refused by the request-side limit and NEVER reaches
    //    the engine channel; the client gets a meaningful error.
    #[tokio::test]
    async fn oversized_request_refused_before_engine() {
        let (mut client, mut rx) = pair();
        // Any body above MAX_REQUEST_FRAME: the codec refuses before JSON parsing.
        let body = vec![b'x'; MAX_REQUEST_FRAME + 1];
        write_raw(&mut client, &body).await;

        let err = read_frame(&mut client, MAX_RESPONSE_FRAME).await;
        match ipc_decode(&err) {
            Response::Error { message } => {
                assert!(message.contains("request rejected"), "{message}")
            }
            other => panic!("expected error response, got {other:?}"),
        }
        assert!(
            rx.try_recv().is_err(),
            "oversized request must not reach the engine channel"
        );
    }

    // 4. A response above MAX_RESPONSE_FRAME does NOT silently disconnect: the client
    //    receives a size-controlled Response::Error naming the limit.
    #[tokio::test]
    async fn oversized_response_becomes_controlled_error() {
        let (mut client, mut rx) = pair();
        write_raw(
            &mut client,
            &serde_json::to_vec(&Request::Overview).unwrap(),
        )
        .await;

        let (_, reply) = rx.recv().await.unwrap();
        let resp = big_range_detail(26_000);
        assert!(serde_json::to_vec(&resp).unwrap().len() > MAX_RESPONSE_FRAME);
        reply.send(resp).unwrap();

        let body = read_frame(&mut client, MAX_RESPONSE_FRAME).await;
        match ipc_decode(&body) {
            Response::Error { message } => {
                assert!(message.contains("protocol limit"), "{message}");
                assert!(message.contains("map_max_entries"), "{message}");
            }
            other => panic!("expected controlled error, got {other:?}"),
        }
    }

    // 5. Frame-limit boundaries, both directions, pure.
    #[test]
    fn frame_limits_boundaries() {
        for max in [MAX_REQUEST_FRAME, MAX_RESPONSE_FRAME] {
            assert_eq!(validate_frame_len(max as u32 - 1, max), Ok(max - 1));
            assert_eq!(validate_frame_len(max as u32, max), Ok(max));
            assert!(validate_frame_len(max as u32 + 1, max).is_err());
            assert!(validate_frame_len(u32::MAX, max).is_err());
        }
    }

    /// A RangeDetail with an ASCII-padded name: serialized length is base + pad,
    /// so one measurement plus one delta adjustment lands exactly on a target.
    fn padded_range_detail(pad: usize) -> Response {
        Response::RangeDetail(Box::new(RangeDetail {
            name: "a".repeat(pad),
            range: "10.0.0.0/8".to_string(),
            ips: (0..32)
                .map(|i| IpDetail {
                    ip: i,
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }))
    }

    // 6. A response body of EXACTLY MAX_RESPONSE_FRAME round-trips over a real
    //    socket through the daemon's real FramedWrite and a real client codec.
    //    Pure validate_frame_len boundaries are covered above; this exercises the
    //    ceiling on the wire. Payload size is adjusted dynamically against the
    //    actual serde_json output length (no assumed JSON overhead).
    #[tokio::test]
    async fn response_at_exactly_max_frame_round_trips_over_real_socket() {
        let (mut client, mut rx) = pair();
        write_raw(
            &mut client,
            &serde_json::to_vec(&Request::Overview).unwrap(),
        )
        .await;
        let (_, reply) = rx.recv().await.unwrap();

        let mut pad = MAX_RESPONSE_FRAME - 1_000_000;
        let resp = loop {
            let candidate = padded_range_detail(pad);
            let len = serde_json::to_vec(&candidate).unwrap().len();
            if len == MAX_RESPONSE_FRAME {
                break candidate;
            }
            // ASCII padding is byte-linear in the JSON output: one delta lands it.
            pad = (pad as i64 + MAX_RESPONSE_FRAME as i64 - len as i64) as usize;
        };
        reply.send(resp).unwrap();

        // Client side: a real LengthDelimitedCodec configured with the response
        // ceiling, reading the whole frame off the socket.
        let mut framed = FramedRead::new(
            client,
            LengthDelimitedCodec::builder()
                .length_field_type::<u32>()
                .max_frame_length(MAX_RESPONSE_FRAME)
                .new_codec(),
        );
        let frame = framed
            .next()
            .await
            .expect("frame expected")
            .expect("frame must decode at the ceiling");
        assert_eq!(
            frame.len(),
            MAX_RESPONSE_FRAME,
            "body must sit exactly on the response ceiling"
        );
        match serde_json::from_slice::<Response>(&frame).unwrap() {
            Response::RangeDetail(rd) => {
                assert_eq!(rd.ips.len(), 32, "payload content must be intact");
                assert_eq!(rd.name.len(), pad);
                assert!(rd.name.bytes().all(|b| b == b'a'));
            }
            other => panic!("expected range detail, got {other:?}"),
        }
    }

    fn ipc_decode(body: &[u8]) -> Response {
        let v: serde_json::Value = serde_json::from_slice(body).unwrap();
        serde_json::from_value(v.clone()).unwrap_or_else(|_| {
            panic!("undecodable response: {v}");
        })
    }
}
