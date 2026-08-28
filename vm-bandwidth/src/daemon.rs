//! Long-running daemon: eBPF lifecycle, traffic collection, rolling-window threshold
//! evaluation, rate-limit enforcement with selectable algorithms, config hot reload and
//! the read-only IPC server.
//!
//! A single "engine" task owns every mutable piece of state (eBPF maps, TAP attachments,
//! the collector, the limiter). Everything else — the IPC server, the file watcher, signal
//! handling — talks to it through bounded channels, so there is exactly one writer and no
//! shared-mutable locking.

use std::collections::HashSet;
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
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use vm_bandwidth_common::{
    LimitKey, LimitPolicy, LimitState, PolicerStats, SwlRing, TrafficKey, TrafficValue,
    ALGO_SLIDING_WINDOW_LOG, DIR_RX, DIR_TX,
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

/// Refuse IPC frames larger than this (guards against a misbehaving client).
const MAX_FRAME: usize = 64 * 1024 * 1024;
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
    /// Affected flows are unarmed (fail-open) until they re-trigger; the flag stays
    /// on so operators can see the degradation instead of it being swallowed.
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
    /// At most one metrics push in flight (see push_metrics).
    push_inflight: Arc<std::sync::atomic::AtomicBool>,

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
        for key in &stale_traffic {
            let _ = self.traffic.remove(key);
        }
        for key in &stale_traffic6 {
            let _ = self.traffic6.remove(key);
        }
        if !(stale_traffic.is_empty() && stale_traffic6.is_empty()) {
            log::debug!(
                "evicted {} idle TRAFFIC / {} idle TRAFFIC6 key(s)",
                stale_traffic.len(),
                stale_traffic6.len()
            );
        }
        let now = self.now_secs();
        let actions = self.limiter.tick(now, &totals);
        if !actions.is_empty() {
            let mut journal = crate::txmaps::TxJournal::default();
            if let Err(e) = self.execute_limit_actions(&actions, &mut journal) {
                // A half-applied batch is worse than none: roll the dataplane back and
                // let the flows re-evaluate from NORMAL on their next threshold cross.
                self.rollback_map_apply(&journal);
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
        if lines.is_empty() {
            return;
        }
        if self
            .push_inflight
            .swap(true, std::sync::atomic::Ordering::Acquire)
        {
            log::debug!("metrics push skipped: previous push still in flight");
            return;
        }
        let flag = self.push_inflight.clone();
        let http = self.http.clone();
        let url = cfg.metrics_url.clone();
        tokio::spawn(async move {
            let result = crate::metrics::push(&http, &url, &lines).await;
            flag.store(false, std::sync::atomic::Ordering::Release);
            match result {
                Ok(()) => log::debug!("metrics push: {} line(s)", lines.lines().count()),
                Err(e) => log::warn!("metrics push to {url} failed: {e:#}"),
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
                    for key in &stale {
                        let _ = self.traffic.remove(key);
                    }
                    if !stale.is_empty() {
                        log::debug!("pruned {} stale TRAFFIC key(s)", stale.len());
                    }
                    self.collector.prune_ifindexes(&new_ifindexes);
                }
                self.taps = new_taps;
            }
            Err(e) => log::warn!("TAP scan failed: {e}"),
        }
    }

    /// Execute limit actions against the eBPF maps transactionally via the
    /// [`txmaps`] layer: removes first (they free capacity), installs after. For each
    /// flow the order is disarm -> clear foreign artifacts -> fresh state -> arm LAST;
    /// the journal exists before the first destructive write of every action.
    fn execute_limit_actions(
        &mut self,
        actions: &[LimitAction],
        journal: &mut crate::txmaps::TxJournal,
    ) -> Result<()> {
        let mut maps = EngineMaps {
            policies: &mut self.limit_policies,
            state: &mut self.limit_state,
            swl: &mut self.swl_log,
            policer: &mut self.policer_stats,
        };

        // Pass 1: removals.
        for action in actions {
            let LimitAction::Remove { ipv4, direction } = action else {
                continue;
            };
            let key = LimitKey::new(*ipv4, *direction);
            let addr = std::net::Ipv4Addr::from(*ipv4);
            crate::txmaps::remove_limit(&mut maps, journal, key)
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
            crate::txmaps::install_limit(&mut maps, journal, key, policy)
                .with_context(|| format!("installing limit policy for {addr} dir={direction}"))?;
            log::info!(
                "LIMITED {} dir={} algo={} at {} bps (burst {} B, window {} ns)",
                addr,
                direction,
                Self::algorithm_name(*algorithm),
                rate_bps,
                burst_bytes,
                window_ns
            );
        }
        Ok(())
    }

    /// Play the journal back in reverse and surface the outcome. Never silent: a
    /// failed step logs at error severity and flags the dataplane degraded (affected
    /// flows are unarmed / fail-open until they re-trigger).
    fn rollback_map_apply(
        &mut self,
        journal: &crate::txmaps::TxJournal,
    ) -> crate::txmaps::RollbackReport {
        let mut maps = EngineMaps {
            policies: &mut self.limit_policies,
            state: &mut self.limit_state,
            swl: &mut self.swl_log,
            policer: &mut self.policer_stats,
        };
        let mut wl = EngineWhitelist(&mut self.monitored);
        let report = crate::txmaps::rollback_journal(&mut maps, &mut wl, journal);
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
                "dataplane DEGRADED after rollback: {} of {} step(s) failed;                  affected flows are unarmed (fail-open) until they re-trigger",
                report.failures.len(),
                report.attempted
            );
        }
        report
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

        self.generation += 1;
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

        let mut journal = crate::txmaps::TxJournal::default();
        if let Err(e) = self.apply_maps(&plan.actions, &old_prefixes, &new_prefixes, &mut journal) {
            self.rollback_map_apply(&journal);
            return Err(e);
        }

        // Commit phase: limiter internals, then collector, then the visible switch.
        self.limiter.commit_reload(plan);
        self.collector.prune_ips(&new_cfg.ip_ranges());
        self.config.store(Arc::new(new_cfg));
        Ok(())
    }

    /// §27 ordering with journal bookkeeping: whitelist additions first, limit-map
    /// actions second, whitelist removals last. Each successful operation is
    /// journaled immediately, so any mid-way failure rolls back exactly what ran.
    fn apply_maps(
        &mut self,
        actions: &[LimitAction],
        old_prefixes: &HashSet<Cidr>,
        new_prefixes: &HashSet<Cidr>,
        journal: &mut crate::txmaps::TxJournal,
    ) -> Result<()> {
        let additions: Vec<Cidr> = new_prefixes.difference(old_prefixes).copied().collect();
        {
            let mut wl = EngineWhitelist(&mut self.monitored);
            crate::txmaps::apply_whitelist_additions(&mut wl, journal, &additions)
                .context("whitelisting new prefixes")?;
        }
        self.execute_limit_actions(actions, journal)?;
        let removals: Vec<Cidr> = old_prefixes.difference(new_prefixes).copied().collect();
        {
            let mut wl = EngineWhitelist(&mut self.monitored);
            crate::txmaps::apply_whitelist_removals(&mut wl, journal, &removals)
                .context("dropping removed whitelist prefixes")?;
        }
        Ok(())
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
fn prefix_set(cfg: &ValidatedConfig) -> HashSet<Cidr> {
    cfg.ranges.iter().flat_map(|r| r.inner.cidrs()).collect()
}

/// Entry point for daemon mode.
pub async fn run_daemon(config_path: PathBuf, object: &'static [u8]) -> Result<()> {
    use std::fs::File;

    // 1. Load and validate the initial config. Refuse to start on any problem.
    let cfg = config::load(&config_path).map_err(anyhow::Error::msg)?;
    let initial_config_bytes = std::fs::read(&config_path)?;
    log::info!(
        "loaded {} IP range(s) for bridge {}",
        cfg.ranges.len(),
        cfg.bridge
    );

    // 2. Single-instance lock.
    let lock_file = File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(LOCK_PATH)
        .with_context(|| format!("cannot create lock file {LOCK_PATH}"))?;
    lock_file
        .try_lock()
        .context("another vm-bandwidth-monitor instance is already running")?;

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
        .map_max_entries("SWL_LOG", cfg.map_max_entries)
        .map_max_entries("POLICER_STATS", cfg.map_max_entries)
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

    // 4. Discover TAPs and attach (one loaded object, one link pair per TAP).
    let mut manager = AttachManager::new(base)?;
    let mut taps = Vec::new();
    match interface::discover_taps(&cfg.bridge) {
        Ok(found) => {
            let (added, failed) = manager.reconcile(&found);
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
        whitelist_capacity,
        monitored,
        limit_policies,
        limit_state,
        swl_log,
        traffic,
        traffic6,
        policer_stats,
        http: crate::metrics::client(),
        push_inflight: Arc::new(std::sync::atomic::AtomicBool::new(false)),
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
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let tx = ipc_tx.clone();
                    tokio::spawn(handle_connection(stream, tx));
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
    drop(lock_file);
    let _ = std::fs::remove_file(LOCK_PATH);
    log::info!("daemon stopped cleanly");
    Ok(())
}

/// Serve one IPC client: length-delimited JSON request/response until it disconnects.
async fn handle_connection(stream: UnixStream, tx: mpsc::Sender<IpcReq>) {
    let mut framed = Framed::new(
        stream,
        LengthDelimitedCodec::builder()
            .length_field_type::<u32>()
            .max_frame_length(MAX_FRAME)
            .new_codec(),
    );
    while let Some(frame) = framed.next().await {
        let body = match frame {
            Ok(b) => b,
            Err(_) => break,
        };
        let req: Request = match ipc::decode(&body) {
            Ok(r) => r,
            Err(e) => {
                let resp = Response::Error { message: e };
                send_response(&mut framed, &resp).await;
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
        if !send_response(&mut framed, &resp).await {
            break;
        }
    }
}

async fn send_response(
    framed: &mut Framed<UnixStream, LengthDelimitedCodec>,
    resp: &Response,
) -> bool {
    let body = match serde_json::to_vec(resp) {
        Ok(b) => b,
        Err(_) => return false,
    };
    framed.send(body.into()).await.is_ok()
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
