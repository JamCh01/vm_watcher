//! Long-running daemon: eBPF lifecycle, traffic collection, rolling-window threshold
//! evaluation, GCRA limit enforcement, config hot reload and the read-only IPC server.
//!
//! A single "engine" task owns every mutable piece of state (eBPF maps, TAP attachments,
//! the collector, the limiter). Everything else — the IPC server, the file watcher, signal
//! handling — talks to it through bounded channels, so there is exactly one writer and no
//! shared-mutable locking.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use aya::maps::{HashMap as AyaHashMap, MapData, PerCpuHashMap};
use futures::{SinkExt, StreamExt};
use notify::event::{AccessKind, AccessMode, CreateKind, EventKind, ModifyKind};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use vm_bandwidth_common::{
    LimitKey, LimitPolicy, LimitState, SwlRing, TrafficKey, TrafficValue, ALGO_SLIDING_WINDOW_LOG,
    DIR_RX, DIR_TX,
};

use vm_bandwidth_core::config::{self, ValidatedConfig};
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

/// All the eBPF + runtime state the engine owns.
struct Engine {
    cfg: ValidatedConfig,
    generation: u64,
    config_loaded_at: String,
    last_reload_at: String,
    last_reload_ok: bool,
    last_reload_error: String,
    /// Raw bytes of the last successfully applied config (dedup spurious triggers).
    last_config_bytes: Vec<u8>,

    bridge: String,
    manager: AttachManager,
    taps: Vec<Tap>,

    collector: Collector,
    limiter: Limiter,
    last_snapshot: Option<crate::collector::Snapshot>,
    /// Last poll's cumulative per-IP counters, for the VictoriaMetrics push.
    last_totals: std::collections::HashMap<u32, vm_bandwidth_core::limiter::IpTotals>,

    monitored: AyaHashMap<MapData, u32, u8>,
    #[allow(dead_code)] // kept alive so its map fd stays open
    limit_policies: AyaHashMap<MapData, LimitKey, LimitPolicy>,
    limit_state: AyaHashMap<MapData, LimitKey, LimitState>,
    /// Bounded sliding-window-log rings; only populated for flows limited with
    /// the `sliding_window_log` algorithm.
    swl_log: AyaHashMap<MapData, LimitKey, SwlRing>,
    traffic: PerCpuHashMap<MapData, TrafficKey, TrafficValue>,

    epoch: std::time::Instant,
}

impl Engine {
    fn now_secs(&self) -> u64 {
        self.epoch.elapsed().as_secs()
    }

    fn collect_tick(&mut self) {
        let ranges = self.cfg.ip_ranges();
        let PollResult { snapshot, totals } = self.collector.poll(&self.traffic, &ranges);
        let now = self.now_secs();
        let actions = self.limiter.tick(now, &totals);
        self.apply_limit_actions(&actions);
        self.last_totals = totals;
        self.last_snapshot = Some(snapshot);
    }

    /// Push cumulative per-IP counters to VictoriaMetrics (no-op when disabled).
    /// A push failure is logged and skipped; the next interval simply retries.
    fn push_metrics(&self) {
        if !self.cfg.metrics_enabled {
            return;
        }
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let lines =
            crate::metrics::render_prom_lines(&self.last_totals, |ip| self.range_name(ip), now_ms);
        if lines.is_empty() {
            return;
        }
        if let Err(e) = crate::metrics::push(&self.cfg.metrics_url, &lines) {
            log::warn!("metrics push to {} failed: {e:#}", self.cfg.metrics_url);
        } else {
            log::debug!("metrics push: {} line(s)", lines.lines().count());
        }
    }

    fn range_name(&self, ip: u32) -> String {
        self.cfg
            .ranges
            .iter()
            .find(|r| (r.inner.start..=r.inner.end).contains(&ip))
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

    fn apply_limit_actions(&mut self, actions: &[LimitAction]) {
        for action in actions {
            match action {
                LimitAction::Install {
                    ipv4,
                    direction,
                    rate_bps,
                    burst_bytes,
                    algorithm,
                    window_ns,
                } => {
                    let key = LimitKey::new(*ipv4, *direction);
                    // When the flow was previously limited with the sliding-window-log
                    // algorithm and now switches away from it, its log ring is dead weight.
                    let was_swl = self
                        .limit_policies
                        .get(&key, 0)
                        .map(|p: LimitPolicy| p.algorithm == ALGO_SLIDING_WINDOW_LOG)
                        .unwrap_or(false);
                    if was_swl && *algorithm != ALGO_SLIDING_WINDOW_LOG {
                        let _ = self.swl_log.remove(&key);
                    }
                    let policy = LimitPolicy {
                        enabled: 1,
                        _pad0: [0; 3],
                        algorithm: *algorithm,
                        rate_bps: *rate_bps,
                        burst_bytes: *burst_bytes,
                        window_ns: *window_ns,
                    };
                    match self.limit_policies.insert(key, policy, 0) {
                        Ok(()) => {
                            // (Re)create the runtime state so the new policy starts clean;
                            // the data path never creates lock-bearing values.
                            let fresh = LimitState::default();
                            if *algorithm == ALGO_SLIDING_WINDOW_LOG {
                                if let Err(e) = self.swl_log.insert(key, SwlRing::default(), 0) {
                                    log::error!(
                                        "failed to init sliding-window log for {}: {e}",
                                        std::net::Ipv4Addr::from(*ipv4)
                                    );
                                }
                            } else if let Err(e) = self.limit_state.insert(key, fresh, 0) {
                                log::error!(
                                    "failed to init limit state for {}: {e}",
                                    std::net::Ipv4Addr::from(*ipv4)
                                );
                            }
                            log::info!(
                                "LIMITED {} dir={} algo={} at {} bps (burst {} B, window {} ns)",
                                std::net::Ipv4Addr::from(*ipv4),
                                direction,
                                Self::algorithm_name(*algorithm),
                                rate_bps,
                                burst_bytes,
                                window_ns
                            );
                        }
                        Err(e) => log::error!(
                            "failed to install limit for {}: {e}",
                            std::net::Ipv4Addr::from(*ipv4)
                        ),
                    }
                }
                LimitAction::Remove { ipv4, direction } => {
                    let key = LimitKey::new(*ipv4, *direction);
                    let _ = self.limit_policies.remove(&key);
                    let _ = self.limit_state.remove(&key);
                    let _ = self.swl_log.remove(&key);
                    log::info!(
                        "back to NORMAL {} dir={}",
                        std::net::Ipv4Addr::from(*ipv4),
                        direction
                    );
                }
            }
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
        self.last_reload_ok = true;
        self.last_reload_error.clear();
        self.config_loaded_at = stamp;
        self.last_config_bytes = bytes;
        log::info!("config reload succeeded; generation {}", self.generation);
    }

    /// Apply an already-validated config: reconcile whitelist, policies and limiter state.
    fn apply_config(&mut self, new_cfg: ValidatedConfig) -> Result<()> {
        if new_cfg.bridge != self.bridge {
            anyhow::bail!(
                "changing network.bridge ({} -> {}) is not supported by hot reload;                  restart the daemon instead",
                self.bridge,
                new_cfg.bridge
            );
        }
        let now = self.now_secs();
        let old_ips = ip_set(&self.cfg);
        let new_ips = ip_set(&new_cfg);

        // §27 ordering — additions write the whitelist first ...
        for ip in new_ips.difference(&old_ips) {
            self.monitored
                .insert(*ip, 1u8, 0)
                .with_context(|| format!("whitelisting {ip}"))?;
        }

        // ... reconcile policies / limiter (returns map actions for LIMITED flows) ...
        let actions = self
            .limiter
            .apply_config(&new_cfg, now)
            .map_err(anyhow::Error::msg)?;
        self.apply_limit_actions(&actions);

        // ... and deletions drop the whitelist last.
        for ip in old_ips.difference(&new_ips) {
            let _ = self.monitored.remove(ip);
        }

        self.collector.prune_ips(&new_ips);
        self.cfg = new_cfg;
        Ok(())
    }

    // ----- IPC response builders -----

    fn build_status(&self) -> Status {
        let mut ranges = Vec::new();
        if let Some(snap) = &self.last_snapshot {
            for (i, rs) in snap.ranges.iter().enumerate() {
                let limited = self
                    .cfg
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
                });
            }
        }
        Status {
            generation: self.generation,
            config_loaded_at: self.config_loaded_at.clone(),
            last_reload_at: self.last_reload_at.clone(),
            last_reload_ok: self.last_reload_ok,
            last_reload_error: self.last_reload_error.clone(),
            bridge: self.bridge.clone(),
            tap_count: self.taps.len(),
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

fn state_label(limited: bool) -> String {
    if limited {
        "LIMITED".to_string()
    } else {
        "NORMAL".to_string()
    }
}

fn ip_set(cfg: &ValidatedConfig) -> HashSet<u32> {
    let mut set = HashSet::new();
    for range in &cfg.ranges {
        for ip in range.start..=range.end {
            set.insert(ip);
        }
    }
    set
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
    if total_ips > 1 << 20 {
        bail!("configured IP ranges cover {total_ips} addresses, which is too large for v1");
    }
    let whitelist_capacity = (total_ips.max(1) as u32)
        .saturating_mul(2)
        .next_power_of_two();

    let mut base = aya::EbpfLoader::new()
        .map_max_entries("TRAFFIC", cfg.map_max_entries)
        .map_max_entries("MONITORED_IPS", whitelist_capacity)
        .map_max_entries("LIMIT_POLICIES", cfg.map_max_entries)
        .map_max_entries("LIMIT_STATE", cfg.map_max_entries)
        .map_max_entries("SWL_LOG", cfg.map_max_entries)
        .load(object)
        .context(
            "failed to load the eBPF object; this program needs root (CAP_BPF + CAP_NET_ADMIN), \
             a kernel with TC eBPF support, and bpffs mounted at /sys/fs/bpf",
        )?;

    let mut monitored = AyaHashMap::<_, u32, u8>::try_from(
        base.take_map("MONITORED_IPS")
            .context("MONITORED_IPS map missing")?,
    )
    .context("MONITORED_IPS has the wrong type")?;
    for range in &cfg.ranges {
        for ip in range.start..=range.end {
            monitored
                .insert(ip, 1u8, 0)
                .with_context(|| format!("inserting whitelist IP {ip}"))?;
        }
    }
    log::info!("whitelisted {total_ips} IPv4 address(es)");

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

    let tick_secs = (cfg.refresh_interval_ms / 1000).max(1);
    let mut engine = Engine {
        generation: 1,
        config_loaded_at: format_unix_utc(now_unix()),
        last_reload_at: String::new(),
        last_reload_ok: true,
        last_reload_error: String::new(),
        last_config_bytes: initial_config_bytes,
        bridge: cfg.bridge.clone(),
        manager,
        taps,
        collector: Collector::new(),
        limiter: Limiter::new(tick_secs),
        last_snapshot: None,
        last_totals: std::collections::HashMap::new(),
        monitored,
        limit_policies,
        limit_state,
        swl_log,
        traffic,
        epoch: std::time::Instant::now(),
        cfg,
    };
    // Apply the initial limiter policy index (no LIMITs yet; just builds lookups).
    let _ = engine
        .limiter
        .apply_config(&engine.cfg.clone(), engine.now_secs())
        .map_err(anyhow::Error::msg)?;

    // 5. IPC server.
    let _ = std::fs::remove_file(SOCK_PATH);
    let listener = UnixListener::bind(SOCK_PATH).with_context(|| format!("binding {SOCK_PATH}"))?;
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
    let (reload_tx, mut reload_rx) = mpsc::channel::<()>(8);
    let _watcher = spawn_watcher(config_path.clone(), reload_tx.clone())?;

    // 7. Signals.
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sighup = signal(SignalKind::hangup())?;

    // 8. Engine loop.
    let mut next_collect =
        tokio::time::Instant::now() + Duration::from_millis(engine.cfg.refresh_interval_ms.max(1));
    let mut next_scan = tokio::time::Instant::now()
        + Duration::from_secs(engine.cfg.interface_scan_interval_secs.max(1));
    let mut next_push = tokio::time::Instant::now()
        + Duration::from_secs(engine.cfg.metrics_push_interval_secs.max(5));

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
                let _ = reload_tx.try_send(());
            }
            maybe = reload_rx.recv() => {
                if maybe.is_some() {
                    engine.reload(&config_path);
                }
            }
            maybe = ipc_rx.recv() => {
                if let Some((req, reply)) = maybe {
                    let resp = engine.handle_request(req);
                    let _ = reply.send(resp);
                }
            }
            _ = tokio::time::sleep_until(next_collect) => {
                engine.collect_tick();
                next_collect = tokio::time::Instant::now()
                    + Duration::from_millis(engine.cfg.refresh_interval_ms.max(1));
            }
            _ = tokio::time::sleep_until(next_scan) => {
                engine.rescan_taps();
                next_scan = tokio::time::Instant::now()
                    + Duration::from_secs(engine.cfg.interface_scan_interval_secs.max(1));
            }
            _ = tokio::time::sleep_until(next_push) => {
                engine.push_metrics();
                next_push = tokio::time::Instant::now()
                    + Duration::from_secs(engine.cfg.metrics_push_interval_secs.max(5));
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

/// Watch the config file's parent directory; debounce bursts and trigger one reload (§29).
/// Watching the directory (not the file) survives editors that save via atomic rename.
fn spawn_watcher(path: PathBuf, reload_tx: mpsc::Sender<()>) -> Result<RecommendedWatcher> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let target_name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();

    let (tx, rx) = std::sync::mpsc::channel::<notify::Result<Event>>();
    let mut watcher = notify::recommended_watcher(move |res| {
        let _ = tx.send(res);
    })
    .context("creating file watcher")?;
    watcher
        .watch(&dir, RecursiveMode::NonRecursive)
        .with_context(|| format!("watching {}", dir.display()))?;

    std::thread::spawn(move || {
        while let Ok(res) = rx.recv() {
            let Ok(event) = res else { continue };
            // Only real content changes count: in-place writes, atomic renames onto the
            // target, and (re)creation. Reads (OPEN/CLOSE-read — including this daemon's
            // own reload reads), metadata touches (ATTRIB) and deletions are ignored;
            // accepting them would make the daemon's reload re-trigger itself.
            let content_change = matches!(
                event.kind,
                EventKind::Modify(ModifyKind::Data(_) | ModifyKind::Name(_))
            ) || matches!(
                event.kind,
                EventKind::Create(CreateKind::File | CreateKind::Any)
            ) || matches!(
                event.kind,
                EventKind::Access(AccessKind::Close(AccessMode::Write))
            );
            let touches_config = event
                .paths
                .iter()
                .any(|p| p.file_name().map(|n| n == target_name).unwrap_or(false));
            if !content_change || !touches_config {
                continue;
            }
            // Trailing-edge debounce: keep absorbing events as long as they keep
            // arriving within the window, then fire one reload once things go quiet.
            // A single save (open/write/close, atomic rename, multi-chunk writes)
            // collapses to one reload.
            loop {
                std::thread::sleep(Duration::from_millis(RELOAD_DEBOUNCE_MS));
                let mut more = false;
                while rx.try_recv().is_ok() {
                    more = true;
                }
                if !more {
                    break;
                }
            }
            if reload_tx.blocking_send(()).is_err() {
                break;
            }
        }
    });
    Ok(watcher)
}
