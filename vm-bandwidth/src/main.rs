//! vm-bandwidth-monitor: per-IP bandwidth accounting for VMs on a Linux bridge.
//!
//! Pipeline: config.toml → validated IP ranges → eBPF whitelist → TC classifiers on each
//! TAP under the bridge → per-CPU counters → 1 Hz collector → ratatui TUI.

mod bandwidth;
mod collector;
mod config;
mod interface;
mod ip_range;
mod tc;
mod tui;

use std::fs::File;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use aya::maps::{HashMap as AyaHashMap, MapData, PerCpuHashMap};
use aya::{include_bytes_aligned, Ebpf, EbpfLoader};
use clap::Parser;
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;
use vm_bandwidth_common::{TrafficKey, TrafficValue};

use crate::collector::{Collector, Snapshot};
use crate::config::ValidatedConfig;
use crate::interface::Tap;

#[derive(Parser)]
#[command(
    name = "vm-bandwidth-monitor",
    about = "Real-time per-IP bandwidth monitor for VMs behind a Linux bridge (eBPF/TC)"
)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
}

/// Pinned map locations (aya's default pin directory, libbpf-compatible).
const PIN_MONITORED_IPS: &str = "/sys/fs/bpf/MONITORED_IPS";
const PIN_TRAFFIC: &str = "/sys/fs/bpf/TRAFFIC";
const LOCK_PATH: &str = "/run/vm-bandwidth-monitor.lock";

fn main() {
    if let Err(e) = tokio_main() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn tokio_main() -> Result<()> {
    // All BPF and netlink work is blocking and cheap; a small runtime is plenty.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run())
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // 1. Read and validate the configuration. Refuse to start on any problem.
    let cfg = config::load(&cli.config).map_err(anyhow::Error::msg)?;
    log::info!(
        "loaded {} IP range(s) for bridge {}",
        cfg.ranges.len(),
        cfg.bridge
    );

    // 2. Single-instance lock. Dropping the file handle releases it on exit.
    let lock_file = File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(LOCK_PATH)
        .with_context(|| format!("cannot create lock file {LOCK_PATH}"))?;
    lock_file
        .try_lock()
        .context("another vm-bandwidth-monitor instance is already running")?;

    // 3. Start from clean maps: drop pins left by a previous run (safe under the lock),
    //    then load the base object, which creates and pins both maps.
    let _ = std::fs::remove_file(PIN_MONITORED_IPS);
    let _ = std::fs::remove_file(PIN_TRAFFIC);

    let total_ips: u64 = cfg.ranges.iter().map(|r| r.len()).sum();
    // Every whitelisted IP is inserted with its own syscall at startup; keep it sane.
    if total_ips > 1 << 20 {
        bail!("configured IP ranges cover {total_ips} addresses, which is too large for v1");
    }
    let whitelist_capacity = (total_ips.max(1) as u32)
        .saturating_mul(2)
        .next_power_of_two();

    let object: &'static [u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/vm-bandwidth"));
    let mut base = EbpfLoader::new()
        .map_max_entries("TRAFFIC", cfg.map_max_entries)
        .map_max_entries("MONITORED_IPS", whitelist_capacity)
        .load(object)
        .context(
            "failed to load the eBPF object; this program needs root (CAP_BPF + CAP_NET_ADMIN), \
             a kernel with TC eBPF support, and bpffs mounted at /sys/fs/bpf",
        )?;

    // 4. Expand the configured ranges into the eBPF IP whitelist. Only these addresses
    //    ever create counters.
    {
        let mut monitored = AyaHashMap::<_, u32, u8>::try_from(
            base.map_mut("MONITORED_IPS")
                .context("MONITORED_IPS map missing from eBPF object")?,
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
    }

    let traffic = PerCpuHashMap::<MapData, TrafficKey, TrafficValue>::try_from(
        base.take_map("TRAFFIC")
            .context("TRAFFIC map missing from eBPF object")?,
    )
    .context("TRAFFIC has the wrong type")?;

    // 5. Restore the terminal even if a panic tears the TUI down.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        ratatui::restore();
        default_hook(info);
    }));

    let result = run_pipeline(cfg, base, traffic, object).await;

    // 6. Cleanup: dropping attachments (inside run_pipeline) detached our TC filters;
    //    remove the pins so the next start gets fresh counters.
    ratatui::restore();
    let _ = std::fs::remove_file(PIN_MONITORED_IPS);
    let _ = std::fs::remove_file(PIN_TRAFFIC);
    result
}

async fn run_pipeline(
    cfg: ValidatedConfig,
    _base: Ebpf,
    traffic: PerCpuHashMap<MapData, TrafficKey, TrafficValue>,
    object: &'static [u8],
) -> Result<()> {
    // Discover TAPs and attach before the TUI comes up.
    let mut manager = tc::AttachManager::new();
    let taps_shared: Arc<RwLock<Vec<Tap>>> = Arc::new(RwLock::new(Vec::new()));
    match interface::discover_taps(&cfg.bridge) {
        Ok(found) => {
            let (added, failed) = manager.reconcile(&found, object);
            log::info!("initial scan: {} TAP(s) attached, {} failed", added, failed);
            *taps_shared.write().unwrap() = manager.taps();
        }
        Err(e) => log::warn!("initial TAP discovery failed: {e}"),
    }

    let (snap_tx, snap_rx) = mpsc::channel::<Snapshot>(2);
    let (refresh_tx, mut refresh_rx) = mpsc::channel::<()>(1);

    // Periodic TAP rescan: attach new VMs, detach gone ones, never restart required.
    let bridge = cfg.bridge.clone();
    let scan_interval = Duration::from_secs(cfg.interface_scan_interval_secs);
    let taps_for_scan = taps_shared.clone();
    let scan_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(scan_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        interval.tick().await; // first tick fires immediately; we already scanned
        loop {
            interval.tick().await;
            match interface::discover_taps(&bridge) {
                Ok(found) => {
                    let (added, failed) = manager.reconcile(&found, object);
                    if added > 0 || failed > 0 {
                        log::info!("scan: {added} attached, {failed} failed");
                    }
                    *taps_for_scan.write().unwrap() = manager.taps();
                }
                Err(e) => log::warn!("TAP scan failed: {e}"),
            }
        }
    });

    // 1 Hz collector: read per-CPU maps, compute rates, snapshot per range.
    let ranges = cfg.ranges.clone();
    let poll_interval = Duration::from_millis(cfg.refresh_interval_ms.max(1));
    let collect_task = tokio::spawn(async move {
        let mut collector = Collector::new();
        let mut interval = tokio::time::interval(poll_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                maybe = refresh_rx.recv() => {
                    if maybe.is_none() {
                        break;
                    }
                }
            }
            let taps = taps_shared.read().unwrap().clone();
            let snapshot = collector.poll(&traffic, &taps, &ranges);
            // Bounded channel: drop the stale snapshot if the TUI fell behind.
            let _ = snap_tx.try_send(snapshot);
        }
    });

    let result = tui::run(snap_rx, refresh_tx, &cfg).await;

    // Aborting the scan task drops the AttachManager, which detaches our TC filters.
    scan_task.abort();
    collect_task.abort();
    result
}
