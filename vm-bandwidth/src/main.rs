//! vm-bandwidth-monitor: per-IP bandwidth accounting + rate limiting with selectable
//! algorithms for VMs on a Linux bridge (eBPF/TC), with a long-running daemon and a
//! read-only `--ui` client.
//!
//! Modes: default runs the daemon (eBPF, collection, limiting, hot reload, IPC server);
//! `--ui` runs a ratatui client that connects to a running daemon.

mod collector;
mod daemon;
mod interface;
mod metrics;
mod tc;
mod tui;
mod ui;

use std::path::PathBuf;

use anyhow::Result;
use aya::include_bytes_aligned;
use clap::Parser;

#[derive(Parser)]
#[command(
    name = "vm-bandwidth-monitor",
    about = "Per-IP bandwidth monitoring and GCRA rate limiting for VMs behind a Linux bridge (eBPF/TC)"
)]
struct Cli {
    /// Path to the TOML configuration file (daemon mode).
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,

    /// Run the read-only TUI client that connects to a running daemon. Never loads eBPF.
    #[arg(long)]
    ui: bool,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    if cli.ui {
        // The UI prints errors to the normal terminal (no raw mode yet).
        return ui::run_ui(cli.config);
    }

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    raise_fd_limit();

    let object: &'static [u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/vm-bandwidth"));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(daemon::run_daemon(cli.config, object))
}

/// aya keeps roughly a dozen file descriptors open per attached TAP (program, map and
/// link fds), so a bridge with many VMs easily exceeds the default 1024 soft limit.
/// When the limit runs out the daemon cannot open new fds and misbehaves. Claim the hard
/// limit up front so large hosts work.
fn raise_fd_limit() -> u64 {
    let mut rlim = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    let (cur, max) = unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, rlim.as_mut_ptr()) != 0 {
            return 0;
        }
        let r = rlim.assume_init();
        (r.rlim_cur, r.rlim_max)
    };
    let want = max.min(1 << 20);
    if cur >= want {
        return cur;
    }
    let raised = libc::rlimit {
        rlim_cur: want,
        rlim_max: max,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } == 0 {
        log::info!("raised open-file limit from {cur} to {want}");
        want
    } else {
        log::warn!("open-file limit is {cur} and could not be raised; large hosts may exhaust it");
        cur
    }
}
