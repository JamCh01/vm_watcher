//! Pure domain logic for vm-bandwidth-monitor: config parsing/validation, IP ranges,
//! limiter policies, unit parsing, rolling windows, limiter state machine and IPC types.
//!
//! This crate deliberately has no dependency on `aya` or any eBPF runtime so the whole
//! policy/config/window/limiter layer can be unit-tested on any host.

pub mod bandwidth;
pub mod config;
pub mod ip_range;
pub mod ipc;
pub mod limiter;
pub mod policy;
pub mod timefmt;
pub mod units;
pub mod window;
