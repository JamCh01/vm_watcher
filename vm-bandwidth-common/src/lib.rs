//! Data structures shared between the eBPF programs and userspace.
#![no_std]

/// Key of the TRAFFIC map: one counter set per (interface, IPv4) pair.
///
/// The ifindex comes first so the layout matches the requirement document.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TrafficKey {
    pub ifindex: u32,
    pub ipv4: u32,
}

/// Monotonic byte/packet counters. Userspace computes rates from deltas.
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct TrafficValue {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TrafficKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TrafficValue {}
