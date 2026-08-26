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

/// Direction of traffic relative to the VM. Kept as plain `u8` constants so the
/// value is usable identically in `#![no_std]` eBPF code and userspace.
pub const DIR_RX: u8 = 0; // packet is being received by the VM (TAP egress)
pub const DIR_TX: u8 = 1; // packet is being sent by the VM (TAP ingress)

/// Key of the GCRA / limit maps: one limiter per (IPv4, direction).
///
/// Deliberately *not* keyed by ifindex: the same IP+direction must share a single
/// rate budget across all CPUs and whichever TAP the packet currently traverses.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct GcraKey {
    pub ipv4: u32,
    pub direction: u8,
    // Pad to a stable 8-byte layout so the key hashes identically on both sides.
    pub _pad: [u8; 3],
}

impl GcraKey {
    pub fn new(ipv4: u32, direction: u8) -> Self {
        Self {
            ipv4,
            direction,
            _pad: [0; 3],
        }
    }
}

/// A limiter policy installed by the daemon into `LIMIT_POLICIES`.
///
/// eBPF does no policy math beyond the per-packet GCRA increment; the daemon has
/// already resolved inheritance, windows and thresholds. `rate_bps == 0` or
/// `enabled == 0` means "do not police" (fail-open).
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct GcraPolicy {
    pub enabled: u8,
    pub _pad: [u8; 3],
    /// Policed bit rate (bits per second).
    pub rate_bps: u64,
    /// Burst allowance expressed in bytes; converted to a time tolerance in eBPF.
    pub burst_bytes: u64,
}

/// Runtime GCRA state per (IPv4, direction): the Theoretical Arrival Time (TAT).
///
/// In the kernel this value also carries a `struct bpf_spin_lock` (declared in the eBPF
/// object so BTF describes it to the verifier); the userspace view only ever writes it
/// (install/reset) or deletes it, so the lock field is simply carried as zeroed bytes.
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct GcraState {
    pub tat_ns: u64,
    pub lock: u32,
    pub _pad: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TrafficKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TrafficValue {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for GcraKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for GcraPolicy {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for GcraState {}
