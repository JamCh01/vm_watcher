//! Data structures shared between the eBPF programs and userspace.
#![no_std]

/// Key of the TRAFFIC map: one counter set per (interface, IPv4) pair.
///
/// The ifindex comes first so the layout matches the requirement document.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TrafficKey {
    pub ifindex: u32,
    pub ipv4: u32,
}

/// Key of the TRAFFIC6 map: one counter set per (interface, IPv6) pair.
/// IPv6 is counted but never policed (there is no IPv6 limit policy).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TrafficKey6 {
    pub ifindex: u32,
    pub ipv6: [u8; 16],
}

/// Monotonic byte/packet counters. Userspace computes rates from deltas.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TrafficValue {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

/// Cumulative policer verdict counters for one (ipv4, direction) flow, per-CPU.
/// `TRAFFIC` records demand (what arrived); this records what the policer actually
/// let through versus dropped. Only flows with an active policy get entries.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PolicerStats {
    pub passed_bytes: u64,
    pub passed_packets: u64,
    pub dropped_bytes: u64,
    pub dropped_packets: u64,
}

/// Direction of traffic relative to the VM. Kept as plain `u8` constants so the
/// value is usable identically in `#![no_std]` eBPF code and userspace.
pub const DIR_RX: u8 = 0; // packet is being received by the VM (TAP egress)
pub const DIR_TX: u8 = 1; // packet is being sent by the VM (TAP ingress)

/// Rate-limiting algorithm selected per IP range. The daemon writes the tag into
/// `LIMIT_POLICIES`; the eBPF data path dispatches on it per packet.
///
/// * [`ALGO_TOKEN_BUCKET`] — refill at `rate_bps`, spend per packet, capacity `burst_bytes`.
/// * [`ALGO_LEAKY_BUCKET`] — queue level drains at `rate_bps`, capacity `burst_bytes`.
/// * [`ALGO_FIXED_WINDOW`] — allow `rate_bps × window_ns` bytes per fixed window.
/// * [`ALGO_SLIDING_WINDOW_COUNTER`] — weighted two-window approximation of a sliding window.
/// * [`ALGO_SLIDING_WINDOW_LOG`] — exact sliding window over a bounded per-flow log.
/// * [`ALGO_GCRA`] — virtual-scheduling Theoretical Arrival Time policer.
///
/// Plain `u32` constants (not a Rust enum) so the eBPF match is a trivial integer
/// compare and no conversion helper needs to exist on either side of the boundary.
pub const ALGO_TOKEN_BUCKET: u32 = 0;
pub const ALGO_LEAKY_BUCKET: u32 = 1;
pub const ALGO_FIXED_WINDOW: u32 = 2;
pub const ALGO_SLIDING_WINDOW_COUNTER: u32 = 3;
pub const ALGO_SLIDING_WINDOW_LOG: u32 = 4;
pub const ALGO_GCRA: u32 = 5;

/// Key of the limit maps: one limiter per (IPv4, direction).
///
/// Deliberately *not* keyed by ifindex: the same IP+direction must share a single
/// rate budget across all CPUs and whichever TAP the packet currently traverses.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LimitKey {
    pub ipv4: u32,
    pub direction: u8,
    // Pad to a stable 8-byte layout so the key hashes identically on both sides.
    pub _pad: [u8; 3],
}

impl LimitKey {
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
/// eBPF does no policy math beyond the per-packet algorithm step; the daemon has
/// already resolved inheritance, windows and thresholds. `rate_bps == 0` or
/// `enabled == 0` means "do not police" (fail-open). An unknown `algorithm` value
/// also fails open.
///
/// Field meaning per algorithm:
/// * `rate_bps` — sustained limit for every algorithm.
/// * `burst_bytes` — bucket capacity (token/leaky bucket) or GCRA burst tolerance.
///   Unused by the window algorithms.
/// * `window_ns` — window length for the window algorithms; 0 otherwise.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LimitPolicy {
    pub enabled: u8,
    pub _pad0: [u8; 3],
    /// One of the `ALGO_*` constants.
    pub algorithm: u32,
    /// Policed bit rate (bits per second).
    pub rate_bps: u64,
    pub burst_bytes: u64,
    pub window_ns: u64,
}

/// Runtime limiter state per (IPv4, direction). Generic fields whose meaning depends
/// on the installed algorithm:
///
/// | algorithm              | a                | b              | c            |
/// |------------------------|------------------|----------------|--------------|
/// | token bucket           | tokens (nbytes)  | last refill ns | —            |
/// | leaky bucket           | level (nbytes)   | last drain ns  | —            |
/// | fixed window           | used bytes       | window start   | —            |
/// | sliding window counter | previous window  | current window | window start |
/// | GCRA                   | TAT              | —              | —            |
///
/// "nbytes" = bytes × 10⁹ so sub-byte refills at low rates accumulate without loss.
/// The sliding-window-log algorithm does not use this map (it keeps a bounded log
/// ring in `SWL_LOG` instead).
///
/// In the kernel this value also carries a `struct bpf_spin_lock` (declared in the eBPF
/// object so BTF describes it to the verifier); the userspace view only ever writes it
/// (install/reset) or deletes it, so the lock field is simply carried as zeroed bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LimitState {
    pub a: u64,
    pub b: u64,
    pub c: u64,
    pub lock: u32,
    pub _pad: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TrafficKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TrafficKey6 {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TrafficValue {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PolicerStats {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for LimitKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for LimitPolicy {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for LimitState {}

/// Capacity of the sliding-window-log ring per (IPv4, direction). Each packet admitted
/// while LIMITED consumes one entry; when full, the oldest entry is overwritten, which
/// makes the log an *under-counting* approximation at packet rates above roughly
/// `CAP / window` packets per second (documented in the README).
pub const SWL_LOG_CAP: usize = 1024;

/// One logged packet: arrival time and wire length.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SwlEntry {
    pub ts_ns: u64,
    pub len: u32,
    pub _pad: u32,
}

/// Bounded per-flow log ring used by the sliding-window-log algorithm. In the kernel the
/// value also carries a `struct bpf_spin_lock` (declared in the eBPF object); userspace
/// only inserts a zeroed ring or deletes it.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwlRing {
    pub head: u32,
    pub _pad: u32,
    pub entries: [SwlEntry; SWL_LOG_CAP],
    pub lock: u32,
    pub _pad1: u32,
}

impl Default for SwlRing {
    fn default() -> Self {
        Self {
            head: 0,
            _pad: 0,
            entries: [SwlEntry {
                ts_ns: 0,
                len: 0,
                _pad: 0,
            }; SWL_LOG_CAP],
            lock: 0,
            _pad1: 0,
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SwlRing {}
