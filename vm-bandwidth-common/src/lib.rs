//! Data structures shared between the eBPF programs and userspace.
#![cfg_attr(not(test), no_std)]

/// Key of the TRAFFIC map: one counter set per (interface, IPv4) pair.
///
/// The ifindex comes first so the layout matches the requirement document.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TrafficKey {
    pub ifindex: u32,
    pub ipv4: u32,
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

/// Largest frame the policer judges (`skb->len`, L2 header included). Larger frames
/// pass unpoliced and are counted in `OVERSIZED`. Frames up to this size — GSO/TSO
/// aggregates included — are judged as a whole, so a bucket or window allowance below
/// it can never admit them; it also keeps the time-increment arithmetic inside `u64`.
pub const MAX_POLICED_LEN: u64 = 65535;

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

// SAFETY: `repr(C)` with two `u32` fields and no padding: every bit pattern is a
// valid value, so aya may copy it to and from kernel map memory.
#[cfg(feature = "user")]
unsafe impl aya::Pod for TrafficKey {}

// SAFETY: `repr(C)` with only `u64` fields and no padding; any bit pattern is valid.
#[cfg(feature = "user")]
unsafe impl aya::Pod for TrafficValue {}

// SAFETY: `repr(C)` with only `u64` fields and no padding; any bit pattern is valid.
#[cfg(feature = "user")]
unsafe impl aya::Pod for PolicerStats {}

// SAFETY: `repr(C)` integers whose padding is an explicit, zeroed `_pad` field; any bit
// pattern is valid.
#[cfg(feature = "user")]
unsafe impl aya::Pod for LimitKey {}

// SAFETY: `repr(C)` integers whose padding is an explicit `_pad0` field; any bit pattern
// is valid.
#[cfg(feature = "user")]
unsafe impl aya::Pod for LimitPolicy {}

// SAFETY: `repr(C)` integers with explicit padding (`lock` is carried as raw bytes);
// any bit pattern is valid.
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

// SAFETY: `repr(C)` integers and arrays of `repr(C)` integer structs, all padding
// explicit; any bit pattern is valid.
#[cfg(feature = "user")]
unsafe impl aya::Pod for SwlRing {}

/// Cumulative counters of packets too large to police (above `MAX_POLICED_LEN`),
/// per direction, while a limit policy WAS armed for the flow. Pure observability:
/// such packets fail open, and the numbers tell operators whether that path is
/// actually reachable on their kernel/offload configuration.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OversizedStats {
    pub packets: u64,
    pub bytes: u64,
}

// SAFETY: `repr(C)` with two `u64` fields and no padding; any bit pattern is valid.
#[cfg(feature = "user")]
unsafe impl aya::Pod for OversizedStats {}

// ---------------------------------------------------------------------------
// Policer arithmetic, shared between the eBPF data path and userspace tests.
// ---------------------------------------------------------------------------

const NS_PER_MS: u64 = 1_000_000;

/// Bytes the sliding window counter carries over from the previous window:
/// `prev_bytes × (window − elapsed) / window`.
///
/// The weight is taken in whole milliseconds, so the product stays inside `u64` under
/// the config bounds (`prev_bytes` ≤ the window allowance ≤ 7.5e12 B and a window of at
/// most 60 s = 60 000 ms keep it ≤ 4.5e17) while the byte count itself stays exact.
/// An elapsed time at or beyond the window carries nothing, and so does a window
/// shorter than 1 ms (config validation never produces one).
#[inline(always)]
pub fn swc_carried_bytes(prev_bytes: u64, window_ns: u64, elapsed_ns: u64) -> u64 {
    let window_ms = window_ns / NS_PER_MS;
    if window_ms == 0 {
        return 0;
    }
    let remaining_ms = (window_ns - elapsed_ns.min(window_ns)) / NS_PER_MS;
    // Wrapping, not checked or saturating: those lower to helpers BPF cannot link, and
    // the bound above keeps the product from wrapping.
    prev_bytes.wrapping_mul(remaining_ms) / window_ms
}

// ---------------------------------------------------------------------------
// L2 parsing, shared between the eBPF data path and userspace tests.
// ---------------------------------------------------------------------------

/// 802.1Q VLAN tag (host-order value; convert from network order before comparing).
pub const ETHERTYPE_VLAN: u16 = 0x8100;
/// 802.1ad provider bridging (QinQ outer tag).
pub const ETHERTYPE_QINQ: u16 = 0x88a8;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_IPV6: u16 = 0x86dd;

/// One 802.1Q/802.1ad tag: 2 bytes TCI followed by the inner EtherType, both in
/// network byte order on the wire.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VlanHdr {
    pub tci: u16,
    pub ether_type: u16,
}

/// Bytes one VLAN tag adds between EtherTypes.
pub const VLAN_HDR_LEN: usize = 4;

/// Maximum VLAN tags the data path walks (single tag + QinQ). Compile-time bound:
/// the eBPF walk performs at most this many header loads, never a loop over data.
pub const MAX_VLAN_TAGS: usize = 2;

/// True for the two tag EtherTypes (host-order argument).
pub fn is_vlan_tag(ether_type: u16) -> bool {
    ether_type == ETHERTYPE_VLAN || ether_type == ETHERTYPE_QINQ
}

/// Pure VLAN-stack walk over the EtherType sequence encountered (host order).
/// `et0` is the frame's EtherType; `et1`/`et2` are the inner EtherTypes and are only
/// consulted when the previous one was a tag (pass 0 when they were never read).
///
/// Returns `Some((tags, final_ether_type))` — the L3 header starts
/// `tags * VLAN_HDR_LEN` octets after the Ethernet header — or `None` when the stack
/// is deeper than [`MAX_VLAN_TAGS`], in which case callers give up (fail open).
pub fn vlan_walk(et0: u16, et1: u16, et2: u16) -> Option<(usize, u16)> {
    let mut tags = 0;
    let mut et = et0;
    if is_vlan_tag(et) {
        tags = 1;
        et = et1;
        if is_vlan_tag(et) {
            tags = 2;
            et = et2;
            if is_vlan_tag(et) {
                return None;
            }
        }
    }
    Some((tags, et))
}

#[cfg(test)]
mod policer_math_tests {
    use super::*;

    const SEC: u64 = 1_000_000_000;

    #[test]
    fn carry_is_linear_in_the_remaining_window() {
        assert_eq!(swc_carried_bytes(1_000_000, SEC, 0), 1_000_000);
        assert_eq!(swc_carried_bytes(1_000_000, SEC, SEC / 2), 500_000);
        assert_eq!(swc_carried_bytes(1_000_000, SEC, SEC / 4), 750_000);
        assert_eq!(swc_carried_bytes(1_000_000, SEC, SEC), 0);
        assert_eq!(swc_carried_bytes(1_000_000, SEC, 3 * SEC), 0);
    }

    #[test]
    fn sub_mib_previous_windows_still_carry() {
        // 5Mbps over a 1s window allows 625 000 B, below one MiB. Truncating the
        // previous window to whole MiB carried nothing at all here, which turned
        // the counter into a fixed window with a 2x boundary burst.
        assert_eq!(swc_carried_bytes(625_000, SEC, SEC / 10), 562_500);
    }

    #[test]
    fn config_bounds_cannot_wrap() {
        // 1Tbps for a 60s window: the largest previous window config allows.
        let max_prev = 1_000_000_000_000 / 8 * 60;
        assert_eq!(swc_carried_bytes(max_prev, 60 * SEC, 0), max_prev);
        assert_eq!(
            swc_carried_bytes(max_prev, 60 * SEC, 30 * SEC),
            max_prev / 2
        );
    }

    #[test]
    fn degenerate_windows_carry_nothing() {
        assert_eq!(swc_carried_bytes(1_000_000, 0, 0), 0);
        assert_eq!(swc_carried_bytes(1_000_000, 999_999, 0), 0);
    }
}

#[cfg(test)]
mod l2_tests {
    use super::*;

    // Wire shape sanity: the eBPF ctx.load offsets rely on this.
    #[test]
    fn vlan_header_is_four_bytes_aligned_two() {
        assert_eq!(core::mem::size_of::<VlanHdr>(), 4);
        assert_eq!(core::mem::align_of::<VlanHdr>(), 2);
    }

    fn walk(ets: &[u16]) -> Option<(usize, u16)> {
        // Mirror how the data path feeds the walk: one EtherType per tag level.
        vlan_walk(
            ets.first().copied().unwrap_or(0),
            ets.get(1).copied().unwrap_or(0),
            ets.get(2).copied().unwrap_or(0),
        )
    }

    // Frame vectors: (untagged / tagged, inner payload) -> expected walk outcome.
    #[test]
    fn untagged_frames_pass_straight_through() {
        assert_eq!(walk(&[ETHERTYPE_IPV4]), Some((0, ETHERTYPE_IPV4)));
        assert_eq!(walk(&[ETHERTYPE_IPV6]), Some((0, ETHERTYPE_IPV6)));
        // ARP and anything else: no tags, final type handed to the caller's match.
        assert_eq!(walk(&[0x0806]), Some((0, 0x0806)));
    }

    #[test]
    fn single_8021q_tag() {
        assert_eq!(
            walk(&[ETHERTYPE_VLAN, ETHERTYPE_IPV4]),
            Some((1, ETHERTYPE_IPV4))
        );
        assert_eq!(
            walk(&[ETHERTYPE_VLAN, ETHERTYPE_IPV6]),
            Some((1, ETHERTYPE_IPV6))
        );
        // VLAN + ARP: walked, but the inner type is not IP.
        assert_eq!(walk(&[ETHERTYPE_VLAN, 0x0806]), Some((1, 0x0806)));
    }

    #[test]
    fn single_8021ad_tag() {
        assert_eq!(
            walk(&[ETHERTYPE_QINQ, ETHERTYPE_IPV4]),
            Some((1, ETHERTYPE_IPV4))
        );
    }

    #[test]
    fn qinq_double_tag() {
        assert_eq!(
            walk(&[ETHERTYPE_QINQ, ETHERTYPE_VLAN, ETHERTYPE_IPV4]),
            Some((2, ETHERTYPE_IPV4))
        );
        assert_eq!(
            walk(&[ETHERTYPE_VLAN, ETHERTYPE_VLAN, ETHERTYPE_IPV6]),
            Some((2, ETHERTYPE_IPV6))
        );
        assert_eq!(
            walk(&[ETHERTYPE_QINQ, ETHERTYPE_VLAN, 0x0806]),
            Some((2, 0x0806))
        );
    }

    #[test]
    fn deeper_stacks_are_given_up() {
        // Three tags: beyond MAX_VLAN_TAGS -> None (fail open).
        assert_eq!(
            walk(&[ETHERTYPE_QINQ, ETHERTYPE_VLAN, ETHERTYPE_VLAN,]),
            None
        );
        assert_eq!(
            walk(&[ETHERTYPE_VLAN, ETHERTYPE_VLAN, ETHERTYPE_VLAN]),
            None
        );
    }

    #[test]
    fn truncated_walk_inputs_are_safe() {
        // The data path passes 0 for EtherTypes it never managed to read; a tag whose
        // inner field is unreadable never matches IP, it degrades to give-up-or-no-IP.
        assert_eq!(walk(&[ETHERTYPE_VLAN]), Some((1, 0)));
        assert_eq!(walk(&[ETHERTYPE_VLAN, ETHERTYPE_VLAN]), Some((2, 0)));
        assert_eq!(walk(&[]), Some((0, 0)));
    }
}
