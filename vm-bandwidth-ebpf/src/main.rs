//! TC classifiers for VM bandwidth accounting + per-algorithm rate-limit policing.
//!
//! The daemon loads this object exactly once and attaches `tc_ingress` / `tc_egress` to
//! every TAP under the bridge, so all interfaces share the same maps by construction:
//! * `tc_ingress` on TC ingress — packets the VM sends out (VM TX), keyed by source IP
//! * `tc_egress` on TC egress — packets the VM receives (VM RX), keyed by destination IP
//!
//! The interface index is read straight from the skb context, so no per-interface
//! reloading of the object is needed.
//!
//! L2 handling: untagged frames and frames with up to `MAX_VLAN_TAGS` (2) 802.1Q/802.1ad
//! tags (single tag and QinQ) are walked to their inner IPv4/IPv6 header so tagged VM
//! traffic is counted and policed like untagged traffic. Deeper stacks, truncated tags
//! and non-IP payloads fail open like every other unhandled frame.
//!
//! Every path — parse failure, IP not whitelisted, map pressure, missing or invalid
//! policy, arithmetic anomaly — ends in `TC_ACT_PIPE`: traffic is never dropped unless
//! a policer explicitly classifies a packet as non-conforming while a valid limit is
//! active.
//!
//! Policing algorithms (selected per flow via `LimitPolicy.algorithm`):
//! * token bucket — refill at the limit rate, spend per packet, bounded by `burst`
//! * leaky bucket — queue level drains at the limit rate, bounded by `burst`
//! * fixed window — byte allowance per window, anchored at the flow's first packet
//! * sliding window counter — weighted two-window approximation (MiB granularity)
//! * sliding window log — exact window bytes over a bounded per-flow log ring
//! * GCRA — virtual-scheduling Theoretical Arrival Time
//!
//! Concurrency: per-flow state lives in shared (NOT per-CPU) maps guarded by
//! `bpf_spin_lock`. The timestamp is read before taking the lock, only state fields are
//! touched while the lock is held, no helpers are called inside the critical section, and
//! every path releases the lock. Entries are created/removed by the daemon when it
//! installs/removes a limit policy, so the data path never constructs a lock-bearing value.
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{bpf_spin_lock as SpinLockTy, TC_ACT_PIPE, TC_ACT_SHOT},
    btf_maps::{HashMap, PerCpuHashMap},
    helpers::{bpf_ktime_get_ns, bpf_spin_lock, bpf_spin_unlock},
    macros::{btf_map, classifier, map},
    maps::{lpm_trie::Key as TrieKey, LpmTrie},
    programs::TcContext,
};
use network_types::{
    eth::EthHdr,
    ip::{Ipv4Hdr, Ipv6Hdr},
};
use vm_bandwidth_common::{
    is_vlan_tag, vlan_walk, LimitKey, LimitPolicy, PolicerStats, SwlEntry, TrafficKey, TrafficKey6,
    TrafficValue, VlanHdr, ALGO_FIXED_WINDOW, ALGO_GCRA, ALGO_LEAKY_BUCKET,
    ALGO_SLIDING_WINDOW_COUNTER, ALGO_SLIDING_WINDOW_LOG, ALGO_TOKEN_BUCKET, ETHERTYPE_IPV4,
    ETHERTYPE_IPV6, SWL_LOG_CAP, VLAN_HDR_LEN,
};

/// Compile-time default; userspace overrides `max_entries` at load time
/// (`EbpfLoader::map_max_entries`) before the maps are created.
const MAP_CAPACITY: usize = 8192;

/// Packets larger than this are never policed (fail open); it also keeps the
/// time-increment arithmetic provably inside `u64`.
const MAX_POLICED_LEN: u64 = 65535;

const NS_PER_SEC: u64 = 1_000_000_000;
const BITS_PER_BYTE: u64 = 8;

/// Bucket state is stored in bytes × 10⁹ ("nbytes") so sub-byte refills at low rates
/// accumulate instead of being truncated to zero on every packet.
const NBYTES_PER_BYTE: u64 = 1_000_000_000;

/// Whitelist: CIDR prefixes of the configured ranges. An address is monitored iff it
/// matches some prefix (longest-prefix lookup), so membership costs O(log n) map
/// entries per range instead of one entry per address.
#[map]
static MONITORED_IPS: LpmTrie<u32, u8> = LpmTrie::with_max_entries(MAP_CAPACITY as u32, 0);

/// (ifindex, ipv4) -> per-CPU monotonic counters.
#[btf_map]
static TRAFFIC: PerCpuHashMap<TrafficKey, TrafficValue, MAP_CAPACITY> = PerCpuHashMap::new();

/// (ifindex, ipv6) -> per-CPU monotonic counters. IPv6 is counted but never
/// policed and has no whitelist (config has no IPv6 ranges); the map cap is the
/// only bound on distinct flows.
#[btf_map]
static TRAFFIC6: PerCpuHashMap<TrafficKey6, TrafficValue, MAP_CAPACITY> = PerCpuHashMap::new();

/// (ipv4, direction) -> limiter policy installed by the daemon. Absent or
/// `enabled == 0` means the flow is not policed.
#[btf_map]
static LIMIT_POLICIES: HashMap<LimitKey, LimitPolicy, MAP_CAPACITY> = HashMap::new();

/// Generic runtime state for one (IPv4, direction) flow. Field meaning depends on the
/// algorithm (see `vm_bandwidth_common::LimitState`):
///
/// | algorithm              | a               | b               | c            |
/// |------------------------|-----------------|-----------------|--------------|
/// | token bucket           | tokens (nbytes) | last refill ns  | —            |
/// | leaky bucket           | level (nbytes)  | last drain ns   | —            |
/// | fixed window           | used bytes      | window start ns | —            |
/// | sliding window counter | previous window | current window  | window start |
/// | GCRA                   | TAT             | —               | —            |
///
/// The `lock` field is a real `struct bpf_spin_lock` so the map's BTF tells the verifier
/// exactly where the lock lives. The kernel owns the struct layout inside the map; the
/// userspace view (common::LimitState) is byte-compatible and only ever writes or deletes.
#[repr(C)]
struct LimitStateVal {
    a: u64,
    b: u64,
    c: u64,
    lock: SpinLockTy,
}

/// (ipv4, direction) -> limiter runtime state. Shared (NOT per-CPU) so all CPUs and all
/// TAPs enforce one common rate budget per flow.
#[btf_map]
static LIMIT_STATE: HashMap<LimitKey, LimitStateVal, MAP_CAPACITY> = HashMap::new();

/// Bounded log ring for the sliding-window-log algorithm. Only flows limited with that
/// algorithm get an entry (created by the daemon together with the policy).
#[repr(C)]
struct SwlRingVal {
    head: u32,
    _pad: u32,
    entries: [SwlEntry; SWL_LOG_CAP],
    lock: SpinLockTy,
}

#[btf_map]
static SWL_LOG: HashMap<LimitKey, SwlRingVal, MAP_CAPACITY> = HashMap::new();

/// (ipv4, direction) -> cumulative verdict counters, per-CPU. TRAFFIC records demand
/// (what arrived); this records what the policer actually let through versus dropped,
/// so userspace can see loss instead of only inferring it. Only flows with an active
/// policy are recorded; fail-open paths make no entry.
#[btf_map]
static POLICER_STATS: PerCpuHashMap<LimitKey, PolicerStats, MAP_CAPACITY> = PerCpuHashMap::new();

/// TAP ingress: the VM is sending. The VM's address is the IPv4 source.
#[classifier]
pub fn tc_ingress(ctx: TcContext) -> i32 {
    handle(&ctx, true)
}

/// TAP egress: the VM is receiving. The VM's address is the IPv4 destination.
#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    handle(&ctx, false)
}

#[inline(always)]
fn handle(ctx: &TcContext, is_tx: bool) -> i32 {
    let eth: EthHdr = match ctx.load(0) {
        Ok(e) => e,
        Err(_) => return TC_ACT_PIPE,
    };

    // Walk the VLAN stack (bounded by common::MAX_VLAN_TAGS: one load per level, no
    // loop over data). A truncated tag header fails open like any other parse failure.
    let et0 = u16::from_be(eth.ether_type);
    let mut et1 = 0u16;
    let mut et2 = 0u16;
    if is_vlan_tag(et0) {
        let v: VlanHdr = match ctx.load(EthHdr::LEN) {
            Ok(v) => v,
            Err(_) => return TC_ACT_PIPE,
        };
        et1 = u16::from_be(v.ether_type);
        if is_vlan_tag(et1) {
            let v: VlanHdr = match ctx.load(EthHdr::LEN + VLAN_HDR_LEN) {
                Ok(v) => v,
                Err(_) => return TC_ACT_PIPE,
            };
            et2 = u16::from_be(v.ether_type);
        }
    }
    let (tags, ether_type) = match vlan_walk(et0, et1, et2) {
        // Deeper stack than supported: give up (fail open).
        None => return TC_ACT_PIPE,
        Some(t) => t,
    };
    let l3_off = EthHdr::LEN + tags * VLAN_HDR_LEN;

    match ether_type {
        ETHERTYPE_IPV4 => {}
        ETHERTYPE_IPV6 => return handle_v6(ctx, is_tx, l3_off),
        // ARP, LLDP, STP and other non-IP payloads are not counted.
        _ => return TC_ACT_PIPE,
    }
    let ip: Ipv4Hdr = match ctx.load(l3_off) {
        Ok(i) => i,
        Err(_) => return TC_ACT_PIPE,
    };
    let ipv4 = u32::from_be_bytes(if is_tx { ip.src_addr } else { ip.dst_addr });

    // The TAP's ifindex, read from the skb context (valid for TC programs).
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };

    unsafe {
        // The trie stores addresses in network byte order (see userspace trie_key).
        if MONITORED_IPS.get(TrieKey::new(32, ipv4.to_be())).is_none() {
            return TC_ACT_PIPE;
        }

        count(ctx, ipv4, ifindex, is_tx);

        let direction = if is_tx {
            vm_bandwidth_common::DIR_TX
        } else {
            vm_bandwidth_common::DIR_RX
        };
        // Police this flow. `police` returns `true` only to DROP a non-conforming packet.
        if police(ipv4, direction, ctx.len() as u64) {
            return TC_ACT_SHOT;
        }
    }
    TC_ACT_PIPE
}

/// Accumulate byte/packet counters for a whitelisted flow. Never fails the packet.
#[inline(always)]
unsafe fn count(ctx: &TcContext, ipv4: u32, ifindex: u32, is_tx: bool) {
    let key = TrafficKey { ifindex, ipv4 };
    let value = match TRAFFIC.get_ptr_mut(key) {
        Some(ptr) => &mut *ptr,
        None => {
            // Map full (E2BIG) or transient failure: pass the packet without counting.
            // `&` is load-bearing: passing the 32-byte struct by value makes LLVM
            // lower its zero-initialization to a memset call, which BPF cannot link.
            #[allow(clippy::needless_borrows_for_generic_args)]
            if TRAFFIC
                .insert(
                    &key,
                    &TrafficValue {
                        rx_bytes: 0,
                        tx_bytes: 0,
                        rx_packets: 0,
                        tx_packets: 0,
                    },
                    0,
                )
                .is_err()
            {
                return;
            }
            match TRAFFIC.get_ptr_mut(key) {
                Some(ptr) => &mut *ptr,
                None => return,
            }
        }
    };

    let len = ctx.len() as u64;
    if is_tx {
        value.tx_bytes += len;
        value.tx_packets += 1;
    } else {
        value.rx_bytes += len;
        value.rx_packets += 1;
    }
}

/// IPv6 accounting: counted like IPv4 but never policed and never whitelisted
/// (config has no IPv6 ranges). Every error path fails open, same as IPv4.
#[inline(always)]
fn handle_v6(ctx: &TcContext, is_tx: bool, l3_off: usize) -> i32 {
    let ip: Ipv6Hdr = match ctx.load(l3_off) {
        Ok(i) => i,
        Err(_) => return TC_ACT_PIPE,
    };
    // Extension headers, when present, come after the fixed 40-byte header, so the
    // addresses are always at these offsets.
    let addr = if is_tx { ip.src_addr } else { ip.dst_addr };
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    unsafe { count6(ctx, &addr, ifindex, is_tx) };
    TC_ACT_PIPE
}

/// Accumulate byte/packet counters for one IPv6 flow. Never fails the packet.
#[inline(always)]
unsafe fn count6(ctx: &TcContext, ipv6: &[u8; 16], ifindex: u32, is_tx: bool) {
    let key = TrafficKey6 {
        ifindex,
        ipv6: *ipv6,
    };
    let value = match TRAFFIC6.get_ptr_mut(key) {
        Some(ptr) => &mut *ptr,
        None => {
            // Same E2BIG fail-open as the IPv4 path; see `count` for the `&` note.
            #[allow(clippy::needless_borrows_for_generic_args)]
            if TRAFFIC6
                .insert(
                    &key,
                    &TrafficValue {
                        rx_bytes: 0,
                        tx_bytes: 0,
                        rx_packets: 0,
                        tx_packets: 0,
                    },
                    0,
                )
                .is_err()
            {
                return;
            }
            match TRAFFIC6.get_ptr_mut(key) {
                Some(ptr) => &mut *ptr,
                None => return,
            }
        }
    };
    let len = ctx.len() as u64;
    if is_tx {
        value.tx_bytes += len;
        value.tx_packets += 1;
    } else {
        value.rx_bytes += len;
        value.rx_packets += 1;
    }
}

/// Policer dispatch. Returns `true` to DROP (non-conforming), `false` to PASS.
///
/// Any uncertainty fails open (returns `false`): no policy, disabled policy, zero rate,
/// oversized packet, unknown algorithm, or missing runtime state (the daemon creates it
/// when installing the policy; until then policing cannot be proven safe, so traffic
/// passes).
#[inline(always)]
unsafe fn police(ipv4: u32, direction: u8, len_bytes: u64) -> bool {
    if len_bytes == 0 || len_bytes > MAX_POLICED_LEN {
        return false;
    }

    let key = LimitKey::new(ipv4, direction);
    let policy = match LIMIT_POLICIES.get(key) {
        Some(p) => *p,
        None => return false,
    };
    if policy.enabled == 0 || policy.rate_bps == 0 {
        return false;
    }

    // The sliding-window log keeps its state in a separate map with its own shape.
    if policy.algorithm == ALGO_SLIDING_WINDOW_LOG {
        return swl_police(&key, &policy, len_bytes);
    }

    // Timestamp taken before the lock: the critical section holds no helper calls.
    let now = bpf_ktime_get_ns();

    let state = match LIMIT_STATE.get_ptr_mut(key) {
        Some(ptr) => &mut *ptr,
        // No runtime state: the daemon creates it together with the policy. Fail open.
        None => return false,
    };

    let lock_ptr = &mut state.lock as *mut SpinLockTy;
    bpf_spin_lock(lock_ptr);

    let conform = match policy.algorithm {
        ALGO_TOKEN_BUCKET => token_bucket(&policy, state, now, len_bytes),
        ALGO_LEAKY_BUCKET => leaky_bucket(&policy, state, now, len_bytes),
        ALGO_FIXED_WINDOW => fixed_window(&policy, state, now, len_bytes),
        ALGO_SLIDING_WINDOW_COUNTER => sliding_window_counter(&policy, state, now, len_bytes),
        ALGO_GCRA => gcra(&policy, state, now, len_bytes),
        // Unknown algorithm: fail open.
        _ => true,
    };

    bpf_spin_unlock(lock_ptr);
    record_verdict(&key, len_bytes, conform);
    !conform
}

/// Record a policer verdict (pass or drop) for a flow with an active policy.
/// Failure to record never affects the verdict itself.
#[inline(always)]
unsafe fn record_verdict(key: &LimitKey, len_bytes: u64, passed: bool) {
    let stats = match POLICER_STATS.get_ptr_mut(*key) {
        Some(ptr) => &mut *ptr,
        None => {
            // Map full (E2BIG) or transient failure: verdict stands, stats skipped.
            // `&` is load-bearing: passing the struct by value makes LLVM lower its
            // zero-initialization to a memset call, which BPF cannot link.
            #[allow(clippy::needless_borrows_for_generic_args)]
            if POLICER_STATS
                .insert(key, &PolicerStats::default(), 0)
                .is_err()
            {
                return;
            }
            match POLICER_STATS.get_ptr_mut(*key) {
                Some(ptr) => &mut *ptr,
                None => return,
            }
        }
    };
    if passed {
        stats.passed_bytes += len_bytes;
        stats.passed_packets += 1;
    } else {
        stats.dropped_bytes += len_bytes;
        stats.dropped_packets += 1;
    }
}

/// Bucket capacity in nbytes and refill rate in nbytes/ns. `rate_bps >= 100Kbps` is
/// enforced by config validation, so `rate_bps / 8` is never zero.
#[inline(always)]
fn bucket_params(policy: &LimitPolicy) -> (u64, u64) {
    let capacity = policy.burst_bytes.wrapping_mul(NBYTES_PER_BYTE);
    let per_ns = policy.rate_bps / BITS_PER_BYTE;
    (capacity, per_ns.max(1))
}

/// Token bucket: tokens refill at the limit rate up to `burst`, each packet spends its
/// wire length. State: `a` = tokens (nbytes), `b` = last refill timestamp.
#[inline(always)]
unsafe fn token_bucket(
    policy: &LimitPolicy,
    state: &mut LimitStateVal,
    now: u64,
    len_bytes: u64,
) -> bool {
    let (capacity, per_ns) = bucket_params(policy);
    let mut tokens = state.a;
    if now >= state.b {
        let elapsed = now - state.b;
        // Cap the refill interval so the multiplication cannot wrap; anything past a
        // full refill just fills the bucket.
        let full_ns = capacity / per_ns;
        tokens = if elapsed >= full_ns {
            capacity
        } else {
            let t = tokens.wrapping_add(elapsed.wrapping_mul(per_ns));
            if t > capacity || t < tokens {
                capacity
            } else {
                t
            }
        };
    }
    let cost = len_bytes.wrapping_mul(NBYTES_PER_BYTE);
    let conform = tokens >= cost;
    if conform {
        tokens -= cost;
    }
    // Always advance the refill timestamp so partial credit survives a drop.
    state.a = tokens;
    state.b = now;
    conform
}

/// Leaky bucket: the queue level drains at the limit rate; a packet is admitted while
/// the level plus its length fits the capacity. State: `a` = level (nbytes),
/// `b` = last drain timestamp.
#[inline(always)]
unsafe fn leaky_bucket(
    policy: &LimitPolicy,
    state: &mut LimitStateVal,
    now: u64,
    len_bytes: u64,
) -> bool {
    let (capacity, per_ns) = bucket_params(policy);
    let mut level = state.a;
    if now >= state.b {
        let elapsed = now - state.b;
        let full_ns = capacity / per_ns;
        level = if elapsed >= full_ns {
            0
        } else {
            let drained = elapsed.wrapping_mul(per_ns);
            level.saturating_sub(drained)
        };
    }
    let cost = len_bytes.wrapping_mul(NBYTES_PER_BYTE);
    let conform = capacity >= cost && level <= capacity - cost;
    if conform {
        level += cost;
    }
    state.a = level;
    state.b = now;
    conform
}

/// Byte allowance of one window: `(bytes per second) × (whole seconds)`. The config
/// bounds (rate ≤ 1Tbps, window ≤ 60s) keep the product inside `u64`.
#[inline(always)]
fn window_allowance(policy: &LimitPolicy) -> u64 {
    (policy.rate_bps / BITS_PER_BYTE).wrapping_mul(policy.window_ns / NS_PER_SEC)
}

/// Fixed window counter: allow `rate × window` bytes per window, anchored at the first
/// packet after each reset. State: `a` = used bytes, `b` = window start.
#[inline(always)]
unsafe fn fixed_window(
    policy: &LimitPolicy,
    state: &mut LimitStateVal,
    now: u64,
    len_bytes: u64,
) -> bool {
    if policy.window_ns == 0 {
        return true;
    }
    if state.b == 0 || now >= state.b.wrapping_add(policy.window_ns) {
        state.a = 0;
        state.b = now;
    }
    let conform = state.a.saturating_add(len_bytes) <= window_allowance(policy);
    if conform {
        state.a += len_bytes;
    }
    conform
}

/// Sliding window counter: weighted estimate `prev × (1 − elapsed/window) + curr`.
/// Window accounting is in MiB so the weighted product stays inside `u64` under the
/// config bounds (allowance ≤ 7.5e12 B, window ≤ 60s); that granularity can make very
/// small allowances behave like a fixed window. State: `a` = previous window bytes,
/// `b` = current window bytes, `c` = window start.
#[inline(always)]
unsafe fn sliding_window_counter(
    policy: &LimitPolicy,
    state: &mut LimitStateVal,
    now: u64,
    len_bytes: u64,
) -> bool {
    let w = policy.window_ns;
    if w == 0 {
        return true;
    }
    if state.c == 0 {
        state.c = now;
    } else if now >= state.c.wrapping_add(2 * w) {
        // Both windows fully elapsed (idle flow): nothing carried over.
        state.a = 0;
        state.b = 0;
        state.c = now;
    } else if now >= state.c.wrapping_add(w) {
        // Current becomes previous; a fresh current window starts.
        state.a = state.b;
        state.b = 0;
        state.c = state.c.wrapping_add(w);
    }

    let elapsed = now.saturating_sub(state.c).min(w);
    let prev_mib = state.a >> 20;
    let carried = prev_mib.wrapping_mul(w - elapsed) / w;
    let est_bytes = (carried << 20).saturating_add(state.b);

    let conform = est_bytes.saturating_add(len_bytes) <= window_allowance(policy);
    if conform {
        state.b += len_bytes;
    }
    conform
}

/// GCRA (virtual scheduling): the Theoretical Arrival Time advances by the packet's
/// emission time; a packet conforms while its TAT stays inside the burst tolerance.
/// State: `a` = TAT.
#[inline(always)]
unsafe fn gcra(policy: &LimitPolicy, state: &mut LimitStateVal, now: u64, len_bytes: u64) -> bool {
    // Time cost of this packet: len * 8 * 1e9 / rate. The operands are bounded so the
    // products fit in u64 (MAX_POLICED_LEN * 8 * 1e9 ≈ 5.2e14 << u64::MAX); wrapping
    // arithmetic avoids any overflow-check helper calls that BPF cannot link.
    let increment_ns = len_bytes
        .wrapping_mul(BITS_PER_BYTE)
        .wrapping_mul(NS_PER_SEC)
        / policy.rate_bps;
    let tolerance_ns = policy
        .burst_bytes
        .wrapping_mul(BITS_PER_BYTE)
        .wrapping_mul(NS_PER_SEC)
        / policy.rate_bps;

    let base = if now > state.a { now } else { state.a };
    let candidate_tat = base.wrapping_add(increment_ns);
    let deadline = now.wrapping_add(tolerance_ns);
    let conform = candidate_tat <= deadline;
    if conform {
        state.a = candidate_tat;
    }
    conform
}

/// Sliding window log: exact byte count over the last `window` using a bounded ring of
/// (timestamp, length) entries. When the ring is full the oldest entry is overwritten,
/// so at very high packet rates the log under-counts and policing gets lenient.
#[inline(always)]
unsafe fn swl_police(key: &LimitKey, policy: &LimitPolicy, len_bytes: u64) -> bool {
    if policy.window_ns == 0 {
        return false;
    }
    let ring = match SWL_LOG.get_ptr_mut(*key) {
        Some(ptr) => &mut *ptr,
        // No ring: the daemon creates it together with the policy. Fail open.
        None => return false,
    };

    let now = bpf_ktime_get_ns();
    let lock_ptr = &mut ring.lock as *mut SpinLockTy;
    bpf_spin_lock(lock_ptr);

    let mut used: u64 = 0;
    let mut i = 0;
    while i < SWL_LOG_CAP {
        let entry = ring.entries[i];
        // Wrapping subtraction is harmless: before the clock reaches `window` the
        // wrapped bound is huge and no zero-initialized entry can match it.
        if entry.ts_ns > now.wrapping_sub(policy.window_ns) {
            used += entry.len as u64;
        }
        i += 1;
    }

    let conform = used.saturating_add(len_bytes) <= window_allowance(policy);
    if conform {
        let head = (ring.head % SWL_LOG_CAP as u32) as usize;
        ring.entries[head] = SwlEntry {
            ts_ns: now,
            len: len_bytes as u32,
            _pad: 0,
        };
        ring.head = (head + 1) as u32;
    }

    bpf_spin_unlock(lock_ptr);
    record_verdict(key, len_bytes, conform);
    !conform
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
