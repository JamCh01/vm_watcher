//! TC classifiers for VM bandwidth accounting + GCRA policing.
//!
//! The daemon loads this object exactly once and attaches `tc_ingress` / `tc_egress` to
//! every TAP under the bridge, so all interfaces share the same maps by construction:
//! * `tc_ingress` on TC ingress — packets the VM sends out (VM TX), keyed by source IP
//! * `tc_egress` on TC egress — packets the VM receives (VM RX), keyed by destination IP
//!
//! The interface index is read straight from the skb context, so no per-interface
//! reloading of the object is needed.
//!
//! Every path — parse failure, IP not whitelisted, map pressure, missing or invalid
//! policy, arithmetic anomaly — ends in `TC_ACT_PIPE`: traffic is never dropped unless
//! the GCRA policer explicitly classifies a packet as non-conforming while a valid limit
//! is active.
//!
//! GCRA concurrency: the per-flow TAT lives in a shared (NOT per-CPU) map guarded by a
//! `bpf_spin_lock`. The timestamp is read before taking the lock, only the TAT field is
//! touched while the lock is held, no helpers are called inside the critical section, and
//! every path releases the lock. Entries are created/removed by the daemon when it
//! installs/removes a limit policy, so the data path never constructs a lock-bearing value.
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{bpf_spin_lock as SpinLockTy, TC_ACT_PIPE, TC_ACT_SHOT},
    btf_maps::{HashMap, PerCpuHashMap},
    helpers::{bpf_ktime_get_ns, bpf_spin_lock, bpf_spin_unlock},
    macros::{btf_map, classifier},
    programs::TcContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};
use vm_bandwidth_common::{GcraKey, GcraPolicy, TrafficKey, TrafficValue};

/// Compile-time default; userspace overrides `max_entries` at load time
/// (`EbpfLoader::map_max_entries`) before the maps are created.
const MAP_CAPACITY: usize = 8192;

/// Packets larger than this are never policed (fail open); it also keeps the
/// time-increment arithmetic provably inside `u64`.
const MAX_POLICED_LEN: u64 = 65535;

const NS_PER_SEC: u64 = 1_000_000_000;
const BITS_PER_BYTE: u64 = 8;

/// Whitelist: only IPv4 addresses present here are ever counted.
#[btf_map]
static MONITORED_IPS: HashMap<u32, u8, MAP_CAPACITY> = HashMap::new();

/// (ifindex, ipv4) -> per-CPU monotonic counters.
#[btf_map]
static TRAFFIC: PerCpuHashMap<TrafficKey, TrafficValue, MAP_CAPACITY> = PerCpuHashMap::new();

/// (ipv4, direction) -> limiter policy installed by the daemon. Absent or
/// `enabled == 0` means the flow is not policed.
#[btf_map]
static LIMIT_POLICIES: HashMap<GcraKey, GcraPolicy, MAP_CAPACITY> = HashMap::new();

/// GCRA runtime state for one (IPv4, direction) flow: the Theoretical Arrival Time.
///
/// The `lock` field is a real `struct bpf_spin_lock` so the map's BTF tells the verifier
/// exactly where the lock lives. The kernel owns the struct layout inside the map; the
/// userspace view (common::GcraState) is byte-compatible and only ever writes or deletes.
#[repr(C)]
struct GcraStateVal {
    tat_ns: u64,
    lock: SpinLockTy,
}

/// (ipv4, direction) -> GCRA runtime state. Shared (NOT per-CPU) so all CPUs and all TAPs
/// enforce one common rate budget per flow.
#[btf_map]
static GCRA_STATE: HashMap<GcraKey, GcraStateVal, MAP_CAPACITY> = HashMap::new();

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
    match eth.ether_type() {
        Ok(EtherType::Ipv4) => {}
        // ARP, IPv6, LLDP, STP, VLAN, ... are not counted in v1.
        _ => return TC_ACT_PIPE,
    }
    let ip: Ipv4Hdr = match ctx.load(EthHdr::LEN) {
        Ok(i) => i,
        Err(_) => return TC_ACT_PIPE,
    };
    let ipv4 = u32::from_be_bytes(if is_tx { ip.src_addr } else { ip.dst_addr });

    // The TAP's ifindex, read from the skb context (valid for TC programs).
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };

    unsafe {
        if MONITORED_IPS.get(ipv4).is_none() {
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

/// GCRA policer. Returns `true` to DROP (non-conforming), `false` to PASS.
///
/// Any uncertainty fails open (returns `false`): no policy, disabled policy, zero rate,
/// oversized packet, or missing runtime state (the daemon creates it when installing the
/// policy; until then policing cannot be proven safe, so traffic passes).
#[inline(always)]
unsafe fn police(ipv4: u32, direction: u8, len_bytes: u64) -> bool {
    if len_bytes == 0 || len_bytes > MAX_POLICED_LEN {
        return false;
    }

    let key = GcraKey::new(ipv4, direction);
    let policy = match LIMIT_POLICIES.get(key) {
        Some(p) => *p,
        None => return false,
    };
    if policy.enabled == 0 || policy.rate_bps == 0 {
        return false;
    }

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

    // Timestamp taken before the lock: the critical section holds no helper calls.
    let now = bpf_ktime_get_ns();

    let state = match GCRA_STATE.get_ptr_mut(key) {
        Some(ptr) => &mut *ptr,
        // No runtime state: the daemon creates it together with the policy. Fail open.
        None => return false,
    };

    let lock_ptr = &mut state.lock as *mut SpinLockTy;
    bpf_spin_lock(lock_ptr);

    let base = if now > state.tat_ns {
        now
    } else {
        state.tat_ns
    };
    let candidate_tat = base.wrapping_add(increment_ns);
    let deadline = now.wrapping_add(tolerance_ns);
    let conform = candidate_tat <= deadline;
    if conform {
        state.tat_ns = candidate_tat;
    }

    bpf_spin_unlock(lock_ptr);
    !conform
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
