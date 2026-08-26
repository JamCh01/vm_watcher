//! TC classifiers for VM bandwidth accounting + GCRA policing.
//!
//! Userspace loads one instance of this object per TAP interface and attaches
//! * `tc_ingress` to TC ingress — packets the VM sends out (VM TX), keyed by source IP
//! * `tc_egress` to TC egress — packets the VM receives (VM RX), keyed by destination IP
//!
//! `aya`'s TC context does not expose `skb->ifindex`, so the interface index is baked in
//! as a global (`IFINDEX`) that userspace overrides before each per-interface load. All
//! maps are pinned, so every per-interface instance shares the same whitelist, counters
//! and limiter state.
//!
//! Every path — parse failure, IP not whitelisted, map full, missing or invalid policy —
//! ends in `TC_ACT_PIPE`: traffic is never dropped unless the GCRA policer explicitly
//! classifies a packet as non-conforming while a valid limit is active.
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{bpf_spin_lock as SpinLockTy, TC_ACT_PIPE, TC_ACT_SHOT},
    helpers::{bpf_ktime_get_ns, bpf_spin_lock, bpf_spin_unlock},
    macros::{classifier, map},
    maps::{HashMap, PerCpuHashMap},
    programs::TcContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};
use vm_bandwidth_common::{GcraKey, GcraPolicy, GcraState, TrafficKey, TrafficValue};

/// ifindex of the TAP interface this object instance is attached to.
/// Overridden from userspace with `EbpfLoader::override_global` before load.
#[no_mangle]
static IFINDEX: u32 = 0;

/// Compile-time floor; userspace overrides `max_entries` at load time
/// (`EbpfLoader::map_max_entries`) before the maps are created.
const MAP_CAPACITY: u32 = 8192;

/// Whitelist: only IPv4 addresses present here are ever counted.
#[map]
static MONITORED_IPS: HashMap<u32, u8> = HashMap::pinned(MAP_CAPACITY, 0);

/// (ifindex, ipv4) -> per-CPU monotonic counters.
#[map]
static TRAFFIC: PerCpuHashMap<TrafficKey, TrafficValue> = PerCpuHashMap::pinned(MAP_CAPACITY, 0);

/// (ipv4, direction) -> limiter policy installed by the daemon. Absent or
/// `enabled == 0` means the flow is not policed.
#[map]
static LIMIT_POLICIES: HashMap<GcraKey, GcraPolicy> = HashMap::pinned(MAP_CAPACITY, 0);

/// (ipv4, direction) -> GCRA runtime state (TAT). Shared (NOT per-CPU) so all CPUs and
/// all TAPs enforce one common rate budget per flow; protected by a bpf_spin_lock.
#[map]
static GCRA_STATE: HashMap<GcraKey, GcraState> = HashMap::pinned(MAP_CAPACITY, 0);

/// Nanoseconds in one second, used to turn a bit rate into a per-byte time increment.
const NS_PER_SEC: u64 = 1_000_000_000;
const BITS_PER_BYTE: u64 = 8;

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
    match process(ctx, is_tx) {
        // The only DROP path is an explicit GCRA non-conformance verdict.
        Ok(action) => action,
        // Any error (short packet, non-IPv4, not whitelisted, map pressure, missing
        // policy, arithmetic anomaly) must fail open and let the packet through.
        Err(_) => TC_ACT_PIPE,
    }
}

fn process(ctx: &TcContext, is_tx: bool) -> Result<i32, ()> {
    let eth: EthHdr = ctx.load(0).map_err(|_| ())?;
    match eth.ether_type() {
        Ok(EtherType::Ipv4) => {}
        // ARP, IPv6, LLDP, STP, VLAN, ... are not counted in v1.
        _ => return Ok(TC_ACT_PIPE),
    }

    let ip: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let ipv4 = u32::from_be_bytes(if is_tx { ip.src_addr } else { ip.dst_addr });

    unsafe {
        if MONITORED_IPS.get(ipv4).is_none() {
            return Ok(TC_ACT_PIPE);
        }

        count(ctx, ipv4, is_tx);

        // Police this flow. `police` returns `true` when the packet must be dropped.
        let direction = if is_tx {
            vm_bandwidth_common::DIR_TX
        } else {
            vm_bandwidth_common::DIR_RX
        };
        if police(ipv4, direction, ctx.len() as u64) {
            return Ok(TC_ACT_SHOT);
        }
    }
    Ok(TC_ACT_PIPE)
}

/// Accumulate byte/packet counters for a whitelisted flow. Never fails the packet.
#[inline(always)]
unsafe fn count(ctx: &TcContext, ipv4: u32, is_tx: bool) {
    let key = TrafficKey {
        ifindex: IFINDEX,
        ipv4,
    };
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
/// Any uncertainty fails open (returns `false`): no policy, disabled policy, zero
/// rate, missing/locked state, or arithmetic that cannot be proven safe.
#[inline(always)]
unsafe fn police(ipv4: u32, direction: u8, len_bytes: u64) -> bool {
    let key = GcraKey::new(ipv4, direction);

    let policy = match LIMIT_POLICIES.get(key) {
        Some(p) => *p,
        None => return false,
    };
    if policy.enabled == 0 || policy.rate_bps == 0 {
        return false;
    }

    // Time cost of this packet: len * 8 bits * 1e9 ns / rate_bps.
    // len is bounded by the MTU/skb length, so the products fit in u64; saturating
    // arithmetic guards against any future change making that untrue.
    let increment_ns = len_bytes
        .saturating_mul(BITS_PER_BYTE)
        .saturating_mul(NS_PER_SEC)
        / policy.rate_bps;

    // Burst tolerance in ns: burst_bytes * 8 * 1e9 / rate_bps.
    let tolerance_ns = policy
        .burst_bytes
        .saturating_mul(BITS_PER_BYTE)
        .saturating_mul(NS_PER_SEC)
        / policy.rate_bps;

    let now = bpf_ktime_get_ns();

    match GCRA_STATE.get_ptr_mut(key) {
        Some(ptr) => {
            let state = &mut *ptr;
            // Only the `lock` field may be passed to the helpers; `tat_ns` is accessed
            // strictly between lock/unlock. All paths below release the lock.
            let lock_ptr = &mut state.lock as *mut u32 as *mut SpinLockTy;
            bpf_spin_lock(lock_ptr);

            let base = if now > state.tat_ns {
                now
            } else {
                state.tat_ns
            };
            let candidate_tat = base.saturating_add(increment_ns);
            let deadline = now.saturating_add(tolerance_ns);
            let conform = candidate_tat <= deadline;
            if conform {
                state.tat_ns = candidate_tat;
            }

            bpf_spin_unlock(lock_ptr);
            !conform
        }
        None => {
            // First packet for this flow: initialize state and always conform. If the
            // insert loses a race with another CPU or the map is full, fail open.
            #[allow(clippy::needless_borrows_for_generic_args)]
            let _ = GCRA_STATE.insert(
                &key,
                &GcraState {
                    tat_ns: now.saturating_add(increment_ns),
                    lock: 0,
                },
                0,
            );
            false
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
