//! TC classifiers for VM bandwidth accounting.
//!
//! Userspace loads one instance of this object per TAP interface and attaches
//! * `tc_ingress` to TC ingress — packets the VM sends out (VM TX), keyed by source IP
//! * `tc_egress` to TC egress — packets the VM receives (VM RX), keyed by destination IP
//!
//! `aya`'s TC context does not expose `skb->ifindex`, so the interface index is baked in
//! as a global (`IFINDEX`) that userspace overrides before each per-interface load. Both
//! maps are pinned, so every per-interface instance shares the same whitelist and counters.
//!
//! The programs only observe and count. Every path — parse failure, IP not whitelisted,
//! map full — ends in `TC_ACT_PIPE`: traffic always passes through.
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::{HashMap, PerCpuHashMap},
    programs::TcContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};
use vm_bandwidth_common::{TrafficKey, TrafficValue};

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

/// TAP ingress: the VM is sending. The VM's address is the IPv4 source.
#[classifier]
pub fn tc_ingress(ctx: TcContext) -> i32 {
    let _ = observe(&ctx, true);
    TC_ACT_PIPE
}

/// TAP egress: the VM is receiving. The VM's address is the IPv4 destination.
#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    let _ = observe(&ctx, false);
    TC_ACT_PIPE
}

fn observe(ctx: &TcContext, is_tx: bool) -> Result<(), ()> {
    let eth: EthHdr = ctx.load(0).map_err(|_| ())?;
    match eth.ether_type() {
        Ok(EtherType::Ipv4) => {}
        // ARP, IPv6, LLDP, STP, VLAN, ... are not counted in v1.
        _ => return Ok(()),
    }

    let ip: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let ipv4 = u32::from_be_bytes(if is_tx { ip.src_addr } else { ip.dst_addr });

    unsafe {
        if MONITORED_IPS.get(ipv4).is_none() {
            return Ok(());
        }

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
                    return Ok(());
                }
                match TRAFFIC.get_ptr_mut(key) {
                    Some(ptr) => &mut *ptr,
                    None => return Ok(()),
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
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
