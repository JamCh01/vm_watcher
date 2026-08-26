//! Reads the per-CPU TRAFFIC map, computes per-IP deltas/rates and aggregates per range.
//!
//! Counters in the kernel are monotonic; userspace keeps the previous sample to compute
//! deltas over the actual sampling interval. A key whose counter went backwards (reset)
//! contributes a zero delta for that interval — bandwidth is never negative.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use aya::maps::{MapData, PerCpuHashMap};
use vm_bandwidth_common::{TrafficKey, TrafficValue};

use vm_bandwidth_core::ip_range::IpRange;
use vm_bandwidth_core::limiter::IpTotals;

#[derive(Debug, Clone, Default)]
pub struct IpStats {
    pub rx_bps: f64,
    pub tx_bps: f64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

#[derive(Debug, Clone, Default)]
pub struct RangeStats {
    pub name: String,
    pub range: String,
    pub rx_bps: f64,
    pub tx_bps: f64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    /// Every IP of the configured range, including IPs without traffic (all zeros).
    pub ips: Vec<(u32, IpStats)>,
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub ranges: Vec<RangeStats>,
}

/// One collector poll: the TUI-facing snapshot plus per-IP cumulative totals
/// (aggregated across all TAPs) for the limiter's rolling-window deltas.
#[derive(Debug)]
pub struct PollResult {
    pub snapshot: Snapshot,
    pub totals: HashMap<u32, IpTotals>,
}

#[derive(Default, Clone, Copy)]
struct Delta {
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,
}

impl std::ops::AddAssign for Delta {
    fn add_assign(&mut self, other: Delta) {
        self.rx_bytes += other.rx_bytes;
        self.tx_bytes += other.tx_bytes;
        self.rx_packets += other.rx_packets;
        self.tx_packets += other.tx_packets;
    }
}

impl Delta {
    fn is_zero(self) -> bool {
        self.rx_bytes | self.tx_bytes | self.rx_packets | self.tx_packets == 0
    }
}

pub struct Collector {
    prev: HashMap<TrafficKey, TrafficValue>,
    totals: HashMap<u32, IpStats>,
    last_poll: Option<Instant>,
}

impl Collector {
    pub fn new() -> Self {
        Self {
            prev: HashMap::new(),
            totals: HashMap::new(),
            last_poll: None,
        }
    }

    /// Drop state for IPs that are no longer configured (§33: no stale entries linger
    /// after a range is removed by a hot reload).
    pub fn prune_ips(&mut self, keep: &HashSet<u32>) {
        self.totals.retain(|ip, _| keep.contains(ip));
        self.prev.retain(|key, _| keep.contains(&key.ipv4));
    }

    pub fn poll(
        &mut self,
        traffic: &PerCpuHashMap<MapData, TrafficKey, TrafficValue>,
        ranges: &[IpRange],
    ) -> PollResult {
        let now = Instant::now();
        // 0.0 on the first poll: no previous sample, all rates zero.
        let elapsed_secs = self
            .last_poll
            .map(|t| now.duration_since(t).as_secs_f64().max(0.001))
            .unwrap_or(0.0);
        self.last_poll = Some(now);

        // Sum every CPU's counters per key.
        let mut cur: HashMap<TrafficKey, TrafficValue> = HashMap::new();
        for item in traffic.iter() {
            match item {
                Ok((key, values)) => {
                    let mut acc = TrafficValue::default();
                    for v in values.iter() {
                        acc.rx_bytes += v.rx_bytes;
                        acc.tx_bytes += v.tx_bytes;
                        acc.rx_packets += v.rx_packets;
                        acc.tx_packets += v.tx_packets;
                    }
                    cur.insert(key, acc);
                }
                Err(e) => log::warn!("reading TRAFFIC map: {e}"),
            }
        }

        // Per-IP deltas. New keys (first observation) get no delta: their rate starts at 0.
        // saturating_sub turns counter resets into zero deltas, never negative rates.
        let mut deltas: HashMap<u32, Delta> = HashMap::new();
        if elapsed_secs > 0.0 {
            for (key, value) in &cur {
                let Some(prev) = self.prev.get(key) else {
                    continue;
                };
                let d = Delta {
                    rx_bytes: value.rx_bytes.saturating_sub(prev.rx_bytes),
                    tx_bytes: value.tx_bytes.saturating_sub(prev.tx_bytes),
                    rx_packets: value.rx_packets.saturating_sub(prev.rx_packets),
                    tx_packets: value.tx_packets.saturating_sub(prev.tx_packets),
                };
                if !d.is_zero() {
                    *deltas.entry(key.ipv4).or_default() += d;
                }
            }
        }
        self.prev = cur;

        for (ip, delta) in &deltas {
            let stats = self.totals.entry(*ip).or_default();
            stats.rx_bytes += delta.rx_bytes;
            stats.tx_bytes += delta.tx_bytes;
            stats.rx_packets += delta.rx_packets;
            stats.tx_packets += delta.tx_packets;
            stats.rx_bps = delta.rx_bytes as f64 * 8.0 / elapsed_secs;
            stats.tx_bps = delta.tx_bytes as f64 * 8.0 / elapsed_secs;
        }
        for (ip, stats) in self.totals.iter_mut() {
            if !deltas.contains_key(ip) {
                stats.rx_bps = 0.0;
                stats.tx_bps = 0.0;
            }
        }

        // Per-range aggregation over every configured IP, traffic or not.
        let mut snap_ranges = Vec::with_capacity(ranges.len());
        for range in ranges {
            let mut rs = RangeStats {
                name: range.name.clone(),
                range: range.display(),
                ..Default::default()
            };
            for ip in range.start..=range.end {
                let stats = self.totals.get(&ip).cloned().unwrap_or_default();
                rs.rx_bps += stats.rx_bps;
                rs.tx_bps += stats.tx_bps;
                rs.rx_bytes += stats.rx_bytes;
                rs.tx_bytes += stats.tx_bytes;
                rs.rx_packets += stats.rx_packets;
                rs.tx_packets += stats.tx_packets;
                rs.ips.push((ip, stats));
            }
            snap_ranges.push(rs);
        }

        let totals = self
            .totals
            .iter()
            .map(|(ip, s)| {
                (
                    *ip,
                    IpTotals {
                        rx_bytes: s.rx_bytes,
                        tx_bytes: s.tx_bytes,
                    },
                )
            })
            .collect();

        PollResult {
            snapshot: Snapshot {
                ranges: snap_ranges,
            },
            totals,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delta_math_is_reset_safe() {
        let mut a = Delta::default();
        a += Delta {
            rx_bytes: 100,
            tx_bytes: 50,
            rx_packets: 1,
            tx_packets: 1,
        };
        assert_eq!(a.rx_bytes, 100);
        assert!(!a.is_zero());
        assert!(Delta::default().is_zero());
    }
}
