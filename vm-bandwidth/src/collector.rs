//! Reads the per-CPU TRAFFIC map, computes per-IP deltas/rates and aggregates per range.
//!
//! Counters in the kernel are monotonic; userspace keeps the previous sample to compute
//! deltas over the actual sampling interval. A key whose counter went backwards (reset)
//! contributes a zero delta for that interval — bandwidth is never negative.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use aya::maps::{MapData, PerCpuHashMap};
use vm_bandwidth_common::{LimitKey, PolicerStats, TrafficKey, TrafficKey6, TrafficValue};

use vm_bandwidth_core::ip_range::IpRange;
use vm_bandwidth_core::limiter::IpTotals;

/// Eviction discipline for the eBPF counter maps: a key whose counters did not change
/// for [`IDLE_EVICT_POLLS`] consecutive polls is reported for removal. Entries are
/// recreated by the data path on the first packet if traffic returns (cumulative
/// counters restart; userspace deltas are reset-safe and `rate()` in VictoriaMetrics
/// handles counter resets). This is what bounds the maps under IP churn — TAP
/// recreation is additionally covered by the ifindex-based reclaim in rescan.
pub const IDLE_EVICT_POLLS: u32 = 300; // ~5 minutes at the default 1s cadence

struct IdleTracker<K: Eq + std::hash::Hash> {
    counts: HashMap<K, u32>,
}

impl<K: Eq + std::hash::Hash> Default for IdleTracker<K> {
    fn default() -> Self {
        Self {
            counts: HashMap::new(),
        }
    }
}

impl<K: Eq + std::hash::Hash + Copy> IdleTracker<K> {
    /// Record one poll: `present` = keys currently in the map, `changed` = the subset
    /// whose counters moved since the last poll. Returns keys that reached the idle
    /// threshold and should be evicted from the map.
    fn observe(&mut self, present: &HashSet<K>, changed: &HashSet<K>) -> Vec<K> {
        let mut evict = Vec::new();
        for key in present {
            let n = self.counts.entry(*key).or_insert(0);
            if changed.contains(key) {
                *n = 0;
            } else {
                *n += 1;
                if *n >= IDLE_EVICT_POLLS {
                    evict.push(*key);
                }
            }
        }
        // Keys gone from the map (evicted or TAP removed) stop being tracked.
        self.counts.retain(|k, _| present.contains(k));
        evict
    }
}

#[derive(Debug, Clone, Default)]
pub struct IpStats {
    pub rx_bps: f64,
    pub tx_bps: f64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    // Cumulative policer verdicts (only ever nonzero for policed flows).
    pub rx_passed_bytes: u64,
    pub tx_passed_bytes: u64,
    pub rx_passed_packets: u64,
    pub tx_passed_packets: u64,
    pub rx_dropped_bytes: u64,
    pub tx_dropped_bytes: u64,
    pub rx_dropped_packets: u64,
    pub tx_dropped_packets: u64,
    /// Live drop rates for this interval (0 when nothing was dropped).
    pub rx_dropped_bps: f64,
    pub tx_dropped_bps: f64,
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
    // Aggregate policer verdicts across the range's IPs.
    pub rx_dropped_bps: f64,
    pub tx_dropped_bps: f64,
    pub rx_dropped_bytes: u64,
    pub tx_dropped_bytes: u64,
    pub rx_dropped_packets: u64,
    pub tx_dropped_packets: u64,
    /// IPs of this range observed since daemon start (the LPM-trie whitelist makes
    /// ranges arbitrarily large, so idle addresses are never enumerated).
    pub ips: Vec<(u32, IpStats)>,
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub ranges: Vec<RangeStats>,
}

/// Per-CPU map values aggregated for one poll — the boundary between reading the
/// kernel maps and the pure delta math (see [`Collector::apply_poll`]).
#[derive(Debug, Default)]
pub struct PollInputs {
    pub cur: HashMap<TrafficKey, TrafficValue>,
    pub cur6: HashMap<TrafficKey6, TrafficValue>,
    pub cur_policer: HashMap<LimitKey, PolicerStats>,
}

/// One collector poll: the TUI-facing snapshot plus per-IP cumulative totals
/// (aggregated across all TAPs) for the limiter's rolling-window deltas.
#[derive(Debug)]
pub struct PollResult {
    pub snapshot: Snapshot,
    pub totals: HashMap<u32, IpTotals>,
    /// Aggregate IPv6 counters and rates. IPv6 has no per-IP breakdown in the
    /// snapshot and never enters the limiter.
    pub ipv6: IpStats,
    /// Cumulative policer verdict counters per IP, for the metrics push.
    pub policer: HashMap<u32, PolicerIpTotals>,
    /// Counter-map keys idle long enough to be evicted (daemon removes them).
    pub stale_traffic: Vec<TrafficKey>,
    pub stale_traffic6: Vec<TrafficKey6>,
}

/// Cumulative policer verdicts for one IP (both directions), for metrics export.
#[derive(Debug, Clone, Copy, Default)]
pub struct PolicerIpTotals {
    pub rx_passed_bytes: u64,
    pub tx_passed_bytes: u64,
    pub rx_passed_packets: u64,
    pub tx_passed_packets: u64,
    pub rx_dropped_bytes: u64,
    pub tx_dropped_bytes: u64,
    pub rx_dropped_packets: u64,
    pub tx_dropped_packets: u64,
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
    prev6: HashMap<TrafficKey6, TrafficValue>,
    /// Running IPv6 aggregate (cumulative counters + last-interval rates).
    ipv6: IpStats,
    prev_policer: HashMap<LimitKey, PolicerStats>,
    /// Idle-eviction tracking per counter-map key (see [`IdleTracker`]).
    idle4: IdleTracker<TrafficKey>,
    idle6: IdleTracker<TrafficKey6>,
    last_poll: Option<Instant>,
}

impl Collector {
    pub fn new() -> Self {
        Self {
            prev: HashMap::new(),
            totals: HashMap::new(),
            prev6: HashMap::new(),
            ipv6: IpStats::default(),
            prev_policer: HashMap::new(),
            idle4: IdleTracker::default(),
            idle6: IdleTracker::default(),
            last_poll: None,
        }
    }

    /// Drop state for IPs that are no longer configured (§33: no stale entries linger
    /// after a range is removed by a hot reload). Membership is a range-containment
    /// test over the observed IPs — the ranges themselves are never enumerated.
    pub fn prune_ips(&mut self, ranges: &[IpRange]) {
        let kept = |ip: &u32| ranges.iter().any(|r| r.contains(*ip));
        self.totals.retain(|ip, _| kept(ip));
        self.prev.retain(|key, _| kept(&key.ipv4));
        self.prev_policer.retain(|key, _| kept(&key.ipv4));
    }

    /// Drop previous-sample entries for TAPs that no longer exist (pairs that can never
    /// produce a delta again).
    pub fn prune_ifindexes(&mut self, live: &HashSet<u32>) {
        self.prev.retain(|key, _| live.contains(&key.ifindex));
        self.prev6.retain(|key, _| live.contains(&key.ifindex));
    }

    pub fn poll(
        &mut self,
        traffic: &PerCpuHashMap<MapData, TrafficKey, TrafficValue>,
        traffic6: &PerCpuHashMap<MapData, TrafficKey6, TrafficValue>,
        policer: &PerCpuHashMap<MapData, LimitKey, PolicerStats>,
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

        let mut cur6: HashMap<TrafficKey6, TrafficValue> = HashMap::new();
        for item in traffic6.iter() {
            match item {
                Ok((key, values)) => {
                    let mut acc = TrafficValue::default();
                    for v in values.iter() {
                        acc.rx_bytes += v.rx_bytes;
                        acc.tx_bytes += v.tx_bytes;
                        acc.rx_packets += v.rx_packets;
                        acc.tx_packets += v.tx_packets;
                    }
                    cur6.insert(key, acc);
                }
                Err(e) => log::warn!("reading TRAFFIC6 map: {e}"),
            }
        }
        let mut cur_policer: HashMap<LimitKey, PolicerStats> = HashMap::new();
        for item in policer.iter() {
            match item {
                Ok((key, values)) => {
                    let mut acc = PolicerStats::default();
                    for v in values.iter() {
                        acc.passed_bytes += v.passed_bytes;
                        acc.passed_packets += v.passed_packets;
                        acc.dropped_bytes += v.dropped_bytes;
                        acc.dropped_packets += v.dropped_packets;
                    }
                    cur_policer.insert(key, acc);
                }
                Err(e) => log::warn!("reading POLICER_STATS map: {e}"),
            }
        }

        let inputs = PollInputs {
            cur,
            cur6,
            cur_policer,
        };
        self.apply_poll(inputs, elapsed_secs, ranges)
    }

    /// Pure delta/rate math over one poll's aggregated map values. Split out of
    /// [`Collector::poll`] so consecutive-poll semantics (rate resets, eviction,
    /// TAP rebuilds) are unit-testable without kernel maps.
    fn apply_poll(
        &mut self,
        inputs: PollInputs,
        elapsed_secs: f64,
        ranges: &[IpRange],
    ) -> PollResult {
        let PollInputs {
            cur,
            cur6,
            cur_policer,
        } = inputs;

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
        // Idle eviction: keys frozen for IDLE_EVICT_POLLS consecutive polls are
        // reported; the daemon removes them and the data path recreates them on the
        // next packet. Also prune per-IP totals down to IPs that still own a key, so
        // userspace state cannot grow past what the counter map actually holds.
        let present4: HashSet<TrafficKey> = cur.keys().copied().collect();
        let changed4: HashSet<TrafficKey> = cur
            .iter()
            .filter(|(k, v)| self.prev.get(k).map(|p| p != *v).unwrap_or(true))
            .map(|(k, _)| *k)
            .collect();
        let stale_traffic = self.idle4.observe(&present4, &changed4);
        let live_ips: HashSet<u32> = present4.iter().map(|k| k.ipv4).collect();
        self.totals.retain(|ip, _| live_ips.contains(ip));

        self.prev = cur;

        // IPv6: identical delta logic, collapsed into one grand total — there is no
        // per-address breakdown and no IPv6 limit policy to feed.
        let mut d6 = Delta::default();
        if elapsed_secs > 0.0 {
            for (key, value) in &cur6 {
                let Some(prev) = self.prev6.get(key) else {
                    continue;
                };
                let d = Delta {
                    rx_bytes: value.rx_bytes.saturating_sub(prev.rx_bytes),
                    tx_bytes: value.tx_bytes.saturating_sub(prev.tx_bytes),
                    rx_packets: value.rx_packets.saturating_sub(prev.rx_packets),
                    tx_packets: value.tx_packets.saturating_sub(prev.tx_packets),
                };
                if !d.is_zero() {
                    d6 += d;
                }
            }
        }
        let present6: HashSet<TrafficKey6> = cur6.keys().copied().collect();
        let changed6: HashSet<TrafficKey6> = cur6
            .iter()
            .filter(|(k, v)| self.prev6.get(k).map(|p| p != *v).unwrap_or(true))
            .map(|(k, _)| *k)
            .collect();
        let stale_traffic6 = self.idle6.observe(&present6, &changed6);

        self.prev6 = cur6;
        self.ipv6.rx_bytes += d6.rx_bytes;
        self.ipv6.tx_bytes += d6.tx_bytes;
        self.ipv6.rx_packets += d6.rx_packets;
        self.ipv6.tx_packets += d6.tx_packets;
        if elapsed_secs > 0.0 {
            self.ipv6.rx_bps = d6.rx_bytes as f64 * 8.0 / elapsed_secs;
            self.ipv6.tx_bps = d6.tx_bytes as f64 * 8.0 / elapsed_secs;
        }

        // Cumulative counters and instantaneous rates are updated separately: the rates
        // are recomputed purely from THIS poll's deltas. Zero every rate field first,
        // then fill what moved — a direction without a new delta can never leak the
        // previous round's value into this one.
        for stats in self.totals.values_mut() {
            stats.rx_bps = 0.0;
            stats.tx_bps = 0.0;
            stats.rx_dropped_bps = 0.0;
            stats.tx_dropped_bps = 0.0;
        }

        for (ip, delta) in &deltas {
            let stats = self.totals.entry(*ip).or_default();
            stats.rx_bytes += delta.rx_bytes;
            stats.tx_bytes += delta.tx_bytes;
            stats.rx_packets += delta.rx_packets;
            stats.tx_packets += delta.tx_packets;
            if elapsed_secs > 0.0 {
                stats.rx_bps = delta.rx_bytes as f64 * 8.0 / elapsed_secs;
                stats.tx_bps = delta.tx_bytes as f64 * 8.0 / elapsed_secs;
            }
        }

        // Policer verdicts: same delta discipline, keyed by (ip, direction) and folded
        // into the same per-IP totals. A dropped packet was already counted in TRAFFIC,
        // so the entry exists; or_default keeps this safe either way.
        if elapsed_secs > 0.0 {
            for (key, value) in &cur_policer {
                let Some(prev) = self.prev_policer.get(key) else {
                    continue;
                };
                let d_passed_bytes = value.passed_bytes.saturating_sub(prev.passed_bytes);
                let d_passed_packets = value.passed_packets.saturating_sub(prev.passed_packets);
                let d_dropped_bytes = value.dropped_bytes.saturating_sub(prev.dropped_bytes);
                let d_dropped_packets = value.dropped_packets.saturating_sub(prev.dropped_packets);
                if d_passed_bytes | d_passed_packets | d_dropped_bytes | d_dropped_packets == 0 {
                    continue;
                }
                let stats = self.totals.entry(key.ipv4).or_default();
                if key.direction == vm_bandwidth_common::DIR_TX {
                    stats.tx_passed_bytes += d_passed_bytes;
                    stats.tx_passed_packets += d_passed_packets;
                    stats.tx_dropped_bytes += d_dropped_bytes;
                    stats.tx_dropped_packets += d_dropped_packets;
                    stats.tx_dropped_bps = d_dropped_bytes as f64 * 8.0 / elapsed_secs;
                } else {
                    stats.rx_passed_bytes += d_passed_bytes;
                    stats.rx_passed_packets += d_passed_packets;
                    stats.rx_dropped_bytes += d_dropped_bytes;
                    stats.rx_dropped_packets += d_dropped_packets;
                    stats.rx_dropped_bps = d_dropped_bytes as f64 * 8.0 / elapsed_secs;
                }
            }
        }
        self.prev_policer = cur_policer;

        // Per-range aggregation over OBSERVED IPs only (the LPM-trie whitelist makes
        // ranges arbitrarily large, so enumerating them is impossible by design).
        // Idle addresses contribute zero anyway; `ips` is now "seen since daemon start".
        let mut snap_ranges: Vec<RangeStats> = ranges
            .iter()
            .map(|range| RangeStats {
                name: range.name.clone(),
                range: range.display(),
                ..Default::default()
            })
            .collect();
        for (&ip, stats) in self.totals.iter() {
            let Some(idx) = ranges.iter().position(|r| r.contains(ip)) else {
                continue;
            };
            let rs = &mut snap_ranges[idx];
            rs.rx_bps += stats.rx_bps;
            rs.tx_bps += stats.tx_bps;
            rs.rx_bytes += stats.rx_bytes;
            rs.tx_bytes += stats.tx_bytes;
            rs.rx_packets += stats.rx_packets;
            rs.tx_packets += stats.tx_packets;
            rs.rx_dropped_bps += stats.rx_dropped_bps;
            rs.tx_dropped_bps += stats.tx_dropped_bps;
            rs.rx_dropped_bytes += stats.rx_dropped_bytes;
            rs.tx_dropped_bytes += stats.tx_dropped_bytes;
            rs.rx_dropped_packets += stats.rx_dropped_packets;
            rs.tx_dropped_packets += stats.tx_dropped_packets;
            rs.ips.push((ip, stats.clone()));
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
                        rx_packets: s.rx_packets,
                        tx_packets: s.tx_packets,
                    },
                )
            })
            .collect();

        let policer = self
            .totals
            .iter()
            .filter(|(_, s)| {
                s.rx_passed_bytes | s.tx_passed_bytes | s.rx_dropped_bytes | s.tx_dropped_bytes != 0
            })
            .map(|(ip, s)| {
                (
                    *ip,
                    PolicerIpTotals {
                        rx_passed_bytes: s.rx_passed_bytes,
                        tx_passed_bytes: s.tx_passed_bytes,
                        rx_passed_packets: s.rx_passed_packets,
                        tx_passed_packets: s.tx_passed_packets,
                        rx_dropped_bytes: s.rx_dropped_bytes,
                        tx_dropped_bytes: s.tx_dropped_bytes,
                        rx_dropped_packets: s.rx_dropped_packets,
                        tx_dropped_packets: s.tx_dropped_packets,
                    },
                )
            })
            .collect();

        PollResult {
            snapshot: Snapshot {
                ranges: snap_ranges,
            },
            totals,
            ipv6: self.ipv6.clone(),
            policer,
            stale_traffic,
            stale_traffic6,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_tracker_evicts_after_threshold_and_forgets_removed_keys() {
        let mut t = IdleTracker::default();
        let k: u32 = 7;
        let present: HashSet<u32> = [k].into_iter().collect();
        let nothing: HashSet<u32> = HashSet::new();
        // One change resets the counter.
        assert!(t.observe(&present, &present).is_empty());
        for _ in 0..(IDLE_EVICT_POLLS - 1) {
            assert!(t.observe(&present, &nothing).is_empty());
        }
        assert_eq!(t.observe(&present, &nothing), vec![k]); // threshold reached
                                                            // A key gone from the map stops being tracked: it must re-idle from zero.
        assert!(t.observe(&nothing, &nothing).is_empty());
        assert!(t.observe(&present, &nothing).is_empty());
    }

    // ---------- consecutive-poll tests (drive the pure apply_poll directly) ----------

    fn ip4(a: u8, b: u8, c: u8, d: u8) -> u32 {
        u32::from_be_bytes([a, b, c, d])
    }

    fn tkey(ifindex: u32, ip: u32) -> TrafficKey {
        TrafficKey { ifindex, ipv4: ip }
    }

    fn tval(rx_bytes: u64, tx_bytes: u64) -> TrafficValue {
        TrafficValue {
            rx_bytes,
            tx_bytes,
            rx_packets: rx_bytes / 100,
            tx_packets: tx_bytes / 100,
        }
    }

    /// One per-direction policer entry with `dropped` dropped bytes.
    fn pstats(dropped: u64) -> PolicerStats {
        PolicerStats {
            passed_bytes: 1000,
            passed_packets: 10,
            dropped_bytes: dropped,
            dropped_packets: dropped / 100,
        }
    }

    /// One poll round at a fixed 1s cadence over one range covering every address,
    /// so the snapshot carries the per-IP instantaneous stats the assertions need.
    fn round(
        c: &mut Collector,
        traffic: &[(TrafficKey, TrafficValue)],
        policer: &[(LimitKey, PolicerStats)],
    ) -> PollResult {
        let inputs = PollInputs {
            cur: traffic.iter().copied().collect(),
            cur6: HashMap::new(),
            cur_policer: policer.iter().copied().collect(),
        };
        let all = IpRange {
            name: "all".to_string(),
            start: 0,
            end: u32::MAX,
        };
        c.apply_poll(inputs, 1.0, &[all])
    }

    fn ip_stats(r: &PollResult, ip: u32) -> &IpStats {
        r.snapshot.ranges[0]
            .ips
            .iter()
            .find(|(i, _)| *i == ip)
            .map(|(_, s)| s)
            .expect("ip present in snapshot")
    }

    // 1. First round is the baseline: no deltas, zero rates.
    #[test]
    fn first_round_is_baseline() {
        let mut c = Collector::new();
        let ip = ip4(10, 0, 0, 1);
        round(&mut c, &[(tkey(3, ip), tval(5000, 0))], &[]);
        let r = round(&mut c, &[(tkey(3, ip), tval(9000, 0))], &[]);
        assert_eq!(ip_stats(&r, ip).rx_bytes, 4000);
        assert!((ip_stats(&r, ip).rx_bps - 32000.0).abs() < 1e-9);
    }

    // 2. A policer drop delta shows up as an RX drop rate.
    #[test]
    fn rx_drop_appears_on_delta() {
        let mut c = Collector::new();
        let ip = ip4(10, 0, 0, 2);
        let k = LimitKey::new(ip, vm_bandwidth_common::DIR_RX);
        round(&mut c, &[(tkey(3, ip), tval(1000, 0))], &[(k, pstats(0))]);
        let r = round(&mut c, &[(tkey(3, ip), tval(2000, 0))], &[(k, pstats(400))]);
        assert!((ip_stats(&r, ip).rx_dropped_bps - 3200.0).abs() < 1e-9);
        assert_eq!(ip_stats(&r, ip).rx_dropped_bytes, 400);
    }

    // 3. Traffic keeps flowing but there is no NEW drop: the drop rate must go back
    //    to zero this round (regression: it used to linger from the previous round).
    #[test]
    fn drop_rate_resets_when_no_new_drops() {
        let mut c = Collector::new();
        let ip = ip4(10, 0, 0, 3);
        let k = LimitKey::new(ip, vm_bandwidth_common::DIR_RX);
        round(&mut c, &[(tkey(3, ip), tval(1000, 0))], &[(k, pstats(0))]);
        let r = round(&mut c, &[(tkey(3, ip), tval(2000, 0))], &[(k, pstats(400))]);
        assert!(ip_stats(&r, ip).rx_dropped_bps > 0.0);
        // Third round: fresh traffic delta, unchanged policer counters.
        let r = round(&mut c, &[(tkey(3, ip), tval(3000, 0))], &[(k, pstats(400))]);
        assert_eq!(
            ip_stats(&r, ip).rx_dropped_bps,
            0.0,
            "phantom drop rate lingered across polls"
        );
        // Cumulative dropped bytes are NOT reset.
        assert_eq!(ip_stats(&r, ip).rx_dropped_bytes, 400);
    }

    // 4. Only TX drops this round: RX drop rate must be zero.
    #[test]
    fn tx_only_drops_zero_rx_rate() {
        let mut c = Collector::new();
        let ip = ip4(10, 0, 0, 4);
        let rx = LimitKey::new(ip, vm_bandwidth_common::DIR_RX);
        let tx = LimitKey::new(ip, vm_bandwidth_common::DIR_TX);
        round(
            &mut c,
            &[(tkey(3, ip), tval(1000, 1000))],
            &[(rx, pstats(0)), (tx, pstats(0))],
        );
        let r = round(
            &mut c,
            &[(tkey(3, ip), tval(2000, 2000))],
            &[(rx, pstats(300)), (tx, pstats(500))],
        );
        assert!(ip_stats(&r, ip).rx_dropped_bps > 0.0);
        assert!(ip_stats(&r, ip).tx_dropped_bps > 0.0);
        // Next round: only TX drops again.
        let r = round(
            &mut c,
            &[(tkey(3, ip), tval(3000, 3000))],
            &[(rx, pstats(300)), (tx, pstats(900))],
        );
        assert_eq!(ip_stats(&r, ip).rx_dropped_bps, 0.0);
        assert!(ip_stats(&r, ip).tx_dropped_bps > 0.0);
    }

    // 5. Only RX drops this round: TX drop rate must be zero.
    #[test]
    fn rx_only_drops_zero_tx_rate() {
        let mut c = Collector::new();
        let ip = ip4(10, 0, 0, 5);
        let rx = LimitKey::new(ip, vm_bandwidth_common::DIR_RX);
        let tx = LimitKey::new(ip, vm_bandwidth_common::DIR_TX);
        round(
            &mut c,
            &[(tkey(3, ip), tval(1000, 1000))],
            &[(rx, pstats(0)), (tx, pstats(0))],
        );
        let r = round(
            &mut c,
            &[(tkey(3, ip), tval(2000, 2000))],
            &[(rx, pstats(300)), (tx, pstats(500))],
        );
        assert!(ip_stats(&r, ip).rx_dropped_bps > 0.0);
        assert!(ip_stats(&r, ip).tx_dropped_bps > 0.0);
        let r = round(
            &mut c,
            &[(tkey(3, ip), tval(3000, 3000))],
            &[(rx, pstats(700)), (tx, pstats(500))],
        );
        assert!(ip_stats(&r, ip).rx_dropped_bps > 0.0);
        assert_eq!(ip_stats(&r, ip).tx_dropped_bps, 0.0);
    }

    // 6. Policer counters going backwards (session reset) saturate to a zero delta.
    #[test]
    fn policer_counter_reset_is_safe() {
        let mut c = Collector::new();
        let ip = ip4(10, 0, 0, 6);
        let k = LimitKey::new(ip, vm_bandwidth_common::DIR_RX);
        round(&mut c, &[(tkey(3, ip), tval(1000, 0))], &[(k, pstats(900))]);
        let r = round(&mut c, &[(tkey(3, ip), tval(2000, 0))], &[(k, pstats(0))]);
        assert_eq!(ip_stats(&r, ip).rx_dropped_bps, 0.0);
        assert_eq!(ip_stats(&r, ip).rx_dropped_bytes, 0);
    }

    // 7. TAP rebuild (new ifindex for the same IP): no phantom deltas, counting
    //    resumes from the new baseline.
    #[test]
    fn ifindex_rebuild_rebaselines() {
        let mut c = Collector::new();
        let ip = ip4(10, 0, 0, 7);
        round(&mut c, &[(tkey(5, ip), tval(1000, 0))], &[]);
        let r = round(&mut c, &[(tkey(5, ip), tval(2000, 0))], &[]);
        assert_eq!(ip_stats(&r, ip).rx_bytes, 1000);
        // TAP gone: prune like rescan does.
        c.prune_ifindexes(&HashSet::new());
        round(&mut c, &[], &[]);
        // Recreated TAP, fresh counters.
        round(&mut c, &[(tkey(9, ip), tval(500, 0))], &[]);
        let r = round(&mut c, &[(tkey(9, ip), tval(800, 0))], &[]);
        assert!(
            (ip_stats(&r, ip).rx_bps - 2400.0).abs() < 1e-9,
            "new baseline counted"
        );
    }

    // 8. Idle eviction: a frozen key is reported after the threshold; when the daemon
    //    removes it and traffic returns on a fresh entry, no wrapped spike appears.
    #[test]
    fn idle_eviction_and_reappearance() {
        let mut c = Collector::new();
        let ip = ip4(10, 0, 0, 8);
        let key = tkey(3, ip);
        // Baseline + enough frozen rounds to trip the eviction threshold.
        round(&mut c, &[(key, tval(1000, 0))], &[]);
        let mut stale = Vec::new();
        for _ in 0..IDLE_EVICT_POLLS {
            let r = round(&mut c, &[(key, tval(1000, 0))], &[]);
            stale = r.stale_traffic;
        }
        assert_eq!(stale, vec![key]);
        // Daemon removed the key; the IP's totals are gone with it.
        let r = round(&mut c, &[], &[]);
        assert!(!r.totals.contains_key(&ip));
        // Traffic returns on a recreated entry: rebaselined, no spike.
        round(&mut c, &[(key, tval(100, 0))], &[]);
        let r = round(&mut c, &[(key, tval(160, 0))], &[]);
        assert!((ip_stats(&r, ip).rx_bps - 480.0).abs() < 1e-9);
    }

    // 9. The same IP on two TAPs aggregates into one total.
    #[test]
    fn same_ip_across_taps_aggregates() {
        let mut c = Collector::new();
        let ip = ip4(10, 0, 0, 9);
        round(
            &mut c,
            &[(tkey(3, ip), tval(1000, 0)), (tkey(4, ip), tval(500, 0))],
            &[],
        );
        let r = round(
            &mut c,
            &[(tkey(3, ip), tval(2000, 0)), (tkey(4, ip), tval(900, 0))],
            &[],
        );
        assert_eq!(ip_stats(&r, ip).rx_bytes, 1400);
        assert!((ip_stats(&r, ip).rx_bps - (1400.0 * 8.0)).abs() < 1e-9);
    }

    // 10. Traffic and policer counters first appear in different rounds: each gets its
    //     own baseline when it appears.
    #[test]
    fn traffic_and_policer_appear_in_different_rounds() {
        let mut c = Collector::new();
        let ip = ip4(10, 0, 0, 10);
        let k = LimitKey::new(ip, vm_bandwidth_common::DIR_RX);
        round(&mut c, &[(tkey(3, ip), tval(1000, 0))], &[]);
        // Policer entry appears one round late: baseline round for it.
        round(&mut c, &[(tkey(3, ip), tval(2000, 0))], &[(k, pstats(100))]);
        let r = round(&mut c, &[(tkey(3, ip), tval(3000, 0))], &[(k, pstats(350))]);
        assert_eq!(ip_stats(&r, ip).rx_dropped_bytes, 250);
        assert!((ip_stats(&r, ip).rx_dropped_bps - 2000.0).abs() < 1e-9);
    }

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
