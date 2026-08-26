//! NORMAL / LIMITED lifecycle for per-(IP, direction) limiters.
//!
//! The limiter is pure userspace logic: it owns the rolling windows, evaluates thresholds,
//! tracks LIMITED expiry, and emits [`GcraAction`]s describing what the runtime must write
//! into (or remove from) the eBPF `LIMIT_POLICIES` / `GCRA_STATE` maps. It never touches
//! eBPF directly, so the whole state machine is unit-testable.

use std::collections::HashMap;

use vm_bandwidth_common::{DIR_RX, DIR_TX};

use crate::config::ValidatedConfig;
use crate::policy::{self, DirPolicy, EffectivePolicy};
use crate::window::RollingWindow;

/// Cumulative per-IP byte counters (across all TAPs), as reported by the collector.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IpTotals {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// (ipv4, direction) identifies one limiter / one rolling window.
pub type FlowKey = (u32, u8);

/// What the runtime must do to the eBPF maps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GcraAction {
    /// Install (or update) a limit and reset the GCRA runtime state.
    Install {
        ipv4: u32,
        direction: u8,
        rate_bps: u64,
        burst_bytes: u64,
    },
    /// Remove the limit and any GCRA state; policing stops (fail-open).
    Remove { ipv4: u32, direction: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Phase {
    #[default]
    Normal,
    Limited,
}

/// Per-direction limiter state.
#[derive(Debug, Clone, Default)]
pub struct DirState {
    pub phase: Phase,
    pub limited_since: u64,
    pub limited_until: u64,
    /// The policy currently being enforced while LIMITED (None when NORMAL).
    pub applied: Option<DirPolicy>,
}

/// A configured range and its base (pre-override) effective policy.
#[derive(Debug, Clone)]
struct PolicyRange {
    start: u32,
    end: u32,
    policy: EffectivePolicy,
}

/// Field-based lookup so callers can borrow `ranges`/`overrides` disjointly from
/// `windows`/`states` (avoids a whole-`self` borrow inside `retain` closures).
fn lookup(
    ranges: &[PolicyRange],
    overrides: &HashMap<u32, EffectivePolicy>,
    ip: u32,
) -> Option<EffectivePolicy> {
    if let Some(p) = overrides.get(&ip) {
        return Some(*p);
    }
    ranges
        .iter()
        .find(|r| ip >= r.start && ip <= r.end)
        .map(|r| r.policy)
        .filter(|p| !p.is_empty())
}

pub struct Limiter {
    tick_secs: u64,
    ranges: Vec<PolicyRange>,
    overrides: HashMap<u32, EffectivePolicy>,
    windows: HashMap<FlowKey, RollingWindow>,
    states: HashMap<FlowKey, DirState>,
    prev_totals: HashMap<u32, IpTotals>,
}

impl Limiter {
    pub fn new(tick_secs: u64) -> Self {
        Self {
            tick_secs: tick_secs.max(1),
            ranges: Vec::new(),
            overrides: HashMap::new(),
            windows: HashMap::new(),
            states: HashMap::new(),
            prev_totals: HashMap::new(),
        }
    }

    /// Effective policy for one IP: override first, then the containing range.
    pub fn effective_policy(&self, ip: u32) -> Option<EffectivePolicy> {
        lookup(&self.ranges, &self.overrides, ip)
    }

    /// Build the policy index from a validated config.
    fn build_index(
        cfg: &ValidatedConfig,
    ) -> Result<(Vec<PolicyRange>, HashMap<u32, EffectivePolicy>), String> {
        let mut ranges = Vec::with_capacity(cfg.ranges.len());
        let mut overrides = HashMap::new();
        for vr in &cfg.ranges {
            let base = policy::resolve(&vr.policy, None, &vr.inner.name)?;
            for (ip, fields) in &vr.overrides {
                let eff = policy::resolve(
                    &vr.policy,
                    Some(fields),
                    &format!("{} ip {ip}", vr.inner.name),
                )?;
                overrides.insert(*ip, eff);
            }
            ranges.push(PolicyRange {
                start: vr.inner.start,
                end: vr.inner.end,
                policy: base,
            });
        }
        ranges.sort_by_key(|r| r.start);
        Ok((ranges, overrides))
    }

    /// Apply a (new) configuration, reconciling limiter state. Used at startup and on every
    /// successful reload. Returns the map actions needed to converge (§18, §22–§27).
    pub fn apply_config(
        &mut self,
        cfg: &ValidatedConfig,
        now: u64,
    ) -> Result<Vec<GcraAction>, String> {
        let (new_ranges, new_overrides) = Self::build_index(cfg)?;
        let mut actions = Vec::new();

        // Flows that are currently LIMITED, reconciled against the NEW config (§22–§25).
        let limited: Vec<FlowKey> = self
            .states
            .iter()
            .filter(|(_, s)| s.phase == Phase::Limited)
            .map(|(k, _)| *k)
            .collect();

        // Install the new index so lookups below see the new config.
        self.ranges = new_ranges;
        self.overrides = new_overrides;

        for flow in limited {
            let (ip, dir) = flow;
            let new_dir = lookup(&self.ranges, &self.overrides, ip).and_then(|p| match dir {
                DIR_RX => p.rx,
                DIR_TX => p.tx,
                _ => None,
            });
            let state = match self.states.get_mut(&flow) {
                Some(s) => s,
                None => continue,
            };
            let applied = match state.applied {
                Some(a) => a,
                None => continue,
            };
            match new_dir {
                // §25 / range-or-IP removed: stop policing, back to NORMAL.
                None => {
                    actions.push(GcraAction::Remove {
                        ipv4: ip,
                        direction: dir,
                    });
                    *state = DirState::default();
                    if let Some(w) = self.windows.get_mut(&flow) {
                        w.reset();
                    }
                }
                Some(np) => {
                    // §24: duration re-anchored to the original limited_since.
                    let limited_until = state.limited_since.saturating_add(np.limit_duration_secs);
                    if limited_until <= now {
                        actions.push(GcraAction::Remove {
                            ipv4: ip,
                            direction: dir,
                        });
                        *state = DirState::default();
                        if let Some(w) = self.windows.get_mut(&flow) {
                            w.reset();
                        }
                        continue;
                    }
                    // §22 / §23: rate or burst changed → re-install (runtime resets GCRA).
                    if np.limit_bps != applied.limit_bps || np.burst_bytes != applied.burst_bytes {
                        actions.push(GcraAction::Install {
                            ipv4: ip,
                            direction: dir,
                            rate_bps: np.limit_bps,
                            burst_bytes: np.burst_bytes,
                        });
                    }
                    state.limited_until = limited_until;
                    state.applied = Some(np);
                }
            }
        }

        // Drop windows for IPs that no longer resolve to a policy (§18). A window-length
        // change restarts accumulation instead of migrating old samples (§20).
        let ranges = &self.ranges;
        let overrides = &self.overrides;
        let tick_secs = self.tick_secs;
        self.windows.retain(|flow, w| {
            let (ip, dir) = *flow;
            let dir_policy = lookup(ranges, overrides, ip).and_then(|p| match dir {
                DIR_RX => p.rx,
                DIR_TX => p.tx,
                _ => None,
            });
            match dir_policy {
                None => false,
                Some(np) => {
                    if np.window_secs != w.capacity_secs() {
                        w.resize(np.window_secs, tick_secs);
                    }
                    true
                }
            }
        });
        // Drop NORMAL states for flows with no policy; LIMITED states were handled above.
        self.states.retain(|flow, s| {
            let (ip, dir) = *flow;
            s.phase == Phase::Limited
                || lookup(ranges, overrides, ip)
                    .and_then(|p| match dir {
                        DIR_RX => p.rx,
                        DIR_TX => p.tx,
                        _ => None,
                    })
                    .is_some()
        });

        Ok(actions)
    }

    /// Advance one tick with the current per-IP cumulative totals. Returns the actions the
    /// runtime must apply (entering / leaving LIMITED).
    pub fn tick(&mut self, now: u64, totals: &HashMap<u32, IpTotals>) -> Vec<GcraAction> {
        let mut actions = Vec::new();

        // Evaluate every IP that either has traffic or is currently LIMITED.
        let mut ips: Vec<u32> = totals.keys().copied().collect();
        for (flow, state) in &self.states {
            if state.phase == Phase::Limited && !ips.contains(&flow.0) {
                ips.push(flow.0);
            }
        }

        for ip in ips {
            let Some(policy) = self.effective_policy(ip) else {
                continue;
            };
            let cur = totals.get(&ip).copied().unwrap_or_default();
            // First observation of an IP (e.g. a policy hot-added to a flow that already
            // has traffic): record a baseline and start measuring from now — never treat
            // the accumulated history as a single-tick delta (§6, §21).
            let (rx_delta, tx_delta) = match self.prev_totals.get(&ip).copied() {
                None => (0, 0),
                // saturating_sub turns counter resets / TAP rebuilds into a zero delta (§6).
                Some(prev) => (
                    cur.rx_bytes.saturating_sub(prev.rx_bytes),
                    cur.tx_bytes.saturating_sub(prev.tx_bytes),
                ),
            };
            self.prev_totals.insert(ip, cur);

            self.eval_dir(ip, DIR_RX, policy.rx, rx_delta, now, &mut actions);
            self.eval_dir(ip, DIR_TX, policy.tx, tx_delta, now, &mut actions);
        }

        actions
    }

    fn eval_dir(
        &mut self,
        ip: u32,
        dir: u8,
        dir_policy: Option<DirPolicy>,
        delta: u64,
        now: u64,
        actions: &mut Vec<GcraAction>,
    ) {
        let Some(np) = dir_policy else { return };
        let flow: FlowKey = (ip, dir);

        let window = self
            .windows
            .entry(flow)
            .or_insert_with(|| RollingWindow::new(np.window_secs, self.tick_secs));
        window.add(delta);

        let state = self.states.entry(flow).or_default();
        match state.phase {
            Phase::Normal => {
                if window.is_full() && window.average_bps() >= np.trigger_bps() as f64 {
                    state.phase = Phase::Limited;
                    state.limited_since = now;
                    state.limited_until = now.saturating_add(np.limit_duration_secs);
                    state.applied = Some(np);
                    actions.push(GcraAction::Install {
                        ipv4: ip,
                        direction: dir,
                        rate_bps: np.limit_bps,
                        burst_bytes: np.burst_bytes,
                    });
                }
            }
            Phase::Limited => {
                if now >= state.limited_until {
                    // Duration expired: stop policing, clear the window, re-observe (§7).
                    actions.push(GcraAction::Remove {
                        ipv4: ip,
                        direction: dir,
                    });
                    window.reset();
                    *state = DirState::default();
                }
            }
        }
    }

    // ----- status accessors (used to build the IPC/TUI payload) -----

    pub fn window_avg_bps(&self, ip: u32, dir: u8) -> f64 {
        self.windows
            .get(&(ip, dir))
            .map(|w| w.average_bps())
            .unwrap_or(0.0)
    }

    pub fn state(&self, ip: u32, dir: u8) -> &DirState {
        static DEFAULT: DirState = DirState {
            phase: Phase::Normal,
            limited_since: 0,
            limited_until: 0,
            applied: None,
        };
        self.states.get(&(ip, dir)).unwrap_or(&DEFAULT)
    }

    pub fn is_limited(&self, ip: u32, dir: u8) -> bool {
        self.state(ip, dir).phase == Phase::Limited
    }

    /// Seconds of limiting left for a flow (0 when not LIMITED).
    pub fn remaining_secs(&self, ip: u32, dir: u8, now: u64) -> u64 {
        let s = self.state(ip, dir);
        if s.phase != Phase::Limited {
            return 0;
        }
        s.limited_until.saturating_sub(now)
    }

    /// Count of LIMITED flows within `[start, end]` (overview "Limited" column).
    pub fn limited_count(&self, start: u32, end: u32) -> usize {
        self.states
            .iter()
            .filter(|((ip, _), s)| s.phase == Phase::Limited && *ip >= start && *ip <= end)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{self, SortMode};
    use crate::ip_range::IpRange;
    use crate::policy::PolicyFields;

    fn cfg_from(ranges: Vec<config::ValidatedRange>) -> ValidatedConfig {
        ValidatedConfig {
            bridge: "br0".into(),
            refresh_interval_ms: 1000,
            interface_scan_interval_secs: 5,
            map_max_entries: 8192,
            show_interface: false,
            show_packets: false,
            default_sort: SortMode::Ip,
            ranges,
        }
    }

    fn policy_fields() -> PolicyFields {
        PolicyFields {
            rx_threshold_bps: Some(1_000_000_000),
            tx_threshold_bps: Some(1_000_000_000),
            rx_limit_bps: Some(500_000_000),
            tx_limit_bps: Some(500_000_000),
            window_secs: Some(3), // short window for fast tests
            trigger_ratio_pct: Some(80),
            limit_duration_secs: Some(10),
            burst_bytes: Some(1024),
        }
    }

    fn range(
        name: &str,
        start: [u8; 4],
        end: [u8; 4],
        policy: PolicyFields,
    ) -> config::ValidatedRange {
        config::ValidatedRange {
            inner: IpRange {
                name: name.into(),
                start: u32::from(std::net::Ipv4Addr::from(start)),
                end: u32::from(std::net::Ipv4Addr::from(end)),
            },
            policy,
            overrides: HashMap::new(),
        }
    }

    fn totals(ip: [u8; 4], rx: u64, tx: u64) -> HashMap<u32, IpTotals> {
        let mut m = HashMap::new();
        m.insert(
            u32::from(std::net::Ipv4Addr::from(ip)),
            IpTotals {
                rx_bytes: rx,
                tx_bytes: tx,
            },
        );
        m
    }

    const IP: [u8; 4] = [10, 30, 8, 1];
    const BYTES_PER_TICK: u64 = 125_000_000; // 1 Gbps at 1-second ticks

    fn drive_to_limited(l: &mut Limiter) -> u64 {
        let mut cumulative = 0u64;
        // Tick 1 is the baseline observation (zero delta); the window then needs a full
        // ring of real traffic before it may trigger.
        for t in 1..=4 {
            cumulative += BYTES_PER_TICK;
            l.tick(t, &totals(IP, cumulative, 0));
        }
        cumulative
    }

    #[test]
    fn triggers_after_full_window() {
        let cfg = cfg_from(vec![range("A", IP, IP, policy_fields())]);
        let mut l = Limiter::new(1);
        l.apply_config(&cfg, 0).unwrap();

        let mut cumulative = 0u64;
        let mut actions = Vec::new();
        for t in 1..=4 {
            cumulative += BYTES_PER_TICK;
            actions.extend(l.tick(t, &totals(IP, cumulative, 0)));
        }
        assert_eq!(actions.len(), 1, "{actions:?}");
        match &actions[0] {
            GcraAction::Install {
                ipv4,
                direction,
                rate_bps,
                ..
            } => {
                assert_eq!(*ipv4, u32::from(std::net::Ipv4Addr::from(IP)));
                assert_eq!(*direction, DIR_RX);
                assert_eq!(*rate_bps, 500_000_000);
            }
            other => panic!("expected Install, got {other:?}"),
        }
        assert!(l.is_limited(u32::from(std::net::Ipv4Addr::from(IP)), DIR_RX));
        assert!(!l.is_limited(u32::from(std::net::Ipv4Addr::from(IP)), DIR_TX));
    }

    #[test]
    fn does_not_trigger_before_window_full() {
        let cfg = cfg_from(vec![range("A", IP, IP, policy_fields())]);
        let mut l = Limiter::new(1);
        l.apply_config(&cfg, 0).unwrap();
        let mut cumulative = 0u64;
        for t in 1..=2 {
            cumulative += BYTES_PER_TICK;
            let actions = l.tick(t, &totals(IP, cumulative, 0));
            assert!(actions.is_empty(), "tick {t}: {actions:?}");
        }
        assert!(!l.is_limited(u32::from(std::net::Ipv4Addr::from(IP)), DIR_RX));
    }

    #[test]
    fn expires_after_duration() {
        let cfg = cfg_from(vec![range("A", IP, IP, policy_fields())]);
        let mut l = Limiter::new(1);
        l.apply_config(&cfg, 0).unwrap();
        let cumulative = drive_to_limited(&mut l);
        assert!(l.is_limited(u32::from(std::net::Ipv4Addr::from(IP)), DIR_RX));
        // limited at t=4 with duration 10 → until t=14.
        let actions = l.tick(14, &totals(IP, cumulative, 0));
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], GcraAction::Remove { .. }));
        assert!(!l.is_limited(u32::from(std::net::Ipv4Addr::from(IP)), DIR_RX));
        assert_eq!(
            l.window_avg_bps(u32::from(std::net::Ipv4Addr::from(IP)), DIR_RX),
            0.0
        );
    }

    #[test]
    fn counter_reset_yields_zero_delta() {
        let cfg = cfg_from(vec![range("A", IP, IP, policy_fields())]);
        let mut l = Limiter::new(1);
        l.apply_config(&cfg, 0).unwrap();
        l.tick(1, &totals(IP, 1_000_000, 0));
        let actions = l.tick(2, &totals(IP, 0, 0));
        assert!(actions.is_empty(), "{actions:?}");
        // Tick 1 is the baseline (zero delta) and the backwards counter on tick 2 also
        // yields a zero delta: the window stays empty — never a wrapped ~2^64 spike.
        let avg = l.window_avg_bps(u32::from(std::net::Ipv4Addr::from(IP)), DIR_RX);
        assert!(avg.abs() < 1e-9, "avg={avg}");
    }

    #[test]
    fn override_inherits_and_targets_only_that_ip() {
        let mut r = range("A", [10, 30, 8, 1], [10, 30, 8, 2], policy_fields());
        let ov = PolicyFields {
            rx_threshold_bps: Some(100_000_000),
            ..Default::default()
        };
        r.overrides
            .insert(u32::from(std::net::Ipv4Addr::new(10, 30, 8, 2)), ov);
        let cfg = cfg_from(vec![r]);
        let mut l = Limiter::new(1);
        l.apply_config(&cfg, 0).unwrap();

        let eff = l
            .effective_policy(u32::from(std::net::Ipv4Addr::new(10, 30, 8, 2)))
            .unwrap();
        assert_eq!(eff.rx.unwrap().threshold_bps, 100_000_000);
        assert_eq!(eff.rx.unwrap().limit_bps, 500_000_000);

        let eff1 = l
            .effective_policy(u32::from(std::net::Ipv4Addr::new(10, 30, 8, 1)))
            .unwrap();
        assert_eq!(eff1.rx.unwrap().threshold_bps, 1_000_000_000);
    }

    #[test]
    fn reload_removes_limiter_when_policy_deleted() {
        let cfg_with = cfg_from(vec![range("A", IP, IP, policy_fields())]);
        let mut l = Limiter::new(1);
        l.apply_config(&cfg_with, 0).unwrap();
        drive_to_limited(&mut l);
        assert!(l.is_limited(u32::from(std::net::Ipv4Addr::from(IP)), DIR_RX));

        let cfg_without = cfg_from(vec![range("A", IP, IP, PolicyFields::default())]);
        let actions = l.apply_config(&cfg_without, 5).unwrap();
        assert!(actions
            .iter()
            .any(|a| matches!(a, GcraAction::Remove { direction, .. } if *direction == DIR_RX)));
        assert!(!l.is_limited(u32::from(std::net::Ipv4Addr::from(IP)), DIR_RX));
    }

    #[test]
    fn reload_updates_limit_for_limited_flow() {
        let cfg = cfg_from(vec![range("A", IP, IP, policy_fields())]);
        let mut l = Limiter::new(1);
        l.apply_config(&cfg, 0).unwrap();
        drive_to_limited(&mut l);
        assert!(l.is_limited(u32::from(std::net::Ipv4Addr::from(IP)), DIR_RX));

        let mut pf = policy_fields();
        pf.rx_limit_bps = Some(300_000_000);
        let cfg2 = cfg_from(vec![range("A", IP, IP, pf)]);
        let actions = l.apply_config(&cfg2, 5).unwrap();
        let install = actions
            .iter()
            .find(|a| matches!(a, GcraAction::Install { direction, .. } if *direction == DIR_RX))
            .expect("re-install action");
        match install {
            GcraAction::Install { rate_bps, .. } => assert_eq!(*rate_bps, 300_000_000),
            _ => unreachable!(),
        }
        assert!(l.is_limited(u32::from(std::net::Ipv4Addr::from(IP)), DIR_RX));
    }

    #[test]
    fn reload_duration_reanchored_and_may_release() {
        let cfg = cfg_from(vec![range("A", IP, IP, policy_fields())]);
        let mut l = Limiter::new(1);
        l.apply_config(&cfg, 0).unwrap();
        drive_to_limited(&mut l);
        // limited_since = 4, duration 10 → until 14; at now=5 that is 9s left.
        assert_eq!(
            l.remaining_secs(u32::from(std::net::Ipv4Addr::from(IP)), DIR_RX, 5),
            9
        );

        let mut pf = policy_fields();
        pf.limit_duration_secs = Some(1);
        let cfg2 = cfg_from(vec![range("A", IP, IP, pf)]);
        let actions = l.apply_config(&cfg2, 5).unwrap();
        assert!(actions
            .iter()
            .any(|a| matches!(a, GcraAction::Remove { direction, .. } if *direction == DIR_RX)));
        assert!(!l.is_limited(u32::from(std::net::Ipv4Addr::from(IP)), DIR_RX));
    }

    #[test]
    fn reload_window_change_resets_accumulation() {
        let cfg = cfg_from(vec![range("A", IP, IP, policy_fields())]);
        let mut l = Limiter::new(1);
        l.apply_config(&cfg, 0).unwrap();
        // Partially fill the window.
        l.tick(1, &totals(IP, BYTES_PER_TICK, 0));
        l.tick(2, &totals(IP, BYTES_PER_TICK * 2, 0));
        assert!(l.window_avg_bps(u32::from(std::net::Ipv4Addr::from(IP)), DIR_RX) > 0.0);

        // Change window 3s -> 10s: history discarded, must reaccumulate (§20).
        let mut pf = policy_fields();
        pf.window_secs = Some(10);
        let cfg2 = cfg_from(vec![range("A", IP, IP, pf)]);
        l.apply_config(&cfg2, 3).unwrap();
        assert_eq!(
            l.window_avg_bps(u32::from(std::net::Ipv4Addr::from(IP)), DIR_RX),
            0.0
        );
    }
}
