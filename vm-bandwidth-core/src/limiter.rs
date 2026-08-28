//! NORMAL / LIMITED lifecycle for per-(IP, direction) limiters.
//!
//! The limiter is pure userspace logic: it owns the rolling windows, evaluates thresholds,
//! tracks LIMITED expiry, and emits [`LimitAction`]s describing what the runtime must write
//! into (or remove from) the eBPF `LIMIT_POLICIES` / `LIMIT_STATE` maps. It never touches
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
    /// Cumulative packet counters (unused by the limiter; carried for metrics export).
    pub rx_packets: u64,
    pub tx_packets: u64,
}

/// (ipv4, direction) identifies one limiter / one rolling window.
pub type FlowKey = (u32, u8);

/// What the runtime must do to the eBPF maps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LimitAction {
    /// Install (or update) a limit and reset the algorithm's runtime state.
    /// `algorithm` is one of the `vm_bandwidth_common::ALGO_*` constants;
    /// `window_ns` is the policy window for window-based algorithms (0 otherwise).
    Install {
        ipv4: u32,
        direction: u8,
        rate_bps: u64,
        burst_bytes: u64,
        algorithm: u32,
        window_ns: u64,
    },
    /// Remove the limit and any runtime state; policing stops (fail-open).
    Remove { ipv4: u32, direction: u8 },
}

/// A reload change plan: pure output of `plan_reload`, consumed by `commit_reload`
/// only after the runtime has applied every map action successfully.
#[derive(Debug)]
pub struct ReloadPlan {
    /// Map actions in execution order: Removes first (they free capacity), Installs last.
    pub actions: Vec<LimitAction>,
    new_ranges: Vec<PolicyRange>,
    new_overrides: HashMap<u32, EffectivePolicy>,
    /// LIMITED flows returning to NORMAL (phase state + window reset at commit).
    flow_resets: Vec<FlowKey>,
    /// LIMITED flows staying limited: new `limited_until` and newly applied policy.
    flow_updates: Vec<(FlowKey, u64, DirPolicy)>,
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
    /// Compute the reload change plan against the NEW config without touching any mutable
    /// state. The runtime executes `plan.actions` against the eBPF maps first; only after
    /// every map operation succeeds does [`commit_reload`] apply the internal transitions.
    /// A rejected plan leaves the limiter (and the dataplane) exactly as they were.
    pub fn plan_reload(&self, cfg: &ValidatedConfig, now: u64) -> Result<ReloadPlan, String> {
        let (new_ranges, new_overrides) = Self::build_index(cfg)?;
        let mut removes = Vec::new();
        let mut installs = Vec::new();
        let mut flow_resets = Vec::new();
        let mut flow_updates = Vec::new();

        // Flows that are currently LIMITED, reconciled against the NEW config (§22–§25).
        let limited: Vec<FlowKey> = self
            .states
            .iter()
            .filter(|(_, s)| s.phase == Phase::Limited)
            .map(|(k, _)| *k)
            .collect();

        for flow in limited {
            let (ip, dir) = flow;
            let new_dir = lookup(&new_ranges, &new_overrides, ip).and_then(|p| match dir {
                DIR_RX => p.rx,
                DIR_TX => p.tx,
                _ => None,
            });
            let state = match self.states.get(&flow) {
                Some(s) => s,
                None => continue,
            };
            let applied = match &state.applied {
                Some(a) => a,
                None => continue,
            };
            match new_dir {
                // §25 / range-or-IP removed: stop policing, back to NORMAL.
                None => {
                    removes.push(LimitAction::Remove {
                        ipv4: ip,
                        direction: dir,
                    });
                    flow_resets.push(flow);
                }
                Some(np) => {
                    // §24: duration re-anchored to the original limited_since.
                    let limited_until = state.limited_since.saturating_add(np.limit_duration_secs);
                    if limited_until <= now {
                        removes.push(LimitAction::Remove {
                            ipv4: ip,
                            direction: dir,
                        });
                        flow_resets.push(flow);
                        continue;
                    }
                    // §22 / §23: rate, burst, algorithm or window changed → re-install
                    // (the runtime resets the algorithm's state).
                    if np.limit_bps != applied.limit_bps
                        || np.burst_bytes != applied.burst_bytes
                        || np.algorithm != applied.algorithm
                        || np.limit_window_secs != applied.limit_window_secs
                    {
                        installs.push(LimitAction::Install {
                            ipv4: ip,
                            direction: dir,
                            rate_bps: np.limit_bps,
                            burst_bytes: np.burst_bytes,
                            algorithm: np.algorithm,
                            window_ns: np.limit_window_secs.saturating_mul(1_000_000_000),
                        });
                    }
                    flow_updates.push((flow, limited_until, np));
                }
            }
        }

        // Removes run first: they free map capacity before installs spend it.
        let mut actions = removes;
        actions.extend(installs);
        Ok(ReloadPlan {
            actions,
            new_ranges,
            new_overrides,
            flow_resets,
            flow_updates,
        })
    }

    /// Apply a plan's internal transitions after the runtime has executed every map
    /// operation successfully. Never called on a rejected plan.
    pub fn commit_reload(&mut self, plan: ReloadPlan) {
        self.ranges = plan.new_ranges;
        self.overrides = plan.new_overrides;

        // Baselines for IPs that no longer have any policy are dead weight (§33). If a
        // policy comes back for such an IP later it starts from a fresh baseline, which
        // is the same semantics as any newly added policy.
        self.prev_totals
            .retain(|ip, _| lookup(&self.ranges, &self.overrides, *ip).is_some());

        for flow in plan.flow_resets {
            if let Some(s) = self.states.get_mut(&flow) {
                *s = DirState::default();
            }
            if let Some(w) = self.windows.get_mut(&flow) {
                w.reset();
            }
        }
        for (flow, limited_until, applied) in plan.flow_updates {
            if let Some(s) = self.states.get_mut(&flow) {
                s.limited_until = limited_until;
                s.applied = Some(applied);
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
    }

    /// Drop the phase state of one flow (keeps its rolling window/baseline). Used after a
    /// failed runtime map apply so the flow re-evaluates from NORMAL instead of sitting
    /// in a LIMITED phase the dataplane does not share.
    pub fn reset_flow(&mut self, ip: u32, dir: u8) {
        if let Some(s) = self.states.get_mut(&(ip, dir)) {
            *s = DirState::default();
        }
    }

    /// Advance one tick with the current per-IP cumulative totals. Returns the actions the
    /// runtime must apply (entering / leaving LIMITED).
    pub fn tick(&mut self, now: u64, totals: &HashMap<u32, IpTotals>) -> Vec<LimitAction> {
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
        actions: &mut Vec<LimitAction>,
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
                    actions.push(LimitAction::Install {
                        ipv4: ip,
                        direction: dir,
                        rate_bps: np.limit_bps,
                        burst_bytes: np.burst_bytes,
                        algorithm: np.algorithm,
                        window_ns: np.limit_window_secs.saturating_mul(1_000_000_000),
                    });
                }
            }
            Phase::Limited => {
                if now >= state.limited_until {
                    // Duration expired: stop policing, clear the window, re-observe (§7).
                    actions.push(LimitAction::Remove {
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
            swl_map_max_entries: 256,
            ip_ownership: "external".into(),
            show_interface: false,
            show_packets: false,
            default_sort: SortMode::Ip,
            metrics_enabled: false,
            metrics_url: String::new(),
            metrics_push_interval_secs: 60,
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
            ..Default::default()
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
                rx_packets: 0,
                tx_packets: 0,
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
        let plan = l.plan_reload(&cfg, 0).unwrap();
        l.commit_reload(plan);

        let mut cumulative = 0u64;
        let mut actions = Vec::new();
        for t in 1..=4 {
            cumulative += BYTES_PER_TICK;
            actions.extend(l.tick(t, &totals(IP, cumulative, 0)));
        }
        assert_eq!(actions.len(), 1, "{actions:?}");
        match &actions[0] {
            LimitAction::Install {
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
        let plan = l.plan_reload(&cfg, 0).unwrap();
        l.commit_reload(plan);
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
        let plan = l.plan_reload(&cfg, 0).unwrap();
        l.commit_reload(plan);
        let cumulative = drive_to_limited(&mut l);
        assert!(l.is_limited(u32::from(std::net::Ipv4Addr::from(IP)), DIR_RX));
        // limited at t=4 with duration 10 → until t=14.
        let actions = l.tick(14, &totals(IP, cumulative, 0));
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], LimitAction::Remove { .. }));
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
        let plan = l.plan_reload(&cfg, 0).unwrap();
        l.commit_reload(plan);
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
        let plan = l.plan_reload(&cfg, 0).unwrap();
        l.commit_reload(plan);

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
        let plan = l.plan_reload(&cfg_with, 0).unwrap();
        l.commit_reload(plan);
        drive_to_limited(&mut l);
        assert!(l.is_limited(u32::from(std::net::Ipv4Addr::from(IP)), DIR_RX));

        let cfg_without = cfg_from(vec![range("A", IP, IP, PolicyFields::default())]);
        let plan = l.plan_reload(&cfg_without, 5).unwrap();
        let actions = plan.actions.clone();
        l.commit_reload(plan);
        assert!(actions
            .iter()
            .any(|a| matches!(a, LimitAction::Remove { direction, .. } if *direction == DIR_RX)));
        assert!(!l.is_limited(u32::from(std::net::Ipv4Addr::from(IP)), DIR_RX));
    }

    #[test]
    fn reload_updates_limit_for_limited_flow() {
        let cfg = cfg_from(vec![range("A", IP, IP, policy_fields())]);
        let mut l = Limiter::new(1);
        let plan = l.plan_reload(&cfg, 0).unwrap();
        l.commit_reload(plan);
        drive_to_limited(&mut l);
        assert!(l.is_limited(u32::from(std::net::Ipv4Addr::from(IP)), DIR_RX));

        let mut pf = policy_fields();
        pf.rx_limit_bps = Some(300_000_000);
        let cfg2 = cfg_from(vec![range("A", IP, IP, pf)]);
        let plan = l.plan_reload(&cfg2, 5).unwrap();
        let actions = plan.actions.clone();
        l.commit_reload(plan);
        let install = actions
            .iter()
            .find(|a| matches!(a, LimitAction::Install { direction, .. } if *direction == DIR_RX))
            .expect("re-install action");
        match install {
            LimitAction::Install { rate_bps, .. } => assert_eq!(*rate_bps, 300_000_000),
            _ => unreachable!(),
        }
        assert!(l.is_limited(u32::from(std::net::Ipv4Addr::from(IP)), DIR_RX));
    }

    #[test]
    fn reload_duration_reanchored_and_may_release() {
        let cfg = cfg_from(vec![range("A", IP, IP, policy_fields())]);
        let mut l = Limiter::new(1);
        let plan = l.plan_reload(&cfg, 0).unwrap();
        l.commit_reload(plan);
        drive_to_limited(&mut l);
        // limited_since = 4, duration 10 → until 14; at now=5 that is 9s left.
        assert_eq!(
            l.remaining_secs(u32::from(std::net::Ipv4Addr::from(IP)), DIR_RX, 5),
            9
        );

        let mut pf = policy_fields();
        pf.limit_duration_secs = Some(1);
        let cfg2 = cfg_from(vec![range("A", IP, IP, pf)]);
        let plan = l.plan_reload(&cfg2, 5).unwrap();
        let actions = plan.actions.clone();
        l.commit_reload(plan);
        assert!(actions
            .iter()
            .any(|a| matches!(a, LimitAction::Remove { direction, .. } if *direction == DIR_RX)));
        assert!(!l.is_limited(u32::from(std::net::Ipv4Addr::from(IP)), DIR_RX));
    }

    #[test]
    fn reload_window_change_resets_accumulation() {
        let cfg = cfg_from(vec![range("A", IP, IP, policy_fields())]);
        let mut l = Limiter::new(1);
        let plan = l.plan_reload(&cfg, 0).unwrap();
        l.commit_reload(plan);
        // Partially fill the window.
        l.tick(1, &totals(IP, BYTES_PER_TICK, 0));
        l.tick(2, &totals(IP, BYTES_PER_TICK * 2, 0));
        assert!(l.window_avg_bps(u32::from(std::net::Ipv4Addr::from(IP)), DIR_RX) > 0.0);

        // Change window 3s -> 10s: history discarded, must reaccumulate (§20).
        let mut pf = policy_fields();
        pf.window_secs = Some(10);
        let cfg2 = cfg_from(vec![range("A", IP, IP, pf)]);
        let plan = l.plan_reload(&cfg2, 3).unwrap();
        l.commit_reload(plan);
        assert_eq!(
            l.window_avg_bps(u32::from(std::net::Ipv4Addr::from(IP)), DIR_RX),
            0.0
        );
    }

    #[test]
    fn reload_plan_orders_removes_before_installs() {
        // Two flows LIMITED under cfg1; cfg2 deletes A's policy and changes B's rate.
        // The plan must execute A's Remove before B's Install: removes free map
        // capacity that installs then spend.
        let ip_a = [10u8, 0, 0, 1];
        let ip_b = [10u8, 0, 0, 2];
        let a = u32::from(std::net::Ipv4Addr::from(ip_a));
        let b = u32::from(std::net::Ipv4Addr::from(ip_b));

        let cfg1 = cfg_from(vec![
            range("A", ip_a, ip_a, policy_fields()),
            range("B", ip_b, ip_b, policy_fields()),
        ]);
        let mut l = Limiter::new(1);
        let plan = l.plan_reload(&cfg1, 0).unwrap();
        l.commit_reload(plan);

        let (mut cum_a, mut cum_b) = (0u64, 0u64);
        for t in 1..=4 {
            cum_a += BYTES_PER_TICK;
            cum_b += BYTES_PER_TICK;
            let mut m = HashMap::new();
            for (ip, cum) in [(a, cum_a), (b, cum_b)] {
                m.insert(
                    ip,
                    IpTotals {
                        rx_bytes: cum,
                        tx_bytes: 0,
                        rx_packets: 0,
                        tx_packets: 0,
                    },
                );
            }
            l.tick(t, &m);
        }
        assert!(l.is_limited(a, DIR_RX));
        assert!(l.is_limited(b, DIR_RX));

        let mut pf_b = policy_fields();
        pf_b.rx_limit_bps = Some(300_000_000);
        let cfg2 = cfg_from(vec![
            range("A", ip_a, ip_a, PolicyFields::default()),
            range("B", ip_b, ip_b, pf_b),
        ]);
        let plan = l.plan_reload(&cfg2, 5).unwrap();
        let pos_remove = plan
            .actions
            .iter()
            .position(|x| matches!(x, LimitAction::Remove { ipv4, .. } if *ipv4 == a))
            .expect("remove action for A");
        let pos_install = plan
            .actions
            .iter()
            .position(|x| matches!(x, LimitAction::Install { ipv4, .. } if *ipv4 == b))
            .expect("install action for B");
        assert!(
            pos_remove < pos_install,
            "removes must execute before installs"
        );
    }
}
