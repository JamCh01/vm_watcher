//! Transactional LIMIT-map updates.
//!
//! The invariant every operation sequence must preserve:
//!
//! ```text
//! armed policy (LIMIT_POLICIES entry) => the algorithm's state artifact exists
//! ```
//!
//! Install therefore DISARMS the displaced policy first, prepares the new state, and
//! arms the policy LAST (the policy is the only arming marker). Rollback restores the
//! displaced policy in the same shape: fresh state first, policy last. The reverse
//! order would open a window where an armed policy points at missing state, and the
//! data path would silently fail open for that flow.
//!
//! Journal records are established BEFORE the first destructive write of each action
//! and updated as each step succeeds, so a failure at any point leaves enough
//! information to roll back exactly what happened.

use anyhow::Result;

use vm_bandwidth_common::{LimitKey, LimitPolicy};
use vm_bandwidth_core::ip_range::Cidr;

/// Map operations a limit transaction needs. The daemon implements this on the real
/// aya maps; tests drive a scripted fake with failure injection.
///
/// Absence semantics: `disarm_policy` and `clear_state`/`clear_policer` treat an
/// already-absent entry as success (cleanup must not fail on a missing artifact).
pub trait LimitMaps {
    fn get_policy(&mut self, key: &LimitKey) -> Result<Option<LimitPolicy>>;
    /// Insert/overwrite into LIMIT_POLICIES — the ONLY arming marker.
    fn arm_policy(&mut self, key: &LimitKey, policy: LimitPolicy) -> Result<()>;
    /// Remove from LIMIT_POLICIES; absent counts as success.
    fn disarm_policy(&mut self, key: &LimitKey) -> Result<()>;
    /// Zero-initialise the state artifact of `algorithm` (LIMIT_STATE for bucket and
    /// window algorithms, the SWL_LOG ring for sliding-window-log).
    fn write_fresh_state(&mut self, key: &LimitKey, algorithm: u32) -> Result<()>;
    /// Remove the state artifact of `algorithm`; absent counts as success.
    fn clear_state(&mut self, key: &LimitKey, algorithm: u32) -> Result<()>;
    /// Remove policer verdict counters; absent counts as success.
    fn clear_policer(&mut self, key: &LimitKey) -> Result<()>;
}

/// Whitelist-trie operations, journaled alongside limit-map actions so one rollback
/// covers the whole reload transaction.
pub trait WhitelistOps {
    fn wl_insert(&mut self, cidr: &Cidr) -> Result<()>;
    /// Absent counts as success.
    fn wl_remove(&mut self, cidr: &Cidr) -> Result<()>;
}

/// One journaled install: which policy was displaced and how far the new one got.
#[derive(Debug, Clone)]
pub struct InstallRecord {
    pub key: LimitKey,
    pub old: Option<LimitPolicy>,
    /// Set once the NEW algorithm's state artifact has been written.
    pub new_algorithm: Option<u32>,
    /// Set once the new policy is armed.
    pub armed: bool,
}

/// One journaled remove of a previously armed policy.
#[derive(Debug, Clone)]
pub struct RemoveRecord {
    pub key: LimitKey,
    pub old: LimitPolicy,
}

/// Journal of executed operations, played back in reverse on failure.
#[derive(Debug, Default)]
pub struct TxJournal {
    pub installs: Vec<InstallRecord>,
    pub removes: Vec<RemoveRecord>,
    pub wl_added: Vec<Cidr>,
    pub wl_removed: Vec<Cidr>,
}

impl TxJournal {
    pub fn is_empty(&self) -> bool {
        self.installs.is_empty()
            && self.removes.is_empty()
            && self.wl_added.is_empty()
            && self.wl_removed.is_empty()
    }
}

/// One failed rollback step.
#[derive(Debug)]
pub struct RollbackFailure {
    pub key: LimitKey,
    pub op: &'static str,
    pub error: String,
}

/// Structured outcome of a rollback playback: never a silent best-effort.
#[derive(Debug, Default)]
pub struct RollbackReport {
    pub attempted: usize,
    pub succeeded: usize,
    pub failures: Vec<RollbackFailure>,
    /// False when any step failed: at least one flow is unarmed that used to be
    /// armed (fail-open) or a whitelist entry could not be restored.
    pub dataplane_consistent: bool,
}

/// Install (or update) one limit. Order: disarm displaced policy, clear foreign
/// artifacts, write fresh state, arm LAST. The journal record exists before the
/// first destructive write.
pub fn install_limit<M: LimitMaps>(
    m: &mut M,
    journal: &mut TxJournal,
    key: LimitKey,
    policy: LimitPolicy,
) -> Result<()> {
    let old = m.get_policy(&key)?;
    journal.installs.push(InstallRecord {
        key,
        old,
        new_algorithm: None,
        armed: false,
    });
    let rec = journal.installs.last_mut().expect("record just pushed");

    if let Some(old) = rec.old {
        // Disarm first: no state may be rewritten while a policy is armed.
        m.disarm_policy(&key)?;
        if old.algorithm != policy.algorithm {
            m.clear_state(&key, old.algorithm)?;
        }
    }
    m.write_fresh_state(&key, policy.algorithm)?;
    rec.new_algorithm = Some(policy.algorithm);
    m.arm_policy(&key, policy)?;
    rec.armed = true;
    Ok(())
}

/// Remove one limit. Order: disarm first, then clean up artifacts.
pub fn remove_limit<M: LimitMaps>(m: &mut M, journal: &mut TxJournal, key: LimitKey) -> Result<()> {
    let Some(old) = m.get_policy(&key)? else {
        return Ok(()); // nothing armed: removal is a no-op
    };
    journal.removes.push(RemoveRecord { key, old });
    m.disarm_policy(&key)?;
    m.clear_state(&key, old.algorithm)?;
    m.clear_policer(&key)?;
    Ok(())
}

/// Whitelist additions, journaled one entry at a time (each push right after the
/// successful insert) so a mid-way failure rolls back exactly what was added.
pub fn apply_whitelist_additions<W: WhitelistOps>(
    w: &mut W,
    journal: &mut TxJournal,
    additions: &[Cidr],
) -> Result<()> {
    for c in additions {
        w.wl_insert(c)?;
        journal.wl_added.push(*c);
    }
    Ok(())
}

/// Whitelist removals, journaled the same way.
pub fn apply_whitelist_removals<W: WhitelistOps>(
    w: &mut W,
    journal: &mut TxJournal,
    removals: &[Cidr],
) -> Result<()> {
    for c in removals {
        w.wl_remove(c)?;
        journal.wl_removed.push(*c);
    }
    Ok(())
}

/// Play a journal back in reverse. Returns a structured report; callers must surface
/// `dataplane_consistent == false` instead of swallowing it.
pub fn rollback_journal<M: LimitMaps, W: WhitelistOps>(
    m: &mut M,
    w: &mut W,
    journal: &TxJournal,
) -> RollbackReport {
    let mut report = RollbackReport::default();

    for rec in journal.installs.iter().rev() {
        report.attempted += 1;
        let mut ok = true;
        if rec.armed {
            if let Err(e) = m.disarm_policy(&rec.key) {
                fail(&mut report, rec.key, "disarm new policy", e);
                ok = false;
            }
        }
        if let Some(algo) = rec.new_algorithm {
            if let Err(e) = m.clear_state(&rec.key, algo) {
                fail(&mut report, rec.key, "clear new state", e);
                ok = false;
            }
        }
        if let Some(old) = rec.old {
            // Restore the displaced policy: fresh state FIRST, arming LAST. If the
            // state cannot be restored the flow stays unarmed (fail-open) — an armed
            // policy without state is the one thing that must never happen.
            match m.write_fresh_state(&rec.key, old.algorithm) {
                Ok(()) => {
                    if let Err(e) = m.arm_policy(&rec.key, old) {
                        fail(&mut report, rec.key, "re-arm old policy", e);
                        ok = false;
                    }
                }
                Err(e) => {
                    fail(
                        &mut report,
                        rec.key,
                        "restore state (flow stays unarmed)",
                        e,
                    );
                    ok = false;
                }
            }
        }
        if ok {
            report.succeeded += 1;
        }
    }

    for rec in journal.removes.iter().rev() {
        report.attempted += 1;
        let mut ok = true;
        match m.write_fresh_state(&rec.key, rec.old.algorithm) {
            Ok(()) => {
                if let Err(e) = m.arm_policy(&rec.key, rec.old) {
                    fail(&mut report, rec.key, "re-arm removed policy", e);
                    ok = false;
                }
            }
            Err(e) => {
                fail(
                    &mut report,
                    rec.key,
                    "restore state (flow stays unarmed)",
                    e,
                );
                ok = false;
            }
        }
        if ok {
            report.succeeded += 1;
        }
    }

    for c in journal.wl_removed.iter().rev() {
        report.attempted += 1;
        if let Err(e) = w.wl_insert(c) {
            fail(
                &mut report,
                LimitKey::new(0, 0),
                "re-add whitelist prefix",
                e,
            );
        } else {
            report.succeeded += 1;
        }
    }
    for c in journal.wl_added.iter().rev() {
        report.attempted += 1;
        if let Err(e) = w.wl_remove(c) {
            fail(
                &mut report,
                LimitKey::new(0, 0),
                "remove whitelist prefix",
                e,
            );
        } else {
            report.succeeded += 1;
        }
    }

    report.dataplane_consistent = report.failures.is_empty();
    report
}

fn fail(report: &mut RollbackReport, key: LimitKey, op: &'static str, error: anyhow::Error) {
    report.failures.push(RollbackFailure {
        key,
        op,
        error: format!("{error:#}"),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, VecDeque};
    use vm_bandwidth_common::{ALGO_GCRA, ALGO_SLIDING_WINDOW_LOG, ALGO_TOKEN_BUCKET, DIR_RX};

    fn key(ip: u8) -> LimitKey {
        LimitKey::new(u32::from(ip), DIR_RX)
    }

    fn policy(algorithm: u32) -> LimitPolicy {
        LimitPolicy {
            enabled: 1,
            _pad0: [0; 3],
            algorithm,
            rate_bps: 1_000_000,
            burst_bytes: 1024,
            window_ns: 0,
        }
    }

    /// Scripted maps with per-(op, key) failure injection and a full call log.
    #[derive(Default)]
    struct FakeMaps {
        policies: HashMap<LimitKey, LimitPolicy>,
        /// Value = the algorithm the artifact was fresh-written for.
        state: HashMap<LimitKey, u32>,
        rings: HashMap<LimitKey, u32>,
        policer: HashMap<LimitKey, ()>,
        /// Pending injections: consumed when the matching op+key is attempted.
        inject: VecDeque<(String, LimitKey)>,
        log: Vec<String>,
    }

    impl FakeMaps {
        fn fail_next(&mut self, op: &str, k: LimitKey) {
            self.inject.push_back((op.to_string(), k));
        }

        fn injected(&mut self, op: &str, k: &LimitKey) -> bool {
            if let Some(pos) = self
                .inject
                .iter()
                .position(|(o, key)| o == op && *key == *k)
            {
                self.inject.remove(pos);
                true
            } else {
                false
            }
        }

        fn check(&mut self, op: &str, k: &LimitKey) -> Result<()> {
            self.log.push(format!("{op}({k:?})"));
            if self.injected(op, k) {
                anyhow::bail!("injected failure in {op}")
            }
            Ok(())
        }

        fn artifact(&self, k: &LimitKey, algorithm: u32) -> bool {
            if algorithm == ALGO_SLIDING_WINDOW_LOG {
                self.rings.contains_key(k)
            } else {
                self.state.contains_key(k)
            }
        }

        /// The HARD invariant: every armed policy has its algorithm's artifact.
        /// Must hold even after a degraded rollback.
        fn assert_invariants(&self) {
            for (k, p) in &self.policies {
                assert!(
                    self.artifact(k, p.algorithm),
                    "armed policy for {k:?} without artifact"
                );
            }
        }

        /// The SOFT invariant: no unreachable artifact. Holds after clean
        /// transactions; a rollback that itself failed may leave one bounded
        /// orphan per failed flow (reported via RollbackReport).
        fn assert_no_orphans(&self) {
            for k in self.state.keys().chain(self.rings.keys()) {
                assert!(
                    self.policies.contains_key(k),
                    "orphan state artifact for {k:?}"
                );
            }
        }
    }

    impl LimitMaps for FakeMaps {
        fn get_policy(&mut self, key: &LimitKey) -> Result<Option<LimitPolicy>> {
            Ok(self.policies.get(key).copied())
        }

        fn arm_policy(&mut self, key: &LimitKey, policy: LimitPolicy) -> Result<()> {
            self.check("arm_policy", key)?;
            self.policies.insert(*key, policy);
            Ok(())
        }

        fn disarm_policy(&mut self, key: &LimitKey) -> Result<()> {
            self.check("disarm_policy", key)?;
            self.policies.remove(key);
            Ok(())
        }

        fn write_fresh_state(&mut self, key: &LimitKey, algorithm: u32) -> Result<()> {
            self.check("write_fresh_state", key)?;
            if algorithm == ALGO_SLIDING_WINDOW_LOG {
                self.rings.insert(*key, algorithm);
            } else {
                self.state.insert(*key, algorithm);
            }
            Ok(())
        }

        fn clear_state(&mut self, key: &LimitKey, algorithm: u32) -> Result<()> {
            self.check("clear_state", key)?;
            if algorithm == ALGO_SLIDING_WINDOW_LOG {
                self.rings.remove(key);
            } else {
                self.state.remove(key);
            }
            Ok(())
        }

        fn clear_policer(&mut self, key: &LimitKey) -> Result<()> {
            self.check("clear_policer", key)?;
            self.policer.remove(key);
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeWhitelist {
        present: Vec<Cidr>,
        inject: VecDeque<String>,
        log: Vec<String>,
    }

    impl FakeWhitelist {
        fn fail_next(&mut self, op: &str) {
            self.inject.push_back(op.to_string());
        }
        fn check(&mut self, op: &str) -> Result<()> {
            self.log.push(op.to_string());
            if self.inject.front().map(|s| s.as_str()) == Some(op) {
                self.inject.pop_front();
                anyhow::bail!("injected whitelist failure in {op}")
            }
            Ok(())
        }
    }

    impl WhitelistOps for FakeWhitelist {
        fn wl_insert(&mut self, cidr: &Cidr) -> Result<()> {
            self.check("wl_insert")?;
            self.present.push(*cidr);
            Ok(())
        }
        fn wl_remove(&mut self, cidr: &Cidr) -> Result<()> {
            self.check("wl_remove")?;
            self.present.retain(|c| c != cidr);
            Ok(())
        }
    }

    fn cidr(network: u32) -> Cidr {
        Cidr {
            prefix_len: 24,
            network,
        }
    }

    // 1. State creation fails: the policy is never armed, nothing to clean up.
    #[test]
    fn state_creation_failure_leaves_nothing_armed() {
        let mut m = FakeMaps::default();
        let mut w = FakeWhitelist::default();
        let mut j = TxJournal::default();
        let k = key(1);
        m.fail_next("write_fresh_state", k);

        assert!(install_limit(&mut m, &mut j, k, policy(ALGO_GCRA)).is_err());
        let report = rollback_journal(&mut m, &mut w, &j);
        assert!(m.policies.is_empty());
        assert!(m.state.is_empty() && m.rings.is_empty());
        assert!(report.dataplane_consistent);
        m.assert_invariants();
        m.assert_no_orphans();
    }

    // 2. State written but policy insert fails: rollback removes the orphan state.
    #[test]
    fn failed_arming_leaves_no_orphan_state() {
        let mut m = FakeMaps::default();
        let mut w = FakeWhitelist::default();
        let mut j = TxJournal::default();
        let k = key(2);
        m.fail_next("arm_policy", k);

        assert!(install_limit(&mut m, &mut j, k, policy(ALGO_GCRA)).is_err());
        let report = rollback_journal(&mut m, &mut w, &j);
        assert!(m.policies.is_empty(), "policy must not be armed");
        assert!(m.state.is_empty(), "orphan state left behind");
        assert!(report.dataplane_consistent);
        m.assert_invariants();
        m.assert_no_orphans();
    }

    // 3. Same for the SWL ring: a failed arming must not leave an orphan ring.
    #[test]
    fn failed_arming_leaves_no_orphan_swl_ring() {
        let mut m = FakeMaps::default();
        let mut w = FakeWhitelist::default();
        let mut j = TxJournal::default();
        let k = key(3);
        m.fail_next("arm_policy", k);

        assert!(install_limit(&mut m, &mut j, k, policy(ALGO_SLIDING_WINDOW_LOG)).is_err());
        let report = rollback_journal(&mut m, &mut w, &j);
        assert!(m.policies.is_empty());
        assert!(m.rings.is_empty(), "orphan SWL ring left behind");
        assert!(report.dataplane_consistent);
        m.assert_invariants();
        m.assert_no_orphans();
    }

    // 4. Same-algorithm update fails at arming: the old policy is re-armed with a
    //    fresh (never half-updated) state artifact.
    #[test]
    fn same_algorithm_update_failure_restores_old_policy() {
        let mut m = FakeMaps::default();
        let mut w = FakeWhitelist::default();
        let mut j = TxJournal::default();
        let k = key(4);
        let old = policy(ALGO_GCRA);
        install_limit(&mut m, &mut j, k, old).unwrap();
        j = TxJournal::default();

        // The fresh write for the new (same) algorithm succeeds, the arming fails.
        m.fail_next("arm_policy", k);
        let mut new = policy(ALGO_GCRA);
        new.rate_bps = 2_000_000;
        assert!(install_limit(&mut m, &mut j, k, new).is_err());

        let report = rollback_journal(&mut m, &mut w, &j);
        assert_eq!(
            m.policies.get(&k).copied(),
            Some(old),
            "old policy restored"
        );
        assert!(m.artifact(&k, ALGO_GCRA), "state artifact present");
        assert!(report.dataplane_consistent);
        m.assert_invariants();
        m.assert_no_orphans();
    }

    // 5. bucket -> SWL switch fails while writing the ring: old bucket policy returns.
    #[test]
    fn bucket_to_swl_switch_failure_restores_bucket() {
        let mut m = FakeMaps::default();
        let mut w = FakeWhitelist::default();
        let mut j = TxJournal::default();
        let k = key(5);
        install_limit(&mut m, &mut j, k, policy(ALGO_TOKEN_BUCKET)).unwrap();
        j = TxJournal::default();

        m.fail_next("write_fresh_state", k);
        assert!(install_limit(&mut m, &mut j, k, policy(ALGO_SLIDING_WINDOW_LOG)).is_err());

        let report = rollback_journal(&mut m, &mut w, &j);
        let armed = m.policies.get(&k).expect("old policy re-armed");
        assert_eq!(armed.algorithm, ALGO_TOKEN_BUCKET);
        assert!(m.artifact(&k, ALGO_TOKEN_BUCKET));
        assert!(m.rings.is_empty(), "no half-created ring");
        assert!(report.dataplane_consistent);
        m.assert_invariants();
        m.assert_no_orphans();
    }

    // 6. SWL -> bucket switch fails while writing the state: old SWL policy returns
    //    with a fresh ring.
    #[test]
    fn swl_to_bucket_switch_failure_restores_swl() {
        let mut m = FakeMaps::default();
        let mut w = FakeWhitelist::default();
        let mut j = TxJournal::default();
        let k = key(6);
        install_limit(&mut m, &mut j, k, policy(ALGO_SLIDING_WINDOW_LOG)).unwrap();
        j = TxJournal::default();

        m.fail_next("write_fresh_state", k);
        assert!(install_limit(&mut m, &mut j, k, policy(ALGO_GCRA)).is_err());

        let report = rollback_journal(&mut m, &mut w, &j);
        let armed = m.policies.get(&k).expect("old policy re-armed");
        assert_eq!(armed.algorithm, ALGO_SLIDING_WINDOW_LOG);
        assert!(m.artifact(&k, ALGO_SLIDING_WINDOW_LOG));
        assert!(m.state.is_empty(), "no half-created state");
        assert!(report.dataplane_consistent);
        m.assert_invariants();
        m.assert_no_orphans();
    }

    // 7. Remove: policy disarmed but state cleanup fails -> rollback re-arms the old
    //    policy (its artifact is still there).
    #[test]
    fn remove_with_state_cleanup_failure_rearms_old_policy() {
        let mut m = FakeMaps::default();
        let mut w = FakeWhitelist::default();
        let mut j = TxJournal::default();
        let k = key(7);
        let old = policy(ALGO_GCRA);
        install_limit(&mut m, &mut j, k, old).unwrap();
        j = TxJournal::default();

        m.fail_next("clear_state", k);
        assert!(remove_limit(&mut m, &mut j, k).is_err());

        let report = rollback_journal(&mut m, &mut w, &j);
        assert_eq!(m.policies.get(&k).copied(), Some(old));
        assert!(report.dataplane_consistent);
        m.assert_invariants();
        m.assert_no_orphans();
    }

    // 8. Rollback cannot restore state: the policy stays UNARMED and the report says
    //    the dataplane is degraded — never an armed policy without state.
    #[test]
    fn failed_state_restore_leaves_flow_unarmed_and_reported() {
        let mut m = FakeMaps::default();
        let mut w = FakeWhitelist::default();
        let mut j = TxJournal::default();
        let k = key(8);
        install_limit(&mut m, &mut j, k, policy(ALGO_GCRA)).unwrap();
        j = TxJournal::default();

        m.fail_next("clear_state", k);
        assert!(remove_limit(&mut m, &mut j, k).is_err());
        // Now make the rollback's state restore fail too.
        m.fail_next("write_fresh_state", k);

        let report = rollback_journal(&mut m, &mut w, &j);
        assert!(m.policies.is_empty(), "policy must stay unarmed");
        assert!(!report.dataplane_consistent);
        assert_eq!(report.failures.len(), 1);
        assert!(report.failures[0].op.contains("restore state"));
        m.assert_invariants();
        // Degraded case: the artifact whose cleanup/restore failed stays behind,
        // unreachable (policy unarmed) — a bounded leak the report makes visible.
        assert!(m.artifact(&k, ALGO_GCRA));
    }

    // 9. Ordering: forward install is disarm/clear/state-before-arm; rollback restore
    //    is state-before-policy. Verified from the call log.
    #[test]
    fn ordering_is_state_first_policy_last_in_both_directions() {
        let mut m = FakeMaps::default();
        let mut w = FakeWhitelist::default();
        let mut j = TxJournal::default();
        let k = key(9);
        install_limit(&mut m, &mut j, k, policy(ALGO_TOKEN_BUCKET)).unwrap();
        // Forward update over a different algorithm exercises every step.
        j = TxJournal::default();
        m.log.clear();
        let mut new = policy(ALGO_GCRA);
        new.rate_bps = 42;
        install_limit(&mut m, &mut j, k, new).unwrap();
        let disarm = m.log.iter().position(|c| c.starts_with("disarm")).unwrap();
        let clear = m
            .log
            .iter()
            .position(|c| c.starts_with("clear_state"))
            .unwrap();
        let fresh = m
            .log
            .iter()
            .position(|c| c.starts_with("write_fresh_state"))
            .unwrap();
        let arm = m
            .log
            .iter()
            .position(|c| c.starts_with("arm_policy"))
            .unwrap();
        assert!(
            disarm < clear && clear < fresh && fresh < arm,
            "{:?}",
            m.log
        );

        // Rollback of a failed update must write state before re-arming.
        j = TxJournal::default();
        m.log.clear();
        m.fail_next("arm_policy", k);
        let mut new2 = policy(ALGO_GCRA);
        new2.rate_bps = 43;
        assert!(install_limit(&mut m, &mut j, k, new2).is_err());
        m.log.clear();
        rollback_journal(&mut m, &mut w, &j);
        let fresh = m
            .log
            .iter()
            .position(|c| c.starts_with("write_fresh_state"))
            .unwrap();
        let arm = m
            .log
            .iter()
            .position(|c| c.starts_with("arm_policy"))
            .unwrap();
        assert!(
            fresh < arm,
            "rollback must restore state before arming: {:?}",
            m.log
        );
    }

    // 10. Whitelist additions fail mid-way: rollback removes exactly what was added.
    #[test]
    fn whitelist_addition_failure_rolls_back_added_prefixes() {
        let mut m = FakeMaps::default();
        let mut w = FakeWhitelist::default();
        let mut j = TxJournal::default();
        let cs = [cidr(1), cidr(2), cidr(3)];
        // First two insertions succeed, then inject a failure for the third.
        assert!(apply_whitelist_additions(&mut w, &mut j, &cs[..2]).is_ok());
        w.fail_next("wl_insert");
        assert!(apply_whitelist_additions(&mut w, &mut j, &cs[2..]).is_err());
        assert_eq!(w.present.len(), 2);

        let report = rollback_journal(&mut m, &mut w, &j);
        assert!(w.present.is_empty(), "added prefixes rolled back");
        assert!(report.dataplane_consistent);
    }

    // 11. Rollback itself hits a second error: both failures are reported and the
    //     dataplane is flagged inconsistent.
    #[test]
    fn rollback_second_failure_is_reported_not_swallowed() {
        let mut m = FakeMaps::default();
        let mut w = FakeWhitelist::default();
        let mut j = TxJournal::default();
        let k = key(11);
        install_limit(&mut m, &mut j, k, policy(ALGO_GCRA)).unwrap();
        j = TxJournal::default();

        // Primary failure: arming the update.
        m.fail_next("arm_policy", k);
        assert!(install_limit(&mut m, &mut j, k, policy(ALGO_GCRA)).is_err());
        // Secondary failure during rollback: the state restore.
        m.fail_next("write_fresh_state", k);

        let report = rollback_journal(&mut m, &mut w, &j);
        assert_eq!(report.failures.len(), 1);
        assert!(!report.dataplane_consistent);
        assert!(m.policies.is_empty());
        m.assert_invariants();
        m.assert_no_orphans();
    }

    // 12. Mixed batch with a mid-batch failure: after rollback the observable
    //     dataplane is exactly the pre-batch state (modulo fresh state resets, which
    //     are unrecoverable by design) and every invariant holds.
    #[test]
    fn mixed_batch_failure_returns_to_consistent_state() {
        let mut m = FakeMaps::default();
        let mut w = FakeWhitelist::default();
        let mut j = TxJournal::default();
        let (a, b, c) = (key(12), key(13), key(14));
        // Pre-existing: A armed GCRA, B armed SWL.
        install_limit(&mut m, &mut j, a, policy(ALGO_GCRA)).unwrap();
        install_limit(&mut m, &mut j, b, policy(ALGO_SLIDING_WINDOW_LOG)).unwrap();
        j = TxJournal::default();

        // Batch: remove A, update B (SWL rate change), install C. C's state write fails.
        remove_limit(&mut m, &mut j, a).unwrap();
        let mut b2 = policy(ALGO_SLIDING_WINDOW_LOG);
        b2.rate_bps = 7;
        install_limit(&mut m, &mut j, b, b2).unwrap();
        m.fail_next("write_fresh_state", c);
        assert!(install_limit(&mut m, &mut j, c, policy(ALGO_TOKEN_BUCKET)).is_err());

        let report = rollback_journal(&mut m, &mut w, &j);
        assert!(report.dataplane_consistent, "{:?}", report.failures);
        // A restored (fresh state), B restored to its OLD policy, C absent.
        assert!(m.policies.contains_key(&a));
        assert_eq!(m.policies.get(&b).unwrap().rate_bps, 1_000_000);
        assert!(!m.policies.contains_key(&c));
        m.assert_invariants();
        m.assert_no_orphans();
    }
}
