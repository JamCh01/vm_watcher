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
/// Every progress flag is set ONLY after the corresponding map operation returned
/// success — a record's existence alone never implies any step succeeded.
#[derive(Debug, Clone)]
pub struct InstallRecord {
    pub key: LimitKey,
    pub old: Option<LimitPolicy>,
    /// True only after the displaced policy was confirmed removed from
    /// LIMIT_POLICIES. While false the old policy may still be armed and the
    /// rollback must not rewrite or re-arm on top of it.
    pub old_disarmed: bool,
    /// Set only after the NEW algorithm's state artifact has been written.
    pub new_algorithm: Option<u32>,
    /// Set only after the new policy is armed.
    pub armed: bool,
}

/// One journaled remove of a previously armed policy.
#[derive(Debug, Clone)]
pub struct RemoveRecord {
    pub key: LimitKey,
    pub old: LimitPolicy,
    /// True only after the policy was confirmed removed from LIMIT_POLICIES. While
    /// false the old policy may still be armed with its state, and the rollback must
    /// leave that pair untouched.
    pub disarmed: bool,
}

/// Journal of executed operations, played back in reverse on failure.
#[derive(Debug, Default)]
pub struct TxJournal {
    pub installs: Vec<InstallRecord>,
    pub removes: Vec<RemoveRecord>,
    pub wl_added: Vec<Cidr>,
    pub wl_removed: Vec<Cidr>,
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
    /// False when any rollback step failed. A rollback failure means the
    /// intended pre-transaction state was not fully restored; the surviving
    /// dataplane state depends on the failed step and is reported per
    /// `RollbackFailure` (e.g. a failed disarm-new leaves the NEW policy armed
    /// with its state, a failed re-arm leaves the flow unarmed with a bounded
    /// orphan state). It does NOT uniformly mean every affected flow is
    /// unarmed. The hard invariant `armed policy => matching state exists`
    /// holds either way.
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
        old_disarmed: false,
        new_algorithm: None,
        armed: false,
    });
    let rec = journal.installs.last_mut().expect("record just pushed");

    if let Some(old) = rec.old {
        // Disarm first: no state may be rewritten while a policy is armed. The
        // progress flag flips only once the removal is confirmed.
        m.disarm_policy(&key)?;
        rec.old_disarmed = true;
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
    journal.removes.push(RemoveRecord {
        key,
        old,
        disarmed: false,
    });
    m.disarm_policy(&key)?;
    journal
        .removes
        .last_mut()
        .expect("record just pushed")
        .disarmed = true;
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
            match m.disarm_policy(&rec.key) {
                Ok(()) => {}
                Err(e) => {
                    // The new policy may still be armed; its state artifact must not
                    // be cleared, overwritten or replaced. Leaving the (new policy +
                    // new state) pair in place still satisfies the hard invariant —
                    // the dataplane keeps the NEW limit for this flow, and the report
                    // says so. Stop this record's destructive rollback, but keep
                    // rolling back the independent records so every failure surfaces.
                    fail(
                        &mut report,
                        rec.key,
                        "disarm new policy (kept new policy + state)",
                        e,
                    );
                    continue;
                }
            }
        }
        if let Some(algo) = rec.new_algorithm {
            if let Err(e) = m.clear_state(&rec.key, algo) {
                fail(&mut report, rec.key, "clear new state", e);
                ok = false;
                // Continue: a leftover artifact is a bounded orphan; restoring the
                // displaced policy matters more (a same-algorithm restore overwrites
                // the leftover anyway).
            }
        }
        if let Some(old) = rec.old {
            if !rec.old_disarmed {
                // The forward disarm never succeeded: the old policy may still be
                // armed with its own state. Rewriting or re-arming on top of a live
                // pair would corrupt it — leave the pair untouched.
            } else {
                // Restore the displaced policy: fresh state FIRST, arming LAST. If
                // the state cannot be restored the flow stays unarmed (fail-open) —
                // an armed policy without state is the one thing that must never
                // happen.
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
        }
        if ok {
            report.succeeded += 1;
        }
    }

    for rec in journal.removes.iter().rev() {
        report.attempted += 1;
        if !rec.disarmed {
            // The policy never left LIMIT_POLICIES: it may still be armed with its
            // state. Nothing to roll back — and rewriting its state would corrupt a
            // live flow.
            report.succeeded += 1;
            continue;
        }
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

    pub(crate) fn key(ip: u8) -> LimitKey {
        LimitKey::new(u32::from(ip), DIR_RX)
    }

    pub(crate) fn policy(algorithm: u32) -> LimitPolicy {
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
    pub(crate) struct FakeMaps {
        pub(crate) policies: HashMap<LimitKey, LimitPolicy>,
        /// Value = the algorithm the artifact was fresh-written for.
        pub(crate) state: HashMap<LimitKey, u32>,
        pub(crate) rings: HashMap<LimitKey, u32>,
        pub(crate) policer: HashMap<LimitKey, ()>,
        /// Pending injections: consumed when the matching op+key is attempted.
        inject: VecDeque<(String, LimitKey)>,
        pub(crate) log: Vec<String>,
    }

    impl FakeMaps {
        pub(crate) fn fail_next(&mut self, op: &str, k: LimitKey) {
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

        pub(crate) fn artifact(&self, k: &LimitKey, algorithm: u32) -> bool {
            if algorithm == ALGO_SLIDING_WINDOW_LOG {
                self.rings.contains_key(k)
            } else {
                self.state.contains_key(k)
            }
        }

        /// The HARD invariant: every armed policy has its algorithm's artifact.
        /// Must hold even after a degraded rollback.
        pub(crate) fn assert_invariants(&self) {
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
        pub(crate) fn assert_no_orphans(&self) {
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
    pub(crate) struct FakeWhitelist {
        pub(crate) present: Vec<Cidr>,
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

    pub(crate) fn cidr(network: u32) -> Cidr {
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

    // ---------- rollback disarm-failure scenarios (merge blockers) ----------

    /// A batch where a second flow fails so that rollback runs, used to exercise one
    /// record's rollback while another record drives the abort.
    fn batch_with_failing_flow(m: &mut FakeMaps, journal: &mut TxJournal, second_key: LimitKey) {
        m.fail_next("write_fresh_state", second_key);
        assert!(install_limit(m, journal, second_key, policy(ALGO_GCRA)).is_err());
    }

    // 13. Forward disarm fails during an UPDATE: the old policy and its state must
    //     be completely untouched, no new state written, hard invariant intact.
    #[test]
    fn forward_disarm_failure_on_update_leaves_old_intact() {
        let mut m = FakeMaps::default();
        let mut w = FakeWhitelist::default();
        let mut j = TxJournal::default();
        let k = key(20);
        let old = policy(ALGO_GCRA);
        install_limit(&mut m, &mut j, k, old).unwrap();
        j = TxJournal::default();
        m.log.clear();

        m.fail_next("disarm_policy", k);
        let mut new = policy(ALGO_GCRA);
        new.rate_bps = 42;
        assert!(install_limit(&mut m, &mut j, k, new).is_err());

        let report = rollback_journal(&mut m, &mut w, &j);
        assert_eq!(
            m.policies.get(&k).copied(),
            Some(old),
            "old policy untouched"
        );
        assert_eq!(m.policies.get(&k).unwrap().rate_bps, 1_000_000);
        assert!(m.artifact(&k, ALGO_GCRA), "old state untouched");
        assert_eq!(
            m.state.get(&k).copied(),
            Some(ALGO_GCRA),
            "state was never rewritten"
        );
        assert!(
            !m.log.iter().any(|c| c.starts_with("write_fresh_state")),
            "no new state write may happen: {:?}",
            m.log
        );
        assert!(report.dataplane_consistent);
        m.assert_invariants();
    }

    // 14. Forward disarm fails during a REMOVE: old policy+state stay intact and the
    //     rollback must not rewrite the in-use state.
    #[test]
    fn forward_disarm_failure_on_remove_keeps_old_pair() {
        let mut m = FakeMaps::default();
        let mut w = FakeWhitelist::default();
        let mut j = TxJournal::default();
        let k = key(21);
        let old = policy(ALGO_GCRA);
        install_limit(&mut m, &mut j, k, old).unwrap();
        j = TxJournal::default();

        m.fail_next("disarm_policy", k);
        assert!(remove_limit(&mut m, &mut j, k).is_err());
        m.log.clear();

        let report = rollback_journal(&mut m, &mut w, &j);
        assert_eq!(m.policies.get(&k).copied(), Some(old));
        assert!(m.artifact(&k, ALGO_GCRA));
        assert!(
            m.log.is_empty(),
            "rollback must not touch the live pair: {:?}",
            m.log
        );
        assert!(report.dataplane_consistent);
        m.assert_invariants();
    }

    // 15. Rollback cannot disarm the new policy: the new policy + its state stay (a
    //     pair that satisfies the hard invariant), the old policy is NOT restored,
    //     and the failure is reported with exact op and key.
    #[test]
    fn rollback_disarm_failure_keeps_new_pair_and_reports() {
        let mut m = FakeMaps::default();
        let mut w = FakeWhitelist::default();
        let mut j = TxJournal::default();
        let (a, b) = (key(22), key(23));
        let old = policy(ALGO_GCRA);
        install_limit(&mut m, &mut j, a, old).unwrap();
        j = TxJournal::default();

        // Update A succeeds (old disarmed, new armed); B fails and drives rollback.
        let mut new = policy(ALGO_GCRA);
        new.rate_bps = 42;
        install_limit(&mut m, &mut j, a, new).unwrap();
        batch_with_failing_flow(&mut m, &mut j, b);

        m.fail_next("disarm_policy", a);
        let report = rollback_journal(&mut m, &mut w, &j);

        assert_eq!(
            m.policies.get(&a).copied(),
            Some(new),
            "new policy stays armed"
        );
        assert!(m.artifact(&a, ALGO_GCRA), "new state stays");
        assert_ne!(
            m.policies.get(&a).unwrap().rate_bps,
            1_000_000,
            "old policy must NOT be restored"
        );
        assert!(!report.dataplane_consistent);
        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.failures[0].key, a);
        assert!(
            report.failures[0].op.starts_with("disarm new policy"),
            "{}",
            report.failures[0].op
        );
        m.assert_invariants();
    }

    // 16. Rollback disarms the new policy but clearing its state fails: the restore
    //     of the old policy still proceeds (bounded orphan beats corrupted flow).
    #[test]
    fn rollback_clear_state_failure_still_restores_old() {
        let mut m = FakeMaps::default();
        let mut w = FakeWhitelist::default();
        let mut j = TxJournal::default();
        let k = key(24);
        install_limit(&mut m, &mut j, k, policy(ALGO_TOKEN_BUCKET)).unwrap();
        j = TxJournal::default();

        // bucket -> SWL switch: arming the new policy fails, so rollback must clear
        // the fresh ring and restore the bucket policy.
        m.fail_next("arm_policy", k);
        assert!(install_limit(&mut m, &mut j, k, policy(ALGO_SLIDING_WINDOW_LOG)).is_err());

        m.fail_next("clear_state", k);
        let report = rollback_journal(&mut m, &mut w, &j);

        let armed = m.policies.get(&k).expect("old policy restored");
        assert_eq!(armed.algorithm, ALGO_TOKEN_BUCKET);
        assert!(m.artifact(&k, ALGO_TOKEN_BUCKET), "old state restored");
        // The ring could not be removed: bounded orphan, reported, invariant intact.
        assert!(m.rings.contains_key(&k));
        assert_eq!(report.failures.len(), 1);
        assert!(report.failures[0].op.contains("clear new state"));
        assert!(!report.dataplane_consistent);
        m.assert_invariants();
    }

    // 17/18. Same as 15 but across algorithm switches in both directions: the armed
    //        pair that stays behind is always complete (policy + matching artifact).
    #[test]
    fn rollback_disarm_failure_on_state_to_swl_switch() {
        let mut m = FakeMaps::default();
        let mut w = FakeWhitelist::default();
        let mut j = TxJournal::default();
        let (a, b) = (key(25), key(26));
        install_limit(&mut m, &mut j, a, policy(ALGO_TOKEN_BUCKET)).unwrap();
        j = TxJournal::default();

        install_limit(&mut m, &mut j, a, policy(ALGO_SLIDING_WINDOW_LOG)).unwrap();
        batch_with_failing_flow(&mut m, &mut j, b);

        m.fail_next("disarm_policy", a);
        let report = rollback_journal(&mut m, &mut w, &j);
        assert_eq!(
            m.policies.get(&a).unwrap().algorithm,
            ALGO_SLIDING_WINDOW_LOG,
            "new SWL policy stays armed"
        );
        assert!(m.rings.contains_key(&a), "ring stays with the armed policy");
        assert!(m.state.is_empty(), "bucket state was cleared forward");
        assert!(!report.dataplane_consistent);
        m.assert_invariants();
    }

    #[test]
    fn rollback_disarm_failure_on_swl_to_state_switch() {
        let mut m = FakeMaps::default();
        let mut w = FakeWhitelist::default();
        let mut j = TxJournal::default();
        let (a, b) = (key(27), key(28));
        install_limit(&mut m, &mut j, a, policy(ALGO_SLIDING_WINDOW_LOG)).unwrap();
        j = TxJournal::default();

        install_limit(&mut m, &mut j, a, policy(ALGO_GCRA)).unwrap();
        batch_with_failing_flow(&mut m, &mut j, b);

        m.fail_next("disarm_policy", a);
        let report = rollback_journal(&mut m, &mut w, &j);
        assert_eq!(
            m.policies.get(&a).unwrap().algorithm,
            ALGO_GCRA,
            "new GCRA policy stays armed"
        );
        assert!(
            m.state.contains_key(&a),
            "state stays with the armed policy"
        );
        assert!(m.rings.is_empty(), "ring was cleared forward");
        assert!(!report.dataplane_consistent);
        m.assert_invariants();
    }

    // 19. Same-algorithm update, rollback disarm fails: the NEW rate stays armed with
    //     its state; the old policy is not resurrected.
    #[test]
    fn rollback_disarm_failure_on_same_algorithm_update() {
        let mut m = FakeMaps::default();
        let mut w = FakeWhitelist::default();
        let mut j = TxJournal::default();
        let (a, b) = (key(29), key(30));
        install_limit(&mut m, &mut j, a, policy(ALGO_GCRA)).unwrap();
        j = TxJournal::default();

        let mut new = policy(ALGO_GCRA);
        new.rate_bps = 2_000_000;
        install_limit(&mut m, &mut j, a, new).unwrap();
        batch_with_failing_flow(&mut m, &mut j, b);

        m.fail_next("disarm_policy", a);
        let report = rollback_journal(&mut m, &mut w, &j);
        assert_eq!(m.policies.get(&a).copied(), Some(new));
        assert_eq!(m.policies.get(&a).unwrap().rate_bps, 2_000_000);
        assert!(m.artifact(&a, ALGO_GCRA));
        assert!(!report.dataplane_consistent);
        m.assert_invariants();
    }

    // 20. Mixed batch: one record's rollback fails, the others still roll back, and
    //     the report carries the complete picture.
    #[test]
    fn mixed_batch_continues_after_one_record_fails() {
        let mut m = FakeMaps::default();
        let mut w = FakeWhitelist::default();
        let mut j = TxJournal::default();
        let (a, b, c) = (key(31), key(32), key(33));
        install_limit(&mut m, &mut j, a, policy(ALGO_GCRA)).unwrap();
        install_limit(&mut m, &mut j, b, policy(ALGO_TOKEN_BUCKET)).unwrap();
        j = TxJournal::default();

        // A: update (succeeds, becomes armed); B: remove (succeeds); C: install fails.
        let mut a2 = policy(ALGO_GCRA);
        a2.rate_bps = 7;
        install_limit(&mut m, &mut j, a, a2).unwrap();
        remove_limit(&mut m, &mut j, b).unwrap();
        m.fail_next("write_fresh_state", c);
        assert!(install_limit(&mut m, &mut j, c, policy(ALGO_GCRA)).is_err());

        // During rollback A's disarm fails; B must still be restored.
        m.fail_next("disarm_policy", a);
        let report = rollback_journal(&mut m, &mut w, &j);

        assert_eq!(report.attempted, 3);
        assert_eq!(report.succeeded, 2, "C no-op and B restore succeed");
        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.failures[0].key, a);
        // A keeps the new pair; B is fully restored; C absent.
        assert_eq!(m.policies.get(&a).copied(), Some(a2));
        assert!(m.artifact(&a, ALGO_GCRA));
        let b_pol = m.policies.get(&b).expect("B restored");
        assert_eq!(b_pol.algorithm, ALGO_TOKEN_BUCKET);
        assert!(m.artifact(&b, ALGO_TOKEN_BUCKET));
        assert!(!m.policies.contains_key(&c));
        assert!(!report.dataplane_consistent);
        m.assert_invariants();
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

    // 21. Forward clear_state failure during a GCRA -> SWL switch: the abort
    //     happens before the new state write, and the rollback re-arms the old
    //     GCRA policy on top of its never-cleared artifact. Final maps equal the
    //     pre-update content; no SWL ring exists; report is clean.
    #[test]
    fn forward_clear_state_failure_rolls_back_to_armed_old_policy() {
        let mut m = FakeMaps::default();
        let mut w = FakeWhitelist::default();
        let mut j = TxJournal::default();
        let k = key(25);
        let old = policy(ALGO_GCRA);
        install_limit(&mut m, &mut j, k, old).unwrap();
        j = TxJournal::default();

        m.fail_next("clear_state", k);
        assert!(install_limit(&mut m, &mut j, k, policy(ALGO_SLIDING_WINDOW_LOG)).is_err());
        m.log.clear();

        let report = rollback_journal(&mut m, &mut w, &j);

        // Final map content equals the pre-update state, field for field.
        assert_eq!(m.policies.get(&k).copied(), Some(old), "old GCRA re-armed");
        assert_eq!(
            m.state.get(&k).copied(),
            Some(ALGO_GCRA),
            "old GCRA state present with correct algorithm"
        );
        assert!(m.rings.is_empty(), "SWL ring must not exist");
        // Rollback itself ran clean: report agrees with the maps.
        assert!(report.dataplane_consistent);
        assert!(report.failures.is_empty(), "{:?}", report.failures);
        assert_eq!(report.attempted, 1);
        assert_eq!(report.succeeded, 1);
        // No armed policy may lack its state.
        m.assert_invariants();
        m.assert_no_orphans();
    }

    // 22. Rollback re-arm failure: forward arm of the NEW policy fails, then the
    //     rollback's restore of the OLD state succeeds but re-arming the old
    //     policy fails. End state: old policy NOT armed (never falsely marked
    //     armed), its state remains as a BOUNDED orphan, the hard invariant
    //     holds, and the report carries the exact op and key.
    #[test]
    fn rollback_rearm_failure_leaves_bounded_orphan_state() {
        let mut m = FakeMaps::default();
        let mut w = FakeWhitelist::default();
        let mut j = TxJournal::default();
        let k = key(26);
        let old = policy(ALGO_GCRA);
        install_limit(&mut m, &mut j, k, old).unwrap();
        j = TxJournal::default();

        // Both arm attempts fail: the forward arm of the new SWL policy and the
        // rollback's re-arm of the old GCRA policy.
        m.fail_next("arm_policy", k);
        m.fail_next("arm_policy", k);
        assert!(install_limit(&mut m, &mut j, k, policy(ALGO_SLIDING_WINDOW_LOG)).is_err());

        let report = rollback_journal(&mut m, &mut w, &j);

        // Old policy is not armed — and therefore not falsely marked armed.
        assert!(!m.policies.contains_key(&k), "old policy must not be armed");
        // The restored state stays behind as a bounded orphan.
        assert_eq!(
            m.state.get(&k).copied(),
            Some(ALGO_GCRA),
            "restored old state remains as bounded orphan"
        );
        assert!(m.rings.is_empty(), "new SWL ring must be cleared");
        // Hard invariant: armed policy => state exists. With nothing armed it
        // holds trivially, while the soft no-orphan property is (expectedly) not
        // met — assert the hard one.
        m.assert_invariants();
        assert!(!report.dataplane_consistent);
        assert_eq!(report.attempted, 1);
        assert_eq!(report.succeeded, 0);
        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.failures[0].key, k);
        assert_eq!(report.failures[0].op, "re-arm old policy");
    }
}

/// Test-only re-exports so engine-level tests can drive the same scripted
/// fault-injection fakes against the production transaction code.
#[cfg(test)]
pub(crate) mod testmaps {
    pub(crate) use super::tests::{policy, FakeMaps, FakeWhitelist};
}
