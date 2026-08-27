//! TC attach management: one loaded eBPF object, one pair of TC links per TAP.
//!
//! The same `tc_ingress`/`tc_egress` programs are attached to every TAP under the
//! bridge; each program reads the ifindex from its skb context, so all TAPs share a
//! single object and a single set of maps. Dropping the manager detaches exactly the
//! links this program created; other programs' filters and qdiscs like
//! `fq_codel`/`noqueue` are never touched.
//!
//! qdisc lifecycle:
//! * Kernels >= 6.6: attach goes through TCX (`bpf_link_create`), which needs NO
//!   qdisc. We attach directly first and create nothing, so no stray `clsact` is left
//!   behind to fight other tools over the `ffff:` slot.
//! * Older kernels: legacy netlink TC needs a `clsact` qdisc. It is created only when
//!   the first attach proves the hook's qdisc missing (netlink ENOENT), and an
//!   existing qdisc is reused (netlink EEXIST) — never replaced, never deleted.
//! * A `clsact` created by this program is NOT deleted on detach: aya 0.14 exposes no
//!   safe way to prove that no other tool added filters to it meanwhile, so it is
//!   retained and logged. Stale clsacts left by older versions need the one-time
//!   manual cleanup documented in the README.

use std::collections::HashMap;

use anyhow::{anyhow, Context, Result};
use aya::programs::tc::{SchedClassifierLinkId, TcError};
use aya::programs::{tc, ProgramError, SchedClassifier, TcAttachType};
use aya::Ebpf;

use crate::interface::Tap;

pub const PROGRAM_INGRESS: &str = "tc_ingress";
pub const PROGRAM_EGRESS: &str = "tc_egress";

/// Where a TAP's `ffff:` qdisc came from; decides what cleanup is allowed to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QdiscOrigin {
    /// The attach needed no qdisc from us (TCX on kernels >= 6.6, or an already-present
    /// qdisc served the legacy attach). Nothing to clean up.
    NotRequired,
    /// A qdisc already owned the `ffff:` slot before we attached. Shared state: it is
    /// never deleted by this program.
    ReusedExisting,
    /// This program created the qdisc. Deletion additionally requires proving that no
    /// other tool added filters in the meantime — see [`may_delete_qdisc`].
    CreatedByUs,
}

/// The qdisc-deletion safety rule, explicit and unit-testable. Only a qdisc we created
/// may ever be deleted, and only when its emptiness (no foreign filters) is proven.
/// aya 0.14 exposes no filter enumeration, so the proof is currently unavailable and
/// created qdiscs are retained — deliberately safe over clean.
fn may_delete_qdisc(origin: QdiscOrigin, emptiness_proven: bool) -> bool {
    matches!(origin, QdiscOrigin::CreatedByUs) && emptiness_proven
}

/// Coarse classification of a `SchedClassifier` attach failure. Drives the single
/// clsact-fallback decision; deliberately typed, never string-matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttachFailure {
    /// Legacy netlink attach got ENOENT: the hook's parent qdisc is absent. Creating
    /// (or reusing) clsact and retrying once may succeed.
    QdiscMissing,
    /// Anything else: TCX syscall failures, permissions, vanished interface, ...
    /// Never treated as "already present".
    Other,
}

/// The errno-based core of [`classify_attach_failure`], split out so it is unit
/// testable (`NetlinkError` cannot be constructed outside aya).
///
/// Why ENOENT: on kernels < 6.6 aya attaches via netlink `RTM_NEWTFILTER` against the
/// hook's parent qdisc (`ffff:fff1` ingress / `ffff:fff3` egress). When no qdisc owns
/// that slot the kernel answers ENOENT; with a qdisc present the same call succeeds or
/// fails with a different errno.
fn classify_netlink_errno(errno: Option<i32>) -> AttachFailure {
    if errno == Some(libc::ENOENT) {
        AttachFailure::QdiscMissing
    } else {
        AttachFailure::Other
    }
}

fn classify_attach_failure(err: &ProgramError) -> AttachFailure {
    match err {
        ProgramError::TcError(TcError::NetlinkError(nl)) => {
            classify_netlink_errno(nl.raw_os_error())
        }
        // Kernels >= 6.6 take the TCX path; its failures are bpf_link_create syscall
        // errors and no qdisc can fix them. Same for unknown interface, permissions, ...
        _ => AttachFailure::Other,
    }
}

/// `qdisc_add_clsact` sends `NLM_F_CREATE | NLM_F_EXCL`, so the kernel answers EEXIST
/// whenever ANY qdisc already owns the `ffff:` slot — a clsact to reuse, or a legacy
/// `ingress` qdisc we must not touch. Every other error is a real failure.
fn qdisc_already_present_errno(errno: Option<i32>) -> bool {
    errno == Some(libc::EEXIST)
}

/// Result of ensuring a clsact exists on the legacy path.
enum QdiscAddOutcome {
    Created,
    AlreadyPresent,
}

/// One attach attempt per hook, rollback included — generic over the backend so the
/// decision flow is unit-testable without TAPs or privileges.
trait AttachBackend {
    type Link;
    fn attach_ingress(&mut self, tap: &str) -> Result<Self::Link, AttachFailure>;
    fn attach_egress(&mut self, tap: &str) -> Result<Self::Link, AttachFailure>;
    fn detach_ingress(&mut self, link: Self::Link);
    fn add_clsact(&mut self, tap: &str) -> Result<QdiscAddOutcome, String>;
}

/// Failure of [`attach_flow`], carrying the stage and qdisc origin so callers can log
/// precisely and reason about cleanup.
#[derive(Debug)]
enum AttachFlowError {
    Ingress(String),
    QdiscAdd(String),
    Egress {
        origin: QdiscOrigin,
        /// True when the egress hook stayed unattachable even after a qdisc was
        /// created/reused — the classic legacy `ingress`-only qdisc occupying `ffff:`.
        conflict: bool,
        detail: String,
    },
}

impl std::fmt::Display for AttachFlowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ingress(d) => write!(f, "ingress attach: {d}"),
            Self::QdiscAdd(d) => write!(f, "clsact creation: {d}"),
            Self::Egress {
                origin,
                conflict,
                detail,
            } => write!(
                f,
                "egress attach (qdisc origin {origin:?}, conflict {conflict}): {detail}"
            ),
        }
    }
}

fn ensure_clsact<B: AttachBackend>(b: &mut B, tap: &str) -> Result<QdiscOrigin, AttachFlowError> {
    match b.add_clsact(tap) {
        Ok(QdiscAddOutcome::Created) => Ok(QdiscOrigin::CreatedByUs),
        Ok(QdiscAddOutcome::AlreadyPresent) => Ok(QdiscOrigin::ReusedExisting),
        Err(e) => Err(AttachFlowError::QdiscAdd(e)),
    }
}

/// Attach both hooks to one TAP:
/// 1. try direct attach (TCX on >= 6.6 — no qdisc involved at all);
/// 2. only when the failure PROVES a missing legacy qdisc, create/reuse clsact and
///    retry that hook exactly once (no loops);
/// 3. an egress failure always rolls back the ingress link; nothing half-attached
///    escapes this function.
fn attach_flow<B: AttachBackend>(
    b: &mut B,
    tap: &str,
) -> Result<(B::Link, B::Link, QdiscOrigin), AttachFlowError> {
    let mut origin = QdiscOrigin::NotRequired;

    let ingress = match b.attach_ingress(tap) {
        Ok(link) => link,
        Err(AttachFailure::QdiscMissing) => {
            origin = ensure_clsact(b, tap)?;
            // Exactly one retry after the qdisc exists; a second failure is reported.
            b.attach_ingress(tap).map_err(|e| {
                AttachFlowError::Ingress(format!("still failing after clsact ensure: {e:?}"))
            })?
        }
        Err(AttachFailure::Other) => {
            return Err(AttachFlowError::Ingress(
                "direct attach failed (not a missing qdisc)".into(),
            ))
        }
    };

    let egress = match b.attach_egress(tap) {
        Ok(link) => link,
        Err(AttachFailure::QdiscMissing) if origin == QdiscOrigin::NotRequired => {
            // Ingress attached without us creating anything, but the egress hook has
            // no qdisc — or a legacy ingress-only qdisc occupies the ffff: slot.
            // Ensure clsact once and retry egress once.
            match ensure_clsact(b, tap) {
                Ok(o) => origin = o,
                Err(e) => {
                    b.detach_ingress(ingress);
                    return Err(e);
                }
            }
            match b.attach_egress(tap) {
                Ok(link) => link,
                Err(e) => {
                    b.detach_ingress(ingress);
                    return Err(AttachFlowError::Egress {
                        origin,
                        conflict: true,
                        detail: format!("{e:?}"),
                    });
                }
            }
        }
        Err(e) => {
            b.detach_ingress(ingress);
            return Err(AttachFlowError::Egress {
                origin,
                conflict: false,
                detail: format!("{e:?}"),
            });
        }
    };

    Ok((ingress, egress, origin))
}

/// Best-effort "kernel >= major.minor" for log wording (TCX vs legacy), mirroring the
/// cutoff aya uses internally to pick the attach path. Unknown kernels are assumed
/// modern; this only affects a log line.
fn kernel_at_least(major: u32, minor: u32) -> bool {
    let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") else {
        return true;
    };
    let mut parts = release.split(|c: char| !c.is_ascii_digit());
    let maj = parts
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    let min = parts
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    (maj, min) >= (major, minor)
}

/// Production backend: aya's `SchedClassifier` programs + the netlink clsact helper.
struct AyaBackend<'a> {
    bpf: &'a mut Ebpf,
}

fn sched_program<'a>(bpf: &'a mut Ebpf, name: &str) -> Result<&'a mut SchedClassifier> {
    Ok(bpf
        .program_mut(name)
        .with_context(|| format!("eBPF object is missing the {name} program"))?
        .try_into()?)
}

impl AyaBackend<'_> {
    fn attach_prog(
        &mut self,
        name: &str,
        tap: &str,
        dir: TcAttachType,
    ) -> Result<SchedClassifierLinkId, AttachFailure> {
        let prog = sched_program(self.bpf, name).map_err(|_| AttachFailure::Other)?;
        prog.attach(tap, dir)
            .map_err(|e| classify_attach_failure(&e))
    }
}

impl AttachBackend for AyaBackend<'_> {
    type Link = SchedClassifierLinkId;

    fn attach_ingress(&mut self, tap: &str) -> Result<Self::Link, AttachFailure> {
        self.attach_prog(PROGRAM_INGRESS, tap, TcAttachType::Ingress)
    }

    fn attach_egress(&mut self, tap: &str) -> Result<Self::Link, AttachFailure> {
        self.attach_prog(PROGRAM_EGRESS, tap, TcAttachType::Egress)
    }

    fn detach_ingress(&mut self, link: Self::Link) {
        if let Ok(prog) = sched_program(self.bpf, PROGRAM_INGRESS) {
            let _ = prog.detach(link);
        }
    }

    fn add_clsact(&mut self, tap: &str) -> Result<QdiscAddOutcome, String> {
        match tc::qdisc_add_clsact(tap) {
            Ok(()) => Ok(QdiscAddOutcome::Created),
            Err(TcError::NetlinkError(nl)) if qdisc_already_present_errno(nl.raw_os_error()) => {
                Ok(QdiscAddOutcome::AlreadyPresent)
            }
            Err(e) => Err(format!("{e}")),
        }
    }
}

pub struct AttachManager {
    bpf: Ebpf,
    attached: HashMap<String, AttachedTap>,
}

struct AttachedTap {
    tap: Tap,
    ingress_link: SchedClassifierLinkId,
    egress_link: SchedClassifierLinkId,
    qdisc_origin: QdiscOrigin,
}

impl AttachManager {
    /// Takes ownership of the loaded object; the verifier runs once for both programs.
    pub fn new(mut bpf: Ebpf) -> Result<Self> {
        let ingress: &mut SchedClassifier = bpf
            .program_mut(PROGRAM_INGRESS)
            .context("eBPF object is missing the tc_ingress program")?
            .try_into()?;
        ingress.load().context("verifier rejected tc_ingress")?;

        let egress: &mut SchedClassifier = bpf
            .program_mut(PROGRAM_EGRESS)
            .context("eBPF object is missing the tc_egress program")?
            .try_into()?;
        egress.load().context("verifier rejected tc_egress")?;

        Ok(Self {
            bpf,
            attached: HashMap::new(),
        })
    }

    pub fn taps(&self) -> Vec<Tap> {
        let mut taps: Vec<Tap> = self.attached.values().map(|a| a.tap.clone()).collect();
        taps.sort_by(|a, b| a.name.cmp(&b.name));
        taps
    }

    /// Converge attachments onto `found`. A single failing attach never affects the
    /// rest; it is logged and retried on the next scan. Returns `(added, failed)`.
    pub fn reconcile(&mut self, found: &[Tap]) -> (usize, usize) {
        let attached_view: Vec<(String, u32)> = self
            .attached
            .values()
            .map(|a| (a.tap.name.clone(), a.tap.ifindex))
            .collect();
        let (to_detach, to_add) = reconcile_plan(&attached_view, found);

        for name in &to_detach {
            match found.iter().find(|t| t.name == *name) {
                None => log::info!("TAP {name} removed; detaching"),
                Some(_) => log::info!("TAP {name} recreated with new ifindex; reattaching"),
            }
            self.detach(name);
        }

        let mut added = 0;
        let mut failed = 0;
        for tap in to_add {
            match self.attach(&tap) {
                Ok((ingress_link, egress_link, qdisc_origin)) => {
                    log::info!("attached to TAP {} (ifindex {})", tap.name, tap.ifindex);
                    self.attached.insert(
                        tap.name.clone(),
                        AttachedTap {
                            tap,
                            ingress_link,
                            egress_link,
                            qdisc_origin,
                        },
                    );
                    added += 1;
                }
                Err(e) => {
                    log::warn!("failed to attach to TAP {}: {e:#}", tap.name);
                    failed += 1;
                }
            }
        }
        (added, failed)
    }

    fn attach(
        &mut self,
        tap: &Tap,
    ) -> Result<(SchedClassifierLinkId, SchedClassifierLinkId, QdiscOrigin)> {
        let mut backend = AyaBackend { bpf: &mut self.bpf };
        let (ingress_link, egress_link, origin) =
            attach_flow(&mut backend, &tap.name).map_err(|e| flow_error(e, tap))?;
        match origin {
            QdiscOrigin::NotRequired if kernel_at_least(6, 6) => {
                log::info!("TAP {}: attached via TCX; clsact not required", tap.name);
            }
            QdiscOrigin::NotRequired => {
                log::info!(
                    "TAP {}: attached via existing TC qdisc; clsact not required",
                    tap.name
                );
            }
            QdiscOrigin::ReusedExisting => log::info!("TAP {}: reusing existing clsact", tap.name),
            QdiscOrigin::CreatedByUs => {
                log::info!("TAP {}: created clsact for legacy TC attach", tap.name)
            }
        }
        Ok((ingress_link, egress_link, origin))
    }

    fn detach(&mut self, name: &str) {
        let Some(att) = self.attached.remove(name) else {
            return;
        };
        if let Ok(ingress) = sched_program(&mut self.bpf, PROGRAM_INGRESS) {
            if let Err(e) = ingress.detach(att.ingress_link) {
                log::debug!("detaching ingress on {name}: {e}");
            }
        }
        if let Ok(egress) = sched_program(&mut self.bpf, PROGRAM_EGRESS) {
            if let Err(e) = egress.detach(att.egress_link) {
                log::debug!("detaching egress on {name}: {e}");
            }
        }
        // The qdisc decision: see may_delete_qdisc. With aya 0.14 there is no safe
        // emptiness proof, so a qdisc we created is retained rather than risk deleting
        // a shared mount point another tool is using. If a safe qdisc query/delete API
        // ever becomes available, deletion belongs here behind may_delete_qdisc.
        if att.qdisc_origin == QdiscOrigin::CreatedByUs
            && !may_delete_qdisc(att.qdisc_origin, false)
        {
            log::info!(
                "TAP {name}: retained created clsact because ownership/emptiness could not be proven"
            );
        }
    }
}

fn flow_error(e: AttachFlowError, tap: &Tap) -> anyhow::Error {
    match e {
        AttachFlowError::Ingress(d) => anyhow!(
            "TAP {} (ifindex {}): TC ingress attach failed: {d}",
            tap.name,
            tap.ifindex
        ),
        AttachFlowError::QdiscAdd(d) => anyhow!(
            "TAP {} (ifindex {}): clsact qdisc creation failed: {d}",
            tap.name,
            tap.ifindex
        ),
        AttachFlowError::Egress {
            origin,
            conflict,
            detail,
        } => {
            if conflict {
                log::error!(
                    "TAP {}: legacy ingress qdisc conflicts with required egress attachment",
                    tap.name
                );
            }
            anyhow!(
                "TAP {} (ifindex {}): TC egress attach failed (qdisc origin {:?}, ingress rolled back): {detail}",
                tap.name,
                tap.ifindex,
                origin
            )
        }
    }
}

/// Pure reconcile decision, split out for unit tests: which attached TAPs to detach
/// (removed, or recreated with a new ifindex) and which found TAPs to attach.
fn reconcile_plan(attached: &[(String, u32)], found: &[Tap]) -> (Vec<String>, Vec<Tap>) {
    let to_detach: Vec<String> = attached
        .iter()
        .filter(|(name, ifindex)| {
            found
                .iter()
                .find(|t| t.name == *name)
                .map(|t| t.ifindex != *ifindex)
                .unwrap_or(true)
        })
        .map(|(name, _)| name.clone())
        .collect();
    let to_add: Vec<Tap> = found
        .iter()
        .filter(|t| match attached.iter().find(|(n, _)| n == &t.name) {
            None => true,
            Some((_, ifindex)) => *ifindex != t.ifindex,
        })
        .cloned()
        .collect();
    (to_detach, to_add)
}

impl Drop for AttachManager {
    fn drop(&mut self) {
        // Detach every link we created; leave everything else alone.
        let names: Vec<String> = self.attached.keys().cloned().collect();
        for name in names {
            self.detach(&name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// Scripted backend: served outcomes per hook plus a call record.
    #[derive(Default)]
    struct FakeBackend {
        ingress: VecDeque<Result<(), AttachFailure>>,
        egress: VecDeque<Result<(), AttachFailure>>,
        clsact: Option<Result<QdiscAddOutcome, String>>,
        ingress_calls: u32,
        egress_calls: u32,
        clsact_calls: u32,
        detached_ingress: Vec<u64>,
        /// The design has no qdisc-delete operation at all; tests pin it at zero so a
        /// future "cleanup" cannot sneak in unnoticed.
        qdisc_deletes: u32,
        next_link: u64,
    }

    impl FakeBackend {
        fn fresh() -> Self {
            Self::default()
        }
        fn next_link(&mut self) -> u64 {
            self.next_link += 1;
            self.next_link
        }
        fn scripted(
            script: &mut VecDeque<Result<(), AttachFailure>>,
            what: &str,
        ) -> Result<(), AttachFailure> {
            script
                .pop_front()
                .unwrap_or_else(|| panic!("{what} attach script exhausted"))
        }
    }

    impl AttachBackend for FakeBackend {
        type Link = u64;

        fn attach_ingress(&mut self, _tap: &str) -> Result<u64, AttachFailure> {
            self.ingress_calls += 1;
            match Self::scripted(&mut self.ingress, "ingress") {
                Ok(()) => Ok(self.next_link()),
                Err(f) => Err(f),
            }
        }

        fn attach_egress(&mut self, _tap: &str) -> Result<u64, AttachFailure> {
            self.egress_calls += 1;
            match Self::scripted(&mut self.egress, "egress") {
                Ok(()) => Ok(self.next_link()),
                Err(f) => Err(f),
            }
        }

        fn detach_ingress(&mut self, link: u64) {
            self.detached_ingress.push(link);
        }

        fn add_clsact(&mut self, _tap: &str) -> Result<QdiscAddOutcome, String> {
            self.clsact_calls += 1;
            self.clsact
                .take()
                .unwrap_or_else(|| panic!("add_clsact not scripted"))
        }
    }

    // 1. TCX-style direct success: both hooks attach, no qdisc call ever happens.
    #[test]
    fn direct_attach_never_touches_qdisc() {
        let mut b = FakeBackend::fresh();
        b.ingress.push_back(Ok(()));
        b.egress.push_back(Ok(()));
        let (i, e, origin) = attach_flow(&mut b, "tap0").unwrap();
        assert_eq!((i, e), (1, 2));
        assert_eq!(origin, QdiscOrigin::NotRequired);
        assert_eq!(b.clsact_calls, 0);
        assert_eq!(b.qdisc_deletes, 0);
    }

    // 2. Legacy: ingress proves the qdisc missing -> create clsact -> one retry works.
    #[test]
    fn legacy_missing_qdisc_creates_and_retries_once() {
        let mut b = FakeBackend::fresh();
        b.ingress.push_back(Err(AttachFailure::QdiscMissing));
        b.ingress.push_back(Ok(()));
        b.egress.push_back(Ok(()));
        b.clsact = Some(Ok(QdiscAddOutcome::Created));
        let (_, _, origin) = attach_flow(&mut b, "tap0").unwrap();
        assert_eq!(origin, QdiscOrigin::CreatedByUs);
        assert_eq!(b.clsact_calls, 1);
        assert_eq!(b.ingress_calls, 2); // original attempt + exactly one retry
        assert_eq!(b.detached_ingress.len(), 0);
    }

    // 3. A clsact already present is reused, not recreated.
    #[test]
    fn existing_clsact_is_reused_not_recreated() {
        let mut b = FakeBackend::fresh();
        b.ingress.push_back(Err(AttachFailure::QdiscMissing));
        b.ingress.push_back(Ok(()));
        b.egress.push_back(Ok(()));
        b.clsact = Some(Ok(QdiscAddOutcome::AlreadyPresent));
        let (_, _, origin) = attach_flow(&mut b, "tap0").unwrap();
        assert_eq!(origin, QdiscOrigin::ReusedExisting);
        assert_eq!(b.clsact_calls, 1);
        assert_eq!(b.qdisc_deletes, 0);
    }

    // 4. A non-EEXIST qdisc error is a hard failure (never "typically already
    //    present"), and there is no retry.
    #[test]
    fn qdisc_add_failure_is_not_swallowed() {
        let mut b = FakeBackend::fresh();
        b.ingress.push_back(Err(AttachFailure::QdiscMissing));
        b.clsact = Some(Err("permission denied".into()));
        let err = attach_flow(&mut b, "tap0").unwrap_err();
        assert!(matches!(err, AttachFlowError::QdiscAdd(_)), "{err}");
        assert_eq!(b.ingress_calls, 1); // no retry after a real qdisc failure
    }

    // 5. Ingress succeeded, egress failed: the ingress link is rolled back.
    #[test]
    fn egress_failure_rolls_back_ingress() {
        let mut b = FakeBackend::fresh();
        b.ingress.push_back(Ok(()));
        b.egress.push_back(Err(AttachFailure::Other));
        let err = attach_flow(&mut b, "tap0").unwrap_err();
        assert!(
            matches!(
                err,
                AttachFlowError::Egress {
                    conflict: false,
                    ..
                }
            ),
            "{err}"
        );
        assert_eq!(b.detached_ingress, vec![1]); // the exact ingress link
        assert_eq!(b.clsact_calls, 0);
    }

    // 6. + 7. The deletion safety rule: reused/not-required qdiscs are never deleted
    //    even if proven empty; created ones only with proof (unavailable in aya 0.14,
    //    so detach retains them — pinned by qdisc_deletes staying 0 everywhere).
    #[test]
    fn qdisc_deletion_safety_rule() {
        assert!(!may_delete_qdisc(QdiscOrigin::ReusedExisting, true));
        assert!(!may_delete_qdisc(QdiscOrigin::NotRequired, true));
        assert!(!may_delete_qdisc(QdiscOrigin::CreatedByUs, false));
        assert!(may_delete_qdisc(QdiscOrigin::CreatedByUs, true));
    }

    // 8. Legacy ingress-only qdisc: ingress attaches on it, egress cannot; ensuring
    //    clsact reports the slot taken (EEXIST) and the retried egress still fails ->
    //    diagnosed conflict, ingress rolled back.
    #[test]
    fn legacy_ingress_only_qdisc_conflict_is_diagnosed() {
        let mut b = FakeBackend::fresh();
        b.ingress.push_back(Ok(()));
        b.egress.push_back(Err(AttachFailure::QdiscMissing));
        b.egress.push_back(Err(AttachFailure::QdiscMissing));
        b.clsact = Some(Ok(QdiscAddOutcome::AlreadyPresent));
        let err = attach_flow(&mut b, "tap0").unwrap_err();
        match err {
            AttachFlowError::Egress {
                origin, conflict, ..
            } => {
                assert!(conflict);
                assert_eq!(origin, QdiscOrigin::ReusedExisting);
            }
            other => panic!("expected egress conflict, got {other}"),
        }
        assert_eq!(b.detached_ingress, vec![1]);
        assert_eq!(b.egress_calls, 2); // original + exactly one retry
        assert_eq!(b.qdisc_deletes, 0); // the foreign qdisc is untouched
    }

    // 9. Repeated flows on a healthy (TCX) interface never create qdiscs; a repeated
    //    reconcile adds nothing for an unchanged TAP.
    #[test]
    fn repeated_flows_do_not_recreate_qdiscs() {
        let mut b = FakeBackend::fresh();
        b.ingress.push_back(Ok(()));
        b.egress.push_back(Ok(()));
        attach_flow(&mut b, "tap0").unwrap();
        b.ingress.push_back(Ok(()));
        b.egress.push_back(Ok(()));
        attach_flow(&mut b, "tap0").unwrap();
        assert_eq!(b.clsact_calls, 0);

        let attached = vec![("tap0".to_string(), 7u32)];
        let found = vec![Tap {
            name: "tap0".into(),
            ifindex: 7,
        }];
        let (to_detach, to_add) = reconcile_plan(&attached, &found);
        assert!(to_detach.is_empty());
        assert!(to_add.is_empty());
    }

    // 10. Removed TAPs detach; ifindex changes re-attach; unchanged TAPs are skipped.
    #[test]
    fn reconcile_plan_detaches_removed_and_recreated_taps() {
        let attached = vec![("gone".to_string(), 1u32), ("moved".to_string(), 2u32)];
        let found = vec![
            Tap {
                name: "moved".into(),
                ifindex: 3,
            },
            Tap {
                name: "fresh".into(),
                ifindex: 4,
            },
        ];
        let (to_detach, to_add) = reconcile_plan(&attached, &found);
        assert_eq!(to_detach, vec!["gone".to_string(), "moved".to_string()]);
        let added: Vec<&str> = to_add.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(added, vec!["moved", "fresh"]);
    }

    // Error classification: typed, errno-based, no string matching.
    #[test]
    fn classifies_enoent_as_missing_qdisc() {
        assert_eq!(
            classify_netlink_errno(Some(libc::ENOENT)),
            AttachFailure::QdiscMissing
        );
    }

    #[test]
    fn classifies_other_errnos_as_other() {
        assert_eq!(
            classify_netlink_errno(Some(libc::EACCES)),
            AttachFailure::Other
        );
        assert_eq!(
            classify_netlink_errno(Some(libc::EINVAL)),
            AttachFailure::Other
        );
        assert_eq!(classify_netlink_errno(None), AttachFailure::Other);
    }

    #[test]
    fn syscall_failures_are_never_qdisc_missing() {
        // TCX path failures (kernels >= 6.6) are syscall errors; a qdisc cannot help.
        let err = ProgramError::SyscallError(aya::sys::SyscallError {
            call: "bpf_link_create",
            io_error: std::io::Error::from_raw_os_error(libc::EINVAL),
        });
        assert_eq!(classify_attach_failure(&err), AttachFailure::Other);
    }

    #[test]
    fn eexist_means_qdisc_already_present() {
        assert!(qdisc_already_present_errno(Some(libc::EEXIST)));
        assert!(!qdisc_already_present_errno(Some(libc::EPERM)));
        assert!(!qdisc_already_present_errno(None));
    }
}
