//! TC attach management: one loaded eBPF object, one pair of TC links per TAP.
//!
//! The same `tc_ingress`/`tc_egress` programs are attached to every TAP under the bridge;
//! each program reads the ifindex from its skb context, so all TAPs share a single object
//! and a single set of maps. Dropping the manager detaches exactly the links this program
//! created; other programs' filters and qdiscs like `fq_codel`/`noqueue` are never touched.

use std::collections::HashMap;

use anyhow::{Context, Result};
use aya::programs::tc::SchedClassifierLinkId;
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::Ebpf;

use crate::interface::Tap;

pub const PROGRAM_INGRESS: &str = "tc_ingress";
pub const PROGRAM_EGRESS: &str = "tc_egress";

pub struct AttachManager {
    bpf: Ebpf,
    attached: HashMap<String, AttachedTap>,
}

struct AttachedTap {
    tap: Tap,
    ingress_link: SchedClassifierLinkId,
    egress_link: SchedClassifierLinkId,
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

    /// Converge attachments onto `found`. A single failing attach never affects the rest;
    /// it is logged and retried on the next scan. Returns `(added, failed)`.
    pub fn reconcile(&mut self, found: &[Tap]) -> (usize, usize) {
        // Detach interfaces that disappeared or were recreated with a new ifindex.
        let to_detach: Vec<String> = self
            .attached
            .iter()
            .filter_map(
                |(name, attached)| match found.iter().find(|t| t.name == *name) {
                    None => {
                        log::info!("TAP {name} removed; detaching");
                        Some(name.clone())
                    }
                    Some(tap) if tap.ifindex != attached.tap.ifindex => {
                        log::info!("TAP {name} recreated with new ifindex; reattaching");
                        Some(name.clone())
                    }
                    Some(_) => None,
                },
            )
            .collect();
        for name in to_detach {
            self.detach(&name);
        }

        let mut added = 0;
        let mut failed = 0;
        for tap in found {
            if self.attached.contains_key(&tap.name) {
                continue;
            }
            match self.attach(tap) {
                Ok((ingress_link, egress_link)) => {
                    log::info!("attached to TAP {} (ifindex {})", tap.name, tap.ifindex);
                    self.attached.insert(
                        tap.name.clone(),
                        AttachedTap {
                            tap: tap.clone(),
                            ingress_link,
                            egress_link,
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

    fn attach(&mut self, tap: &Tap) -> Result<(SchedClassifierLinkId, SchedClassifierLinkId)> {
        // Create the clsact qdisc if missing (needed by the netlink attach path on kernels
        // < 6.6; a no-op when TCX is used). Failure usually just means it already exists.
        if let Err(e) = tc::qdisc_add_clsact(&tap.name) {
            log::debug!(
                "qdisc_add_clsact({}): {e} (typically already present)",
                tap.name
            );
        }

        let ingress: &mut SchedClassifier = self
            .bpf
            .program_mut(PROGRAM_INGRESS)
            .context("tc_ingress missing")?
            .try_into()?;
        let ingress_link = ingress
            .attach(&tap.name, TcAttachType::Ingress)
            .with_context(|| format!("attaching TC ingress on {}", tap.name))?;

        // If anything below fails, the ingress link must not be left attached
        // unrecorded: a retry would attach a second one and double-count the TAP.
        let egress_result = self
            .bpf
            .program_mut(PROGRAM_EGRESS)
            .context("tc_egress missing")
            .and_then(|p| -> anyhow::Result<&mut SchedClassifier> { Ok(p.try_into()?) })
            .and_then(|egress| {
                egress
                    .attach(&tap.name, TcAttachType::Egress)
                    .with_context(|| format!("attaching TC egress on {}", tap.name))
            });
        match egress_result {
            Ok(egress_link) => Ok((ingress_link, egress_link)),
            Err(e) => {
                if let Ok(ingress) = self
                    .bpf
                    .program_mut(PROGRAM_INGRESS)
                    .context("tc_ingress missing")
                    .and_then(|p| -> anyhow::Result<&mut SchedClassifier> { Ok(p.try_into()?) })
                {
                    let _ = ingress.detach(ingress_link);
                }
                Err(e)
            }
        }
    }

    fn detach(&mut self, name: &str) {
        let Some(att) = self.attached.remove(name) else {
            return;
        };
        if let Ok(ingress) = self
            .bpf
            .program_mut(PROGRAM_INGRESS)
            .context("tc_ingress missing")
            .and_then(|p| -> anyhow::Result<&mut SchedClassifier> { Ok(p.try_into()?) })
        {
            if let Err(e) = ingress.detach(att.ingress_link) {
                log::debug!("detaching ingress on {name}: {e}");
            }
        }
        if let Ok(egress) = self
            .bpf
            .program_mut(PROGRAM_EGRESS)
            .context("tc_egress missing")
            .and_then(|p| -> anyhow::Result<&mut SchedClassifier> { Ok(p.try_into()?) })
        {
            if let Err(e) = egress.detach(att.egress_link) {
                log::debug!("detaching egress on {name}: {e}");
            }
        }
    }
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
