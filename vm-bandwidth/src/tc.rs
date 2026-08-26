//! TC attach management: one eBPF object instance per TAP interface.
//!
//! `aya`'s TC context does not expose `skb->ifindex`, so each TAP gets its own loaded
//! object with the ifindex baked into the `IFINDEX` global. The pinned maps are shared
//! by all instances. Dropping an instance detaches exactly the filters this program
//! created; other programs' filters, qdiscs like `fq_codel`/`noqueue` are never touched.

use std::collections::HashMap;

use anyhow::{Context, Result};
use aya::programs::{tc, SchedClassifier, TcAttachType};
use aya::{Ebpf, EbpfLoader};

use crate::interface::Tap;

pub const PROGRAM_INGRESS: &str = "tc_ingress";
pub const PROGRAM_EGRESS: &str = "tc_egress";

pub struct AttachManager {
    attached: HashMap<String, AttachedTap>,
}

struct AttachedTap {
    tap: Tap,
    /// Dropping the object detaches both filters.
    _bpf: Ebpf,
}

impl AttachManager {
    pub fn new() -> Self {
        Self {
            attached: HashMap::new(),
        }
    }

    pub fn taps(&self) -> Vec<Tap> {
        let mut taps: Vec<Tap> = self.attached.values().map(|a| a.tap.clone()).collect();
        taps.sort_by(|a, b| a.name.cmp(&b.name));
        taps
    }

    /// Converge attachments onto `found`. A single failing attach never affects the rest;
    /// it is logged and retried on the next scan. Returns `(added, failed)`.
    pub fn reconcile(&mut self, found: &[Tap], object: &[u8]) -> (usize, usize) {
        // Detach interfaces that disappeared or were recreated with a new ifindex.
        self.attached.retain(
            |name, attached| match found.iter().find(|t| t.name == *name) {
                None => {
                    log::info!("TAP {name} removed; detaching");
                    false
                }
                Some(tap) if tap.ifindex != attached.tap.ifindex => {
                    log::info!("TAP {name} recreated with new ifindex; reattaching");
                    false
                }
                Some(_) => true,
            },
        );

        let mut added = 0;
        let mut failed = 0;
        for tap in found {
            if self.attached.contains_key(&tap.name) {
                continue;
            }
            match attach(tap, object) {
                Ok(bpf) => {
                    log::info!("attached to TAP {} (ifindex {})", tap.name, tap.ifindex);
                    self.attached.insert(
                        tap.name.clone(),
                        AttachedTap {
                            tap: tap.clone(),
                            _bpf: bpf,
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
}

fn attach(tap: &Tap, object: &[u8]) -> Result<Ebpf> {
    // Create the clsact qdisc if missing (needed by the netlink attach path on kernels
    // < 6.6; a no-op when TCX is used). Failure usually just means it already exists.
    if let Err(e) = tc::qdisc_add_clsact(&tap.name) {
        log::debug!(
            "qdisc_add_clsact({}): {e} (typically already present)",
            tap.name
        );
    }

    let mut bpf = EbpfLoader::new()
        .override_global("IFINDEX", &tap.ifindex, true)
        .load(object)
        .with_context(|| format!("loading eBPF object for TAP {}", tap.name))?;

    let ingress: &mut SchedClassifier = bpf
        .program_mut(PROGRAM_INGRESS)
        .context("eBPF object is missing the tc_ingress program")?
        .try_into()?;
    ingress.load().context("verifier rejected tc_ingress")?;
    ingress
        .attach(&tap.name, TcAttachType::Ingress)
        .with_context(|| format!("attaching TC ingress on {}", tap.name))?;

    let egress: &mut SchedClassifier = bpf
        .program_mut(PROGRAM_EGRESS)
        .context("eBPF object is missing the tc_egress program")?
        .try_into()?;
    egress.load().context("verifier rejected tc_egress")?;
    egress
        .attach(&tap.name, TcAttachType::Egress)
        .with_context(|| format!("attaching TC egress on {}", tap.name))?;

    Ok(bpf)
}
