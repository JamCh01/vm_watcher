//! Effective limit-policy resolution.
//!
//! Each IP range may declare a default policy; individual IPs may override any subset of
//! it. Resolution is a plain field-level merge (override wins, range is the fallback),
//! followed by a completeness check per direction. eBPF never sees inheritance: the
//! daemon hands it fully-resolved per-(IP, direction) parameters only.

/// Raw, per-direction-optional policy fields. Used for both the range default and an
/// IP override; every field is optional so a partial override can inherit the rest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyFields {
    pub rx_threshold_bps: Option<u64>,
    pub tx_threshold_bps: Option<u64>,
    pub rx_limit_bps: Option<u64>,
    pub tx_limit_bps: Option<u64>,
    pub window_secs: Option<u64>,
    pub trigger_ratio_pct: Option<u8>,
    pub limit_duration_secs: Option<u64>,
    pub burst_bytes: Option<u64>,
}

impl PolicyFields {
    pub fn is_empty(&self) -> bool {
        self == &PolicyFields::default()
    }

    /// Field-level merge: `other` wins wherever it is present.
    pub fn merged_with(&self, other: &PolicyFields) -> PolicyFields {
        PolicyFields {
            rx_threshold_bps: other.rx_threshold_bps.or(self.rx_threshold_bps),
            tx_threshold_bps: other.tx_threshold_bps.or(self.tx_threshold_bps),
            rx_limit_bps: other.rx_limit_bps.or(self.rx_limit_bps),
            tx_limit_bps: other.tx_limit_bps.or(self.tx_limit_bps),
            window_secs: other.window_secs.or(self.window_secs),
            trigger_ratio_pct: other.trigger_ratio_pct.or(self.trigger_ratio_pct),
            limit_duration_secs: other.limit_duration_secs.or(self.limit_duration_secs),
            burst_bytes: other.burst_bytes.or(self.burst_bytes),
        }
    }
}

/// A fully-specified limiter for one direction. Only built when every parameter exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirPolicy {
    pub threshold_bps: u64,
    pub limit_bps: u64,
    pub window_secs: u64,
    pub trigger_ratio_pct: u8,
    pub limit_duration_secs: u64,
    pub burst_bytes: u64,
}

impl DirPolicy {
    /// Trigger line in bits per second: `threshold * trigger_ratio`.
    pub fn trigger_bps(&self) -> u64 {
        // u64 × u8 cannot overflow in practice (threshold is bounded by config sanity),
        // but saturate anyway so a bogus value degrades to "never trigger" not a panic.
        self.threshold_bps
            .saturating_mul(self.trigger_ratio_pct as u64)
            / 100
    }
}

/// Resolved policy for one IP. `None` on a direction means that direction is not policed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EffectivePolicy {
    pub rx: Option<DirPolicy>,
    pub tx: Option<DirPolicy>,
}

impl EffectivePolicy {
    pub fn is_empty(&self) -> bool {
        self.rx.is_none() && self.tx.is_none()
    }
}

/// Merge `range` with an optional `override_fields` and resolve into an effective policy.
///
/// A direction is policed only when its threshold, its limit and all four shared
/// parameters (window, trigger_ratio, limit_duration, burst) are present after the merge.
/// Specifying only some of them is a configuration error, reported with `what` naming the
/// offending range or IP.
pub fn resolve(
    range: &PolicyFields,
    override_fields: Option<&PolicyFields>,
    what: &str,
) -> Result<EffectivePolicy, String> {
    let empty = PolicyFields::default();
    let merged = range.merged_with(override_fields.unwrap_or(&empty));

    let rx = build_dir(
        merged.rx_threshold_bps,
        merged.rx_limit_bps,
        &merged,
        what,
        "rx",
    )?;
    let tx = build_dir(
        merged.tx_threshold_bps,
        merged.tx_limit_bps,
        &merged,
        what,
        "tx",
    )?;

    Ok(EffectivePolicy { rx, tx })
}

fn build_dir(
    threshold: Option<u64>,
    limit: Option<u64>,
    merged: &PolicyFields,
    what: &str,
    dir: &str,
) -> Result<Option<DirPolicy>, String> {
    // Nothing configured for this direction: not policed.
    if threshold.is_none() && limit.is_none() {
        return Ok(None);
    }

    let missing = |name: &str, present: bool| -> Option<String> {
        if present {
            None
        } else {
            Some(name.to_string())
        }
    };
    let mut missing_fields: Vec<String> = Vec::new();
    if let Some(m) = missing("threshold", threshold.is_some()) {
        missing_fields.push(format!("{dir}_{m}"));
    }
    if let Some(m) = missing("limit", limit.is_some()) {
        missing_fields.push(format!("{dir}_{m}"));
    }
    if merged.window_secs.is_none() {
        missing_fields.push("window".to_string());
    }
    if merged.trigger_ratio_pct.is_none() {
        missing_fields.push("trigger_ratio".to_string());
    }
    if merged.limit_duration_secs.is_none() {
        missing_fields.push("limit_duration".to_string());
    }
    if merged.burst_bytes.is_none() {
        missing_fields.push("burst".to_string());
    }
    if !missing_fields.is_empty() {
        return Err(format!(
            "policy for {what}: {dir} direction is incomplete; missing {}",
            missing_fields.join(", ")
        ));
    }

    Ok(Some(DirPolicy {
        threshold_bps: threshold.unwrap(),
        limit_bps: limit.unwrap(),
        window_secs: merged.window_secs.unwrap(),
        trigger_ratio_pct: merged.trigger_ratio_pct.unwrap(),
        limit_duration_secs: merged.limit_duration_secs.unwrap(),
        burst_bytes: merged.burst_bytes.unwrap(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full() -> PolicyFields {
        PolicyFields {
            rx_threshold_bps: Some(1_000_000_000),
            tx_threshold_bps: Some(500_000_000),
            rx_limit_bps: Some(500_000_000),
            tx_limit_bps: Some(200_000_000),
            window_secs: Some(300),
            trigger_ratio_pct: Some(80),
            limit_duration_secs: Some(1800),
            burst_bytes: Some(4 * 1024 * 1024),
        }
    }

    #[test]
    fn empty_policy_resolves_to_none() {
        let eff = resolve(&PolicyFields::default(), None, "R").unwrap();
        assert!(eff.is_empty());
    }

    #[test]
    fn full_policy_resolves_both_directions() {
        let eff = resolve(&full(), None, "R").unwrap();
        let rx = eff.rx.unwrap();
        assert_eq!(rx.threshold_bps, 1_000_000_000);
        assert_eq!(rx.limit_bps, 500_000_000);
        assert_eq!(rx.window_secs, 300);
        assert_eq!(rx.trigger_ratio_pct, 80);
        assert_eq!(rx.limit_duration_secs, 1800);
        assert_eq!(rx.trigger_bps(), 800_000_000);
        assert!(eff.tx.is_some());
        assert_eq!(eff.tx.unwrap().trigger_bps(), 400_000_000);
    }

    #[test]
    fn partial_direction_is_rejected() {
        let mut p = full();
        p.rx_limit_bps = None;
        let err = resolve(&p, None, "R").unwrap_err();
        assert!(err.contains("rx_limit"), "{err}");
        assert!(err.contains("incomplete"), "{err}");
    }

    #[test]
    fn override_replaces_and_inherits() {
        let ov = PolicyFields {
            rx_threshold_bps: Some(2_000_000_000),
            rx_limit_bps: Some(800_000_000),
            ..Default::default()
        };
        let eff = resolve(&full(), Some(&ov), "10.0.0.3").unwrap();
        let rx = eff.rx.unwrap();
        // overridden
        assert_eq!(rx.threshold_bps, 2_000_000_000);
        assert_eq!(rx.limit_bps, 800_000_000);
        // inherited from range
        assert_eq!(rx.window_secs, 300);
        assert_eq!(rx.burst_bytes, 4 * 1024 * 1024);
        // tx untouched
        assert_eq!(eff.tx.unwrap().threshold_bps, 500_000_000);
    }

    #[test]
    fn override_without_range_policy_is_incomplete() {
        let ov = PolicyFields {
            rx_threshold_bps: Some(1_000),
            ..Default::default()
        };
        let err = resolve(&PolicyFields::default(), Some(&ov), "10.0.0.3").unwrap_err();
        assert!(err.contains("incomplete"), "{err}");
    }

    #[test]
    fn merge_prefers_override() {
        let base = full();
        let ov = PolicyFields {
            window_secs: Some(600),
            ..Default::default()
        };
        let merged = base.merged_with(&ov);
        assert_eq!(merged.window_secs, Some(600));
        assert_eq!(merged.rx_threshold_bps, base.rx_threshold_bps);
    }
}
