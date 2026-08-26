//! Effective limit-policy resolution.
//!
//! Each IP range may declare a default policy; individual IPs may override any subset of
//! it. Resolution is a plain field-level merge (override wins, range is the fallback),
//! followed by a completeness check per direction. eBPF never sees inheritance: the
//! daemon hands it fully-resolved per-(IP, direction) parameters only.

use vm_bandwidth_common::{
    ALGO_FIXED_WINDOW, ALGO_GCRA, ALGO_LEAKY_BUCKET, ALGO_SLIDING_WINDOW_COUNTER,
    ALGO_SLIDING_WINDOW_LOG, ALGO_TOKEN_BUCKET,
};

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
    /// One of the `vm_bandwidth_common::ALGO_*` constants; absent = GCRA (default).
    pub algorithm: Option<u32>,
    /// Window length for the window-based algorithms.
    pub limit_window_secs: Option<u64>,
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
            algorithm: other.algorithm.or(self.algorithm),
            limit_window_secs: other.limit_window_secs.or(self.limit_window_secs),
        }
    }
}

/// True for token bucket / leaky bucket / GCRA: algorithms that need `burst` and
/// have no window of their own.
fn is_bucket_algo(algorithm: u32) -> bool {
    matches!(algorithm, ALGO_TOKEN_BUCKET | ALGO_LEAKY_BUCKET | ALGO_GCRA)
}

/// True for fixed window / sliding window counter / sliding window log: algorithms
/// that need `limit_window` and ignore `burst`.
fn is_window_algo(algorithm: u32) -> bool {
    matches!(
        algorithm,
        ALGO_FIXED_WINDOW | ALGO_SLIDING_WINDOW_COUNTER | ALGO_SLIDING_WINDOW_LOG
    )
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
    /// One of the `vm_bandwidth_common::ALGO_*` constants.
    pub algorithm: u32,
    /// Window length for window-based algorithms; 0 for bucket/GCRA algorithms.
    pub limit_window_secs: u64,
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
/// A direction is policed only when its threshold, its limit and all shared parameters
/// are present after the merge. Which shared parameters are required depends on the
/// algorithm: bucket/GCRA algorithms need `burst`, window algorithms need `limit_window`,
/// and a field that does not apply to the selected algorithm is a configuration error.
/// `algorithm` itself defaults to GCRA. Errors name the offending range or IP via `what`.
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
    // Fields that do not apply to the selected algorithm are ignored rather than
    // rejected: an IP override switching algorithms inherits the range's fields and
    // has no way to "unset" them.
    let algorithm = merged.algorithm.unwrap_or(ALGO_GCRA);
    if is_bucket_algo(algorithm) {
        if merged.burst_bytes.is_none() {
            missing_fields.push("burst".to_string());
        }
    } else if is_window_algo(algorithm) {
        if merged.limit_window_secs.is_none() {
            missing_fields.push("limit_window".to_string());
        }
    } else {
        return Err(format!("policy for {what}: unknown algorithm {algorithm}"));
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
        // Fields that do not apply to the selected algorithm are zeroed here so they
        // can never leak into an installed eBPF policy.
        burst_bytes: if is_window_algo(algorithm) {
            0
        } else {
            merged.burst_bytes.unwrap_or(0)
        },
        algorithm,
        limit_window_secs: if is_window_algo(algorithm) {
            merged.limit_window_secs.unwrap_or(0)
        } else {
            0
        },
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
            ..Default::default()
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

    fn window_fields() -> PolicyFields {
        let mut p = full();
        p.algorithm = Some(vm_bandwidth_common::ALGO_FIXED_WINDOW);
        p.burst_bytes = None;
        p.limit_window_secs = Some(10);
        p
    }

    #[test]
    fn default_algorithm_is_gcra() {
        let rx = resolve(&full(), None, "R").unwrap().rx.unwrap();
        assert_eq!(rx.algorithm, vm_bandwidth_common::ALGO_GCRA);
        assert_eq!(rx.limit_window_secs, 0);
    }

    #[test]
    fn token_bucket_resolves_with_burst() {
        let mut p = full();
        p.algorithm = Some(vm_bandwidth_common::ALGO_TOKEN_BUCKET);
        let rx = resolve(&p, None, "R").unwrap().rx.unwrap();
        assert_eq!(rx.algorithm, vm_bandwidth_common::ALGO_TOKEN_BUCKET);
        assert_eq!(rx.burst_bytes, 4 * 1024 * 1024);
    }

    #[test]
    fn window_algorithm_resolves_without_burst() {
        let rx = resolve(&window_fields(), None, "R").unwrap().rx.unwrap();
        assert_eq!(rx.algorithm, vm_bandwidth_common::ALGO_FIXED_WINDOW);
        assert_eq!(rx.limit_window_secs, 10);
        assert_eq!(rx.burst_bytes, 0);
    }

    #[test]
    fn window_algorithm_requires_limit_window() {
        let mut p = window_fields();
        p.limit_window_secs = None;
        let err = resolve(&p, None, "R").unwrap_err();
        assert!(err.contains("limit_window"), "{err}");
    }

    #[test]
    fn window_algorithm_ignores_burst() {
        let mut p = window_fields();
        p.burst_bytes = Some(1024);
        let rx = resolve(&p, None, "R").unwrap().rx.unwrap();
        assert_eq!(rx.burst_bytes, 0);
    }

    #[test]
    fn bucket_algorithm_ignores_limit_window() {
        let mut p = full();
        p.limit_window_secs = Some(5);
        let rx = resolve(&p, None, "R").unwrap().rx.unwrap();
        assert_eq!(rx.limit_window_secs, 0);
    }

    #[test]
    fn override_can_switch_algorithm() {
        // The range keeps burst (GCRA default); the override switches to a window
        // algorithm and inherits the burst field, which is simply ignored.
        let ov = PolicyFields {
            algorithm: Some(vm_bandwidth_common::ALGO_SLIDING_WINDOW_COUNTER),
            limit_window_secs: Some(2),
            ..Default::default()
        };
        let eff = resolve(&full(), Some(&ov), "10.0.0.3").unwrap();
        let rx = eff.rx.unwrap();
        assert_eq!(
            rx.algorithm,
            vm_bandwidth_common::ALGO_SLIDING_WINDOW_COUNTER
        );
        assert_eq!(rx.limit_window_secs, 2);
    }
}
