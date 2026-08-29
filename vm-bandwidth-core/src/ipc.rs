//! IPC message types exchanged between the daemon and `--ui` clients.
//!
//! The transport is a Unix domain socket carrying length-delimited JSON frames (a u32
//! big-endian length prefix followed by a UTF-8 JSON payload). These types are pure data;
//! the framing/IO lives in the runtime crate. The UI is strictly read-only: there are no
//! mutating requests, and `config.toml` remains the only source of configuration truth.

use serde::{Deserialize, Serialize};

/// Display name of the aggregate IPv6 pseudo-range. Counted like a range but
/// never policed and without a per-IP breakdown; shared by daemon, metrics push
/// and UI so the name never drifts between the three.
pub const IPV6_RANGE_NAME: &str = "IPv6";

/// Protocol version carried in [`Status`]. Bump only on incompatible changes;
/// additive fields must keep working via `serde(default)`.
pub const PROTOCOL_VERSION: u32 = 1;

/// Requests are tiny JSON documents; a larger frame is a misbehaving client.
pub const MAX_REQUEST_FRAME: usize = 64 * 1024;

/// Largest legitimate response: a RangeDetail listing ~map_max_entries IPs at
/// roughly 350 B JSON each (8192 IPs ≈ 3 MiB). 8 MiB leaves headroom while refusing
/// to allocate on an untrusted u32 length.
pub const MAX_RESPONSE_FRAME: usize = 8 * 1024 * 1024;

/// Validate an untrusted frame length BEFORE allocating. `max` is one of the limits
/// above, chosen by the reading side.
pub fn validate_frame_len(len: u32, max: usize) -> Result<usize, String> {
    let len = len as usize;
    if len > max {
        Err(format!("frame length {len} exceeds limit {max}"))
    } else {
        Ok(len)
    }
}

/// A request from the UI to the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    /// Range overview + daemon/config/reload status.
    Overview,
    /// Per-IP detail for the range at `index` (overview ordering).
    RangeDetail { index: usize },
}

/// The daemon's reply to a [`Request`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Status(Box<Status>),
    RangeDetail(Box<RangeDetail>),
    Error { message: String },
}

/// Everything the overview screen needs (§30, §31, §32).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Status {
    /// Protocol version of the daemon. `#[serde(default)]` → 0 when talking to a
    /// daemon older than versioning, which clients treat as "legacy, best effort".
    #[serde(default)]
    pub protocol_version: u32,
    pub generation: u64,
    /// Wall-clock string for when the current config was loaded.
    pub config_loaded_at: String,
    /// Wall-clock string of the most recent reload attempt (success or failure).
    pub last_reload_at: String,
    pub last_reload_ok: bool,
    /// Empty when `last_reload_ok`.
    pub last_reload_error: String,
    pub bridge: String,
    pub tap_count: usize,
    /// False once the file watcher reported an error (hot reload may be dead).
    pub config_watcher_healthy: bool,
    pub config_watcher_errors_total: u64,
    pub config_watcher_last_error: String,
    /// True once a map rollback could not fully restore the dataplane. The
    /// dataplane may then differ from the active configuration; the exact state
    /// of each affected flow is carried by the per-step `RollbackFailure` entries
    /// in the daemon log (an old policy may be re-armed, a new limit may stay
    /// armed, or a flow may be unarmed with a bounded orphan artifact). The hard
    /// invariant `armed policy => matching state exists` still holds. The flag
    /// persists so the degradation stays visible. `#[serde(default)]` keeps older
    /// daemons readable.
    #[serde(default)]
    pub dataplane_degraded: bool,
    #[serde(default)]
    pub rollback_failures_total: u64,
    /// Operational counters, cumulative since daemon start (additive protocol
    /// fields: older daemons omit them, `#[serde(default)]` → 0).
    ///
    /// Lag semantics — two DIFFERENT surfaces:
    /// - IPC `Status` (this struct): reads the process atomics directly, so
    ///   these values are CURRENT at query time and never lag.
    /// - The VictoriaMetrics payload: a push cannot include its own outcome
    ///   (it has not finished yet), so the `vmbw_metrics_push_successes_total`
    ///   SERIES exported to VM lags the true count by at most one push
    ///   interval. failures/skipped are rendered before the request, so they
    ///   are current even in the payload.
    #[serde(default)]
    pub tap_attach_failures_total: u64,
    /// TAP recreations seen since daemon start (same name, new ifindex). Each
    /// event means external per-ifindex enforcement (anti-spoofing rules) is
    /// INACTIVE on that TAP until the platform re-applies it; the daemon warns
    /// with a SECURITY log line and counts the event here. 0 in steady state.
    #[serde(default)]
    pub antispoof_reapply_alerts_total: u64,
    #[serde(default)]
    pub metrics_push_successes_total: u64,
    #[serde(default)]
    pub metrics_push_failures_total: u64,
    #[serde(default)]
    pub metrics_push_skipped_total: u64,
    /// Anti-spoofing contract (see config `[security]`): which mode is in effect,
    /// whether THIS program enforces it (currently always false — external), and that
    /// the operator acknowledgement is on file.
    #[serde(default)]
    pub anti_spoof_mode: String,
    #[serde(default)]
    pub anti_spoof_enforced_by_program: bool,
    #[serde(default)]
    pub anti_spoof_acknowledged: bool,
    /// Packets above the policer's MAX_POLICED_LEN that passed fail-open while a
    /// limit policy was armed (cumulative since daemon start). Nonzero values mean
    /// the environment can produce oversized frames at the TC hooks — see
    /// docs/kernel-validation.md for how to judge them.
    #[serde(default)]
    pub oversized_rx_packets: u64,
    #[serde(default)]
    pub oversized_rx_bytes: u64,
    #[serde(default)]
    pub oversized_tx_packets: u64,
    #[serde(default)]
    pub oversized_tx_bytes: u64,
    /// Sliding-window-log map: configured capacity vs entries currently installed.
    /// Each entry preallocates ~16.4 KiB of kernel memory.
    #[serde(default)]
    pub swl_map_capacity: u32,
    #[serde(default)]
    pub swl_map_used: u32,
    pub ranges: Vec<RangeSummary>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RangeSummary {
    pub name: String,
    pub range: String,
    pub rx_bps: f64,
    pub tx_bps: f64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub ip_count: usize,
    /// Number of flows (IP+direction) currently LIMITED in this range.
    pub limited: usize,
    /// Aggregate policer drops across the range (0 unless something is policed).
    pub rx_dropped_bps: f64,
    pub tx_dropped_bps: f64,
    pub rx_dropped_bytes: u64,
    pub tx_dropped_bytes: u64,
}

/// Everything the detail screen needs for one range (§31).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RangeDetail {
    pub name: String,
    pub range: String,
    pub rx_bps: f64,
    pub tx_bps: f64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// Cumulative policer drops for the range (0 unless something is policed).
    pub rx_dropped_bytes: u64,
    pub tx_dropped_bytes: u64,
    pub rx_dropped_packets: u64,
    pub tx_dropped_packets: u64,
    pub ips: Vec<IpDetail>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IpDetail {
    pub ip: u32,
    // Current rates and cumulative totals.
    pub rx_bps: f64,
    pub tx_bps: f64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    // Rolling-window averages (threshold input).
    pub rx_window_bps: f64,
    pub tx_window_bps: f64,
    // Effective policy (0 = no limiter on that direction).
    pub rx_threshold: u64,
    pub tx_threshold: u64,
    pub rx_limit: u64,
    pub tx_limit: u64,
    // NORMAL / LIMITED per direction.
    pub rx_state: String,
    pub tx_state: String,
    // Seconds of limiting remaining per direction (0 when NORMAL).
    pub rx_remaining: u64,
    pub tx_remaining: u64,
    // Cumulative policer verdicts per direction (0 unless this flow is policed).
    pub rx_dropped_bytes: u64,
    pub tx_dropped_bytes: u64,
    pub rx_dropped_packets: u64,
    pub tx_dropped_packets: u64,
}

/// Encode a frame: u32 big-endian length + JSON bytes.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let body = serde_json::to_vec(value).map_err(|e| format!("serialize: {e}"))?;
    if body.len() > u32::MAX as usize {
        return Err("frame too large".to_string());
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decode the JSON body of a frame (without its 4-byte length prefix).
pub fn decode<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T, String> {
    serde_json::from_slice(body).map_err(|e| format!("deserialize: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip() {
        for req in [Request::Overview, Request::RangeDetail { index: 3 }] {
            let frame = encode(&req).unwrap();
            let len = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
            assert_eq!(len, frame.len() - 4);
            let back: Request = decode(&frame[4..]).unwrap();
            assert!(matches!(
                (&req, &back),
                (Request::Overview, Request::Overview)
                    | (Request::RangeDetail { .. }, Request::RangeDetail { .. })
            ));
        }
    }

    #[test]
    fn response_roundtrip() {
        let status = Status {
            generation: 12,
            bridge: "br0".into(),
            tap_count: 42,
            ranges: vec![RangeSummary {
                name: "A".into(),
                range: "10.30.8.1-10.30.8.16".into(),
                rx_bps: 1.2e9,
                limited: 2,
                ..Default::default()
            }],
            ..Default::default()
        };
        let frame = encode(&Response::Status(Box::new(status))).unwrap();
        let back: Response = decode(&frame[4..]).unwrap();
        match back {
            Response::Status(s) => {
                assert_eq!(s.generation, 12);
                assert_eq!(s.tap_count, 42);
                assert_eq!(s.ranges[0].limited, 2);
            }
            other => panic!("expected Status, got {other:?}"),
        }
    }

    #[test]
    fn rejects_garbage() {
        let err = decode::<Request>(b"not json").unwrap_err();
        assert!(err.contains("deserialize"), "{err}");
    }

    #[test]
    fn frame_length_validation_boundaries() {
        let max = 1024;
        assert_eq!(validate_frame_len(1023, max), Ok(1023));
        assert_eq!(validate_frame_len(1024, max), Ok(1024));
        assert!(validate_frame_len(1025, max).is_err());
        assert!(validate_frame_len(u32::MAX, max).is_err());
        assert!(validate_frame_len(u32::MAX, MAX_RESPONSE_FRAME).is_err());
    }

    #[test]
    fn truncated_frame_body_fails_to_decode() {
        let frame = encode(&Request::Overview).unwrap();
        let err = decode::<Request>(&frame[4..frame.len() - 1]).unwrap_err();
        assert!(err.contains("deserialize"), "{err}");
    }

    #[test]
    fn status_without_protocol_version_reads_as_legacy() {
        // A daemon predating versioning sends no field: default must be 0, not an
        // error.
        let json = r#"{"type":"status","generation":1,"config_loaded_at":"","last_reload_at":"","last_reload_ok":true,"last_reload_error":"","bridge":"br0","tap_count":0,"config_watcher_healthy":true,"config_watcher_errors_total":0,"config_watcher_last_error":"","dataplane_degraded":false,"rollback_failures_total":0,"swl_map_capacity":0,"swl_map_used":0,"ranges":[]}"#;
        let resp: Response = serde_json::from_str(json).unwrap();
        match resp {
            Response::Status(s) => {
                assert_eq!(s.protocol_version, 0);
                // Additive operational fields: an older daemon omits them entirely
                // and the client must read zeros, not an error.
                assert_eq!(s.tap_attach_failures_total, 0);
                assert_eq!(s.antispoof_reapply_alerts_total, 0);
                assert_eq!(s.metrics_push_successes_total, 0);
                assert_eq!(s.metrics_push_failures_total, 0);
                assert_eq!(s.metrics_push_skipped_total, 0);
            }
            other => panic!("expected status, got {other:?}"),
        }
    }

    #[test]
    fn operational_counters_round_trip() {
        let status = Status {
            protocol_version: PROTOCOL_VERSION,
            tap_attach_failures_total: 7,
            antispoof_reapply_alerts_total: 2,
            metrics_push_successes_total: 100,
            metrics_push_failures_total: 3,
            metrics_push_skipped_total: 1,
            ..Default::default()
        };
        let frame = encode(&Response::Status(Box::new(status))).unwrap();
        let back: Response = decode(&frame[4..]).unwrap();
        match back {
            Response::Status(s) => {
                assert_eq!(s.tap_attach_failures_total, 7);
                assert_eq!(s.antispoof_reapply_alerts_total, 2);
                assert_eq!(s.metrics_push_successes_total, 100);
                assert_eq!(s.metrics_push_failures_total, 3);
                assert_eq!(s.metrics_push_skipped_total, 1);
            }
            other => panic!("expected status, got {other:?}"),
        }
    }

    #[test]
    fn status_carries_current_protocol_version() {
        let status = Status {
            protocol_version: PROTOCOL_VERSION,
            ..Default::default()
        };
        let frame = encode(&Response::Status(Box::new(status))).unwrap();
        let back: Response = decode(&frame[4..]).unwrap();
        match back {
            Response::Status(s) => assert_eq!(s.protocol_version, PROTOCOL_VERSION),
            other => panic!("expected status, got {other:?}"),
        }
    }
}
