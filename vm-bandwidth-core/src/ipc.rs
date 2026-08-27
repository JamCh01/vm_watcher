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
}
