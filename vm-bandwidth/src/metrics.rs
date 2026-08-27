//! VictoriaMetrics export: the daemon pushes cumulative per-IP counters
//! (bytes + packets, RX/TX) in Prometheus text import format.
//!
//! Counters are cumulative and restart from zero when the daemon restarts;
//! `rate()` / `increase()` on the query side handle resets the same way they
//! do for any Prometheus counter.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use vm_bandwidth_core::ipc::IPV6_RANGE_NAME;
use vm_bandwidth_core::limiter::IpTotals;

const TIMEOUT: Duration = Duration::from_secs(5);
/// Response bodies above this are refused: replies here are small status/error
/// documents, and a misbehaving server must not grow memory unbounded.
const MAX_RESPONSE_BODY: usize = 1 << 20;

/// Render the aggregate IPv6 pseudo-series (`ip="ipv6-all"`, `range="IPv6"`).
/// IPv6 is counted per address in eBPF but surfaced as one aggregate; a single
/// bounded series set keeps VictoriaMetrics cardinality flat.
pub fn render_prom_lines_ipv6(t: &crate::collector::IpStats, now_ms: i64) -> String {
    if t.rx_bytes | t.tx_bytes | t.rx_packets | t.tx_packets == 0 {
        return String::new();
    }
    let mut out = String::with_capacity(192);
    for (name, value) in [
        ("vmbw_rx_bytes_total", t.rx_bytes),
        ("vmbw_tx_bytes_total", t.tx_bytes),
        ("vmbw_rx_packets_total", t.rx_packets),
        ("vmbw_tx_packets_total", t.tx_packets),
    ] {
        out.push_str(name);
        out.push_str(&format!(
            "{{ip=\"ipv6-all\",range=\"{IPV6_RANGE_NAME}\"}} {value} {now_ms}\n"
        ));
    }
    out
}

/// Escape a Prometheus label value (backslash, double quote, newline).
pub fn escape_label(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

/// Render one push payload. IPs with no traffic at all are skipped to keep
/// the series count down.
pub fn render_prom_lines(
    totals: &HashMap<u32, IpTotals>,
    range_name: impl Fn(u32) -> String,
    now_ms: i64,
) -> String {
    let mut out = String::with_capacity(totals.len() * 192);
    let mut ips: Vec<u32> = totals.keys().copied().collect();
    ips.sort_unstable();
    for ip in ips {
        let Some(t) = totals.get(&ip) else { continue };
        if t.rx_bytes | t.tx_bytes | t.rx_packets | t.tx_packets == 0 {
            continue;
        }
        let addr = Ipv4Addr::from(ip);
        let range = escape_label(&range_name(ip));
        for (name, value) in [
            ("vmbw_rx_bytes_total", t.rx_bytes),
            ("vmbw_tx_bytes_total", t.tx_bytes),
            ("vmbw_rx_packets_total", t.rx_packets),
            ("vmbw_tx_packets_total", t.tx_packets),
        ] {
            out.push_str(name);
            out.push_str(&format!(
                "{{ip=\"{addr}\",range=\"{range}\"}} {value} {now_ms}\n"
            ));
        }
    }
    out
}

/// Render the policer verdict series (passed/dropped, bytes/packets) for flows
/// with an active policy. Cumulative like the traffic counters; the daemon resets
/// them per policy session, which `rate()`/`increase()` treat as counter resets.
pub fn render_prom_lines_policer(
    totals: &HashMap<u32, crate::collector::PolicerIpTotals>,
    range_name: impl Fn(u32) -> String,
    now_ms: i64,
) -> String {
    let mut out = String::with_capacity(totals.len() * 384);
    let mut ips: Vec<u32> = totals.keys().copied().collect();
    ips.sort_unstable();
    for ip in ips {
        let Some(t) = totals.get(&ip) else { continue };
        let addr = Ipv4Addr::from(ip);
        let range = escape_label(&range_name(ip));
        for (name, value) in [
            ("vmbw_policer_rx_passed_bytes_total", t.rx_passed_bytes),
            ("vmbw_policer_tx_passed_bytes_total", t.tx_passed_bytes),
            ("vmbw_policer_rx_passed_packets_total", t.rx_passed_packets),
            ("vmbw_policer_tx_passed_packets_total", t.tx_passed_packets),
            ("vmbw_policer_rx_dropped_bytes_total", t.rx_dropped_bytes),
            ("vmbw_policer_tx_dropped_bytes_total", t.tx_dropped_bytes),
            (
                "vmbw_policer_rx_dropped_packets_total",
                t.rx_dropped_packets,
            ),
            (
                "vmbw_policer_tx_dropped_packets_total",
                t.tx_dropped_packets,
            ),
        ] {
            if value == 0 {
                continue;
            }
            out.push_str(name);
            out.push_str(&format!(
                "{{ip=\"{addr}\",range=\"{range}\"}} {value} {now_ms}\n"
            ));
        }
    }
    out
}

/// Shared HTTP client. reqwest pools connections and recommends reusing one
/// instance; the daemon builds it once and hands it to every push.
pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(TIMEOUT)
        .build()
        .expect("failed to build the HTTP client")
}

/// Read a response body with a hard cap.
pub async fn body_capped(mut resp: reqwest::Response) -> Result<String> {
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.context("reading response body")? {
        if body.len() + chunk.len() > MAX_RESPONSE_BODY {
            bail!("response body exceeds {MAX_RESPONSE_BODY} bytes");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// Push one payload to `{base_url}/api/v1/import/prometheus`.
pub async fn push(client: &reqwest::Client, base_url: &str, lines: &str) -> Result<()> {
    if lines.is_empty() {
        return Ok(());
    }
    let url = format!("{base_url}/api/v1/import/prometheus");
    let resp = client
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(lines.to_string())
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = body_capped(resp).await.unwrap_or_default();
        bail!(
            "HTTP {}: {}",
            status.as_u16(),
            body.chars().take(200).collect::<String>()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_sorted_nonzero_only() {
        let mut totals = HashMap::new();
        totals.insert(
            u32::from(Ipv4Addr::new(10, 0, 0, 2)),
            IpTotals {
                rx_bytes: 100,
                tx_bytes: 50,
                rx_packets: 2,
                tx_packets: 1,
            },
        );
        totals.insert(u32::from(Ipv4Addr::new(10, 0, 0, 1)), IpTotals::default());
        let lines = render_prom_lines(&totals, |_| "r1".into(), 123);
        assert!(lines.contains("vmbw_rx_bytes_total{ip=\"10.0.0.2\",range=\"r1\"} 100 123"));
        assert!(lines.contains("vmbw_tx_packets_total{ip=\"10.0.0.2\",range=\"r1\"} 1 123"));
        assert!(
            !lines.contains("10.0.0.1"),
            "zero-traffic IP must be skipped"
        );
        assert_eq!(lines.lines().count(), 4);
    }

    #[test]
    fn escapes_label_values() {
        let mut totals = HashMap::new();
        totals.insert(
            1,
            IpTotals {
                rx_bytes: 1,
                tx_bytes: 0,
                rx_packets: 0,
                tx_packets: 0,
            },
        );
        let lines = render_prom_lines(&totals, |_| "a\"b\\c".into(), 0);
        assert!(lines.contains("range=\"a\\\"b\\\\c\""), "{lines}");
    }

    #[test]
    fn renders_policer_nonzero_only() {
        let mut totals = HashMap::new();
        totals.insert(
            u32::from(Ipv4Addr::new(10, 0, 0, 2)),
            crate::collector::PolicerIpTotals {
                rx_passed_bytes: 100,
                tx_dropped_bytes: 40,
                tx_dropped_packets: 3,
                ..Default::default()
            },
        );
        totals.insert(
            u32::from(Ipv4Addr::new(10, 0, 0, 1)),
            crate::collector::PolicerIpTotals::default(),
        );
        let lines = render_prom_lines_policer(&totals, |_| "r1".into(), 123);
        assert!(lines
            .contains("vmbw_policer_rx_passed_bytes_total{ip=\"10.0.0.2\",range=\"r1\"} 100 123"));
        assert!(lines
            .contains("vmbw_policer_tx_dropped_bytes_total{ip=\"10.0.0.2\",range=\"r1\"} 40 123"));
        assert_eq!(
            lines.lines().count(),
            3,
            "zero series must be skipped: {lines}"
        );
        assert!(
            !lines.contains("10.0.0.1"),
            "unpoliced IP must emit nothing"
        );
    }
}
