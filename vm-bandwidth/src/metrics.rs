//! VictoriaMetrics export: the daemon pushes cumulative per-IP counters
//! (bytes + packets, RX/TX) in Prometheus text import format.
//!
//! Counters are cumulative and restart from zero when the daemon restarts;
//! `rate()` / `increase()` on the query side handle resets the same way they
//! do for any Prometheus counter.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use anyhow::Result;
use vm_bandwidth_core::limiter::IpTotals;

use crate::http;

/// Escape a Prometheus label value (backslash, double quote, newline).
fn escape_label(v: &str) -> String {
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

/// Push one payload to `{base_url}/api/v1/import/prometheus`.
pub fn push(base_url: &str, lines: &str) -> Result<()> {
    if lines.is_empty() {
        return Ok(());
    }
    let url = format!("{base_url}/api/v1/import/prometheus");
    http::post(&url, "text/plain; charset=utf-8", lines)
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
}
