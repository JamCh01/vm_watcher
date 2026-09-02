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
/// IPv6 is counted per TAP (ifindex) in eBPF (TRAFFIC6) and surfaced here as
/// one aggregate — there is no per-address breakdown; a single bounded series
/// set keeps VictoriaMetrics cardinality flat.
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

/// Render the oversized-packet observability series (cumulative, low cardinality).
pub fn render_prom_lines_oversized(
    oversized: &(
        vm_bandwidth_common::OversizedStats,
        vm_bandwidth_common::OversizedStats,
    ),
    now_ms: i64,
) -> String {
    let mut out = String::new();
    for (dir, stats) in [("rx", &oversized.0), ("tx", &oversized.1)] {
        if stats.packets | stats.bytes == 0 {
            continue;
        }
        out.push_str(&format!(
            "vmbw_oversized_{dir}_packets_total {packets} {now_ms}\nvmbw_oversized_{dir}_bytes_total {bytes} {now_ms}\n",
            packets = stats.packets,
            bytes = stats.bytes
        ));
    }
    out
}

/// Process-lifetime operational counters: attach failures and metrics-push
/// outcomes. Fixed label set (`instance="process"`) → exactly four series,
/// constant cardinality. Rendered even when zero so `rate()`/`increase()` have
/// a continuous series from daemon start.
///
/// Success-lag semantics: a push cannot observe its own outcome while it is
/// still running, so the success value in any payload is the count from BEFORE
/// that push — success lags by at most one push interval by construction.
/// failures/skipped are current at render time (they happen before the render).
pub fn render_prom_lines_process(
    tap_attach_failures: u64,
    push_successes: u64,
    push_failures: u64,
    push_skipped: u64,
    now_ms: i64,
) -> String {
    let mut out = String::with_capacity(256);
    for (name, value) in [
        ("vmbw_tap_attach_failures_total", tap_attach_failures),
        ("vmbw_metrics_push_successes_total", push_successes),
        ("vmbw_metrics_push_failures_total", push_failures),
        ("vmbw_metrics_push_skipped_total", push_skipped),
    ] {
        out.push_str(&format!(
            "{name}{{instance=\"process\"}} {value} {now_ms}\n"
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
        // Pushes go out once a minute; the pooled keep-alive connection regularly
        // outlives VictoriaMetrics' shorter idle timeout and dies mid-request
        // ("connection closed before message completed"). A fresh connection per
        // push costs nothing on localhost and removes the race.
        .pool_max_idle_per_host(0)
        .build()
        .expect("failed to build the HTTP client")
}

/// Read a response body with a hard cap.
pub async fn body_capped(mut resp: reqwest::Response) -> Result<String> {
    let mut body = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| e.without_url())
        .context("reading response body")?
    {
        if body.len() + chunk.len() > MAX_RESPONSE_BODY {
            bail!("response body exceeds {MAX_RESPONSE_BODY} bytes");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// Push one payload to `{base_url}/api/v1/import/prometheus`.
///
/// Diagnostics never carry more than scheme://host[:port] of the endpoint
/// (`safe_endpoint_display`): reqwest errors can embed the full URL, so every
/// error leaving this function is passed through `without_url()` and the
/// context strings use the redacted form.
pub async fn push(client: &reqwest::Client, base_url: &str, lines: &str) -> Result<()> {
    if lines.is_empty() {
        return Ok(());
    }
    let url = format!("{base_url}/api/v1/import/prometheus");
    let safe = vm_bandwidth_core::config::safe_endpoint_display(base_url);
    let resp = client
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(lines.to_string())
        .send()
        .await
        .map_err(|e| e.without_url())
        .with_context(|| format!("POST {safe}"))?;
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
    fn renders_oversized_only_when_nonzero() {
        use vm_bandwidth_common::OversizedStats;
        let none = (OversizedStats::default(), OversizedStats::default());
        assert_eq!(render_prom_lines_oversized(&none, 7), "");
        let some = (
            OversizedStats {
                packets: 3,
                bytes: 200_000,
            },
            OversizedStats::default(),
        );
        let out = render_prom_lines_oversized(&some, 7);
        assert!(out.contains("vmbw_oversized_rx_packets_total 3 7"), "{out}");
        assert!(
            out.contains("vmbw_oversized_rx_bytes_total 200000 7"),
            "{out}"
        );
        assert!(!out.contains("_tx_"), "tx was zero: {out}");
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

    #[test]
    fn process_counters_render_fixed_series_with_current_values() {
        let lines = super::render_prom_lines_process(2, 10, 3, 1, 123);
        for needle in [
            "vmbw_tap_attach_failures_total{instance=\"process\"} 2 123",
            "vmbw_metrics_push_successes_total{instance=\"process\"} 10 123",
            "vmbw_metrics_push_failures_total{instance=\"process\"} 3 123",
            "vmbw_metrics_push_skipped_total{instance=\"process\"} 1 123",
        ] {
            assert!(lines.contains(needle), "missing {needle:?} in:\n{lines}");
        }
        // Exactly four series, constant cardinality, cumulative semantics: the
        // values are whatever the daemon accumulated — the renderer adds nothing
        // and drops nothing (zero values still render so rate() sees continuity).
        assert_eq!(lines.lines().count(), 4, "{lines}");
        let zeros = super::render_prom_lines_process(0, 0, 0, 0, 1);
        assert_eq!(zeros.lines().count(), 4, "zero counters must still render");
    }
}

#[cfg(test)]
mod push_io_tests {
    //! Real-socket tests for the push path. Counter semantics are driven through
    //! the PRODUCTION orchestration `daemon::run_metrics_push` (the exact future
    //! `Engine::push_metrics` spawns) — no test-side mirror of the guard/push/
    //! counter sequence. Redaction is asserted on `metrics::push` error chains.

    use crate::daemon::{run_metrics_push, PushCounters};
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    fn payload() -> String {
        "vmbw_rx_bytes_total{ip=\"10.0.0.1\",range=\"r\"} 1 1\n".to_string()
    }

    fn short_timeout_client() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap()
    }

    /// Single-connection HTTP server: reads one request head, writes the canned
    /// response. Returns the base URL and a connection counter.
    fn serve_once(response: &'static str) -> (String, Arc<AtomicUsize>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let accepts = Arc::new(AtomicUsize::new(0));
        let counter = accepts.clone();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                counter.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf); // request head; body irrelevant
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        (url, accepts)
    }

    /// Server that ACCEPTS connections and keeps every socket open without ever
    /// answering, until the test signals stop. This is a genuine stall: the
    /// client waits on a live connection, so only its timeout can end the
    /// request (an immediate close would surface as EOF/reset, not a timeout).
    fn serve_hold() -> (String, Arc<AtomicBool>, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let stop_c = stop.clone();
        let handle = std::thread::spawn(move || {
            let mut held: Vec<std::net::TcpStream> = Vec::new();
            while !stop_c.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => held.push(stream),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
            drop(held); // sockets released only when the test is done
        });
        (url, stop, handle)
    }

    #[tokio::test]
    async fn production_push_2xx_counts_success_and_releases_the_slot() {
        let (url, _accepts) = serve_once("HTTP/1.1 204 No Content\r\n\r\n");
        let counters = Arc::new(PushCounters::new());

        run_metrics_push(counters.clone(), short_timeout_client(), url, payload()).await;

        assert_eq!(counters.successes(), 1);
        assert_eq!(counters.failures(), 0);
        assert_eq!(counters.skipped(), 0);
        // Guard released after the request: the next push can start.
        assert!(counters.try_start().is_some());
    }

    #[tokio::test]
    async fn production_push_5xx_counts_failure() {
        let (url, _accepts) =
            serve_once("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n");
        let counters = Arc::new(PushCounters::new());

        run_metrics_push(counters.clone(), short_timeout_client(), url, payload()).await;

        assert_eq!(counters.failures(), 1);
        assert_eq!(counters.successes(), 0);
        assert_eq!(counters.skipped(), 0);
        assert!(
            counters.try_start().is_some(),
            "slot released after failure"
        );
    }

    #[tokio::test]
    async fn production_push_connection_refused_counts_failure() {
        // Nothing listens on port 1.
        let counters = Arc::new(PushCounters::new());
        run_metrics_push(
            counters.clone(),
            short_timeout_client(),
            "http://127.0.0.1:1".to_string(),
            payload(),
        )
        .await;
        assert_eq!(counters.failures(), 1);
        assert_eq!(counters.successes(), 0);
    }

    #[tokio::test]
    async fn inflight_second_push_skips_without_request_then_recovers() {
        let (url, accepts) = serve_once("HTTP/1.1 204 No Content\r\n\r\n");
        let counters = Arc::new(PushCounters::new());

        // A previous push still in flight: hold its slot.
        let held = counters.try_start().expect("slot free");
        run_metrics_push(
            counters.clone(),
            short_timeout_client(),
            url.clone(),
            payload(),
        )
        .await;
        assert_eq!(counters.skipped(), 1);
        assert_eq!(counters.successes(), 0);
        assert_eq!(counters.failures(), 0);
        // A skipped push must not create an HTTP request.
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(accepts.load(Ordering::SeqCst), 0);
        drop(held);

        // After the previous push ends, the next one runs normally.
        run_metrics_push(counters.clone(), short_timeout_client(), url, payload()).await;
        assert_eq!(counters.successes(), 1, "guard released: recovery works");
        assert_eq!(counters.skipped(), 1, "no extra skip");
        assert_eq!(accepts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn empty_payload_contract_counts_success_without_http() {
        // The contract of the production helper for an empty payload: push()
        // returns Ok without any HTTP, so the run counts as a success. In the
        // daemon this input is unreachable once metrics are enabled — the
        // process-metric renderer always emits four series — and push_metrics
        // returns before spawning when lines are empty.
        let (url, accepts) = serve_once("HTTP/1.1 204 No Content\r\n\r\n");
        let counters = Arc::new(PushCounters::new());
        run_metrics_push(counters.clone(), short_timeout_client(), url, String::new()).await;
        assert_eq!(counters.successes(), 1, "empty payload is an Ok no-op push");
        assert_eq!(counters.failures(), 0);
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(
            accepts.load(Ordering::SeqCst),
            0,
            "no HTTP request for empty payload"
        );
    }

    #[tokio::test]
    async fn http_failure_error_chain_never_echoes_credentials() {
        let (base, _accepts) =
            serve_once("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n");
        let stripped = base.strip_prefix("http://").unwrap();
        let url = format!("http://operator:hunter2@{stripped}/secret/path?api_key=tok123#frag");

        let err = crate::metrics::push(&short_timeout_client(), &url, &payload())
            .await
            .expect_err("500 must fail");
        let shown = format!("{err:#}");
        for secret in [
            "hunter2",
            "operator",
            "secret/path",
            "api_key",
            "tok123",
            "frag",
        ] {
            assert!(!shown.contains(secret), "{secret:?} leaked in: {shown}");
        }
    }

    #[tokio::test]
    async fn connection_refused_error_chain_never_echoes_credentials() {
        let url = "http://operator:hunter2@127.0.0.1:1/secret?api_key=tok123";
        let err = crate::metrics::push(&short_timeout_client(), url, &payload())
            .await
            .expect_err("refused must fail");
        let shown = format!("{err:#}");
        for secret in ["hunter2", "operator", "secret", "api_key", "tok123"] {
            assert!(!shown.contains(secret), "{secret:?} leaked in: {shown}");
        }
    }

    #[tokio::test]
    async fn stalled_server_triggers_a_real_timeout() {
        let (url, stop, handle) = serve_hold();
        let counters = Arc::new(PushCounters::new());
        let timeout = Duration::from_millis(300);
        let client = reqwest::Client::builder().timeout(timeout).build().unwrap();

        // Production orchestration against the stalling server: counts a failure.
        let start = Instant::now();
        run_metrics_push(counters.clone(), client.clone(), url.clone(), payload()).await;
        let production_elapsed = start.elapsed();
        assert_eq!(counters.failures(), 1);
        assert_eq!(counters.successes(), 0);

        // Same server, direct push: the error must be classified as a timeout
        // (not EOF/reset), and it must respect the injected deadline.
        let start = Instant::now();
        let err = crate::metrics::push(&client, &url, &payload())
            .await
            .expect_err("stalled server must fail");
        let elapsed = start.elapsed();
        let reqwest_err = err
            .chain()
            .find_map(|e| e.downcast_ref::<reqwest::Error>())
            .expect("error chain must carry the reqwest error");
        assert!(reqwest_err.is_timeout(), "must be a real timeout: {err:#}");
        assert!(
            elapsed >= timeout.saturating_sub(Duration::from_millis(100)),
            "ended too early ({elapsed:?}) — looks like an immediate close, not a timeout"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "must end by the injected {timeout:?}, elapsed {elapsed:?}"
        );
        assert!(
            production_elapsed < Duration::from_secs(2),
            "production push also bounded by the client timeout"
        );
        // Timeout errors are redacted like every other push failure.
        let shown = format!("{err:#}");
        assert!(
            !shown.contains("hunter2") && !shown.contains("api_key"),
            "{shown}"
        );

        stop.store(true, Ordering::SeqCst);
        handle.join().expect("server thread must exit after stop");
    }
}
