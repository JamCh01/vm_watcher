//! `--ui` client: connects to the daemon's Unix socket and renders a read-only TUI.
//!
//! Deliberately never loads eBPF, creates maps or attaches TC — the daemon is the only
//! owner of the data plane. All data arrives over the IPC socket as [`Status`] /
//! [`RangeDetail`] frames.

use std::io::{IsTerminal, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::widgets::TableState;

use vm_bandwidth_core::config::{self};
use vm_bandwidth_core::ipc::{self, Request, Response};

use crate::daemon::SOCK_PATH;
use crate::tui::{self, Screen, Series, TrendKind, TrendTarget, TrendView, UiState, TREND_WINDOWS};

const REFRESH: Duration = Duration::from_secs(1);
const IO_TIMEOUT: Duration = Duration::from_secs(2);

/// Blocking length-delimited JSON client.
struct Client {
    stream: UnixStream,
}

impl Client {
    fn connect() -> Result<Self> {
        let stream = UnixStream::connect(SOCK_PATH)
            .with_context(|| format!("cannot connect to daemon at {SOCK_PATH}"))?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        Ok(Self { stream })
    }

    fn request(&mut self, req: &Request) -> Result<Response> {
        let frame = ipc::encode(req).map_err(anyhow::Error::msg)?;
        self.stream.write_all(&frame)?;
        let mut lenbuf = [0u8; 4];
        self.stream.read_exact(&mut lenbuf)?;
        // Validate the untrusted length BEFORE allocating; never trust a u32 from
        // the wire with an unbounded vec!.
        let len = ipc::validate_frame_len(u32::from_be_bytes(lenbuf), ipc::MAX_RESPONSE_FRAME)
            .map_err(anyhow::Error::msg)?;
        let mut body = vec![0u8; len];
        self.stream.read_exact(&mut body)?;
        ipc::decode::<Response>(&body).map_err(anyhow::Error::msg)
    }
}

enum UiAction {
    Nothing,
    Quit,
    /// Re-poll the daemon immediately (refresh / screen change).
    Refresh,
}

pub fn run_ui(config_path: std::path::PathBuf) -> Result<()> {
    if !std::io::stdin().is_terminal()
        && std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .is_err()
    {
        anyhow::bail!("cannot open terminal input; run --ui from an interactive terminal (ssh -t)");
    }
    let (cols, rows) = crossterm::terminal::size().unwrap_or((0, 0));
    if cols == 0 || rows == 0 {
        anyhow::bail!("terminal reports a size of {cols}x{rows}; run from a real terminal");
    }

    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        ratatui::restore();
        default_hook(info);
    }));

    // The UI reads the same config file as the daemon, purely for the [metrics]
    // section (trend queries go straight to VictoriaMetrics, never via the daemon).
    // A missing/broken config DEGRADES the UI (trend screen off) instead of exiting:
    // overview and detail come from the daemon, not from this file.
    let metrics_cfg = match config::load(&config_path) {
        Ok(cfg) => Some(cfg),
        Err(e) => {
            eprintln!(
                "warning: cannot load {config_path:?}: {e};                  continuing without the trend screen"
            );
            None
        }
    };
    if let Some(cfg) = &metrics_cfg {
        if cfg.metrics_enabled {
            println!(
                "metrics: querying {} (refresh {}s)",
                vm_bandwidth_core::config::safe_endpoint_display(&cfg.metrics_url),
                cfg.metrics_push_interval_secs
            );
        }
    }

    // Trend queries run on a one-worker tokio runtime with async reqwest, so the
    // TUI keeps rendering while a fetch is in flight; results arrive on a channel.
    // Built before the terminal switches modes: a failure here prints normally.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .context("starting the trend fetch runtime")?;

    let mut terminal = ratatui::init();
    // Every exit from here on, `?` included, must hand the shell back intact.
    let _restore = TerminalGuard;
    let default_sort = metrics_cfg
        .as_ref()
        .map(|c| c.default_sort)
        .unwrap_or(config::SortMode::Ip);
    let mut app = UiState::new("br0".to_string(), REFRESH, default_sort);
    if let Some(cfg) = &metrics_cfg {
        app.metrics_enabled = cfg.metrics_enabled;
        app.metrics_url = cfg.metrics_url.clone();
        // rate() window: at least two push intervals, never below 2 minutes.
        app.rate_window_secs = (cfg.metrics_push_interval_secs * 2).max(120);
    } else {
        app.metrics_enabled = false;
        app.config_warning =
            Some("config unreadable: trend screen disabled (daemon data still shown)".to_string());
    }

    // crossterm input on a dedicated thread (blocking read degrades gracefully).
    let (event_tx, event_rx) = std::sync::mpsc::channel::<Event>();
    std::thread::spawn(move || {
        while let Ok(ev) = event::read() {
            if event_tx.send(ev).is_err() {
                break;
            }
        }
    });

    let (trend_tx, mut trend_rx) =
        tokio::sync::mpsc::unbounded_channel::<(u64, Result<tui::TrendData, String>)>();
    app.trend_tx = Some(trend_tx);
    app.trend_rt = Some(rt.handle().clone());

    let mut client = match Client::connect() {
        Ok(c) => Some(c),
        Err(e) => {
            app.error = Some(format!("{e:#}"));
            None
        }
    };
    poll(&mut client, &mut app);

    let mut next_poll = std::time::Instant::now() + REFRESH;
    let result = loop {
        terminal.draw(|f| tui::draw(f, &mut app))?;

        let wait = next_poll
            .saturating_duration_since(std::time::Instant::now())
            .min(Duration::from_millis(100));
        let action = match event_rx.recv_timeout(wait.max(Duration::from_millis(1))) {
            Ok(Event::Key(key)) => handle_key(&mut app, key),
            Ok(_) => UiAction::Nothing,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => UiAction::Nothing,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => UiAction::Quit,
        };
        match action {
            UiAction::Quit => break Ok(()),
            UiAction::Refresh => next_poll = std::time::Instant::now(),
            UiAction::Nothing => {}
        }
        // Collect finished trend fetches; results from superseded fetches are dropped.
        while let Ok((seq, res)) = trend_rx.try_recv() {
            if seq == app.trend_seq {
                if let Some(t) = app.trend.as_mut() {
                    match res {
                        Ok(d) => {
                            t.data = Some(d);
                            t.error = None;
                        }
                        Err(e) => {
                            t.data = None;
                            t.error = Some(e);
                        }
                    }
                }
            }
        }
        if std::time::Instant::now() >= next_poll {
            poll(&mut client, &mut app);
            next_poll = std::time::Instant::now() + REFRESH;
        }
    };

    result
}

/// Restores the terminal (raw mode, alternate screen) when dropped.
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        ratatui::restore();
    }
}

/// Fetch overview (and detail, when on the detail screen) from the daemon.
fn poll(client: &mut Option<Client>, app: &mut UiState) {
    // Trends come straight from VictoriaMetrics, not from the daemon: keep them fresh
    // even while the daemon is unreachable (the early returns below).
    if matches!(app.screen, Screen::Trend) {
        let stale = app
            .trend
            .as_ref()
            .and_then(|t| t.fetched_at)
            .map(|t| t.elapsed() > Duration::from_secs(30))
            .unwrap_or(true);
        if stale {
            fetch_trend(app);
        }
    }

    if client.is_none() {
        *client = Client::connect().ok();
        if client.is_some() {
            app.error = None;
        }
    }
    let Some(c) = client.as_mut() else {
        app.error = Some("daemon not reachable".to_string());
        app.status = None;
        app.detail = None;
        return;
    };

    match c.request(&Request::Overview) {
        Ok(Response::Status(s)) => {
            app.bridge = s.bridge.clone();
            // Protocol drift: never hard-fail on a version mismatch, just say so.
            app.protocol_note = match s.protocol_version {
                0 => Some("daemon predates protocol versioning (legacy)".to_string()),
                v if v > ipc::PROTOCOL_VERSION => Some(format!(
                    "daemon protocol v{v} is newer than this UI (v{}) — upgrade the UI",
                    ipc::PROTOCOL_VERSION
                )),
                _ => None,
            };
            app.status = Some(*s);
            app.error = None;
        }
        Ok(_) => {
            // A reply of the wrong type means the stream is out of step (e.g. a late
            // reply to a request that timed out): reconnect instead of reading every
            // later reply one request behind.
            app.error = Some("unexpected reply to Overview; reconnecting".to_string());
            *client = None;
            return;
        }
        Err(e) => {
            app.error = Some(format!("{e:#}"));
            *client = None;
            return;
        }
    }

    if matches!(app.screen, Screen::Detail) {
        let idx = app.detail_index.or_else(|| app.overview.selected());
        let reply = match (client.as_mut(), idx) {
            (Some(c), Some(idx)) => Some((idx, c.request(&Request::RangeDetail { index: idx }))),
            _ => None,
        };
        match reply {
            None => {}
            Some((idx, Ok(Response::RangeDetail(d)))) => {
                app.detail = Some(*d);
                app.detail_index = Some(idx);
            }
            // The daemon says why (range gone after a reload, reply over the frame
            // limit, ...): show it instead of an endless "Waiting for daemon data…".
            Some((_, Ok(Response::Error { message }))) => {
                app.detail = None;
                app.error = Some(message);
            }
            // Out of step or broken: reconnect, as for the overview request.
            Some((_, Ok(_))) => {
                app.detail = None;
                app.error = Some("unexpected reply to RangeDetail; reconnecting".to_string());
                *client = None;
            }
            Some((_, Err(e))) => {
                app.detail = None;
                app.error = Some(format!("{e:#}"));
                *client = None;
            }
        }
    }
}

fn move_selection(state: &mut TableState, len: usize, delta: isize) {
    if len == 0 {
        state.select(None);
        return;
    }
    let cur = state.selected().unwrap_or(0) as isize;
    let next = (cur + delta).clamp(0, len as isize - 1) as usize;
    state.select(Some(next));
}

fn handle_key(app: &mut UiState, key: KeyEvent) -> UiAction {
    if key.kind != KeyEventKind::Press {
        return UiAction::Nothing;
    }
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return UiAction::Quit;
    }
    if app.show_help {
        app.show_help = false;
        return UiAction::Nothing;
    }
    match key.code {
        KeyCode::Char('q') => return UiAction::Quit,
        KeyCode::Char('r') => {
            // On the trend screen, "refresh now" includes the VictoriaMetrics query.
            if let Some(trend) = app.trend.as_mut().filter(|_| app.screen == Screen::Trend) {
                trend.fetched_at = None;
            }
            return UiAction::Refresh;
        }
        KeyCode::Char('h') if matches!(app.screen, Screen::Overview) => app.show_help = true,
        KeyCode::Up => match app.screen {
            Screen::Overview => {
                let len = app.status.as_ref().map(|s| s.ranges.len()).unwrap_or(0);
                move_selection(&mut app.overview, len, -1);
            }
            Screen::Detail => {
                let len = app.detail.as_ref().map(|d| d.ips.len()).unwrap_or(0);
                move_selection(&mut app.detail_table, len, -1);
            }
            Screen::Trend => {}
        },
        KeyCode::Down => match app.screen {
            Screen::Overview => {
                let len = app.status.as_ref().map(|s| s.ranges.len()).unwrap_or(0);
                move_selection(&mut app.overview, len, 1);
            }
            Screen::Detail => {
                let len = app.detail.as_ref().map(|d| d.ips.len()).unwrap_or(0);
                move_selection(&mut app.detail_table, len, 1);
            }
            Screen::Trend => {}
        },
        KeyCode::Left
        | KeyCode::Char('1')
        | KeyCode::Char('2')
        | KeyCode::Char('3')
        | KeyCode::Char('4')
            if matches!(app.screen, Screen::Trend) =>
        {
            if let Some(trend) = app.trend.as_mut() {
                let next = match key.code {
                    KeyCode::Char(d) => (d as usize) - ('1' as usize),
                    _ => (trend.win + TREND_WINDOWS.len() - 1) % TREND_WINDOWS.len(),
                };
                if next != trend.win {
                    trend.win = next;
                    trend.clear_for_new_selection();
                    return UiAction::Refresh;
                }
            }
        }
        KeyCode::Right if matches!(app.screen, Screen::Trend) => {
            if let Some(trend) = app.trend.as_mut() {
                trend.win = (trend.win + 1) % TREND_WINDOWS.len();
                trend.clear_for_new_selection();
                return UiAction::Refresh;
            }
        }
        KeyCode::Char('b') if matches!(app.screen, Screen::Trend) => {
            if let Some(trend) = app.trend.as_mut() {
                if trend.kind != TrendKind::Bandwidth {
                    trend.kind = TrendKind::Bandwidth;
                    trend.clear_for_new_selection();
                    return UiAction::Refresh;
                }
            }
        }
        KeyCode::Char('p') if matches!(app.screen, Screen::Trend) => {
            if let Some(trend) = app.trend.as_mut() {
                if trend.kind != TrendKind::Packets {
                    trend.kind = TrendKind::Packets;
                    trend.clear_for_new_selection();
                    return UiAction::Refresh;
                }
            }
        }
        KeyCode::Enter if matches!(app.screen, Screen::Overview) => {
            if let Some(sel) = app.overview.selected() {
                // The aggregate IPv6 pseudo-range has no per-IP detail to open.
                let is_ipv6 = app
                    .status
                    .as_ref()
                    .and_then(|s| s.ranges.get(sel))
                    .is_some_and(|r| r.name == vm_bandwidth_core::ipc::IPV6_RANGE_NAME);
                if is_ipv6 {
                    return UiAction::Nothing;
                }
                app.screen = Screen::Detail;
                app.detail_index = Some(sel);
                app.detail_table.select(Some(0));
                return UiAction::Refresh;
            }
        }
        KeyCode::Enter if matches!(app.screen, Screen::Detail) => {
            // Open the historical trend for the selected IP.
            // Mirror the exact sort the detail table renders with, so the selection
            // index maps to the same IP the user sees highlighted.
            let ip = app.detail.as_ref().and_then(|d| {
                let mut ips = d.ips.clone();
                tui::sort_ips(&mut ips, app.sort);
                app.detail_table
                    .selected()
                    .and_then(|sel| ips.get(sel).map(|i| i.ip))
            });
            if let Some(ip) = ip {
                app.trend = Some(TrendView {
                    target: TrendTarget::Ip(ip),
                    from: Screen::Detail,
                    win: 0,
                    kind: TrendKind::Bandwidth,
                    data: None,
                    fetched_at: None,
                    error: None,
                });
                app.screen = Screen::Trend;
                return UiAction::Refresh;
            }
        }
        KeyCode::Char('t') if matches!(app.screen, Screen::Overview | Screen::Detail) => {
            // Open the aggregated trend for a whole IP range.
            let name = match app.screen {
                Screen::Overview => app.overview.selected().and_then(|sel| {
                    app.status
                        .as_ref()
                        .and_then(|s| s.ranges.get(sel))
                        .map(|r| r.name.clone())
                }),
                // The guard above leaves only Detail here.
                _ => app.detail.as_ref().map(|d| d.name.clone()),
            };
            if let Some(name) = name {
                app.trend = Some(TrendView {
                    target: TrendTarget::Range(name),
                    from: app.screen,
                    win: 0,
                    kind: TrendKind::Bandwidth,
                    data: None,
                    fetched_at: None,
                    error: None,
                });
                app.screen = Screen::Trend;
                return UiAction::Refresh;
            }
        }
        KeyCode::Esc => match app.screen {
            Screen::Detail => {
                app.screen = Screen::Overview;
                app.detail = None;
                app.detail_index = None;
            }
            Screen::Trend => {
                let to = app.trend.as_ref().map(|t| t.from).unwrap_or(Screen::Detail);
                app.trend = None;
                app.screen = to;
                if to == Screen::Overview {
                    app.detail = None;
                    app.detail_index = None;
                }
                return UiAction::Refresh;
            }
            Screen::Overview => {}
        },
        KeyCode::Char('s') if matches!(app.screen, Screen::Detail) => {
            app.sort = app.sort.next();
        }
        _ => {}
    }
    UiAction::Nothing
}

/// Fetch the trend for `app.trend`'s IP/window/kind straight from VictoriaMetrics.
/// Kick off an async fetch of the trend for `app.trend`'s IP/window/kind from
/// VictoriaMetrics. The result arrives on the trend channel; the screen shows
/// "Loading…" while the fetch is in flight.
fn fetch_trend(app: &mut UiState) {
    let Some(trend) = app.trend.as_mut() else {
        return;
    };
    trend.fetched_at = Some(std::time::Instant::now());
    // Keep showing the current chart until the new data arrives (no "Loading…" flash
    // on every periodic refresh); a new window or metric already cleared it.
    trend.error = None;

    if !app.metrics_enabled {
        trend.error = Some(
            "metrics disabled: set [metrics] enabled = true in config.toml and restart".to_string(),
        );
        return;
    }
    let (Some(res_tx), Some(rt)) = (app.trend_tx.clone(), app.trend_rt.clone()) else {
        trend.error = Some("trend fetch runtime unavailable".to_string());
        return;
    };

    let (_, span, step) = TREND_WINDOWS[trend.win];
    let end = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let start = end - span as i64;
    // Two separate queries: rate() drops the metric name, so a single
    // {__name__=~"rx|tx"} selector would produce two series with identical
    // label sets, which VictoriaMetrics rejects as duplicate output timeseries.
    // Range trends wrap the per-series rate in sum() to aggregate all IPs.
    let (rx_metric, tx_metric) = match trend.kind {
        TrendKind::Bandwidth => ("vmbw_rx_bytes_total", "vmbw_tx_bytes_total"),
        TrendKind::Packets => ("vmbw_rx_packets_total", "vmbw_tx_packets_total"),
    };
    let scale = match trend.kind {
        TrendKind::Bandwidth => " * 8",
        TrendKind::Packets => "",
    };
    let rate_window = trend_rate_window(app.rate_window_secs, step);
    let rx_query = trend_query(&trend.target, rx_metric, rate_window, scale);
    let tx_query = trend_query(&trend.target, tx_metric, rate_window, scale);
    let base = app.metrics_url.clone();
    let client = app.trend_client.clone();

    app.trend_seq += 1;
    let seq = app.trend_seq;
    rt.spawn(async move {
        let res = fetch_pair(&client, &base, rx_query, tx_query, start, end, step).await;
        let _ = res_tx.send((seq, res));
    });
}

/// The `rate()` window for a trend sampled every `step_secs`: at least the base
/// window (two push intervals, never below two minutes) and at least one step, so
/// each point summarizes the whole step before it. A window shorter than the step
/// (2 minutes against the 15-minute to 3-hour steps of the long views) turns the
/// chart into spot samples that miss everything in between.
fn trend_rate_window(base_secs: u64, step_secs: u64) -> u64 {
    base_secs.max(step_secs)
}

/// Build one PromQL expression for a trend series.
///
/// The shape is load-bearing: `rate()` drops the metric name, so mixing both
/// directions in one `{__name__=~...}` selector yields duplicate label sets that
/// VictoriaMetrics rejects; and the rate is always wrapped in `sum()` so one series
/// comes back — a range has a series per IP, and even one IP's series splits by its
/// `range` label when a reload renames its range.
fn trend_query(target: &TrendTarget, metric: &str, rate_window: u64, scale: &str) -> String {
    match target {
        TrendTarget::Ip(ipv4) => format!(
            "sum(rate({metric}{{ip=\"{}\"}}[{rate_window}s])){scale}",
            std::net::Ipv4Addr::from(*ipv4)
        ),
        TrendTarget::Range(name) => format!(
            "sum(rate({metric}{{range=\"{}\"}}[{rate_window}s])){scale}",
            crate::metrics::escape_label(name)
        ),
    }
}

/// Fetch the RX and TX series for one trend view.
async fn fetch_pair(
    client: &reqwest::Client,
    base: &str,
    rx_query: String,
    tx_query: String,
    start: i64,
    end: i64,
    step: u64,
) -> Result<tui::TrendData, String> {
    // Both directions in parallel: they are independent queries against the same
    // connection pool, so the round-trip cost is paid once, not twice.
    let (rx, tx) = tokio::try_join!(
        fetch_series(client, base, rx_query, start, end, step),
        fetch_series(client, base, tx_query, start, end, step),
    )?;
    Ok(tui::TrendData {
        rx,
        tx,
        axis: tui::TrendAxis { start, end, step },
    })
}

/// One VictoriaMetrics `query_range` request, with a capped response body.
async fn fetch_series(
    client: &reqwest::Client,
    base: &str,
    query: String,
    start: i64,
    end: i64,
    step: u64,
) -> Result<Series, String> {
    let resp = client
        .get(format!("{base}/api/v1/query_range"))
        .query(&[
            ("query", query),
            ("start", start.to_string()),
            ("end", end.to_string()),
            ("step", step.to_string()),
        ])
        .send()
        .await
        .map_err(|e| format!("metrics GET failed: {}", e.without_url()))?;
    let status = resp.status();
    let body = crate::metrics::body_capped(resp)
        .await
        .map_err(|e| format!("{e:#}"))?;
    if !status.is_success() {
        return Err(format!(
            "HTTP {}: {}",
            status.as_u16(),
            body.chars().take(200).collect::<String>()
        ));
    }
    parse_series(&body).map_err(|e| format!("{e:#}"))
}

/// Extract the (single) series from a VictoriaMetrics `query_range` reply.
fn parse_series(body: &str) -> Result<Series> {
    let v: serde_json::Value = serde_json::from_str(body).context("bad JSON from metrics")?;
    if v["status"] != "success" {
        anyhow::bail!("metrics query failed: {}", v["error"]);
    }
    let mut out = Vec::new();
    for series in v["data"]["result"].as_array().into_iter().flatten() {
        for point in series["values"].as_array().into_iter().flatten() {
            let ts = point[0].as_f64().unwrap_or(0.0) as i64;
            let val: f64 = point[1]
                .as_str()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0.0);
            if val.is_finite() {
                out.push((ts, val));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(addr: [u8; 4]) -> TrendTarget {
        TrendTarget::Ip(u32::from_be_bytes(addr))
    }

    /// A UI client wired to a scripted daemon end over a socketpair.
    fn scripted_client() -> (Option<Client>, UnixStream) {
        let (ui_end, daemon_end) = UnixStream::pair().expect("socketpair");
        ui_end
            .set_read_timeout(Some(IO_TIMEOUT))
            .expect("read timeout");
        (Some(Client { stream: ui_end }), daemon_end)
    }

    fn send(daemon_end: &mut UnixStream, resp: &Response) {
        let frame = ipc::encode(resp).expect("encode");
        daemon_end.write_all(&frame).expect("write reply");
    }

    fn app() -> UiState {
        UiState::new(
            "br0".to_string(),
            REFRESH,
            vm_bandwidth_core::config::SortMode::Ip,
        )
    }

    fn trend_screen_app() -> UiState {
        let mut app = app();
        app.screen = Screen::Trend;
        app.trend = Some(TrendView {
            target: ip([10, 0, 0, 1]),
            from: Screen::Detail,
            win: 0,
            kind: TrendKind::Bandwidth,
            data: Some(tui::TrendData::default()),
            fetched_at: Some(std::time::Instant::now()),
            error: None,
        });
        app
    }

    #[test]
    fn trend_refresh_does_not_wait_for_the_daemon() {
        let mut app = trend_screen_app();
        app.trend.as_mut().unwrap().fetched_at = None; // due for a refresh
                                                       // No daemon socket in the test environment: poll() reports it unreachable,
                                                       // yet the trend (served by VictoriaMetrics) must still have been refreshed.
        let mut client = None;
        poll(&mut client, &mut app);
        assert!(app.trend.as_ref().unwrap().fetched_at.is_some());
    }

    #[test]
    fn switching_the_metric_drops_the_previous_selections_data() {
        let mut app = trend_screen_app();
        let key = KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE);
        assert!(matches!(handle_key(&mut app, key), UiAction::Refresh));
        let trend = app.trend.as_ref().unwrap();
        assert!(trend.kind == TrendKind::Packets);
        assert!(
            trend.data.is_none(),
            "bandwidth data must not be shown as pps"
        );
        assert!(trend.fetched_at.is_none());
    }

    #[test]
    fn refresh_key_refetches_the_trend() {
        let mut app = trend_screen_app();
        let key = KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE);
        assert!(matches!(handle_key(&mut app, key), UiAction::Refresh));
        let trend = app.trend.as_ref().unwrap();
        assert!(trend.fetched_at.is_none());
        assert!(
            trend.data.is_some(),
            "the chart stays up until new data arrives"
        );
    }

    #[test]
    fn out_of_step_reply_drops_the_connection() {
        // A late reply to an earlier (timed-out) RangeDetail request is still queued
        // when the next Overview request goes out.
        let (mut client, mut daemon_end) = scripted_client();
        send(&mut daemon_end, &Response::RangeDetail(Box::default()));
        let mut app = app();
        poll(&mut client, &mut app);
        assert!(
            client.is_none(),
            "an out-of-step stream must be reconnected"
        );
        assert!(
            app.error
                .as_deref()
                .is_some_and(|e| e.contains("unexpected reply")),
            "{:?}",
            app.error
        );
    }

    #[test]
    fn daemon_error_reply_to_detail_is_shown() {
        let (mut client, mut daemon_end) = scripted_client();
        send(&mut daemon_end, &Response::Status(Box::default()));
        send(
            &mut daemon_end,
            &Response::Error {
                message: "range index 3 out of bounds".to_string(),
            },
        );
        let mut app = app();
        app.screen = Screen::Detail;
        app.detail_index = Some(3);
        poll(&mut client, &mut app);
        assert!(
            client.is_some(),
            "a well-formed error reply keeps the stream"
        );
        assert!(app.detail.is_none());
        assert_eq!(app.error.as_deref(), Some("range index 3 out of bounds"));
    }

    #[test]
    fn ip_bandwidth_query_is_a_per_ip_rate_scaled_to_bits() {
        // sum(): an IP whose range was renamed by a reload has one series per
        // `range` label value; unsummed they came back as two interleaved series.
        let q = trend_query(&ip([10, 30, 10, 121]), "vmbw_rx_bytes_total", 120, " * 8");
        assert_eq!(
            q,
            "sum(rate(vmbw_rx_bytes_total{ip=\"10.30.10.121\"}[120s])) * 8"
        );
    }

    #[test]
    fn ip_packets_query_carries_no_scale() {
        let q = trend_query(&ip([10, 30, 10, 121]), "vmbw_rx_packets_total", 120, "");
        assert_eq!(
            q,
            "sum(rate(vmbw_rx_packets_total{ip=\"10.30.10.121\"}[120s]))"
        );
    }

    #[test]
    fn rate_window_covers_at_least_one_step() {
        for (label, _, step) in TREND_WINDOWS {
            let w = trend_rate_window(120, step);
            assert!(w >= step, "{label}: window {w}s shorter than step {step}s");
            assert!(w >= 120, "{label}: window {w}s below the base window");
        }
        assert_eq!(trend_rate_window(120, 60), 120);
        assert_eq!(trend_rate_window(120, 10_800), 10_800);
    }

    #[test]
    fn range_query_aggregates_all_ips_with_sum() {
        let q = trend_query(
            &TrendTarget::Range("aois_a Seednet-0".into()),
            "vmbw_tx_bytes_total",
            120,
            " * 8",
        );
        assert_eq!(
            q,
            "sum(rate(vmbw_tx_bytes_total{range=\"aois_a Seednet-0\"}[120s])) * 8"
        );
    }

    #[test]
    fn range_label_is_prometheus_escaped() {
        let q = trend_query(
            &TrendTarget::Range("a\"b\\c".into()),
            "vmbw_rx_bytes_total",
            120,
            "",
        );
        assert_eq!(
            q,
            "sum(rate(vmbw_rx_bytes_total{range=\"a\\\"b\\\\c\"}[120s]))"
        );
    }
}
