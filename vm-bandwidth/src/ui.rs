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
use crate::tui::{self, Screen, Series, TrendKind, TrendView, UiState, TREND_WINDOWS};

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
        let len = u32::from_be_bytes(lenbuf) as usize;
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
    let metrics_cfg = match config::load(&config_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("warning: cannot load {config_path:?}: {e}; trend screen disabled");
            return Ok(());
        }
    };
    if metrics_cfg.metrics_enabled {
        println!(
            "metrics: querying {} (refresh {}s)",
            metrics_cfg.metrics_url, metrics_cfg.metrics_push_interval_secs
        );
    }

    let mut terminal = ratatui::init();
    let mut app = UiState::new("br0".to_string(), REFRESH, metrics_cfg.default_sort);
    app.metrics_enabled = metrics_cfg.metrics_enabled;
    app.metrics_url = metrics_cfg.metrics_url.clone();
    // rate() window: at least two push intervals, never below 2 minutes.
    app.rate_window_secs = (metrics_cfg.metrics_push_interval_secs * 2).max(120);

    // crossterm input on a dedicated thread (blocking read degrades gracefully).
    let (event_tx, event_rx) = std::sync::mpsc::channel::<Event>();
    std::thread::spawn(move || {
        while let Ok(ev) = event::read() {
            if event_tx.send(ev).is_err() {
                break;
            }
        }
    });

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
        if std::time::Instant::now() >= next_poll {
            poll(&mut client, &mut app);
            next_poll = std::time::Instant::now() + REFRESH;
        }
    };

    ratatui::restore();
    result
}

/// Fetch overview (and detail, when on the detail screen) from the daemon.
fn poll(client: &mut Option<Client>, app: &mut UiState) {
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
            app.status = Some(*s);
            app.error = None;
        }
        Ok(_) => app.error = Some("unexpected reply to Overview".to_string()),
        Err(e) => {
            app.error = Some(format!("{e:#}"));
            *client = None;
            return;
        }
    }

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

    if matches!(app.screen, Screen::Detail) {
        let idx = app.detail_index.or_else(|| app.overview.selected());
        if let (Some(c), Some(idx)) = (client.as_mut(), idx) {
            match c.request(&Request::RangeDetail { index: idx }) {
                Ok(Response::RangeDetail(d)) => {
                    app.detail = Some(*d);
                    app.detail_index = Some(idx);
                }
                Ok(Response::Error { .. }) => app.detail = None,
                Ok(_) => app.detail = None,
                Err(_) => app.detail = None,
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
        KeyCode::Char('r') => return UiAction::Refresh,
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
                    trend.fetched_at = None;
                    return UiAction::Refresh;
                }
            }
        }
        KeyCode::Right if matches!(app.screen, Screen::Trend) => {
            if let Some(trend) = app.trend.as_mut() {
                trend.win = (trend.win + 1) % TREND_WINDOWS.len();
                trend.fetched_at = None;
                return UiAction::Refresh;
            }
        }
        KeyCode::Char('b') if matches!(app.screen, Screen::Trend) => {
            if let Some(trend) = app.trend.as_mut() {
                if trend.kind != TrendKind::Bandwidth {
                    trend.kind = TrendKind::Bandwidth;
                    trend.fetched_at = None;
                    return UiAction::Refresh;
                }
            }
        }
        KeyCode::Char('p') if matches!(app.screen, Screen::Trend) => {
            if let Some(trend) = app.trend.as_mut() {
                if trend.kind != TrendKind::Packets {
                    trend.kind = TrendKind::Packets;
                    trend.fetched_at = None;
                    return UiAction::Refresh;
                }
            }
        }
        KeyCode::Enter if matches!(app.screen, Screen::Overview) => {
            if let Some(sel) = app.overview.selected() {
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
                    ip,
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
                app.screen = Screen::Detail;
                app.trend = None;
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
fn fetch_trend(app: &mut UiState) {
    let Some(trend) = app.trend.as_mut() else {
        return;
    };
    trend.fetched_at = Some(std::time::Instant::now());
    trend.error = None;

    if !app.metrics_enabled {
        trend.error = Some(
            "metrics disabled: set [metrics] enabled = true in config.toml and restart".to_string(),
        );
        trend.data = None;
        return;
    }

    let (_, span, step) = TREND_WINDOWS[trend.win];
    let end = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let start = end - span as i64;
    let ip = std::net::Ipv4Addr::from(trend.ip);
    // Two separate queries: rate() drops the metric name, so a single
    // {__name__=~"rx|tx"} selector would produce two series with identical
    // label sets, which VictoriaMetrics rejects as duplicate output timeseries.
    let (rx_metric, tx_metric) = match trend.kind {
        TrendKind::Bandwidth => ("vmbw_rx_bytes_total", "vmbw_tx_bytes_total"),
        TrendKind::Packets => ("vmbw_rx_packets_total", "vmbw_tx_packets_total"),
    };
    let scale = match trend.kind {
        TrendKind::Bandwidth => " * 8",
        TrendKind::Packets => "",
    };
    let query_url = |metric: &str| {
        let query = format!(
            "rate({metric}{{ip=\"{ip}\"}}[{}s]){scale}",
            app.rate_window_secs
        );
        format!(
            "{}/api/v1/query_range?query={}&start={start}&end={end}&step={step}",
            app.metrics_url,
            crate::http::percent_encode(&query)
        )
    };

    let rx = match crate::http::get(&query_url(rx_metric)).and_then(|b| parse_series(&b)) {
        Ok(s) => s,
        Err(e) => {
            trend.error = Some(format!("{e:#}"));
            trend.data = None;
            return;
        }
    };
    match crate::http::get(&query_url(tx_metric)).and_then(|b| parse_series(&b)) {
        Ok(tx) => trend.data = Some(tui::TrendData { rx, tx }),
        Err(e) => {
            trend.error = Some(format!("{e:#}"));
            trend.data = None;
        }
    }
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
