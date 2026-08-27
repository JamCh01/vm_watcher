//! Ratatui presentation for the `--ui` client. Pure rendering: all data arrives as IPC
//! [`Status`] / [`RangeDetail`] values; this module never touches eBPF or the network.
//!
//! Screens: Overview (per-range bandwidth, limited count, reload status) and Detail
//! (per-IP window averages, effective policy, NORMAL/LIMITED and remaining time, §31).

use std::time::Duration;

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Clear, Paragraph, Row, Table, TableState};
use ratatui::Frame;

use vm_bandwidth_core::bandwidth::{format_bps, format_bytes};
use vm_bandwidth_core::config::SortMode;
use vm_bandwidth_core::ipc::{IpDetail, RangeDetail, RangeSummary, Status};

#[derive(Clone, Copy, PartialEq)]
pub enum Screen {
    Overview,
    Detail,
    /// Historical trend for one IP or a whole range, served by VictoriaMetrics.
    Trend,
}

/// Time windows offered by the trend screen: (label, span seconds, query step seconds).
pub const TREND_WINDOWS: [(&str, u64, u64); 4] = [
    ("1h", 3600, 60),
    ("24h", 86400, 900),
    ("7d", 7 * 86400, 3600),
    ("30d", 30 * 86400, 10800),
];

#[derive(Clone, Copy, PartialEq)]
pub enum TrendKind {
    Bandwidth,
    Packets,
}

/// One fetched trend: per-direction (timestamp seconds, value) points.
pub type Series = Vec<(i64, f64)>;

#[derive(Default)]
pub struct TrendData {
    pub rx: Series,
    pub tx: Series,
}

/// What the trend screen shows: one IP or a whole IP range aggregated.
pub enum TrendTarget {
    Ip(u32),
    Range(String),
}

pub struct TrendView {
    pub target: TrendTarget,
    /// Screen that Esc returns to.
    pub from: Screen,
    pub win: usize,
    pub kind: TrendKind,
    pub data: Option<TrendData>,
    pub fetched_at: Option<std::time::Instant>,
    pub error: Option<String>,
}

/// Everything the UI needs to render one frame.
pub struct UiState {
    pub bridge: String,
    pub refresh_interval: Duration,

    pub status: Option<Status>,
    pub detail: Option<RangeDetail>,
    /// Range index the current detail view was requested for.
    pub detail_index: Option<usize>,
    /// Last IPC error (daemon unreachable, bad reply, ...).
    pub error: Option<String>,

    pub screen: Screen,
    pub overview: TableState,
    pub detail_table: TableState,
    pub sort: SortMode,
    pub show_help: bool,
    pub trend: Option<TrendView>,
    /// Sender for async trend-fetch results: (sequence, result).
    pub trend_tx: Option<tokio::sync::mpsc::UnboundedSender<(u64, Result<TrendData, String>)>>,
    /// Handle of the small runtime driving the async trend fetches.
    pub trend_rt: Option<tokio::runtime::Handle>,
    /// Sequence of the latest in-flight trend fetch; stale results are dropped.
    pub trend_seq: u64,
    /// Shared HTTP client for trend queries (connection pool is reused across fetches).
    pub trend_client: reqwest::Client,
    /// `[metrics]` section from config.toml (trend queries go straight to VM).
    pub metrics_enabled: bool,
    pub metrics_url: String,
    pub rate_window_secs: u64,
}

impl UiState {
    pub fn new(bridge: String, refresh_interval: Duration, sort: SortMode) -> Self {
        Self {
            bridge,
            refresh_interval,
            status: None,
            detail: None,
            detail_index: None,
            error: None,
            screen: Screen::Overview,
            overview: TableState::default(),
            detail_table: TableState::default(),
            sort,
            show_help: false,
            trend: None,
            trend_tx: None,
            trend_rt: None,
            trend_seq: 0,
            trend_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .expect("failed to build the trend HTTP client"),
            metrics_enabled: false,
            metrics_url: String::new(),
            rate_window_secs: 120,
        }
    }
}

pub fn draw(f: &mut Frame, app: &mut UiState) {
    let chunks = Layout::vertical([
        Constraint::Length(5),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .split(f.area());

    draw_header(f, app, chunks[0]);
    match app.screen {
        Screen::Overview => draw_overview(f, app, chunks[1]),
        Screen::Detail => draw_detail(f, app, chunks[1]),
        Screen::Trend => draw_trend(f, app, chunks[1]),
    }
    draw_footer(f, app, chunks[2]);

    if app.show_help {
        draw_help(f);
    }
}

fn draw_header(f: &mut Frame, app: &UiState, area: Rect) {
    let status = app.status.as_ref();
    let tap_count = status.map(|s| s.tap_count).unwrap_or(0);
    let generation = status.map(|s| s.generation).unwrap_or(0);
    let reload_line = match status {
        Some(s) if !s.last_reload_at.is_empty() => {
            let state = if s.last_reload_ok { "OK" } else { "FAILED" };
            let mut line = format!(
                "Config generation: {}    Last reload: {}    Status: {}",
                generation, s.last_reload_at, state
            );
            if !s.last_reload_ok && !s.last_reload_error.is_empty() {
                line.push_str(&format!("    Error: {}", s.last_reload_error));
            }
            line
        }
        _ => format!("Config generation: {generation}"),
    };

    let mut lines = vec![
        Line::from(Span::styled(
            "VM Bandwidth Monitor",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(format!(
            "Bridge: {}    TAP Interfaces: {}    Refresh: {}",
            app.bridge,
            tap_count,
            format_duration(app.refresh_interval)
        )),
        Line::from(reload_line),
    ];
    if let Some(err) = &app.error {
        lines.push(Line::from(Span::styled(
            format!("daemon: {err}"),
            Style::default()
                .fg(ratatui::style::Color::Red)
                .add_modifier(Modifier::BOLD),
        )));
    }
    f.render_widget(Paragraph::new(lines).block(Block::bordered()), area);
}

fn draw_footer(f: &mut Frame, app: &UiState, area: Rect) {
    let keys = match app.screen {
        Screen::Overview => {
            "↑/↓ select   Enter detail   t range trend   r refresh   h help   q quit"
        }
        Screen::Detail => {
            "↑/↓ select   Enter trend   t range trend   s sort   r refresh   Esc back   q quit"
        }
        Screen::Trend => "←/→ window   b bandwidth   p packets   r refresh   Esc back   q quit",
    };
    let sort_hint = match app.screen {
        Screen::Detail => format!("   [sort: {}]", app.sort.label()),
        Screen::Overview | Screen::Trend => String::new(),
    };
    f.render_widget(
        Paragraph::new(format!("{keys}{sort_hint}"))
            .style(Style::default().add_modifier(Modifier::DIM)),
        area,
    );
}

fn draw_overview(f: &mut Frame, app: &mut UiState, area: Rect) {
    let Some(status) = &app.status else {
        f.render_widget(waiting_widget("IP Range Overview"), area);
        return;
    };

    // Wide terminals get every column; narrower ones drop totals and IP counts
    // progressively instead of overlapping cells (same tiers as the detail page).
    let cols = overview_cols(area.width);

    let mut rows: Vec<Row> = status
        .ranges
        .iter()
        .map(|r| overview_row(r, cols))
        .collect();

    // Grand-total row across all ranges (cumulative totals are since daemon start).
    let (rx_bps, tx_bps) = status
        .ranges
        .iter()
        .fold((0.0f64, 0.0f64), |(r, t), x| (r + x.rx_bps, t + x.tx_bps));
    let (rx_bytes, tx_bytes) = status.ranges.iter().fold((0u64, 0u64), |(r, t), x| {
        (r.saturating_add(x.rx_bytes), t.saturating_add(x.tx_bytes))
    });
    let limited_total: usize = status.ranges.iter().map(|r| r.limited).sum();
    let ip_total: usize = status.ranges.iter().map(|r| r.ip_count).sum();
    rows.push(
        total_row(
            rx_bps,
            tx_bps,
            rx_bytes,
            tx_bytes,
            ip_total,
            limited_total,
            cols,
        )
        .style(Style::default().add_modifier(Modifier::BOLD)),
    );

    let (widths, headers): (&[Constraint], &[&str]) = match cols {
        OverviewCols::Wide => (
            &[
                Constraint::Min(14),
                Constraint::Min(22),
                Constraint::Length(12),
                Constraint::Length(12),
                Constraint::Length(11),
                Constraint::Length(11),
                Constraint::Length(6),
                Constraint::Length(8),
            ],
            &[
                "Name", "IP Range", "RX", "TX", "RX Total", "TX Total", "IPs", "Limited",
            ],
        ),
        OverviewCols::Mid => (
            &[
                Constraint::Min(14),
                Constraint::Min(22),
                Constraint::Length(12),
                Constraint::Length(12),
                Constraint::Length(8),
            ],
            &["Name", "IP Range", "RX", "TX", "Limited"],
        ),
        OverviewCols::Min => (
            &[
                Constraint::Min(12),
                Constraint::Length(12),
                Constraint::Length(12),
                Constraint::Length(8),
            ],
            &["Name / Range", "RX", "TX", "Limited"],
        ),
    };
    let table = Table::new(rows, widths)
        .header(header_row(headers.iter().copied()))
        .block(Block::bordered().title("IP Range Overview"))
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_spacing(ratatui::widgets::HighlightSpacing::Always);

    clamp_selection(&mut app.overview, status.ranges.len());
    f.render_stateful_widget(table, area, &mut app.overview);
}

/// Column density of the overview table, chosen from the available width.
#[derive(Clone, Copy, PartialEq, Debug)]
enum OverviewCols {
    Wide,
    Mid,
    Min,
}

/// Width thresholds for the overview tiers (see `detail_cols` for the invariant).
const OVERVIEW_WIDE_MIN: u16 = 105;
const OVERVIEW_MID_MIN: u16 = 66;

fn overview_cols(width: u16) -> OverviewCols {
    match width {
        w if w >= OVERVIEW_WIDE_MIN => OverviewCols::Wide,
        w if w >= OVERVIEW_MID_MIN => OverviewCols::Mid,
        _ => OverviewCols::Min,
    }
}

fn overview_row(r: &RangeSummary, cols: OverviewCols) -> Row<'static> {
    match cols {
        OverviewCols::Wide => Row::new(vec![
            Cell::from(r.name.clone()),
            Cell::from(r.range.clone()),
            Cell::from(format_bps(r.rx_bps)),
            Cell::from(format_bps(r.tx_bps)),
            Cell::from(format_bytes(r.rx_bytes)),
            Cell::from(format_bytes(r.tx_bytes)),
            Cell::from(r.ip_count.to_string()),
            style_limited(r.limited),
        ]),
        OverviewCols::Mid => Row::new(vec![
            Cell::from(r.name.clone()),
            Cell::from(r.range.clone()),
            Cell::from(format_bps(r.rx_bps)),
            Cell::from(format_bps(r.tx_bps)),
            style_limited(r.limited),
        ]),
        OverviewCols::Min => Row::new(vec![
            // Two-line cell: narrow terminals drop the Range column, so keep the
            // identity visible by stacking name over range in one cell.
            Cell::from(vec![
                Line::from(r.name.clone()),
                Line::from(r.range.clone()),
            ]),
            Cell::from(format_bps(r.rx_bps)),
            Cell::from(format_bps(r.tx_bps)),
            style_limited(r.limited),
        ])
        .height(2),
    }
}

fn total_row(
    rx_bps: f64,
    tx_bps: f64,
    rx_bytes: u64,
    tx_bytes: u64,
    ip_total: usize,
    limited: usize,
    cols: OverviewCols,
) -> Row<'static> {
    match cols {
        OverviewCols::Wide => Row::new(vec![
            Cell::from("Σ All ranges"),
            Cell::from(""),
            Cell::from(format_bps(rx_bps)),
            Cell::from(format_bps(tx_bps)),
            Cell::from(format_bytes(rx_bytes)),
            Cell::from(format_bytes(tx_bytes)),
            Cell::from(ip_total.to_string()),
            Cell::from(limited.to_string()),
        ]),
        OverviewCols::Mid => Row::new(vec![
            Cell::from(format!("Σ All ({ip_total} IPs)")),
            Cell::from(""),
            Cell::from(format_bps(rx_bps)),
            Cell::from(format_bps(tx_bps)),
            Cell::from(limited.to_string()),
        ]),
        OverviewCols::Min => Row::new(vec![
            Cell::from(vec![
                Line::from("Σ All ranges"),
                Line::from(format!("{ip_total} IPs")),
            ]),
            Cell::from(format_bps(rx_bps)),
            Cell::from(format_bps(tx_bps)),
            Cell::from(limited.to_string()),
        ])
        .height(2),
    }
}

fn style_limited(n: usize) -> Cell<'static> {
    let cell = Cell::from(n.to_string());
    if n > 0 {
        cell.style(
            Style::default()
                .fg(ratatui::style::Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        cell
    }
}

fn draw_detail(f: &mut Frame, app: &mut UiState, area: Rect) {
    let Some(detail) = &app.detail else {
        f.render_widget(waiting_widget("IP Range Detail"), area);
        return;
    };

    let chunks = Layout::vertical([Constraint::Length(4), Constraint::Min(1)]).split(area);

    let header = vec![
        Line::from(vec![
            Span::styled("Range: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(detail.name.clone()),
            Span::raw(format!("    {}", detail.range)),
        ]),
        Line::from(format!(
            "Range RX: {}    Range TX: {}    RX Total: {}    TX Total: {}",
            format_bps(detail.rx_bps),
            format_bps(detail.tx_bps),
            format_bytes(detail.rx_bytes),
            format_bytes(detail.tx_bytes),
        )),
    ];
    f.render_widget(Paragraph::new(header).block(Block::bordered()), chunks[0]);

    // Sort the IPs per the current sort mode.
    let mut ips = detail.ips.clone();
    sort_ips(&mut ips, app.sort);

    // Wide terminals get every column; narrower ones drop to progressively compact
    // layouts instead of overlapping cells. Widths sum + gaps + border must fit.
    let cols = detail_cols(chunks[1].width);
    let (widths, headers): (&[Constraint], &[&str]) = match cols {
        DetailCols::Wide => (
            &[
                Constraint::Length(15),
                Constraint::Length(12),
                Constraint::Length(12),
                Constraint::Length(10),
                Constraint::Length(10),
                Constraint::Length(12),
                Constraint::Length(12),
                Constraint::Length(9),
                Constraint::Length(9),
                Constraint::Length(8),
                Constraint::Length(8),
                Constraint::Length(8),
            ],
            &[
                "IPv4", "RX", "TX", "RX Total", "TX Total", "RX win", "TX win", "RX limit",
                "TX limit", "RX st", "TX st", "Remain",
            ],
        ),
        DetailCols::Mid => (
            &[
                Constraint::Length(15),
                Constraint::Length(12),
                Constraint::Length(12),
                Constraint::Length(10),
                Constraint::Length(10),
                Constraint::Length(9),
                Constraint::Length(9),
                Constraint::Length(6),
                Constraint::Length(8),
            ],
            &[
                "IPv4", "RX", "TX", "RX Total", "TX Total", "RX limit", "TX limit", "St", "Remain",
            ],
        ),
        DetailCols::Min => (
            &[
                Constraint::Length(15),
                Constraint::Length(12),
                Constraint::Length(12),
                Constraint::Length(6),
            ],
            &["IPv4", "RX", "TX", "St"],
        ),
    };

    // Column layout adapts to the available width instead of smearing cells together.
    let rows: Vec<Row> = ips.iter().map(|ip| ip_row(ip, cols)).collect();
    let table = Table::new(rows, widths)
        .header(header_row(headers.iter().copied()))
        .block(Block::bordered().title("IP Range Detail"))
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_spacing(ratatui::widgets::HighlightSpacing::Always);

    clamp_selection(&mut app.detail_table, ips.len());
    f.render_stateful_widget(table, chunks[1], &mut app.detail_table);
}

/// Column density of the detail table, chosen from the available width.
#[derive(Clone, Copy, PartialEq, Debug)]
enum DetailCols {
    Wide,
    Mid,
    Min,
}

/// Width thresholds for the detail tiers: every constraint set plus gaps and the
/// table border must fit the triggering width.
const DETAIL_WIDE_MIN: u16 = 138;
const DETAIL_MID_MIN: u16 = 101;

fn detail_cols(width: u16) -> DetailCols {
    match width {
        w if w >= DETAIL_WIDE_MIN => DetailCols::Wide,
        w if w >= DETAIL_MID_MIN => DetailCols::Mid,
        _ => DetailCols::Min,
    }
}

fn ip_row(ip: &IpDetail, cols: DetailCols) -> Row<'static> {
    let limited_style = Style::default()
        .fg(ratatui::style::Color::Yellow)
        .add_modifier(Modifier::BOLD);
    let state_cell = |limited: bool| -> Cell<'static> {
        let label = if limited { "LIMITED" } else { "NORMAL" };
        let cell = Cell::from(label.to_string());
        if limited {
            cell.style(limited_style)
        } else {
            cell
        }
    };
    let fmt_pol = |v: u64| -> String {
        if v == 0 {
            "-".to_string()
        } else {
            format_bps(v as f64)
        }
    };
    let fmt_remain = |rx: u64, tx: u64| -> String {
        match (rx, tx) {
            (0, 0) => "-".to_string(),
            (a, 0) => format!("rx {}s", a),
            (0, b) => format!("tx {}s", b),
            (a, b) => format!("{}s/{}s", a, b),
        }
    };
    let rx_limited = ip.rx_state == "LIMITED";
    let tx_limited = ip.tx_state == "LIMITED";

    match cols {
        DetailCols::Wide => Row::new(vec![
            Cell::from(std::net::Ipv4Addr::from(ip.ip).to_string()),
            Cell::from(format_bps(ip.rx_bps)),
            Cell::from(format_bps(ip.tx_bps)),
            Cell::from(format_bytes(ip.rx_bytes)),
            Cell::from(format_bytes(ip.tx_bytes)),
            Cell::from(format_bps(ip.rx_window_bps)),
            Cell::from(format_bps(ip.tx_window_bps)),
            Cell::from(fmt_pol(ip.rx_limit)),
            Cell::from(fmt_pol(ip.tx_limit)),
            state_cell(rx_limited),
            state_cell(tx_limited),
            Cell::from(fmt_remain(ip.rx_remaining, ip.tx_remaining)),
        ]),
        DetailCols::Mid => {
            // One combined state column (- / RX / TX / BOTH) instead of two.
            let st = match (rx_limited, tx_limited) {
                (false, false) => "-".to_string(),
                (true, false) => "RX".to_string(),
                (false, true) => "TX".to_string(),
                (true, true) => "BOTH".to_string(),
            };
            let st_cell = Cell::from(st);
            let st_cell = if rx_limited || tx_limited {
                st_cell.style(limited_style)
            } else {
                st_cell
            };
            Row::new(vec![
                Cell::from(std::net::Ipv4Addr::from(ip.ip).to_string()),
                Cell::from(format_bps(ip.rx_bps)),
                Cell::from(format_bps(ip.tx_bps)),
                Cell::from(format_bytes(ip.rx_bytes)),
                Cell::from(format_bytes(ip.tx_bytes)),
                Cell::from(fmt_pol(ip.rx_limit)),
                Cell::from(fmt_pol(ip.tx_limit)),
                st_cell,
                Cell::from(fmt_remain(ip.rx_remaining, ip.tx_remaining)),
            ])
        }
        DetailCols::Min => {
            let st = match (rx_limited, tx_limited) {
                (false, false) => "-".to_string(),
                (true, false) => "RX".to_string(),
                (false, true) => "TX".to_string(),
                (true, true) => "BOTH".to_string(),
            };
            let st_cell = Cell::from(st);
            let st_cell = if rx_limited || tx_limited {
                st_cell.style(limited_style)
            } else {
                st_cell
            };
            Row::new(vec![
                Cell::from(std::net::Ipv4Addr::from(ip.ip).to_string()),
                Cell::from(format_bps(ip.rx_bps)),
                Cell::from(format_bps(ip.tx_bps)),
                st_cell,
            ])
        }
    }
}

pub fn sort_ips(ips: &mut [IpDetail], sort: SortMode) {
    match sort {
        SortMode::Ip => ips.sort_by_key(|i| i.ip),
        SortMode::Rx => ips.sort_by(|a, b| {
            b.rx_bps
                .partial_cmp(&a.rx_bps)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.ip.cmp(&b.ip))
        }),
        SortMode::Tx => ips.sort_by(|a, b| {
            b.tx_bps
                .partial_cmp(&a.tx_bps)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.ip.cmp(&b.ip))
        }),
        SortMode::Total => ips.sort_by(|a, b| {
            let ta = a.rx_bps + a.tx_bps;
            let tb = b.rx_bps + b.tx_bps;
            tb.partial_cmp(&ta)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.ip.cmp(&b.ip))
        }),
    }
}

fn header_row<'a>(cells: impl IntoIterator<Item = &'a str>) -> Row<'a> {
    Row::new(cells.into_iter().map(|c| {
        Cell::from(Span::styled(
            c,
            Style::default().add_modifier(Modifier::BOLD),
        ))
    }))
}

fn clamp_selection(state: &mut TableState, len: usize) {
    if len == 0 {
        state.select(None);
    } else {
        let selected = state.selected().map(|s| s.min(len - 1)).unwrap_or(0);
        state.select(Some(selected));
    }
}

fn waiting_widget(title: &'static str) -> Paragraph<'static> {
    Paragraph::new("Waiting for daemon data…")
        .alignment(Alignment::Center)
        .block(Block::bordered().title(title))
}

const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

/// Bucket a series down to `width` columns and render as one sparkline row.
fn sparkline(points: &[(i64, f64)], width: usize) -> (String, f64, f64, f64) {
    if points.is_empty() || width == 0 {
        return ("(no data)".to_string(), 0.0, 0.0, 0.0);
    }
    let max = points
        .iter()
        .map(|p| p.1)
        .fold(f64::NEG_INFINITY, f64::max)
        .max(1e-9);
    let min = points.iter().map(|p| p.1).fold(f64::INFINITY, f64::min);
    let avg = points.iter().map(|p| p.1).sum::<f64>() / points.len() as f64;
    // One bucket per point when the series is shorter than the chart width, so
    // bars stay contiguous instead of scattering across empty space.
    let n = width.max(1).min(points.len().max(1));
    let mut cols = vec![0.0f64; n];
    let mut cnt = vec![0u32; n];
    for (i, p) in points.iter().enumerate() {
        // Bucket by position so a short series still aligns to the right edge.
        let idx = (i * n / points.len()).min(n - 1);
        cols[idx] += p.1;
        cnt[idx] += 1;
    }
    let line: String = cols
        .iter()
        .zip(&cnt)
        .map(|(sum, c)| {
            if *c == 0 {
                ' '
            } else {
                let v = sum / *c as f64;
                BARS[((v / max) * 7.0).round() as usize]
            }
        })
        .collect();
    (line, min, avg, max)
}

fn draw_trend(f: &mut Frame, app: &UiState, area: Rect) {
    let Some(trend) = &app.trend else {
        f.render_widget(waiting_widget("Trend"), area);
        return;
    };

    let mut title = match &trend.target {
        TrendTarget::Ip(ip) => format!("IP Trend: {}   [", std::net::Ipv4Addr::from(*ip)),
        TrendTarget::Range(name) => format!("Range Trend: {name}   ["),
    };
    for (i, (label, _, _)) in TREND_WINDOWS.iter().enumerate() {
        if i == trend.win {
            title.push_str(&format!(" *{label}* "));
        } else {
            title.push_str(&format!(" {label} "));
        }
    }
    let metric = match trend.kind {
        TrendKind::Bandwidth => "bandwidth (bit/s)",
        TrendKind::Packets => "packets (pps)",
    };
    title.push_str(&format!("]   metric: {metric}"));

    let fmt_val = |v: f64| match trend.kind {
        TrendKind::Bandwidth => format_bps(v),
        TrendKind::Packets => {
            if v >= 1_000_000.0 {
                format!("{:.2} Mpps", v / 1e6)
            } else if v >= 1_000.0 {
                format!("{:.1} Kpps", v / 1e3)
            } else {
                format!("{:.0} pps", v)
            }
        }
    };

    let mut lines: Vec<Line> = Vec::new();
    match &trend.data {
        None if trend.error.is_none() => lines.push(Line::from("Loading trend data…")),
        None => {}
        Some(data) => {
            let width = area.width.saturating_sub(4) as usize;
            for (label, series) in [("RX", &data.rx), ("TX", &data.tx)] {
                let (spark, min, avg, max) = sparkline(series, width);
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("{label}  "),
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(spark),
                ]));
                lines.push(Line::from(format!(
                    "     min {}   avg {}   max {}   ({} points)",
                    fmt_val(min),
                    fmt_val(avg),
                    fmt_val(max),
                    series.len()
                )));
                lines.push(Line::from(""));
            }
        }
    }
    if let Some(err) = &trend.error {
        lines.push(Line::from(Span::styled(
            format!("VictoriaMetrics: {err}"),
            Style::default()
                .fg(ratatui::style::Color::Red)
                .add_modifier(Modifier::BOLD),
        )));
    }
    f.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(title)),
        area,
    );
}

fn draw_help(f: &mut Frame) {
    let area = centered_rect(60, 60, f.area());
    let text = vec![
        Line::from(Span::styled(
            "IP Range Overview",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from("↑/↓        select IP range"),
        Line::from("Enter      open selected range"),
        Line::from("t          trend for selected range"),
        Line::from("r          refresh now"),
        Line::from("h          toggle help"),
        Line::from("q          quit"),
        Line::from(""),
        Line::from(Span::styled(
            "IP Range Detail",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from("↑/↓        select IP"),
        Line::from("t          trend for the whole range"),
        Line::from("s          cycle sort (IP → RX → TX → RX+TX)"),
        Line::from("r          refresh now"),
        Line::from("Esc        back to overview"),
        Line::from("q          quit"),
        Line::from(""),
        Line::from(Span::styled(
            "Trend (VictoriaMetrics)",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from("Enter      open trend for selected IP (detail)"),
        Line::from("←/→ 1-4    window: 1h / 24h / 7d / 30d"),
        Line::from("b / p      bandwidth / packets"),
        Line::from("Esc        back"),
        Line::from(""),
        Line::from("any key closes this help"),
    ];
    f.render_widget(Clear, area);
    f.render_widget(
        Paragraph::new(text).block(Block::bordered().title("Help")),
        area,
    );
}

fn centered_rect(width_percent: u16, height_percent: u16, area: Rect) -> Rect {
    let [vertical] = Layout::vertical([Constraint::Percentage(height_percent)])
        .flex(ratatui::layout::Flex::Center)
        .areas(area);
    let [centered] = Layout::horizontal([Constraint::Percentage(width_percent)])
        .flex(ratatui::layout::Flex::Center)
        .areas(vertical);
    centered
}

fn format_duration(d: Duration) -> String {
    let ms = d.as_millis();
    if ms.is_multiple_of(1000) {
        format!("{}s", ms / 1000)
    } else {
        format!("{}ms", ms)
    }
}

#[cfg(test)]
mod tier_tests {
    use super::*;

    #[test]
    fn overview_tier_boundaries() {
        assert_eq!(overview_cols(OVERVIEW_WIDE_MIN), OverviewCols::Wide);
        assert_eq!(overview_cols(OVERVIEW_WIDE_MIN - 1), OverviewCols::Mid);
        assert_eq!(overview_cols(OVERVIEW_MID_MIN), OverviewCols::Mid);
        assert_eq!(overview_cols(OVERVIEW_MID_MIN - 1), OverviewCols::Min);
        assert_eq!(overview_cols(0), OverviewCols::Min);
    }

    #[test]
    fn detail_tier_boundaries() {
        assert_eq!(detail_cols(DETAIL_WIDE_MIN), DetailCols::Wide);
        assert_eq!(detail_cols(DETAIL_WIDE_MIN - 1), DetailCols::Mid);
        assert_eq!(detail_cols(DETAIL_MID_MIN), DetailCols::Mid);
        assert_eq!(detail_cols(DETAIL_MID_MIN - 1), DetailCols::Min);
        assert_eq!(detail_cols(0), DetailCols::Min);
    }
}
