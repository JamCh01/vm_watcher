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
    /// Non-fatal notices: config degradation, protocol drift.
    pub config_warning: Option<String>,
    pub protocol_note: Option<String>,

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
            config_warning: None,
            protocol_note: None,
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
    let area = f.area();
    // The header grows with the number of notices it carries; the body and the
    // footer always keep their minimum space, and on tiny terminals the least
    // important header lines are dropped first (see `fit_header_lines`).
    const FOOTER_ROWS: u16 = 1;
    const BODY_MIN_ROWS: u16 = 1;
    const HEADER_BORDER_ROWS: u16 = 2;
    let header_max = area.height.saturating_sub(FOOTER_ROWS + BODY_MIN_ROWS);
    let max_content = header_max.saturating_sub(HEADER_BORDER_ROWS) as usize;
    let lines = fit_header_lines(header_lines(app), max_content);
    let header_rows = ((lines.len() as u16) + HEADER_BORDER_ROWS)
        .min(header_max.max(HEADER_BORDER_ROWS))
        .min(area.height);

    let chunks = Layout::vertical([
        Constraint::Length(header_rows),
        Constraint::Min(1),
        Constraint::Length(FOOTER_ROWS),
    ])
    .split(area);

    f.render_widget(Paragraph::new(lines).block(Block::bordered()), chunks[0]);
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

/// One header line plus its keep-priority for tiny terminals: when the terminal
/// is too short to hold every line, the lowest priorities are dropped first and
/// the remaining lines keep their visual order. Priority follows the operator's
/// need to know: daemon error first, then dataplane degradation, watcher health,
/// config/reload failure, protocol note, and plain info last.
struct HeaderLine {
    prio: u8,
    line: Line<'static>,
}

const PRIO_PLAIN: u8 = 1;
const PRIO_NOTE: u8 = 3;
const PRIO_CONFIG_FAILURE: u8 = 4;
const PRIO_WATCHER: u8 = 5;
const PRIO_DEGRADED: u8 = 6;
const PRIO_ERROR: u8 = 7;

// The keep-priority ladder, pinned at compile time: daemon error > dataplane
// degraded > watcher unhealthy > config/reload failure > protocol warning >
// plain info.
const _: () = {
    assert!(PRIO_ERROR > PRIO_DEGRADED);
    assert!(PRIO_DEGRADED > PRIO_CONFIG_FAILURE);
    assert!(PRIO_CONFIG_FAILURE > PRIO_NOTE);
    assert!(PRIO_NOTE > PRIO_PLAIN);
};

/// Build every header line the current state asks for (no truncation here).
fn header_lines(app: &UiState) -> Vec<HeaderLine> {
    let status = app.status.as_ref();
    let tap_count = status.map(|s| s.tap_count).unwrap_or(0);
    let generation = status.map(|s| s.generation).unwrap_or(0);
    let mut reload_failed = false;
    let reload_line = match status {
        Some(s) if !s.last_reload_at.is_empty() => {
            reload_failed = !s.last_reload_ok;
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
        HeaderLine {
            prio: PRIO_PLAIN,
            line: Line::from(Span::styled(
                "VM Bandwidth Monitor",
                Style::default().add_modifier(Modifier::BOLD),
            )),
        },
        HeaderLine {
            prio: PRIO_PLAIN,
            line: Line::from(format!(
                "Bridge: {}    TAP Interfaces: {}    Refresh: {}",
                app.bridge,
                tap_count,
                format_duration(app.refresh_interval)
            )),
        },
        HeaderLine {
            // A successful reload / generation line is plain info and must not
            // out-priority a protocol warning; only an actual
            // reload failure earns the config-failure priority.
            prio: if reload_failed {
                PRIO_CONFIG_FAILURE
            } else {
                PRIO_PLAIN
            },
            line: Line::from(reload_line),
        },
    ];
    if let Some(s) = status {
        if !s.config_watcher_healthy {
            lines.push(HeaderLine {
                prio: PRIO_WATCHER,
                line: Line::from(Span::styled(
                    format!(
                        "WATCHER UNHEALTHY: {} error(s), last: {}",
                        s.config_watcher_errors_total, s.config_watcher_last_error
                    ),
                    Style::default().fg(ratatui::style::Color::Yellow),
                )),
            });
        }
        if s.dataplane_degraded {
            lines.push(HeaderLine {
                prio: PRIO_DEGRADED,
                line: Line::from(Span::styled(
                    degraded_notice(s.rollback_failures_total as usize),
                    Style::default()
                        .fg(ratatui::style::Color::Red)
                        .add_modifier(Modifier::BOLD),
                )),
            });
        }
    }
    if let Some(w) = &app.config_warning {
        lines.push(HeaderLine {
            prio: PRIO_CONFIG_FAILURE,
            line: Line::from(Span::styled(
                format!("config: {w}"),
                Style::default()
                    .fg(ratatui::style::Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )),
        });
    }
    if let Some(n) = &app.protocol_note {
        lines.push(HeaderLine {
            prio: PRIO_NOTE,
            line: Line::from(Span::styled(
                format!("protocol: {n}"),
                Style::default().fg(ratatui::style::Color::Yellow),
            )),
        });
    }
    if let Some(err) = &app.error {
        lines.push(HeaderLine {
            prio: PRIO_ERROR,
            line: Line::from(Span::styled(
                format!("daemon: {err}"),
                Style::default()
                    .fg(ratatui::style::Color::Red)
                    .add_modifier(Modifier::BOLD),
            )),
        });
    }
    lines
}

/// Shrink the header to at most `max_content` lines by dropping the lowest
/// keep-priorities; ties keep their visual order. Never reorders what it keeps.
fn fit_header_lines(lines: Vec<HeaderLine>, max_content: usize) -> Vec<Line<'static>> {
    if lines.len() <= max_content {
        return lines.into_iter().map(|h| h.line).collect();
    }
    let mut ranked: Vec<usize> = (0..lines.len()).collect();
    ranked.sort_by_key(|&i| (std::cmp::Reverse(lines[i].prio), i));
    let keep: std::collections::BTreeSet<usize> = ranked.into_iter().take(max_content).collect();
    lines
        .into_iter()
        .enumerate()
        .filter(|(i, _)| keep.contains(i))
        .map(|(_, h)| h.line)
        .collect()
}

/// Header notice for a degraded dataplane. Neutral by construction — see
/// `daemon::degraded_summary`: a failed rollback leaves per-record states that
/// differ, so the notice names no specific outcome, only where to look.
pub(crate) fn degraded_notice(failures: usize) -> String {
    format!("DATAPLANE DEGRADED: {failures} rollback failure(s) — inspect daemon logs")
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
    let dropped_bps: f64 = status
        .ranges
        .iter()
        .map(|r| r.rx_dropped_bps + r.tx_dropped_bps)
        .sum();
    let totals = OverviewTotals {
        rx_bps,
        tx_bps,
        rx_bytes,
        tx_bytes,
        ip_total,
        limited: limited_total,
        dropped_bps,
    };
    rows.push(total_row(&totals, cols).style(Style::default().add_modifier(Modifier::BOLD)));

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

/// Aggregate values behind the Σ All ranges row.
struct OverviewTotals {
    rx_bps: f64,
    tx_bps: f64,
    rx_bytes: u64,
    tx_bytes: u64,
    ip_total: usize,
    limited: usize,
    dropped_bps: f64,
}

fn total_row(t: &OverviewTotals, cols: OverviewCols) -> Row<'static> {
    // Aggregate policer drop rate: the one-line answer to "how much is the limiter
    // actually throwing away". Only shown while something is being dropped.
    let drop_line = |prefix: &str| -> Line<'static> {
        if t.dropped_bps > 0.0 {
            Line::from(format!("{prefix}drop {}", format_bps(t.dropped_bps)))
        } else {
            Line::from(prefix.to_string())
        }
    };
    match cols {
        OverviewCols::Wide => Row::new(vec![
            Cell::from(vec![Line::from("Σ All ranges"), drop_line("")]),
            Cell::from(""),
            Cell::from(format_bps(t.rx_bps)),
            Cell::from(format_bps(t.tx_bps)),
            Cell::from(format_bytes(t.rx_bytes)),
            Cell::from(format_bytes(t.tx_bytes)),
            Cell::from(t.ip_total.to_string()),
            Cell::from(t.limited.to_string()),
        ])
        .height(2),
        OverviewCols::Mid => Row::new(vec![
            Cell::from(vec![
                Line::from(format!("Σ All ({ip_total} IPs)", ip_total = t.ip_total)),
                drop_line(""),
            ]),
            Cell::from(""),
            Cell::from(format_bps(t.rx_bps)),
            Cell::from(format_bps(t.tx_bps)),
            Cell::from(t.limited.to_string()),
        ])
        .height(2),
        OverviewCols::Min => Row::new(vec![
            Cell::from(vec![
                Line::from("Σ All ranges"),
                drop_line(&format!("{ip_total} IPs · ", ip_total = t.ip_total)),
            ]),
            Cell::from(format_bps(t.rx_bps)),
            Cell::from(format_bps(t.tx_bps)),
            Cell::from(t.limited.to_string()),
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

    let dropped_total = detail.rx_dropped_bytes
        | detail.tx_dropped_bytes
        | detail.rx_dropped_packets
        | detail.tx_dropped_packets;
    let header_lines: u16 = if dropped_total > 0 { 3 } else { 2 };
    let chunks =
        Layout::vertical([Constraint::Length(2 + header_lines), Constraint::Min(1)]).split(area);

    let mut header = vec![
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
    // Drop verdicts only earn a header line while something is actually policed.
    if dropped_total > 0 {
        header.push(Line::from(format!(
            "Dropped RX: {} ({} pkts)    Dropped TX: {} ({} pkts)",
            format_bytes(detail.rx_dropped_bytes),
            detail.rx_dropped_packets,
            format_bytes(detail.tx_dropped_bytes),
            detail.tx_dropped_packets,
        )));
    }
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
                "IPv4", "RX", "TX", "RX Total", "TX Total", "Dropped", "RX win", "TX win",
                "RX limit", "TX limit", "RX st", "TX st", "Remain",
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
const DETAIL_WIDE_MIN: u16 = 149;
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
        DetailCols::Wide => {
            // Cumulative policer drops (RX+TX): "-" for unpoliced flows.
            let dropped = ip.rx_dropped_bytes.saturating_add(ip.tx_dropped_bytes);
            let dropped_cell = Cell::from(if dropped == 0 {
                "-".to_string()
            } else {
                format_bytes(dropped)
            });
            let dropped_cell = if dropped > 0 {
                dropped_cell.style(
                    Style::default()
                        .fg(ratatui::style::Color::Red)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                dropped_cell
            };
            Row::new(vec![
                Cell::from(std::net::Ipv4Addr::from(ip.ip).to_string()),
                Cell::from(format_bps(ip.rx_bps)),
                Cell::from(format_bps(ip.tx_bps)),
                Cell::from(format_bytes(ip.rx_bytes)),
                Cell::from(format_bytes(ip.tx_bytes)),
                dropped_cell,
                Cell::from(format_bps(ip.rx_window_bps)),
                Cell::from(format_bps(ip.tx_window_bps)),
                Cell::from(fmt_pol(ip.rx_limit)),
                Cell::from(fmt_pol(ip.tx_limit)),
                state_cell(rx_limited),
                state_cell(tx_limited),
                Cell::from(fmt_remain(ip.rx_remaining, ip.tx_remaining)),
            ])
        }
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
mod header_tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::layout::Position;

    fn render(app: &mut UiState, w: u16, h: u16) -> String {
        let backend = TestBackend::new(w, h);
        let mut terminal = ratatui::Terminal::new(backend).expect("test backend");
        terminal
            .draw(|f| draw(f, app))
            .expect("draw must not panic");
        let buf = terminal.backend().buffer().clone();
        (0..h)
            .map(|y| {
                (0..w)
                    .map(|x| {
                        buf.cell(Position { x, y })
                            .map(|c| c.symbol().to_string())
                            .unwrap_or_default()
                    })
                    .collect::<Vec<_>>()
                    .join("")
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn base_app() -> UiState {
        UiState::new("br0".to_string(), Duration::from_secs(1), SortMode::Ip)
    }

    fn alarmed_status() -> Status {
        Status {
            protocol_version: 1,
            generation: 3,
            config_loaded_at: "t0".to_string(),
            last_reload_at: "t1".to_string(),
            last_reload_ok: false,
            last_reload_error: "bad field".to_string(),
            bridge: "br0".to_string(),
            tap_count: 2,
            config_watcher_healthy: false,
            config_watcher_errors_total: 4,
            config_watcher_last_error: "inotify failed".to_string(),
            dataplane_degraded: true,
            rollback_failures_total: 2,
            ..Default::default()
        }
    }

    fn ok_status() -> Status {
        Status {
            protocol_version: 1,
            generation: 3,
            config_loaded_at: "t0".to_string(),
            last_reload_at: "t1".to_string(),
            last_reload_ok: true,
            last_reload_error: String::new(),
            bridge: "br0".to_string(),
            tap_count: 2,
            config_watcher_healthy: true,
            ..Default::default()
        }
    }

    #[test]
    fn no_notices_keeps_compact_header_with_body_and_footer() {
        let mut app = base_app();
        let text = render(&mut app, 100, 20);
        let rows: Vec<&str> = text.split('\n').collect();
        assert!(rows[0].starts_with('┌'), "header top border: {}", rows[0]);
        assert!(rows[1].contains("VM Bandwidth Monitor"));
        assert!(
            rows[4].starts_with('└'),
            "header bottom border at row 4: {}",
            rows[4]
        );
        assert!(
            !rows[5].starts_with('│'),
            "body must start right after the 5-row header"
        );
        assert!(text.contains("quit"), "footer missing: {text}");
    }

    #[test]
    fn every_notice_visible_on_a_tall_terminal() {
        let mut app = base_app();
        app.status = Some(alarmed_status());
        app.config_warning = Some("swl experimental".to_string());
        app.protocol_note = Some("daemon newer".to_string());
        app.error = Some("daemon gone".to_string());
        let text = render(&mut app, 120, 40);
        for needle in [
            "WATCHER UNHEALTHY",
            "DATAPLANE DEGRADED",
            "config: swl experimental",
            "protocol: daemon newer",
            "daemon: daemon gone",
            "Error: bad field",
        ] {
            assert!(text.contains(needle), "missing {needle:?} in:\n{text}");
        }
        assert!(text.contains("quit"), "footer missing");
    }

    #[test]
    fn short_terminal_drops_low_priority_lines_but_keeps_critical_ones() {
        let mut app = base_app();
        app.status = Some(alarmed_status());
        app.config_warning = Some("swl experimental".to_string());
        app.protocol_note = Some("daemon newer".to_string());
        app.error = Some("daemon gone".to_string());
        // 8 rows total: footer 1 + body min 1 → header ≤ 6 rows = 4 content lines.
        let text = render(&mut app, 120, 8);
        for needle in [
            "daemon: daemon gone",
            "DATAPLANE DEGRADED",
            "WATCHER UNHEALTHY",
        ] {
            assert!(
                text.contains(needle),
                "critical line lost: {needle:?}\n{text}"
            );
        }
        assert!(text.contains("quit"), "footer lost on short terminal");
    }

    #[test]
    fn tiny_terminals_do_not_panic() {
        for (w, h) in [(30u16, 1u16), (20, 3), (10, 2), (80, 4)] {
            let mut app = base_app();
            app.status = Some(alarmed_status());
            app.error = Some("daemon gone".to_string());
            render(&mut app, w, h); // must return without panicking
        }
    }

    /// 1 content row: header border 2 + content 1 + body min 1 + footer 1.
    const ONE_LINE_TERMINAL: (u16, u16) = (120, 5);

    #[test]
    fn successful_reload_loses_to_protocol_warning() {
        let mut app = base_app();
        app.status = Some(ok_status()); // successful reload => plain priority
        app.protocol_note = Some("daemon newer".to_string());
        let text = render(&mut app, ONE_LINE_TERMINAL.0, ONE_LINE_TERMINAL.1);
        assert!(text.contains("protocol: daemon newer"), "{text}");
        assert!(
            !text.contains("Config generation"),
            "plain generation line must be droppable: {text}"
        );
    }

    #[test]
    fn reload_failure_beats_protocol_warning() {
        let mut app = base_app();
        let mut status = ok_status();
        status.last_reload_ok = false;
        status.last_reload_error = "bad field".to_string();
        app.status = Some(status);
        app.protocol_note = Some("daemon newer".to_string());
        let text = render(&mut app, ONE_LINE_TERMINAL.0, ONE_LINE_TERMINAL.1);
        assert!(text.contains("Status: FAILED"), "{text}");
        assert!(!text.contains("protocol:"), "{text}");
    }

    #[test]
    fn equal_priority_lines_keep_their_stable_order() {
        let mut app = base_app();
        let mut status = ok_status();
        status.last_reload_ok = false;
        status.last_reload_error = "bad field".to_string();
        app.status = Some(status);
        // config warning shares PRIO_CONFIG_FAILURE with the failed reload line.
        app.config_warning = Some("swl experimental".to_string());
        app.protocol_note = Some("daemon newer".to_string());
        // 2 content rows: the two config-failure lines survive IN ORIGINAL
        // ORDER; the lower-priority protocol note is dropped.
        let text = render(&mut app, 120, 6);
        let reload_row = text.find("Status: FAILED").expect("reload line kept");
        let warning_row = text.find("config: swl experimental").expect("warning kept");
        assert!(
            reload_row < warning_row,
            "equal priorities must keep visual order:\n{text}"
        );
        assert!(!text.contains("protocol:"), "{text}");
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

    #[test]
    fn degraded_notice_names_no_specific_outcome() {
        let msg = degraded_notice(3);
        for banned in ["unarmed", "fail-open", "fail open", "limited"] {
            assert!(
                !msg.to_lowercase().contains(banned),
                "notice over-generalizes: contains {banned:?} in: {msg}"
            );
        }
        assert!(msg.contains("3 rollback failure(s)"));
        assert!(msg.contains("inspect daemon logs"));
    }
}
