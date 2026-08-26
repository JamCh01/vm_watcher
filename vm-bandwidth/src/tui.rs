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
use vm_bandwidth_core::ipc::{IpDetail, RangeDetail, Status};

pub enum Screen {
    Overview,
    Detail,
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
        Screen::Overview => "↑/↓ select   Enter detail   r refresh   h help   q quit",
        Screen::Detail => "↑/↓ select   s sort   r refresh   Esc back   q quit",
    };
    let sort_hint = match app.screen {
        Screen::Detail => format!("   [sort: {}]", app.sort.label()),
        Screen::Overview => String::new(),
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

    let rows: Vec<Row> = status
        .ranges
        .iter()
        .map(|r| {
            Row::new(vec![
                Cell::from(r.name.clone()),
                Cell::from(r.range.clone()),
                Cell::from(format_bps(r.rx_bps)),
                Cell::from(format_bps(r.tx_bps)),
                Cell::from(format_bytes(r.rx_bytes)),
                Cell::from(format_bytes(r.tx_bytes)),
                Cell::from(r.ip_count.to_string()),
                style_limited(r.limited),
            ])
        })
        .collect();

    let widths = [
        Constraint::Min(14),
        Constraint::Min(22),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Length(11),
        Constraint::Length(11),
        Constraint::Length(6),
        Constraint::Length(8),
    ];
    let table = Table::new(rows, widths)
        .header(header_row([
            "Name", "IP Range", "RX", "TX", "RX Total", "TX Total", "IPs", "Limited",
        ]))
        .block(Block::bordered().title("IP Range Overview"))
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_spacing(ratatui::widgets::HighlightSpacing::Always);

    clamp_selection(&mut app.overview, status.ranges.len());
    f.render_stateful_widget(table, area, &mut app.overview);
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

    let widths = [
        Constraint::Length(16),
        Constraint::Length(11),
        Constraint::Length(11),
        Constraint::Length(11),
        Constraint::Length(11),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(9),
    ];
    let rows: Vec<Row> = ips.iter().map(ip_row).collect();
    let table = Table::new(rows, widths)
        .header(header_row([
            "IPv4", "RX", "TX", "RX win", "TX win", "RX limit", "TX limit", "RX st", "TX st",
            "Remain",
        ]))
        .block(Block::bordered().title("IP Range Detail"))
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_spacing(ratatui::widgets::HighlightSpacing::Always);

    clamp_selection(&mut app.detail_table, ips.len());
    f.render_stateful_widget(table, area, &mut app.detail_table);
}

fn ip_row(ip: &IpDetail) -> Row<'static> {
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

    Row::new(vec![
        Cell::from(std::net::Ipv4Addr::from(ip.ip).to_string()),
        Cell::from(format_bps(ip.rx_bps)),
        Cell::from(format_bps(ip.tx_bps)),
        Cell::from(format_bps(ip.rx_window_bps)),
        Cell::from(format_bps(ip.tx_window_bps)),
        Cell::from(fmt_pol(ip.rx_limit)),
        Cell::from(fmt_pol(ip.tx_limit)),
        state_cell(rx_limited),
        state_cell(tx_limited),
        Cell::from(fmt_remain(ip.rx_remaining, ip.tx_remaining)),
    ])
}

fn sort_ips(ips: &mut [IpDetail], sort: SortMode) {
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

fn draw_help(f: &mut Frame) {
    let area = centered_rect(60, 60, f.area());
    let text = vec![
        Line::from(Span::styled(
            "IP Range Overview",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from("↑/↓        select IP range"),
        Line::from("Enter      open selected range"),
        Line::from("r          refresh now"),
        Line::from("h          toggle help"),
        Line::from("q          quit"),
        Line::from(""),
        Line::from(Span::styled(
            "IP Range Detail",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from("↑/↓        select IP"),
        Line::from("s          cycle sort (IP → RX → TX → RX+TX)"),
        Line::from("r          refresh now"),
        Line::from("Esc        back to overview"),
        Line::from("q          quit"),
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
