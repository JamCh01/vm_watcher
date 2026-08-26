//! Two-screen TUI: IP Range Overview (default) and per-IP Range Detail.

use std::io::IsTerminal;
use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::{bail, Result};
use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Clear, HighlightSpacing, Paragraph, Row, Table, TableState};
use ratatui::Frame;
use tokio::sync::mpsc;

use crate::bandwidth::{format_bps, format_bytes, format_count};
use crate::collector::Snapshot;
use crate::config::{SortMode, ValidatedConfig};

enum Screen {
    Overview,
    Detail,
}

struct DetailState {
    range: usize,
    sort: SortMode,
    table: TableState,
}

struct App {
    bridge: String,
    refresh_interval: Duration,
    show_interface: bool,
    show_packets: bool,
    snapshot: Option<Snapshot>,
    screen: Screen,
    overview: TableState,
    detail: DetailState,
    show_help: bool,
}

impl App {
    fn new(cfg: &ValidatedConfig) -> Self {
        Self {
            bridge: cfg.bridge.clone(),
            refresh_interval: Duration::from_millis(cfg.refresh_interval_ms),
            show_interface: cfg.show_interface,
            show_packets: cfg.show_packets,
            snapshot: None,
            screen: Screen::Overview,
            overview: TableState::default(),
            detail: DetailState {
                range: 0,
                sort: cfg.default_sort,
                table: TableState::default(),
            },
            show_help: false,
        }
    }

    fn range_count(&self) -> usize {
        self.snapshot.as_ref().map(|s| s.ranges.len()).unwrap_or(0)
    }

    fn ip_count(&self) -> usize {
        self.snapshot
            .as_ref()
            .and_then(|s| s.ranges.get(self.detail.range))
            .map(|r| r.ips.len())
            .unwrap_or(0)
    }
}

/// Returns `true` to quit.
fn handle_key(app: &mut App, key: KeyEvent, refresh_tx: &mpsc::Sender<()>) -> bool {
    if key.kind != KeyEventKind::Press {
        return false;
    }
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return true;
    }
    if app.show_help {
        app.show_help = false;
        return false;
    }

    match key.code {
        KeyCode::Char('q') => return true,
        KeyCode::Char('h') if matches!(app.screen, Screen::Overview) => {
            app.show_help = true;
            return false;
        }
        KeyCode::Char('r') => {
            let _ = refresh_tx.try_send(());
            return false;
        }
        _ => {}
    }

    match app.screen {
        Screen::Overview => {
            let len = app.range_count();
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => move_selection(&mut app.overview, len, -1),
                KeyCode::Down | KeyCode::Char('j') => move_selection(&mut app.overview, len, 1),
                KeyCode::Enter => {
                    if let Some(selected) = app.overview.selected() {
                        if selected < len {
                            app.detail.range = selected;
                            app.detail.table = TableState::default();
                            app.screen = Screen::Detail;
                        }
                    }
                }
                _ => {}
            }
        }
        Screen::Detail => {
            let len = app.ip_count();
            match key.code {
                KeyCode::Esc | KeyCode::Backspace => app.screen = Screen::Overview,
                KeyCode::Char('s') => app.detail.sort = app.detail.sort.next(),
                KeyCode::Up | KeyCode::Char('k') => move_selection(&mut app.detail.table, len, -1),
                KeyCode::Down | KeyCode::Char('j') => move_selection(&mut app.detail.table, len, 1),
                _ => {}
            }
        }
    }
    false
}

fn move_selection(state: &mut TableState, len: usize, delta: i32) {
    if len == 0 {
        state.select(None);
        return;
    }
    let current = state.selected().unwrap_or(0) as i32;
    let next = (current + delta).clamp(0, len as i32 - 1) as usize;
    state.select(Some(next));
}

pub async fn run(
    mut snap_rx: mpsc::Receiver<Snapshot>,
    refresh_tx: mpsc::Sender<()>,
    cfg: &ValidatedConfig,
) -> Result<()> {
    if !input_source_available() {
        bail!(
            "cannot open terminal input: stdin is not a terminal and /dev/tty is unavailable. \
             Run this program from an interactive terminal (e.g. ssh with a PTY)."
        );
    }

    let mut terminal = ratatui::init();
    let mut app = App::new(cfg);

    // crossterm's EventStream panics with "reader source not set" when its input source
    // cannot be initialized; a plain blocking read on a dedicated thread degrades to a
    // graceful error instead (and drops the futures dependency).
    let (event_tx, mut event_rx) = mpsc::channel::<Event>(16);
    std::thread::spawn(move || {
        while let Ok(event) = crossterm::event::read() {
            if event_tx.blocking_send(event).is_err() {
                break;
            }
        }
    });

    loop {
        terminal.draw(|f| draw(f, &mut app))?;
        tokio::select! {
            maybe_event = event_rx.recv() => match maybe_event {
                Some(Event::Key(key)) => {
                    if handle_key(&mut app, key, &refresh_tx) {
                        break;
                    }
                }
                Some(_) => {}
                None => break,
            },
            snapshot = snap_rx.recv() => match snapshot {
                Some(s) => app.snapshot = Some(s),
                None => break,
            },
        }
    }
    Ok(())
}

/// Mirrors crossterm's tty_fd(): stdin must be a terminal, or /dev/tty must be openable.
fn input_source_available() -> bool {
    std::io::stdin().is_terminal()
        || std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .is_ok()
}

fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::vertical([
        Constraint::Length(4),
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

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let tap_count = app.snapshot.as_ref().map(|s| s.taps.len()).unwrap_or(0);
    let text = vec![
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
    ];
    f.render_widget(Paragraph::new(text).block(Block::bordered()), area);
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let keys = match app.screen {
        Screen::Overview => "↑/↓ select   Enter detail   r refresh   h help   q quit",
        Screen::Detail => "↑/↓ select   s sort   r refresh   Esc back   q quit",
    };
    let sort_hint = match app.screen {
        Screen::Detail => format!("   [sort: {}]", app.detail.sort.label()),
        Screen::Overview => String::new(),
    };
    f.render_widget(
        Paragraph::new(format!("{keys}{sort_hint}"))
            .style(Style::default().add_modifier(Modifier::DIM)),
        area,
    );
}

fn draw_overview(f: &mut Frame, app: &mut App, area: Rect) {
    let Some(snapshot) = &app.snapshot else {
        f.render_widget(waiting_widget("IP Range Overview"), area);
        return;
    };

    let rows: Vec<Row> = snapshot
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
            ])
        })
        .collect();

    let widths = [
        Constraint::Min(16),
        Constraint::Min(24),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Length(12),
    ];
    let table = Table::new(rows, widths)
        .header(header_row([
            "Name", "IP Range", "RX", "TX", "RX Total", "TX Total",
        ]))
        .block(Block::bordered().title("IP Range Overview"))
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_spacing(HighlightSpacing::Always);

    clamp_selection(&mut app.overview, snapshot.ranges.len());
    f.render_stateful_widget(table, area, &mut app.overview);
}

fn draw_detail(f: &mut Frame, app: &mut App, area: Rect) {
    if app.snapshot.is_none() {
        f.render_widget(waiting_widget("IP Range Detail"), area);
        return;
    }
    if !app
        .snapshot
        .as_ref()
        .is_some_and(|s| s.ranges.get(app.detail.range).is_some())
    {
        app.screen = Screen::Overview;
        return;
    }
    let snapshot = app.snapshot.as_ref().unwrap();
    let range = &snapshot.ranges[app.detail.range];

    let chunks = Layout::vertical([Constraint::Length(4), Constraint::Min(1)]).split(area);

    let header = vec![
        Line::from(vec![
            Span::styled("Range: ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(range.name.clone()),
            Span::raw(format!("    {}", range.range)),
        ]),
        Line::from(format!(
            "Range RX: {}    Range TX: {}    RX Total: {}    TX Total: {}",
            format_bps(range.rx_bps),
            format_bps(range.tx_bps),
            format_bytes(range.rx_bytes),
            format_bytes(range.tx_bytes),
        )),
    ];
    f.render_widget(Paragraph::new(header).block(Block::bordered()), chunks[0]);

    // Every configured IP is shown, sorted per the current sort mode.
    let mut ips = range.ips.clone();
    match app.detail.sort {
        SortMode::Ip => ips.sort_by_key(|(ip, _)| *ip),
        SortMode::Rx => ips.sort_by(|a, b| {
            b.1.rx_bps
                .partial_cmp(&a.1.rx_bps)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.0.cmp(&b.0))
        }),
        SortMode::Tx => ips.sort_by(|a, b| {
            b.1.tx_bps
                .partial_cmp(&a.1.tx_bps)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.0.cmp(&b.0))
        }),
        SortMode::Total => ips.sort_by(|a, b| {
            let ta = a.1.rx_bps + a.1.tx_bps;
            let tb = b.1.rx_bps + b.1.tx_bps;
            tb.partial_cmp(&ta)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.0.cmp(&b.0))
        }),
    }

    let names: Vec<(u32, &str)> = snapshot
        .taps
        .iter()
        .map(|t| (t.ifindex, t.name.as_str()))
        .collect();

    let mut widths = vec![
        Constraint::Length(16),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Length(12),
    ];
    let mut header_cells = vec!["IPv4", "RX", "TX", "RX Total", "TX Total"];
    if app.show_interface {
        header_cells.push("Ifaces");
        widths.push(Constraint::Min(12));
    }
    if app.show_packets {
        header_cells.push("RX Pkts");
        header_cells.push("TX Pkts");
        widths.push(Constraint::Length(10));
        widths.push(Constraint::Length(10));
    }

    let rows: Vec<Row> = ips
        .iter()
        .map(|(ip, stats)| {
            let mut cells = vec![
                Cell::from(Ipv4Addr::from(*ip).to_string()),
                Cell::from(format_bps(stats.rx_bps)),
                Cell::from(format_bps(stats.tx_bps)),
                Cell::from(format_bytes(stats.rx_bytes)),
                Cell::from(format_bytes(stats.tx_bytes)),
            ];
            if app.show_interface {
                let ifaces: Vec<String> = stats
                    .interfaces
                    .iter()
                    .map(|ifindex| {
                        names
                            .iter()
                            .find(|(i, _)| i == ifindex)
                            .map(|(_, name)| name.to_string())
                            .unwrap_or_else(|| ifindex.to_string())
                    })
                    .collect();
                cells.push(Cell::from(ifaces.join(",")));
            }
            if app.show_packets {
                cells.push(Cell::from(format_count(stats.rx_packets)));
                cells.push(Cell::from(format_count(stats.tx_packets)));
            }
            Row::new(cells)
        })
        .collect();

    let table = Table::new(rows, widths)
        .header(header_row(header_cells))
        .block(Block::bordered().title("IP Range Detail"))
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_spacing(HighlightSpacing::Always);

    clamp_selection(&mut app.detail.table, ips.len());
    f.render_stateful_widget(table, chunks[1], &mut app.detail.table);
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
    Paragraph::new("Waiting for first sample…")
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
