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

use vm_bandwidth_core::config::SortMode;
use vm_bandwidth_core::ipc::{self, Request, Response};

use crate::daemon::SOCK_PATH;
use crate::tui::{self, Screen, UiState};

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

pub fn run_ui() -> Result<()> {
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

    let mut terminal = ratatui::init();
    let mut app = UiState::new("br0".to_string(), REFRESH, SortMode::Ip);

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
        },
        KeyCode::Enter if matches!(app.screen, Screen::Overview) => {
            if let Some(sel) = app.overview.selected() {
                app.screen = Screen::Detail;
                app.detail_index = Some(sel);
                app.detail_table.select(Some(0));
                return UiAction::Refresh;
            }
        }
        KeyCode::Esc if matches!(app.screen, Screen::Detail) => {
            app.screen = Screen::Overview;
            app.detail = None;
            app.detail_index = None;
        }
        KeyCode::Char('s') if matches!(app.screen, Screen::Detail) => {
            app.sort = app.sort.next();
        }
        _ => {}
    }
    UiAction::Nothing
}
