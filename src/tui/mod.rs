//! TUI module — ratatui + crossterm async event loop.
//!
//! Design patterns applied here:
//!   MVC     — App is the Model; draw_* functions are the View; handle_key is the Controller.
//!   Strategy— Tab enum: each tab is a discrete, swappable view strategy.
//!   Observer— event_loop subscribes to State::subscribe() broadcast channel for live updates.
//!   Command — each key binding maps to a discrete App method (command object).

use std::time::Duration;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, Cell, Gauge, List, ListItem, ListState,
        Paragraph, Row,
        Table, TableState, Tabs, Wrap,
    },
    Frame, Terminal,
};

use crate::globals::{AppStats, State, APP_VERSION};
use crate::types::{AppEvent, CrackProgress, CrackState, LogLevel};
use crate::{AirError, AirResult};

// ── Brand palette ────────────────────────────────────────────────────────────

const GOLD:    Color = Color::Rgb(200, 162, 60);
const BLACK:   Color = Color::Rgb(13, 13, 13);
const WHITE:   Color = Color::White;
const DIM:     Color = Color::Rgb(120, 120, 120);
const RED:     Color = Color::Rgb(220, 60, 60);
const GREEN:   Color = Color::Rgb(60, 200, 100);
const CYAN:    Color = Color::Rgb(60, 180, 200);

// ── Tab — Strategy pattern ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Scan,
    Attack,
    Crack,
    Log,
    Settings,
}

impl Tab {
    const ALL: &'static [Self] = &[
        Self::Scan, Self::Attack, Self::Crack, Self::Log, Self::Settings,
    ];

    fn title(self) -> &'static str {
        match self {
            Self::Scan     => " Scan [1] ",
            Self::Attack   => " Attack [2] ",
            Self::Crack    => " Crack [3] ",
            Self::Log      => " Log [4] ",
            Self::Settings => " Settings [5] ",
        }
    }
}

// ── App — MVC Model ───────────────────────────────────────────────────────────

struct App {
    active_tab:     Tab,
    ap_table:       TableState,
    client_list:    ListState,
    log_scroll:     usize,
    stats:          AppStats,
    crack_progress: CrackProgress,
    log_entries:    Vec<crate::types::LogEntry>,
    quit:           bool,
    // bssids in stable display order (sorted by power desc)
    ap_order:       Vec<String>,
}

impl App {
    fn new() -> Self {
        let mut ap_table = TableState::default();
        ap_table.select(Some(0));
        Self {
            active_tab:     Tab::Scan,
            ap_table,
            client_list:    ListState::default(),
            log_scroll:     0,
            stats:          AppStats::collect(),
            crack_progress: State::get_crack_progress(),
            log_entries:    State::get_log_entries(),
            quit:           false,
            ap_order:       Vec::new(),
        }
    }

    fn refresh(&mut self) {
        self.stats          = AppStats::collect();
        self.crack_progress = State::get_crack_progress();
        self.log_entries    = State::get_log_entries();

        // Rebuild sorted AP order (strongest signal first)
        let mut aps: Vec<_> = State::get_aps().into_values().collect();
        aps.sort_by(|a, b| b.power.cmp(&a.power));
        self.ap_order = aps.into_iter().map(|ap| ap.bssid).collect();

        // Keep selection in bounds
        let count = self.ap_order.len();
        if count == 0 {
            self.ap_table.select(None);
        } else if self.ap_table.selected().map(|i| i >= count).unwrap_or(true) {
            self.ap_table.select(Some(count.saturating_sub(1)));
        }
    }

    fn on_event(&mut self, ev: &AppEvent) {
        match ev {
            AppEvent::CrackProgress(p) => self.crack_progress = p.clone(),
            AppEvent::Log(..)          => self.log_entries = State::get_log_entries(),
            AppEvent::ApUpdated(_) | AppEvent::ApDiscovered(_) | AppEvent::HandshakeCaptured(_) => {
                self.refresh();
            }
            _ => {}
        }
    }

    // ── Navigation (Command pattern: each method = one command) ─────────────

    fn next_tab(&mut self) {
        let i = Tab::ALL.iter().position(|&t| t == self.active_tab).unwrap_or(0);
        self.active_tab = Tab::ALL[(i + 1) % Tab::ALL.len()];
    }

    fn prev_tab(&mut self) {
        let i = Tab::ALL.iter().position(|&t| t == self.active_tab).unwrap_or(0);
        self.active_tab = Tab::ALL[(i + Tab::ALL.len() - 1) % Tab::ALL.len()];
    }

    fn set_tab_by_number(&mut self, n: usize) {
        if n < Tab::ALL.len() { self.active_tab = Tab::ALL[n]; }
    }

    fn list_down(&mut self) {
        match self.active_tab {
            Tab::Scan => {
                let n = self.ap_order.len();
                if n == 0 { return; }
                let i = self.ap_table.selected().unwrap_or(0);
                self.ap_table.select(Some((i + 1).min(n - 1)));
            }
            Tab::Log => {
                self.log_scroll = self.log_scroll.saturating_add(1);
            }
            _ => {}
        }
    }

    fn list_up(&mut self) {
        match self.active_tab {
            Tab::Scan => {
                let i = self.ap_table.selected().unwrap_or(0);
                self.ap_table.select(Some(i.saturating_sub(1)));
            }
            Tab::Log => {
                self.log_scroll = self.log_scroll.saturating_sub(1);
            }
            _ => {}
        }
    }

    fn selected_ap_bssid(&self) -> Option<&str> {
        self.ap_table.selected()
            .and_then(|i| self.ap_order.get(i))
            .map(|s| s.as_str())
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn run() -> AirResult<()> {
    enable_raw_mode().map_err(|e| AirError::Engine(e.to_string()))?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
        .map_err(|e| AirError::Engine(e.to_string()))?;

    let backend  = CrosstermBackend::new(stdout);
    let mut term = Terminal::new(backend).map_err(|e| AirError::Engine(e.to_string()))?;

    let result = event_loop(&mut term).await;

    disable_raw_mode().ok();
    execute!(term.backend_mut(), LeaveAlternateScreen, DisableMouseCapture).ok();
    term.show_cursor().ok();

    result
}

// ── Event loop — Observer pattern ─────────────────────────────────────────────
// Subscribes to the broadcast bus; any AppEvent triggers an immediate redraw.

async fn event_loop(
    term: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
) -> AirResult<()> {
    let mut app       = App::new();
    let mut bus_rx    = State::subscribe();
    let tick           = Duration::from_millis(250);
    let mut last_tick  = tokio::time::Instant::now();

    loop {
        term.draw(|f| draw(f, &mut app))
            .map_err(|e| AirError::Engine(e.to_string()))?;

        // Drain any pending AppEvents from the broadcast bus (non-blocking)
        loop {
            match bus_rx.try_recv() {
                Ok(ev)  => app.on_event(&ev),
                Err(_)  => break,
            }
        }

        // Check keyboard/mouse with short timeout so the bus stays responsive
        let timeout = tick.saturating_sub(last_tick.elapsed()).min(Duration::from_millis(50));

        if event::poll(timeout).map_err(|e| AirError::Engine(e.to_string()))? {
            if let Event::Key(key) =
                event::read().map_err(|e| AirError::Engine(e.to_string()))?
            {
                handle_key(&mut app, key.code, key.modifiers);
            }
        }

        if last_tick.elapsed() >= tick {
            app.refresh();
            last_tick = tokio::time::Instant::now();
        }

        if app.quit { break; }

        tokio::task::yield_now().await;
    }
    Ok(())
}

// ── Key handler — Command pattern ─────────────────────────────────────────────

fn handle_key(app: &mut App, key: KeyCode, mods: KeyModifiers) {
    match key {
        // Quit
        KeyCode::Char('q') | KeyCode::Char('Q') => app.quit = true,
        KeyCode::Char('c') if mods.contains(KeyModifiers::CONTROL) => app.quit = true,

        // Tab navigation
        KeyCode::Tab              => app.next_tab(),
        KeyCode::BackTab          => app.prev_tab(),
        KeyCode::Char('1')        => app.set_tab_by_number(0),
        KeyCode::Char('2')        => app.set_tab_by_number(1),
        KeyCode::Char('3')        => app.set_tab_by_number(2),
        KeyCode::Char('4')        => app.set_tab_by_number(3),
        KeyCode::Char('5')        => app.set_tab_by_number(4),

        // List navigation (j/k vim-style + arrows)
        KeyCode::Down | KeyCode::Char('j')  => app.list_down(),
        KeyCode::Up   | KeyCode::Char('k')  => app.list_up(),

        _ => {}
    }
}

// ── Root draw — MVC View ──────────────────────────────────────────────────────

fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // tab bar
            Constraint::Min(0),    // body
            Constraint::Length(1), // status bar
        ])
        .split(f.area());

    draw_tabbar(f, app, chunks[0]);
    draw_body(f, app, chunks[1]);
    draw_statusbar(f, app, chunks[2]);
}

// ── Tab bar ───────────────────────────────────────────────────────────────────

fn draw_tabbar(f: &mut Frame, app: &App, area: Rect) {
    let titles: Vec<Line> = Tab::ALL
        .iter()
        .map(|t| Line::from(Span::styled(t.title(), Style::default().fg(WHITE))))
        .collect();
    let active = Tab::ALL.iter().position(|&t| t == app.active_tab).unwrap_or(0);

    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .title(format!(" ⚡ Air v{} ", APP_VERSION))
                .title_style(Style::default().fg(GOLD).add_modifier(Modifier::BOLD))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(GOLD)),
        )
        .select(active)
        .style(Style::default().fg(DIM))
        .highlight_style(Style::default().fg(BLACK).bg(GOLD).add_modifier(Modifier::BOLD))
        .divider(Span::styled("│", Style::default().fg(DIM)));

    f.render_widget(tabs, area);
}

// ── Status bar ────────────────────────────────────────────────────────────────

fn draw_statusbar(f: &mut Frame, app: &App, area: Rect) {
    let iface    = app.stats.iface.as_deref().unwrap_or("none");
    let scanning = if app.stats.is_scanning { "◉ scanning" } else { "○ idle" };
    let update   = if app.stats.has_update  { "  ● UPDATE" } else { "" };
    let aps      = app.stats.ap_count;
    let clients  = app.stats.client_count;
    let attacks  = app.stats.active_attacks;

    let bar = Paragraph::new(format!(
        " {scanning}  iface:{iface}  APs:{aps}  clients:{clients}  attacks:{attacks}{update}\
         │ q:quit  Tab:switch  ↑↓/jk:nav  1-5:tabs"
    ))
    .style(Style::default().fg(GOLD).bg(BLACK));

    f.render_widget(bar, area);
}

// ── Body dispatcher ───────────────────────────────────────────────────────────

fn draw_body(f: &mut Frame, app: &mut App, area: Rect) {
    match app.active_tab {
        Tab::Scan     => draw_scan(f, app, area),
        Tab::Attack   => draw_attack(f, app, area),
        Tab::Crack    => draw_crack(f, app, area),
        Tab::Log      => draw_log(f, app, area),
        Tab::Settings => draw_settings(f, app, area),
    }
}

// ── Scan tab — AP table + client panel ───────────────────────────────────────

fn draw_scan(f: &mut Frame, app: &mut App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(68), Constraint::Percentage(32)])
        .split(area);

    draw_ap_table(f, app, cols[0]);
    draw_client_panel(f, app, cols[1]);
}

fn draw_ap_table(f: &mut Frame, app: &mut App, area: Rect) {
    let aps_map = State::get_aps();

    let header = Row::new(vec![
        Cell::from("HS").style(Style::default().fg(GOLD).add_modifier(Modifier::BOLD)),
        Cell::from("ESSID").style(Style::default().fg(GOLD).add_modifier(Modifier::BOLD)),
        Cell::from("BSSID").style(Style::default().fg(GOLD).add_modifier(Modifier::BOLD)),
        Cell::from("CH").style(Style::default().fg(GOLD).add_modifier(Modifier::BOLD)),
        Cell::from("PWR").style(Style::default().fg(GOLD).add_modifier(Modifier::BOLD)),
        Cell::from("ENC").style(Style::default().fg(GOLD).add_modifier(Modifier::BOLD)),
        Cell::from("CLT").style(Style::default().fg(GOLD).add_modifier(Modifier::BOLD)),
        Cell::from("BAND").style(Style::default().fg(GOLD).add_modifier(Modifier::BOLD)),
    ])
    .height(1)
    .bottom_margin(0);

    let rows: Vec<Row> = app.ap_order.iter().filter_map(|bssid| {
        let ap = aps_map.get(bssid)?;
        let hs_mark = if ap.handshake { "✓" } else { " " };
        let hs_style = if ap.handshake {
            Style::default().fg(GREEN).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(DIM)
        };
        let essid = if ap.essid.is_empty() { "<hidden>".to_string() }
                    else { truncate(&ap.essid, 20) };

        let pwr_col = power_color(ap.power);

        let row = Row::new(vec![
            Cell::from(hs_mark).style(hs_style),
            Cell::from(essid).style(Style::default().fg(WHITE)),
            Cell::from(ap.bssid.clone()).style(Style::default().fg(DIM)),
            Cell::from(ap.channel.to_string()).style(Style::default().fg(CYAN)),
            Cell::from(format!("{}", ap.power)).style(Style::default().fg(pwr_col)),
            Cell::from(ap.privacy.to_string()).style(Style::default().fg(enc_color(&ap.privacy))),
            Cell::from(ap.client_count().to_string()).style(Style::default().fg(WHITE)),
            Cell::from(ap.band.clone()).style(Style::default().fg(DIM)),
        ]);
        Some(row)
    }).collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(2),  // HS
            Constraint::Length(21), // ESSID
            Constraint::Length(18), // BSSID
            Constraint::Length(4),  // CH
            Constraint::Length(5),  // PWR
            Constraint::Length(6),  // ENC
            Constraint::Length(4),  // CLT
            Constraint::Length(7),  // BAND
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(format!(" Access Points  ({} found) ", app.ap_order.len()))
            .title_style(Style::default().fg(GOLD))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(GOLD)),
    )
    .row_highlight_style(Style::default().fg(BLACK).bg(GOLD).add_modifier(Modifier::BOLD))
    .highlight_symbol("► ");

    f.render_stateful_widget(table, area, &mut app.ap_table);
}

fn draw_client_panel(f: &mut Frame, app: &mut App, area: Rect) {
    let aps_map = State::get_aps();

    let clients: Vec<ListItem> = app.selected_ap_bssid()
        .and_then(|b| aps_map.get(b))
        .map(|ap| {
            ap.clients.values().map(|c| {
                let vendor = if c.vendor.is_empty() { "unknown".to_string() } else { truncate(&c.vendor, 16) };
                let probe  = if c.probes.is_empty() { String::new() } else { format!("  → {}", truncate(&c.probes, 14)) };
                ListItem::new(format!(" {} {}dBm {}{}", c.mac, c.power, vendor, probe))
                    .style(Style::default().fg(WHITE))
            }).collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let title = match app.selected_ap_bssid() {
        Some(b) => format!(" Clients of {} ", b),
        None    => " Clients ".to_string(),
    };

    let widget = List::new(clients)
        .block(
            Block::default()
                .title(title)
                .title_style(Style::default().fg(GOLD))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(GOLD)),
        )
        .highlight_style(Style::default().fg(BLACK).bg(GOLD));

    f.render_stateful_widget(widget, area, &mut app.client_list);
}

// ── Attack tab ────────────────────────────────────────────────────────────────

fn draw_attack(f: &mut Frame, _app: &mut App, area: Rect) {
    let aps_map = State::get_aps();
    let items: Vec<ListItem> = aps_map.values()
        .filter(|ap| State::is_attacking(&ap.bssid))
        .map(|ap| {
            let essid = if ap.essid.is_empty() { "<hidden>" } else { ap.essid.as_str() };
            ListItem::new(Line::from(vec![
                Span::styled(" ► ", Style::default().fg(RED).add_modifier(Modifier::BOLD)),
                Span::styled(format!("{} — {} ", ap.bssid, essid), Style::default().fg(WHITE)),
                Span::styled("DEAUTH ACTIVE", Style::default().fg(RED).add_modifier(Modifier::BOLD)),
            ]))
        })
        .collect();

    let content = if items.is_empty() {
        vec![ListItem::new(
            Line::from(Span::styled(" No active attacks.", Style::default().fg(DIM)))
        )]
    } else {
        items
    };

    f.render_widget(
        List::new(content).block(
            Block::default()
                .title(format!(" Active Attacks ({}) ", State::attack_count()))
                .title_style(Style::default().fg(GOLD))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(GOLD)),
        ),
        area,
    );
}

// ── Crack tab — live progress bar ─────────────────────────────────────────────

fn draw_crack(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7),  // progress panel
            Constraint::Min(0),     // help / result
        ])
        .split(area);

    draw_crack_progress(f, app, chunks[0]);
    draw_crack_help(f, app, chunks[1]);
}

fn draw_crack_progress(f: &mut Frame, app: &App, area: Rect) {
    let p = &app.crack_progress;

    let (state_str, state_col) = match p.state {
        CrackState::Idle      => ("idle", DIM),
        CrackState::Running   => ("running", CYAN),
        CrackState::Found     => ("FOUND ✓", GREEN),
        CrackState::Exhausted => ("exhausted", RED),
        CrackState::Stopped   => ("stopped", DIM),
    };

    let pct = p.percent() as u16;
    let speed = p.speed_display();
    let eta   = p.eta_display();

    let block = Block::default()
        .title(format!(
            " Crack  {}  |  target: {}  {}  ",
            state_str,
            if p.essid.is_empty() { "—" } else { &p.essid },
            if p.bssid.is_empty() { "" } else { &p.bssid },
        ))
        .title_style(Style::default().fg(state_col).add_modifier(Modifier::BOLD))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(GOLD));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // stats line
            Constraint::Length(1), // gap
            Constraint::Length(1), // gauge
        ])
        .split(inner);

    // Stats line
    let stats_line = if p.state == CrackState::Idle {
        Line::from(Span::styled(
            " No crack in progress. Use: air crack -f cap.cap -e ESSID -b BSSID -w wordlist.txt",
            Style::default().fg(DIM),
        ))
    } else {
        Line::from(vec![
            Span::styled(format!(" tried: {} ", p.tried), Style::default().fg(WHITE)),
            Span::styled("│ ", Style::default().fg(DIM)),
            Span::styled(format!("speed: {} ", speed), Style::default().fg(CYAN)),
            Span::styled("│ ", Style::default().fg(DIM)),
            Span::styled(format!("ETA: {} ", eta), Style::default().fg(GOLD)),
            Span::styled("│ ", Style::default().fg(DIM)),
            Span::styled(format!("{:.1}%", p.percent()), Style::default().fg(GOLD).add_modifier(Modifier::BOLD)),
        ])
    };
    f.render_widget(Paragraph::new(stats_line), rows[0]);

    // Progress gauge
    let gauge_color = match p.state {
        CrackState::Found     => GREEN,
        CrackState::Exhausted => RED,
        CrackState::Running   => GOLD,
        _                     => DIM,
    };
    let gauge = Gauge::default()
        .gauge_style(Style::default().fg(gauge_color).bg(BLACK))
        .ratio((pct as f64 / 100.0).min(1.0))
        .label(format!("{pct}%"));
    f.render_widget(gauge, rows[2]);
}

fn draw_crack_help(f: &mut Frame, _app: &App, area: Rect) {
    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  WPA/WPA2 dictionary:  ", Style::default().fg(WHITE)),
            Span::styled(
                "air crack -f cap.cap -e ESSID -b BSSID -w /usr/share/wordlists/rockyou.txt",
                Style::default().fg(CYAN),
            ),
        ]),
        Line::from(vec![
            Span::styled("  WPA bruteforce:       ", Style::default().fg(WHITE)),
            Span::styled(
                "air crack -f cap.cap -e ESSID -b BSSID --charset abcdefghijklmnopqrstuvwxyz0123456789 --min-len 8 --max-len 10",
                Style::default().fg(CYAN),
            ),
        ]),
        Line::from(vec![
            Span::styled("  PMKID (no handshake): ", Style::default().fg(WHITE)),
            Span::styled(
                "air pmkid --bssid AA:BB:CC:DD:EE:FF --sta 11:22:33:44:55:66 --pmkid <hex32> -e ESSID -w wl.txt",
                Style::default().fg(CYAN),
            ),
        ]),
        Line::from(vec![
            Span::styled("  WEP:                  ", Style::default().fg(WHITE)),
            Span::styled(
                "air crack-wep -f cap.cap -b BSSID",
                Style::default().fg(CYAN),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  Progress is shown above in real time (updates every 5 000 candidates).",
            Style::default().fg(DIM),
        )),
    ];

    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(
                Block::default()
                    .title(" Commands ")
                    .title_style(Style::default().fg(GOLD))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(GOLD)),
            ),
        area,
    );
}

// ── Log tab — ring buffer viewer ──────────────────────────────────────────────

fn draw_log(f: &mut Frame, app: &mut App, area: Rect) {
    let entries = &app.log_entries;
    let total   = entries.len();

    // Keep scroll in bounds
    let visible = area.height.saturating_sub(2) as usize;
    if app.log_scroll + visible > total && total > visible {
        app.log_scroll = total - visible;
    }

    let items: Vec<ListItem> = entries
        .iter()
        .skip(app.log_scroll)
        .take(visible.max(1))
        .map(|e| {
            let (pfx, col) = match e.level {
                LogLevel::Info    => (" INFO ", WHITE),
                LogLevel::Warn    => (" WARN ", GOLD),
                LogLevel::Error   => (" ERR  ", RED),
                LogLevel::Success => (" OK   ", GREEN),
            };
            ListItem::new(Line::from(vec![
                Span::styled(e.ts_str(), Style::default().fg(DIM)),
                Span::styled(pfx, Style::default().fg(col).add_modifier(Modifier::BOLD)),
                Span::styled(e.message.clone(), Style::default().fg(WHITE)),
            ]))
        })
        .collect();

    f.render_widget(
        List::new(items).block(
            Block::default()
                .title(format!(" Log  ({total} entries)  ↑↓ scroll "))
                .title_style(Style::default().fg(GOLD))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(GOLD)),
        ),
        area,
    );
}

// ── Settings tab ──────────────────────────────────────────────────────────────

fn draw_settings(f: &mut Frame, _app: &mut App, area: Rect) {
    let s = State::get_settings();
    let s_display_hidden    = s.display_hidden_ap.to_string();
    let s_kill_nm           = s.kill_network_manager.to_string();
    let s_auto_save         = s.auto_save_handshakes.to_string();
    let lines = vec![
        Line::from(Span::styled(
            " Settings  (edit /etc/air/config.toml to change)",
            Style::default().fg(GOLD).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        setting_row("mac_address",          &s.mac_address),
        setting_row("display_hidden_ap",    &s_display_hidden),
        setting_row("kill_network_manager", &s_kill_nm),
        setting_row("auto_save_handshakes", &s_auto_save),
        setting_row("handshake_dir",        &s.handshake_dir),
        setting_row("default_attack_tool",  &s.default_attack_tool),
        Line::from(""),
        Line::from(Span::styled(
            "  Required: airmon-ng  airodump-ng  aireplay-ng  aircrack-ng  mergecap  macchanger",
            Style::default().fg(DIM),
        )),
        Line::from(Span::styled(
            "  Optional: mdk4  hashcat  hcxdumptool  hcxtools",
            Style::default().fg(DIM),
        )),
    ];

    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(
                Block::default()
                    .title(" Settings ")
                    .title_style(Style::default().fg(GOLD))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(GOLD)),
            ),
        area,
    );
}

fn setting_row<'a>(key: &'a str, val: &'a str) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("  {:<28}", key), Style::default().fg(GOLD)),
        Span::styled("= ", Style::default().fg(DIM)),
        Span::styled(val.to_string(), Style::default().fg(WHITE)),
    ])
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

fn power_color(dbm: i32) -> Color {
    match dbm {
        p if p >= -50 => GREEN,
        p if p >= -65 => GOLD,
        p if p >= -80 => Color::Rgb(200, 120, 60),
        _             => RED,
    }
}

fn enc_color(p: &crate::types::Privacy) -> Color {
    use crate::types::Privacy::*;
    match p {
        Open => RED,
        Wep  => Color::Rgb(200, 100, 60),
        Wpa  => GOLD,
        Wpa2 => CYAN,
        Wpa3 => GREEN,
        Unknown(_) => DIM,
    }
}
