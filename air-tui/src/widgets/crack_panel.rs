//! CrackPanel — live crack progress: gauge + stats + last result.
//! Pattern: Builder.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, Paragraph},
    Frame,
};
use crate::theme::Theme;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CrackState { #[default] Idle, Running, Found, Exhausted, Stopped }

impl CrackState {
    fn label(self) -> &'static str {
        match self {
            Self::Idle      => "idle",
            Self::Running   => "running",
            Self::Found     => "FOUND ✓",
            Self::Exhausted => "exhausted",
            Self::Stopped   => "stopped",
        }
    }
}

pub struct CrackPanel<'a> {
    theme:     Theme,
    state:     CrackState,
    bssid:     &'a str,
    essid:     &'a str,
    tried:     u64,
    total:     u64,
    speed_wps: f64,
    eta_secs:  Option<u64>,
    last_pass: Option<&'a str>,
}

impl<'a> CrackPanel<'a> {
    pub fn new() -> Self {
        Self {
            theme: Theme::AIR, state: CrackState::Idle,
            bssid: "", essid: "", tried: 0, total: 0,
            speed_wps: 0.0, eta_secs: None, last_pass: None,
        }
    }
    pub fn with_theme(mut self, t: Theme)          -> Self { self.theme = t; self }
    pub fn with_state(mut self, s: CrackState)     -> Self { self.state = s; self }
    pub fn with_target(mut self, b: &'a str, e: &'a str) -> Self { self.bssid = b; self.essid = e; self }
    pub fn with_tried(mut self, n: u64)            -> Self { self.tried = n; self }
    pub fn with_total(mut self, n: u64)            -> Self { self.total = n; self }
    pub fn with_speed(mut self, s: f64)            -> Self { self.speed_wps = s; self }
    pub fn with_eta(mut self, e: Option<u64>)      -> Self { self.eta_secs = e; self }
    pub fn with_password(mut self, p: &'a str)     -> Self { self.last_pass = Some(p); self }

    pub fn render(self, f: &mut Frame, area: Rect) {
        let state_col = match self.state {
            CrackState::Found     => self.theme.success(),
            CrackState::Exhausted => self.theme.danger(),
            CrackState::Running   => self.theme.info(),
            _                     => self.theme.dim(),
        };

        let pct   = if self.total == 0 { 0.0 } else { (self.tried as f64 / self.total as f64).min(1.0) };
        let speed = fmt_speed(self.speed_wps);
        let eta   = fmt_eta(self.eta_secs);

        let block = Block::default()
            .title(format!(
                " Crack  {}  {}  {}  ",
                self.state.label(),
                if self.essid.is_empty() { "—" } else { self.essid },
                if self.bssid.is_empty() { "" } else { self.bssid },
            ))
            .title_style(state_col.add_modifier(Modifier::BOLD))
            .borders(Borders::ALL)
            .border_style(self.theme.border());

        let inner = block.inner(area);
        f.render_widget(block, area);

        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Length(1), Constraint::Length(1)])
            .split(inner);

        // Stats line
        let stats = if self.state == CrackState::Idle {
            Line::from(Span::styled(
                " No crack in progress. Run: air crack -f cap.cap -e ESSID -b BSSID -w wordlist",
                self.theme.dim(),
            ))
        } else if self.state == CrackState::Found {
            Line::from(vec![
                Span::styled(" ✓ PASSWORD: ", self.theme.success().add_modifier(Modifier::BOLD)),
                Span::styled(
                    self.last_pass.unwrap_or("?"),
                    Style::default().fg(self.theme.foreground).add_modifier(Modifier::BOLD),
                ),
            ])
        } else {
            Line::from(vec![
                Span::styled(format!(" tried {:>10}  ", fmt_count(self.tried)), Style::default().fg(self.theme.foreground)),
                Span::styled("│ ", self.theme.dim()),
                Span::styled(format!("speed {}  ", speed), self.theme.info()),
                Span::styled("│ ", self.theme.dim()),
                Span::styled(format!("ETA {}  ", eta), self.theme.primary()),
                Span::styled("│ ", self.theme.dim()),
                Span::styled(format!("{:.1}%", pct * 100.0), self.theme.primary_bold()),
            ])
        };
        f.render_widget(Paragraph::new(stats), rows[0]);

        // Gauge
        let gauge_col = match self.state {
            CrackState::Found     => self.theme.success,
            CrackState::Exhausted => self.theme.danger,
            CrackState::Running   => self.theme.primary,
            _                     => self.theme.dim,
        };
        let gauge = Gauge::default()
            .gauge_style(Style::default().fg(gauge_col).bg(self.theme.background))
            .ratio(pct);
        f.render_widget(gauge, rows[2]);
    }
}

impl Default for CrackPanel<'_> {
    fn default() -> Self { Self::new() }
}

fn fmt_speed(wps: f64) -> String {
    if wps < 1_000.0       { format!("{wps:.0} w/s") }
    else if wps < 1_000_000.0 { format!("{:.1}k w/s", wps/1_000.0) }
    else                    { format!("{:.2}M w/s", wps/1_000_000.0) }
}
fn fmt_eta(eta: Option<u64>) -> String {
    match eta {
        None    => "∞".to_string(),
        Some(s) if s < 60   => format!("{s}s"),
        Some(s) if s < 3600 => format!("{}m{:02}s", s/60, s%60),
        Some(s)             => format!("{}h{:02}m", s/3600, (s%3600)/60),
    }
}
fn fmt_count(n: u64) -> String {
    if n < 1_000        { format!("{n}") }
    else if n < 1_000_000 { format!("{:.1}K", n as f64/1_000.0) }
    else                 { format!("{:.2}M", n as f64/1_000_000.0) }
}
