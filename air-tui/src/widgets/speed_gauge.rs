//! SpeedGauge — animated progress bar with speed + ETA labels.
//! Pattern: Builder — chain .with_*() calls before rendering.

use ratatui::{
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Gauge, Paragraph},
    Frame,
};
use crate::theme::Theme;

pub struct SpeedGauge<'a> {
    theme:     Theme,
    title:     &'a str,
    ratio:     f64,     // 0.0..=1.0
    tried:     u64,
    speed_wps: f64,
    eta:       Option<u64>,
    label:     Option<&'a str>,
}

impl<'a> SpeedGauge<'a> {
    pub fn new() -> Self {
        Self {
            theme:     Theme::AIR,
            title:     " Progress ",
            ratio:     0.0,
            tried:     0,
            speed_wps: 0.0,
            eta:       None,
            label:     None,
        }
    }

    pub fn with_theme(mut self, t: Theme) -> Self       { self.theme = t; self }
    pub fn with_title(mut self, t: &'a str) -> Self     { self.title = t; self }
    pub fn with_ratio(mut self, r: f64) -> Self         { self.ratio = r.clamp(0.0, 1.0); self }
    pub fn with_tried(mut self, n: u64) -> Self         { self.tried = n; self }
    pub fn with_speed(mut self, s: f64) -> Self         { self.speed_wps = s; self }
    pub fn with_eta(mut self, e: Option<u64>) -> Self   { self.eta = e; self }
    pub fn with_label(mut self, l: &'a str) -> Self     { self.label = Some(l); self }

    pub fn render(self, f: &mut Frame, area: Rect) {
        use ratatui::layout::{Constraint, Direction, Layout};

        let pct = (self.ratio * 100.0) as u16;

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Length(1), Constraint::Length(1)])
            .split(area);

        // Stats line
        let speed_str = fmt_speed(self.speed_wps);
        let eta_str   = fmt_eta(self.eta);
        let stats = Line::from(vec![
            Span::styled(format!(" tried {:>12} ", fmt_count(self.tried)), Style::default().fg(self.theme.foreground)),
            Span::styled("│ ", self.theme.dim()),
            Span::styled(format!("speed {speed_str} "), self.theme.info()),
            Span::styled("│ ", self.theme.dim()),
            Span::styled(format!("ETA {eta_str} "), self.theme.primary()),
            Span::styled("│ ", self.theme.dim()),
            Span::styled(format!("{pct}%"), self.theme.primary_bold()),
        ]);
        f.render_widget(Paragraph::new(stats), chunks[0]);

        // Progress bar
        let gauge = Gauge::default()
            .gauge_style(Style::default().fg(self.theme.primary).bg(self.theme.background))
            .ratio(self.ratio)
            .label(self.label.unwrap_or(""));
        f.render_widget(gauge, chunks[1]);
    }
}

impl Default for SpeedGauge<'_> {
    fn default() -> Self { Self::new() }
}

fn fmt_speed(wps: f64) -> String {
    if wps < 1_000.0       { format!("{wps:.0} w/s") }
    else if wps < 1_000_000.0 { format!("{:.1}k w/s", wps / 1_000.0) }
    else                    { format!("{:.2}M w/s", wps / 1_000_000.0) }
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
    else if n < 1_000_000 { format!("{:.1}K", n as f64 / 1_000.0) }
    else                 { format!("{:.2}M", n as f64 / 1_000_000.0) }
}
