//! SplashScreen — brand splash shown on startup for ~1.5s.

use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::Modifier,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};
use crate::{logo::DRAGON_LOGO, theme::Theme};

pub struct SplashScreen {
    theme:   Theme,
    version: String,
}

impl SplashScreen {
    pub fn new(version: impl Into<String>) -> Self {
        Self { theme: Theme::AIR, version: version.into() }
    }
    pub fn with_theme(mut self, t: Theme) -> Self { self.theme = t; self }

    pub fn render(&self, f: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(self.theme.border());
        let inner = block.inner(area);
        f.render_widget(block, area);

        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(3)])
            .split(inner);

        // Logo
        let logo_lines: Vec<Line> = DRAGON_LOGO
            .lines()
            .map(|l| Line::from(Span::styled(l, self.theme.primary_bold())))
            .collect();
        f.render_widget(
            Paragraph::new(logo_lines).alignment(Alignment::Center),
            rows[0],
        );

        // Version line
        let ver_lines = vec![
            Line::from(Span::styled(
                format!("  v{}  ─── async Wi-Fi Auditing Toolkit", self.version),
                self.theme.dim(),
            )),
            Line::from(Span::styled(
                "  C23 + Rust 2024 · WPA · WPA2 · WEP · PMKID · bruteforce",
                self.theme.primary().add_modifier(Modifier::BOLD),
            )),
        ];
        f.render_widget(
            Paragraph::new(ver_lines).alignment(Alignment::Center),
            rows[1],
        );
    }
}
