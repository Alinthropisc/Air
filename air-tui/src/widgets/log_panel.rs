//! LogPanel — scrollable log ring buffer viewer.
//! Pattern: Builder — configure via .with_*() chain.

use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem},
    Frame,
};
use crate::theme::Theme;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel { Info, Warn, Error, Success }

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub level:   LogLevel,
    pub ts:      String,
    pub message: String,
}

pub struct LogPanel<'a> {
    theme:   Theme,
    title:   &'a str,
    entries: &'a [LogEntry],
    scroll:  usize,
}

impl<'a> LogPanel<'a> {
    pub fn new(entries: &'a [LogEntry]) -> Self {
        Self { theme: Theme::AIR, title: " Log ", entries, scroll: 0 }
    }
    pub fn with_theme(mut self, t: Theme) -> Self   { self.theme = t; self }
    pub fn with_title(mut self, t: &'a str) -> Self { self.title = t; self }
    pub fn with_scroll(mut self, s: usize) -> Self  { self.scroll = s; self }

    pub fn render(self, f: &mut Frame, area: Rect) {
        let visible = area.height.saturating_sub(2) as usize;
        let items: Vec<ListItem> = self.entries
            .iter()
            .skip(self.scroll)
            .take(visible.max(1))
            .map(|e| {
                let (pfx, sty) = match e.level {
                    LogLevel::Info    => (" INFO ", self.theme.dim()),
                    LogLevel::Warn    => (" WARN ", self.theme.primary()),
                    LogLevel::Error   => (" ERR  ", self.theme.danger()),
                    LogLevel::Success => (" OK   ", self.theme.success()),
                };
                ListItem::new(Line::from(vec![
                    Span::styled(e.ts.clone(),      self.theme.dim()),
                    Span::styled(pfx, sty.add_modifier(Modifier::BOLD)),
                    Span::styled(e.message.clone(), Style::default().fg(self.theme.foreground)),
                ]))
            })
            .collect();

        f.render_widget(
            List::new(items).block(
                Block::default()
                    .title(format!("{} ({} entries) ↑↓ scroll", self.title, self.entries.len()))
                    .title_style(self.theme.primary())
                    .borders(Borders::ALL)
                    .border_style(self.theme.border()),
            ),
            area,
        );
    }
}
