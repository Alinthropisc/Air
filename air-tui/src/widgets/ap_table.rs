//! ApTable — sortable AP list widget. Builder pattern.

use ratatui::{
    layout::Rect,
    style::Style,
    text::Line,
    widgets::{Block, Borders, Cell, Row, Table, TableState},
    Frame,
};
use crate::theme::Theme;

#[derive(Debug, Clone)]
pub struct ApRow {
    pub bssid:    String,
    pub essid:    String,
    pub channel:  u8,
    pub power:    i32,
    pub privacy:  String,
    pub clients:  usize,
    pub band:     String,
    pub handshake: bool,
}

pub struct ApTable<'a> {
    theme:  Theme,
    title:  &'a str,
    rows:   &'a [ApRow],
    state:  &'a mut TableState,
}

impl<'a> ApTable<'a> {
    pub fn new(rows: &'a [ApRow], state: &'a mut TableState) -> Self {
        Self { theme: Theme::AIR, title: " Access Points ", rows, state }
    }

    pub fn with_theme(mut self, t: Theme) -> Self   { self.theme = t; self }
    pub fn with_title(mut self, t: &'a str) -> Self { self.title = t; self }

    pub fn render(self, f: &mut Frame, area: Rect) {
        use ratatui::layout::Constraint;

        let header = Row::new(vec![
            Cell::from("HS").style(self.theme.primary_bold()),
            Cell::from("ESSID").style(self.theme.primary_bold()),
            Cell::from("BSSID").style(self.theme.primary_bold()),
            Cell::from("CH").style(self.theme.primary_bold()),
            Cell::from("PWR").style(self.theme.primary_bold()),
            Cell::from("ENC").style(self.theme.primary_bold()),
            Cell::from("CLT").style(self.theme.primary_bold()),
            Cell::from("BAND").style(self.theme.primary_bold()),
        ]).height(1);

        let data_rows: Vec<Row> = self.rows.iter().map(|r| {
            let hs = if r.handshake { "✓" } else { " " };
            let hs_style = if r.handshake { self.theme.success() } else { self.theme.dim() };
            let essid = trunc(&r.essid, 20);
            let pwr_col = match r.power {
                p if p >= -50 => self.theme.success(),
                p if p >= -65 => self.theme.primary(),
                p if p >= -80 => Style::default().fg(ratatui::style::Color::Rgb(200, 120, 60)),
                _             => self.theme.danger(),
            };
            let enc_style = match r.privacy.as_str() {
                "OPN"  => self.theme.danger(),
                "WEP"  => Style::default().fg(ratatui::style::Color::Rgb(200, 100, 60)),
                "WPA"  => self.theme.primary(),
                "WPA2" => self.theme.info(),
                "WPA3" => self.theme.success(),
                _      => self.theme.dim(),
            };
            Row::new(vec![
                Cell::from(hs).style(hs_style),
                Cell::from(essid).style(Style::default().fg(self.theme.foreground)),
                Cell::from(r.bssid.clone()).style(self.theme.dim()),
                Cell::from(r.channel.to_string()).style(self.theme.info()),
                Cell::from(format!("{}dBm", r.power)).style(pwr_col),
                Cell::from(r.privacy.clone()).style(enc_style),
                Cell::from(r.clients.to_string()).style(Style::default().fg(self.theme.foreground)),
                Cell::from(r.band.clone()).style(self.theme.dim()),
            ])
        }).collect();

        let table = Table::new(
            data_rows,
            [
                Constraint::Length(2),
                Constraint::Length(21),
                Constraint::Length(18),
                Constraint::Length(4),
                Constraint::Length(8),
                Constraint::Length(6),
                Constraint::Length(4),
                Constraint::Length(7),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .title(format!("{} ({} APs) ", self.title, self.rows.len()))
                .title_style(self.theme.primary())
                .borders(Borders::ALL)
                .border_style(self.theme.border()),
        )
        .row_highlight_style(self.theme.highlight())
        .highlight_symbol("► ");

        f.render_stateful_widget(table, area, self.state);
    }
}

fn trunc(s: &str, max: usize) -> String {
    if s.chars().count() <= max { s.to_string() }
    else { s.chars().take(max - 1).collect::<String>() + "…" }
}
