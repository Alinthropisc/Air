//! StatusBar — bottom one-liner with live stats.

use ratatui::{layout::Rect, text::Line, widgets::Paragraph, Frame};
use crate::theme::Theme;

pub struct StatusBar<'a> {
    theme:    Theme,
    iface:    Option<&'a str>,
    scanning: bool,
    ap_count: usize,
    clients:  usize,
    attacks:  usize,
    update:   bool,
    keys:     &'a str,
}

impl<'a> StatusBar<'a> {
    pub fn new() -> Self {
        Self {
            theme: Theme::AIR, iface: None, scanning: false,
            ap_count: 0, clients: 0, attacks: 0, update: false,
            keys: "q:quit  Tab:switch  ↑↓:nav  1-5:tabs",
        }
    }

    pub fn with_theme(mut self, t: Theme)       -> Self { self.theme = t; self }
    pub fn with_iface(mut self, i: &'a str)     -> Self { self.iface = Some(i); self }
    pub fn with_scanning(mut self, s: bool)     -> Self { self.scanning = s; self }
    pub fn with_ap_count(mut self, n: usize)    -> Self { self.ap_count = n; self }
    pub fn with_clients(mut self, n: usize)     -> Self { self.clients = n; self }
    pub fn with_attacks(mut self, n: usize)     -> Self { self.attacks = n; self }
    pub fn with_update(mut self, u: bool)       -> Self { self.update = u; self }
    pub fn with_keys(mut self, k: &'a str)      -> Self { self.keys = k; self }

    pub fn render(self, f: &mut Frame, area: Rect) {
        let iface    = self.iface.unwrap_or("none");
        let scan_sym = if self.scanning { "◉" } else { "○" };
        let upd      = if self.update   { "  ● UPDATE" } else { "" };

        let text = format!(
            " {scan_sym} iface:{iface}  APs:{}  clients:{}  attacks:{}{upd}  │  {}",
            self.ap_count, self.clients, self.attacks, self.keys
        );

        f.render_widget(
            Paragraph::new(Line::from(text))
                .style(self.theme.primary().bg(self.theme.background)),
            area,
        );
    }
}

impl Default for StatusBar<'_> {
    fn default() -> Self { Self::new() }
}
