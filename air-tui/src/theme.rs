//! Air brand theme — gold on black palette.
//! Pattern: Value Object — immutable, comparable by value.

use ratatui::style::{Color, Modifier, Style};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    pub primary:    Color,
    pub background: Color,
    pub foreground: Color,
    pub dim:        Color,
    pub success:    Color,
    pub warning:    Color,
    pub danger:     Color,
    pub info:       Color,
}

impl Theme {
    /// Air brand: gold `#C8A23C` on black `#0D0D0D`.
    pub const AIR: Self = Self {
        primary:    Color::Rgb(200, 162, 60),
        background: Color::Rgb(13, 13, 13),
        foreground: Color::White,
        dim:        Color::Rgb(100, 100, 100),
        success:    Color::Rgb(60, 200, 100),
        warning:    Color::Rgb(200, 162, 60),
        danger:     Color::Rgb(220, 60, 60),
        info:       Color::Rgb(60, 180, 200),
    };

    /// High-contrast light theme (for bright terminals).
    pub const LIGHT: Self = Self {
        primary:    Color::Rgb(160, 120, 20),
        background: Color::White,
        foreground: Color::Black,
        dim:        Color::Rgb(130, 130, 130),
        success:    Color::Rgb(20, 160, 60),
        warning:    Color::Rgb(160, 120, 20),
        danger:     Color::Rgb(180, 20, 20),
        info:       Color::Rgb(20, 120, 160),
    };

    pub fn base(&self) -> Style {
        Style::default().fg(self.foreground).bg(self.background)
    }

    pub fn primary(&self) -> Style {
        Style::default().fg(self.primary)
    }

    pub fn primary_bold(&self) -> Style {
        Style::default().fg(self.primary).add_modifier(Modifier::BOLD)
    }

    pub fn highlight(&self) -> Style {
        Style::default().fg(self.background).bg(self.primary).add_modifier(Modifier::BOLD)
    }

    pub fn dim(&self) -> Style {
        Style::default().fg(self.dim)
    }

    pub fn success(&self) -> Style {
        Style::default().fg(self.success)
    }

    pub fn danger(&self) -> Style {
        Style::default().fg(self.danger)
    }

    pub fn info(&self) -> Style {
        Style::default().fg(self.info)
    }

    pub fn border(&self) -> Style {
        Style::default().fg(self.primary)
    }
}

impl Default for Theme {
    fn default() -> Self { Self::AIR }
}
