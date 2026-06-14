//! Renderer — Facade pattern: hides terminal setup/teardown.

use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;

pub struct Renderer {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
}

impl Renderer {
    /// Enter alternate screen + raw mode. Must call `drop()` or `shutdown()`.
    pub fn init() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend  = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;
        Ok(Self { terminal })
    }

    pub fn terminal(&mut self) -> &mut Terminal<CrosstermBackend<io::Stdout>> {
        &mut self.terminal
    }

    /// Restore terminal on shutdown.
    pub fn shutdown(&mut self) {
        disable_raw_mode().ok();
        execute!(
            self.terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture,
        ).ok();
        self.terminal.show_cursor().ok();
    }
}

impl Drop for Renderer {
    fn drop(&mut self) { self.shutdown(); }
}
