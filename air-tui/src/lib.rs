//! air-tui — reusable ratatui widget library for the Air toolkit.
//!
//! Design patterns:
//!   Builder  — each widget built via `Widget::new().with_*()`
//!   Strategy — `Theme` is swappable; default = Air brand (gold/black)
//!   Composite— `Dashboard` composes multiple widgets into one Frame call
//!   Facade   — `Renderer::render()` hides terminal setup boilerplate

pub mod theme;
pub mod logo;
pub mod widgets;
pub mod renderer;

pub use theme::Theme;
pub use logo::DRAGON_LOGO;
