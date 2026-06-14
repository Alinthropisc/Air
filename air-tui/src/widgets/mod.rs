//! Reusable TUI widgets — Builder pattern for each.

pub mod speed_gauge;
pub mod ap_table;
pub mod log_panel;
pub mod status_bar;
pub mod crack_panel;
pub mod splash;

pub use speed_gauge::SpeedGauge;
pub use ap_table::ApTable;
pub use log_panel::LogPanel;
pub use status_bar::StatusBar;
pub use crack_panel::CrackPanel;
pub use splash::SplashScreen;
