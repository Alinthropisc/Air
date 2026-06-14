//! Air — async Rust + C23 Wi-Fi auditing toolkit.
//!
//! Architecture (top → bottom):
//!
//! ```text
//!  main.rs / TUI          ← entry points (CLI flags, ratatui event loop)
//!  ┌────────────────────────────────────────────────────┐
//!  │  backend/            async domain logic            │
//!  │    scan     → airodump-ng process + CSV parser     │
//!  │    deauth   → aireplay-ng / mdk4 process manager   │
//!  │    capture  → handshake detect, cap file ops       │
//!  │    inject   → raw packet injection                 │
//!  │    settings → TOML config read/write               │
//!  ├────────────────────────────────────────────────────┤
//!  │  engine.rs           WPA crypto pipeline           │
//!  │    crack_list   → rayon parallel PMK/MIC           │
//!  │    crack_pmkid  → PMKID attack (no handshake)      │
//!  │    crack_channel→ streaming tokio::mpsc channel    │
//!  ├────────────────────────────────────────────────────┤
//!  │  globals.rs          OnceLock<RwLock/Mutex> state  │
//!  │  types.rs            domain Value Objects          │
//!  │  wordlist.rs         async mmap wordlist reader    │
//!  │  memory.rs           AlignedBuffer / BatchPool     │
//!  │  cpu.rs              SIMD/core detection           │
//!  └────────────────────────────────────────────────────┘
//!
//! Design patterns:
//!   Strategy        — SIMD backend dispatch (cpu.rs + engine.rs)
//!   Singleton+Facade— globals::State hides all lock calls
//!   Builder         — ScanConfig, WordlistConfig
//!   Observer        — tokio::broadcast for TUI event bus
//!   Command         — AttackEntry encapsulates running attacks
//!   Value Object    — Ap, Client, Settings (Clone, no identity)

pub mod defs;
pub mod cpu;
pub mod memory;
pub mod types;
pub mod globals;
pub mod wordlist;
pub mod engine;
pub mod backend;
pub mod tui;

use thiserror::Error;

/// Top-level error type — one variant per subsystem.
///
/// Open/Closed: extend with new variants without touching existing callers.
#[derive(Debug, Error)]
pub enum AirError {
    #[error("memory: {0}")]
    Memory(String),

    #[error("engine: {0}")]
    Engine(String),

    #[error("scan: {0}")]
    Scan(String),

    #[error("capture: {0}")]
    Capture(String),

    #[error("deauth: {0}")]
    Deauth(String),

    #[error("crypto: {0}")]
    Crypto(String),

    #[error("config: {0}")]
    Config(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid parameter: {0}")]
    InvalidParam(String),

    #[error("not found")]
    NotFound,
}

pub type AirResult<T> = Result<T, AirError>;

pub use types::*;
pub use globals::State;
