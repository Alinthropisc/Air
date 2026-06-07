pub mod defs;
pub mod wordlist;
pub mod engine;
pub mod cpu;
pub mod memory;
pub mod types;
pub mod globals;
pub mod backend;
pub mod connections;
pub mod interfaces;
pub mod widgets;


/// The main mistake of the project
#[derive(Debug, thiserror::Error)]
pub enum AirError {
    #[error("Memory error: {0}")]
    Memory(String),

    #[error("Engine error: {0}")]
    Engine(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Key not found")]
    NotFound,

    #[error("Invalid parameter: {0}")]
    InvalidParam(String),
}

pub type AirResult<T> = Result<T, AirError>;

































