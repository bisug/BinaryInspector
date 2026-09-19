//! Application error types and process-exit classification.

use std::{fmt, io};

/// A failure encountered while inspecting a file.
#[derive(Debug)]
pub enum AppError {
    /// The input could not be read safely.
    Io(io::Error),
    /// The input is not a supported, valid ELF binary.
    Parse(String),
}

impl AppError {
    /// Returns the documented process exit code for this error.
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::Io(_) => 2,
            Self::Parse(_) => 3,
        }
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Parse(message) => write!(formatter, "parse error: {message}"),
        }
    }
}

impl std::error::Error for AppError {}

impl From<io::Error> for AppError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
