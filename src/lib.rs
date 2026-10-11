#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Safe parsing and reporting primitives for binary inspection.

pub mod cli;
pub mod elf;
pub mod error;
pub mod hash;
pub mod input;
pub mod model;
pub mod pe;
pub mod report;
pub mod text;

use std::path::Path;

use error::AppError;
use model::Binary;

/// Inspects one regular executable file (ELF or PE) without executing or loading it.
pub fn inspect(path: &Path) -> Result<Binary, AppError> {
    let bytes = input::read_regular_file(path)?;
    inspect_bytes(&bytes, bytes.len() as u64)
}

/// Inspects raw executable binary bytes directly.
pub fn inspect_bytes(bytes: &[u8], file_size: u64) -> Result<Binary, AppError> {
    if bytes.starts_with(b"\x7fELF") {
        elf::parse(bytes, file_size)
    } else if bytes.starts_with(b"MZ") {
        pe::parse(bytes, file_size)
    } else {
        Err(AppError::Parse(error::ParseError::InvalidMagic))
    }
}
