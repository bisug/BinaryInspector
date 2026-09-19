#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Safe parsing and reporting primitives for ELF binary inspection.

pub mod cli;
pub mod elf;
pub mod error;
pub mod hash;
pub mod input;
pub mod model;
pub mod report;
pub mod text;

use std::path::Path;

use error::AppError;
use model::Binary;

/// Inspects one regular ELF file without executing or loading it.
pub fn inspect(path: &Path) -> Result<Binary, AppError> {
    let bytes = input::read_regular_file(path)?;
    elf::parse(&bytes, bytes.len() as u64)
}
