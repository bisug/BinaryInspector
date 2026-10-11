#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Safe parsing and reporting primitives for binary inspection.

pub mod cli;
pub mod elf;
pub mod error;
pub mod hash;
pub mod input;
pub mod macho;
pub mod model;
pub mod pe;
pub mod report;
pub mod text;

use std::path::Path;

use error::AppError;
use model::Binary;

/// Inspects one regular executable file (ELF, PE, Mach-O) without executing or loading it.
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
    } else if bytes.starts_with(b"\xfe\xed\xfa\xce")
        || bytes.starts_with(b"\xce\xfa\xed\xfe")
        || bytes.starts_with(b"\xfe\xed\xfa\xcf")
        || bytes.starts_with(b"\xcf\xfa\xed\xfe")
        || bytes.starts_with(b"\xca\xfe\xba\xbe")
        || bytes.starts_with(b"\xbe\xba\xfe\xca")
        || bytes.starts_with(b"\xca\xfe\xba\xbf")
        || bytes.starts_with(b"\xbf\xba\xfe\xca")
    {
        macho::parse(bytes, file_size)
    } else {
        Err(AppError::Parse(error::ParseError::InvalidMagic))
    }
}
