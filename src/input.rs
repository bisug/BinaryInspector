//! Safe bounded reads of command-line file targets.

use std::{fs, io::Read, path::Path};

use crate::error::AppError;

const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;

/// Reads one regular, non-symlink file into an owned bounded buffer.
pub fn read_regular_file(path: &Path) -> Result<Vec<u8>, AppError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AppError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "target must be a regular, non-symlink file",
        )));
    }
    if metadata.len() > MAX_FILE_BYTES {
        return Err(AppError::Parse(format!(
            "file exceeds the {MAX_FILE_BYTES}-byte inspection limit"
        )));
    }

    let mut file = fs::File::open(path)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(AppError::Parse(format!(
            "file exceeds the {MAX_FILE_BYTES}-byte inspection limit"
        )));
    }
    Ok(bytes)
}
