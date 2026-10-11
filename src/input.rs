//! Safe bounded reads of command-line file targets.

use std::{fs, io::Read, path::Path, time::Duration};

use crate::error::AppError;

const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;

/// Reads one regular, non-symlink file into an owned bounded buffer.
pub fn read_regular_file(path: &Path) -> Result<Vec<u8>, AppError> {
    let file = open_target(path)?;
    let metadata = file.metadata()?;
    if metadata.file_type().is_symlink() {
        return Err(AppError::InvalidFileType(
            "symbolic links are not accepted".to_string(),
        ));
    }
    if !metadata.is_file() {
        return Err(AppError::InvalidFileType(
            "target must be a regular file (directories, FIFOs, and special devices are not supported)"
                .to_string(),
        ));
    }
    if metadata.len() > MAX_FILE_BYTES {
        return Err(AppError::FileTooLarge {
            size: metadata.len(),
            limit: MAX_FILE_BYTES,
        });
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    let mut take_reader = file.take(MAX_FILE_BYTES + 1);
    let mut chunk = [0u8; 64 * 1024];
    let mut would_block_retries = 0;
    loop {
        match take_reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                would_block_retries = 0;
                bytes.extend_from_slice(&chunk[..n]);
                if bytes.len() as u64 > MAX_FILE_BYTES {
                    return Err(AppError::FileTooLarge {
                        size: bytes.len() as u64,
                        limit: MAX_FILE_BYTES,
                    });
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if would_block_retries >= 100 {
                    return Err(AppError::Io(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "timed out waiting for non-blocking file read to complete",
                    )));
                }
                would_block_retries += 1;
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(AppError::Io(e)),
        }
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_target(path: &Path) -> Result<fs::File, AppError> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .read(true)
        // Prevent symlink traversal and avoid blocking when a path is swapped for a FIFO.
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| {
            if error.raw_os_error() == Some(libc::ELOOP) {
                AppError::InvalidFileType("symbolic links are not accepted".to_string())
            } else {
                AppError::Io(error)
            }
        })
}

#[cfg(windows)]
fn open_target(path: &Path) -> Result<fs::File, AppError> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .map_err(|error| {
            if path.is_dir() {
                AppError::InvalidFileType(
                    "target must be a regular file (directories, FIFOs, and special devices are not supported)"
                        .to_string(),
                )
            } else {
                AppError::Io(error)
            }
        })
}

#[cfg(not(any(unix, windows)))]
fn open_target(path: &Path) -> Result<fs::File, AppError> {
    Ok(fs::File::open(path)?)
}

#[cfg(all(test, unix))]
mod tests {
    use std::{env, fs, os::unix::fs::symlink, process};

    use super::read_regular_file;

    #[test]
    fn rejects_a_symlink() {
        let directory = env::temp_dir().join(format!("binary-inspector-{}", process::id()));
        fs::create_dir_all(&directory).unwrap_or_else(|error| panic!("{error}"));
        let target = directory.join("target");
        let link = directory.join("link");
        fs::write(&target, b"data").unwrap_or_else(|error| panic!("{error}"));
        symlink(&target, &link).unwrap_or_else(|error| panic!("{error}"));

        let err = read_regular_file(&link).expect_err("symlink must fail");
        assert!(matches!(err, crate::error::AppError::InvalidFileType(_)));
        fs::remove_dir_all(directory).unwrap_or_else(|error| panic!("{error}"));
    }

    #[test]
    fn rejects_a_directory() {
        let directory = env::temp_dir().join(format!("binary-inspector-dir-{}", process::id()));
        fs::create_dir_all(&directory).unwrap_or_else(|error| panic!("{error}"));
        let err = read_regular_file(&directory).expect_err("directory must fail");
        assert!(matches!(err, crate::error::AppError::InvalidFileType(_)));
        fs::remove_dir_all(directory).unwrap_or_else(|error| panic!("{error}"));
    }
}
