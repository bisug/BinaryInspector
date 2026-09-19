//! Application error types and process-exit classification.

use std::{fmt, io};

/// Detailed reasons why parsing an ELF binary failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The file is shorter than the minimum ELF header length.
    FileTooShort {
        /// The number of bytes available in the file.
        actual: usize,
        /// The minimum number of bytes required.
        expected: usize,
    },
    /// The file does not begin with the ELF magic bytes `\x7fELF`.
    InvalidMagic,
    /// The ELF specification version is not supported.
    UnsupportedVersion(u8),
    /// The ELF bitness/class is not supported.
    UnsupportedClass(u8),
    /// The ELF data encoding/endianness is not supported.
    UnsupportedEndianness(u8),
    /// An offset or slice extends beyond the bounds of the binary buffer.
    OutOfBounds {
        /// Description of the field or structure being accessed.
        what: &'static str,
        /// Starting offset of the requested slice.
        offset: u64,
        /// Size in bytes of the requested slice.
        size: u64,
    },
    /// Integer overflow occurred during offset or size arithmetic.
    IntegerOverflow(&'static str),
    /// A header, table, or entry contains invalid or malformed field values.
    InvalidHeader {
        /// Component or table name.
        what: &'static str,
        /// Explanation of why the header is invalid.
        detail: String,
    },
    /// A string table entry is malformed or not null-terminated within limits.
    InvalidStringTable(&'static str),
    /// An analysis limit was reached (e.g. max string size, note count, decoded text size).
    LimitExceeded {
        /// Description of the limit.
        what: &'static str,
        /// The maximum allowed value.
        limit: usize,
    },
    /// General malformed or corrupt ELF data.
    Malformed(String),
}

impl ParseError {
    /// Returns a categorized title and actionable remediation advice for UI presentation.
    pub fn guidance(&self) -> (&'static str, &'static str) {
        match self {
            Self::FileTooShort { .. } => (
                "File Too Small",
                "The file is smaller than the minimum 16-byte ELF identification header.",
            ),
            Self::InvalidMagic => (
                "Not an ELF Binary",
                "The file does not start with standard ELF magic (\\x7fELF). Windows (.exe) and macOS (Mach-O) binaries are not supported.",
            ),
            Self::UnsupportedVersion(_) => (
                "Unsupported ELF Version",
                "Only standard ELF version 1 (EV_CURRENT) is supported.",
            ),
            Self::UnsupportedClass(_) => (
                "Unsupported ELF Class",
                "Only ELF32 (32-bit) and ELF64 (64-bit) binary formats are supported.",
            ),
            Self::UnsupportedEndianness(_) => (
                "Unsupported Endianness",
                "Only Little-Endian (ELFDATA2LSB) and Big-Endian (ELFDATA2MSB) formats are supported.",
            ),
            Self::OutOfBounds { .. } => (
                "Corrupted or Truncated Binary",
                "A header, section, or segment offset extends past the end of the file.",
            ),
            Self::IntegerOverflow(_) => (
                "Header Arithmetic Overflow",
                "An offset or table size computation overflowed, indicating a malformed or adversarial header.",
            ),
            Self::InvalidHeader { .. } => (
                "Malformed Header",
                "A header field or table entry violates ELF structural constraints.",
            ),
            Self::InvalidStringTable(_) => (
                "Corrupted String Table",
                "A required string was not null-terminated or exceeded the inspection limit.",
            ),
            Self::LimitExceeded { .. } => (
                "Safety Limit Exceeded",
                "An internal table or string exceeded the safety limit designed to prevent denial-of-service.",
            ),
            Self::Malformed(_) => (
                "Malformed ELF Structure",
                "The binary file failed ELF specification validation.",
            ),
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileTooShort { actual, expected } => write!(
                formatter,
                "file is shorter than the ELF identifier ({actual} bytes, expected at least {expected})"
            ),
            Self::InvalidMagic => write!(formatter, "not an ELF file (missing \\x7fELF magic)"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported ELF identifier version {version}")
            }
            Self::UnsupportedClass(class) => write!(formatter, "unsupported ELF class {class}"),
            Self::UnsupportedEndianness(endianness) => {
                write!(formatter, "unsupported ELF endianness {endianness}")
            }
            Self::OutOfBounds { what, offset, size } => write!(
                formatter,
                "{what} at offset {offset} (size {size} bytes) is outside the file"
            ),
            Self::IntegerOverflow(what) => {
                write!(formatter, "integer overflow calculating {what}")
            }
            Self::InvalidHeader { what, detail } => {
                write!(formatter, "invalid {what}: {detail}")
            }
            Self::InvalidStringTable(what) => {
                write!(formatter, "{what} is unterminated or exceeds inspection limit")
            }
            Self::LimitExceeded { what, limit } => {
                write!(formatter, "{what} exceeds limit of {limit}")
            }
            Self::Malformed(message) => write!(formatter, "{message}"),
        }
    }
}

impl std::error::Error for ParseError {}

/// A failure encountered while inspecting a file.
#[derive(Debug)]
pub enum AppError {
    /// An I/O error encountered while accessing or opening the file.
    Io(io::Error),
    /// The target path is not a regular file (e.g. symlink, directory, FIFO, or socket).
    InvalidFileType(String),
    /// The input file exceeds the safe inspection size limit.
    FileTooLarge {
        /// Actual file size in bytes.
        size: u64,
        /// Maximum allowed file size in bytes.
        limit: u64,
    },
    /// The input is not a supported or valid ELF binary.
    Parse(ParseError),
}

impl AppError {
    /// Returns the documented process exit code for this error.
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::Io(_) | Self::InvalidFileType(_) => 2,
            Self::FileTooLarge { .. } | Self::Parse(_) => 3,
        }
    }

    /// Returns a categorized title and actionable remediation advice for UI presentation.
    pub fn guidance(&self) -> (&'static str, &'static str) {
        match self {
            Self::Io(_) => (
                "Filesystem I/O Error",
                "Could not read the file from disk. Check file existence and read permissions.",
            ),
            Self::InvalidFileType(_) => (
                "Unsupported File Type",
                "BinaryInspector requires regular files. Symlinks, directories, FIFOs, and special devices are not supported.",
            ),
            Self::FileTooLarge { .. } => (
                "File Size Limit Exceeded",
                "The file exceeds the maximum inspection limit (512 MiB).",
            ),
            Self::Parse(parse_err) => parse_err.guidance(),
        }
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::InvalidFileType(message) => write!(formatter, "invalid file: {message}"),
            Self::FileTooLarge { size, limit } => write!(
                formatter,
                "file size ({size} bytes) exceeds inspection limit ({limit} bytes)"
            ),
            Self::Parse(error) => write!(formatter, "parse error: {error}"),
        }
    }
}

impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Parse(error) => Some(error),
            Self::InvalidFileType(_) | Self::FileTooLarge { .. } => None,
        }
    }
}

impl From<io::Error> for AppError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ParseError> for AppError {
    fn from(error: ParseError) -> Self {
        Self::Parse(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_error_guidance_and_display() {
        let err = ParseError::InvalidMagic;
        assert_eq!(err.guidance().0, "Not an ELF Binary");
        assert!(err.to_string().contains("missing \\x7fELF magic"));

        let err = ParseError::FileTooShort {
            actual: 8,
            expected: 16,
        };
        assert_eq!(err.guidance().0, "File Too Small");
        assert!(err.to_string().contains("8 bytes, expected at least 16"));

        let err = ParseError::UnsupportedClass(99);
        assert_eq!(err.guidance().0, "Unsupported ELF Class");
        assert!(err.to_string().contains("unsupported ELF class 99"));

        let err = ParseError::UnsupportedVersion(2);
        assert_eq!(err.guidance().0, "Unsupported ELF Version");

        let err = ParseError::UnsupportedEndianness(3);
        assert_eq!(err.guidance().0, "Unsupported Endianness");

        let err = ParseError::OutOfBounds {
            what: "section header",
            offset: 1000,
            size: 64,
        };
        assert_eq!(err.guidance().0, "Corrupted or Truncated Binary");
        assert!(err.to_string().contains("section header at offset 1000"));

        let err = ParseError::IntegerOverflow("section table offset");
        assert_eq!(err.guidance().0, "Header Arithmetic Overflow");

        let err = ParseError::InvalidHeader {
            what: "program header",
            detail: "entry size too small".to_string(),
        };
        assert_eq!(err.guidance().0, "Malformed Header");

        let err = ParseError::InvalidStringTable("symbol name");
        assert_eq!(err.guidance().0, "Corrupted String Table");

        let err = ParseError::LimitExceeded {
            what: "note entries",
            limit: 8192,
        };
        assert_eq!(err.guidance().0, "Safety Limit Exceeded");

        let err = ParseError::Malformed("invalid segment alignment".to_string());
        assert_eq!(err.guidance().0, "Malformed ELF Structure");
        assert_eq!(err.to_string(), "invalid segment alignment");
    }

    #[test]
    fn test_app_error_exit_codes_and_source() {
        use std::error::Error;

        let io_err = AppError::Io(io::Error::new(io::ErrorKind::NotFound, "file not found"));
        assert_eq!(io_err.exit_code(), 2);
        assert!(io_err.source().is_some());
        assert_eq!(io_err.guidance().0, "Filesystem I/O Error");

        let file_type_err = AppError::InvalidFileType("symbolic links not allowed".to_string());
        assert_eq!(file_type_err.exit_code(), 2);
        assert!(file_type_err.source().is_none());
        assert_eq!(file_type_err.guidance().0, "Unsupported File Type");

        let file_large_err = AppError::FileTooLarge {
            size: 1000,
            limit: 500,
        };
        assert_eq!(file_large_err.exit_code(), 3);
        assert!(file_large_err.source().is_none());
        assert_eq!(file_large_err.guidance().0, "File Size Limit Exceeded");

        let parse_err: AppError = ParseError::InvalidMagic.into();
        assert_eq!(parse_err.exit_code(), 3);
        assert!(parse_err.source().is_some());
        assert_eq!(parse_err.guidance().0, "Not an ELF Binary");
    }
}
