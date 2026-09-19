//! Serializable domain models independent of output format.

use std::fmt;

use serde::Serialize;

/// A completed inspection result.
#[derive(Debug, Serialize)]
pub struct Binary {
    /// The recognized file format.
    pub format: FileFormat,
    /// Basic metadata obtained from the filesystem.
    pub file: FileMetadata,
    /// ELF identification and header fields.
    pub elf: ElfHeader,
}

/// The inspected file format.
#[derive(Debug, Serialize)]
pub enum FileFormat {
    /// Executable and Linkable Format.
    Elf,
}

/// Safe filesystem metadata included in a report.
#[derive(Debug, Serialize)]
pub struct FileMetadata {
    /// File length in bytes at read time.
    pub size_bytes: u64,
}

/// ELF header fields reported by Phase 1.
#[derive(Debug, Serialize)]
pub struct ElfHeader {
    /// ELF word size.
    pub class: ElfClass,
    /// Byte order used by numeric ELF fields.
    pub endianness: Endianness,
    /// ELF object type.
    pub elf_type: ElfType,
    /// Target instruction-set architecture.
    pub machine: Machine,
    /// Target operating-system ABI.
    pub os_abi: OsAbi,
    /// ABI version byte from the ELF identifier.
    pub abi_version: u8,
    /// Program entry address.
    pub entry_point: u64,
}

/// ELF class from `EI_CLASS`.
#[derive(Debug, Serialize)]
pub enum ElfClass {
    /// 32-bit ELF.
    Elf32,
    /// 64-bit ELF.
    Elf64,
}

impl fmt::Display for ElfClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Elf32 => "ELF32",
            Self::Elf64 => "ELF64",
        })
    }
}

/// ELF byte order from `EI_DATA`.
#[derive(Debug, Serialize)]
pub enum Endianness {
    /// Little-endian encoding.
    Little,
    /// Big-endian encoding.
    Big,
}

impl fmt::Display for Endianness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Little => "little-endian",
            Self::Big => "big-endian",
        })
    }
}

/// ELF object type.
#[derive(Debug, Serialize)]
pub enum ElfType {
    /// Relocatable object.
    Relocatable,
    /// Executable object.
    Executable,
    /// Shared object.
    Shared,
    /// Core dump.
    Core,
    /// An unrecognized standardized or processor-specific value.
    Other(u16),
}

impl fmt::Display for ElfType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Relocatable => formatter.write_str("relocatable"),
            Self::Executable => formatter.write_str("executable"),
            Self::Shared => formatter.write_str("shared object"),
            Self::Core => formatter.write_str("core"),
            Self::Other(value) => write!(formatter, "other ({value:#x})"),
        }
    }
}

/// Common ELF machine values, retaining unknown values losslessly.
#[derive(Debug, Serialize)]
pub enum Machine {
    /// Intel 80386.
    X86,
    /// AMD x86-64.
    X86_64,
    /// 32-bit ARM.
    Arm,
    /// AArch64.
    Aarch64,
    /// RISC-V.
    RiscV,
    /// An unrecognized machine value.
    Other(u16),
}

impl fmt::Display for Machine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X86 => formatter.write_str("Intel 80386"),
            Self::X86_64 => formatter.write_str("x86-64"),
            Self::Arm => formatter.write_str("ARM"),
            Self::Aarch64 => formatter.write_str("AArch64"),
            Self::RiscV => formatter.write_str("RISC-V"),
            Self::Other(value) => write!(formatter, "other ({value:#x})"),
        }
    }
}

/// ELF OS ABI value, retaining unknown values losslessly.
#[derive(Debug, Serialize)]
pub enum OsAbi {
    /// System V ABI.
    SystemV,
    /// GNU extension ABI.
    Gnu,
    /// Linux ABI alias.
    Linux,
    /// FreeBSD ABI.
    FreeBsd,
    /// An unrecognized OS ABI value.
    Other(u8),
}

impl fmt::Display for OsAbi {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SystemV => formatter.write_str("System V"),
            Self::Gnu => formatter.write_str("GNU"),
            Self::Linux => formatter.write_str("Linux"),
            Self::FreeBsd => formatter.write_str("FreeBSD"),
            Self::Other(value) => write!(formatter, "other ({value:#x})"),
        }
    }
}
