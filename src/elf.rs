//! Bounded decoding of the ELF identification and header fields.

use crate::{
    error::AppError,
    model::{
        Binary, ElfClass, ElfHeader, ElfType, Endianness, FileFormat, FileMetadata, Machine, OsAbi,
    },
};

const ELF_IDENT_SIZE: usize = 16;

/// Parses Phase 1 ELF metadata from an owned byte buffer.
pub fn parse(bytes: &[u8], size_bytes: u64) -> Result<Binary, AppError> {
    let ident = bytes
        .get(..ELF_IDENT_SIZE)
        .ok_or_else(|| malformed("file is shorter than the ELF identifier"))?;
    if ident.get(..4) != Some(b"\x7fELF") {
        return Err(malformed("not an ELF file"));
    }
    if ident[6] != 1 {
        return Err(malformed("unsupported ELF identifier version"));
    }

    let class = match ident[4] {
        1 => ElfClass::Elf32,
        2 => ElfClass::Elf64,
        value => return Err(malformed(&format!("unsupported ELF class {value}"))),
    };
    let endianness = match ident[5] {
        1 => Endianness::Little,
        2 => Endianness::Big,
        value => return Err(malformed(&format!("unsupported ELF endianness {value}"))),
    };
    let header_size = match class {
        ElfClass::Elf32 => 52,
        ElfClass::Elf64 => 64,
    };
    if bytes.len() < header_size {
        return Err(malformed("file is shorter than its ELF header"));
    }

    if read_u32(bytes, 20, &endianness)? != 1 {
        return Err(malformed("unsupported ELF header version"));
    }
    let declared_header_size = read_u16(
        bytes,
        match class {
            ElfClass::Elf32 => 40,
            ElfClass::Elf64 => 52,
        },
        &endianness,
    )?;
    if usize::from(declared_header_size) != header_size {
        return Err(malformed("invalid ELF header size"));
    }

    let elf_type = elf_type(read_u16(bytes, 16, &endianness)?);
    let machine = machine(read_u16(bytes, 18, &endianness)?);
    let entry_point = match class {
        ElfClass::Elf32 => u64::from(read_u32(bytes, 24, &endianness)?),
        ElfClass::Elf64 => read_u64(bytes, 24, &endianness)?,
    };

    Ok(Binary {
        format: FileFormat::Elf,
        file: FileMetadata { size_bytes },
        elf: ElfHeader {
            class,
            endianness,
            elf_type,
            machine,
            os_abi: os_abi(ident[7]),
            abi_version: ident[8],
            entry_point,
        },
    })
}

fn malformed(message: &str) -> AppError {
    AppError::Parse(format!("malformed ELF: {message}"))
}

fn read_u16(bytes: &[u8], offset: usize, endianness: &Endianness) -> Result<u16, AppError> {
    let slice = bytes
        .get(
            offset
                ..offset
                    .checked_add(2)
                    .ok_or_else(|| malformed("integer overflow"))?,
        )
        .ok_or_else(|| malformed("truncated numeric field"))?;
    let array = [slice[0], slice[1]];
    Ok(match endianness {
        Endianness::Little => u16::from_le_bytes(array),
        Endianness::Big => u16::from_be_bytes(array),
    })
}

fn read_u32(bytes: &[u8], offset: usize, endianness: &Endianness) -> Result<u32, AppError> {
    let slice = bytes
        .get(
            offset
                ..offset
                    .checked_add(4)
                    .ok_or_else(|| malformed("integer overflow"))?,
        )
        .ok_or_else(|| malformed("truncated numeric field"))?;
    let array = [slice[0], slice[1], slice[2], slice[3]];
    Ok(match endianness {
        Endianness::Little => u32::from_le_bytes(array),
        Endianness::Big => u32::from_be_bytes(array),
    })
}

fn read_u64(bytes: &[u8], offset: usize, endianness: &Endianness) -> Result<u64, AppError> {
    let slice = bytes
        .get(
            offset
                ..offset
                    .checked_add(8)
                    .ok_or_else(|| malformed("integer overflow"))?,
        )
        .ok_or_else(|| malformed("truncated numeric field"))?;
    let array = [
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ];
    Ok(match endianness {
        Endianness::Little => u64::from_le_bytes(array),
        Endianness::Big => u64::from_be_bytes(array),
    })
}

fn elf_type(value: u16) -> ElfType {
    match value {
        1 => ElfType::Relocatable,
        2 => ElfType::Executable,
        3 => ElfType::Shared,
        4 => ElfType::Core,
        _ => ElfType::Other(value),
    }
}

fn machine(value: u16) -> Machine {
    match value {
        3 => Machine::X86,
        40 => Machine::Arm,
        62 => Machine::X86_64,
        183 => Machine::Aarch64,
        243 => Machine::RiscV,
        _ => Machine::Other(value),
    }
}

fn os_abi(value: u8) -> OsAbi {
    match value {
        0 => OsAbi::SystemV,
        3 => OsAbi::Linux,
        9 => OsAbi::FreeBsd,
        _ => OsAbi::Other(value),
    }
}

#[cfg(test)]
mod tests {
    use super::parse;
    use crate::model::{ElfClass, Endianness, Machine};

    #[test]
    fn parses_a_minimal_little_endian_elf64_header() {
        let mut bytes = [0_u8; 64];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4..9].copy_from_slice(&[2, 1, 1, 0, 0]);
        bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x401000_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());

        let binary = parse(&bytes, 64).unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(binary.elf.class, ElfClass::Elf64));
        assert!(matches!(binary.elf.endianness, Endianness::Little));
        assert!(matches!(binary.elf.machine, Machine::X86_64));
        assert_eq!(binary.elf.entry_point, 0x401000);
    }

    #[test]
    fn rejects_truncated_or_non_elf_data() {
        assert!(parse(&[], 0).is_err());
        assert!(parse(&[0; 16], 16).is_err());
    }
}
