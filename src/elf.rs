//! Bounded decoding of ELF headers, sections, and program segments.

use crate::{
    error::AppError,
    model::{
        Binary, ElfClass, ElfHeader, ElfType, Endianness, FileFormat, FileMetadata, Machine, OsAbi,
        Section, Segment,
    },
    text::escape_bytes,
};

const ELF_IDENT_SIZE: usize = 16;
const MAX_TABLE_ENTRIES: u16 = 65_534;

/// Parses Phase 1 and 2 ELF metadata from an owned byte buffer.
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
    let layout = Layout::read(bytes, &class, &endianness)?;
    let sections = parse_sections(bytes, &class, &endianness, &layout)?;
    let segments = parse_segments(bytes, &class, &endianness, &layout)?;

    Ok(Binary {
        format: FileFormat::Elf,
        file: FileMetadata { size_bytes },
        elf: ElfHeader {
            class,
            endianness,
            elf_type: elf_type(read_u16(bytes, 16, &layout.endianness)?),
            machine: machine(read_u16(bytes, 18, &layout.endianness)?),
            os_abi: os_abi(ident[7]),
            abi_version: ident[8],
            entry_point: layout.entry_point,
        },
        sections,
        segments,
    })
}

#[derive(Debug)]
struct Layout {
    endianness: Endianness,
    entry_point: u64,
    program_offset: u64,
    program_entry_size: u16,
    program_count: u16,
    section_offset: u64,
    section_entry_size: u16,
    section_count: u16,
    section_names_index: u16,
}

impl Layout {
    fn read(bytes: &[u8], class: &ElfClass, endianness: &Endianness) -> Result<Self, AppError> {
        let (
            header_size,
            program_offset_at,
            section_offset_at,
            program_size_at,
            program_count_at,
            section_size_at,
            section_count_at,
            names_at,
        ) = match class {
            ElfClass::Elf32 => (52, 28, 32, 42, 44, 46, 48, 50),
            ElfClass::Elf64 => (64, 32, 40, 54, 56, 58, 60, 62),
        };
        if bytes.len() < header_size {
            return Err(malformed("file is shorter than its ELF header"));
        }
        if read_u32(bytes, 20, endianness)? != 1 {
            return Err(malformed("unsupported ELF header version"));
        }
        if usize::from(read_u16(bytes, header_size - 12, endianness)?) != header_size {
            return Err(malformed("invalid ELF header size"));
        }
        let read_word = |offset| match class {
            ElfClass::Elf32 => read_u32(bytes, offset, endianness).map(u64::from),
            ElfClass::Elf64 => read_u64(bytes, offset, endianness),
        };
        let program_count = read_u16(bytes, program_count_at, endianness)?;
        let section_count = read_u16(bytes, section_count_at, endianness)?;
        let section_names_index = read_u16(bytes, names_at, endianness)?;
        if program_count == u16::MAX
            || section_names_index == u16::MAX
            || (section_count == 0 && read_word(section_offset_at)? != 0)
        {
            return Err(malformed("extended ELF table numbering is unsupported"));
        }
        if program_count > MAX_TABLE_ENTRIES || section_count > MAX_TABLE_ENTRIES {
            return Err(malformed(
                "ELF table entry count exceeds the inspection limit",
            ));
        }
        Ok(Self {
            endianness: match endianness {
                Endianness::Little => Endianness::Little,
                Endianness::Big => Endianness::Big,
            },
            entry_point: read_word(24)?,
            program_offset: read_word(program_offset_at)?,
            program_entry_size: read_u16(bytes, program_size_at, endianness)?,
            program_count,
            section_offset: read_word(section_offset_at)?,
            section_entry_size: read_u16(bytes, section_size_at, endianness)?,
            section_count,
            section_names_index,
        })
    }
}

fn parse_sections(
    bytes: &[u8],
    class: &ElfClass,
    endianness: &Endianness,
    layout: &Layout,
) -> Result<Vec<Section>, AppError> {
    if layout.section_count == 0 {
        return Ok(Vec::new());
    }
    let expected_size = match class {
        ElfClass::Elf32 => 40,
        ElfClass::Elf64 => 64,
    };
    validate_table(
        bytes,
        layout.section_offset,
        layout.section_entry_size,
        layout.section_count,
        expected_size,
        "section",
    )?;
    if layout.section_names_index >= layout.section_count {
        return Err(malformed(
            "section-name table index is outside the section table",
        ));
    }
    let mut raw = Vec::with_capacity(usize::from(layout.section_count));
    for index in 0..layout.section_count {
        let offset = table_offset(layout.section_offset, layout.section_entry_size, index)?;
        raw.push(RawSection::read(bytes, offset, class, endianness)?);
    }
    let names = &raw[usize::from(layout.section_names_index)];
    let string_table = file_slice(bytes, names.offset, names.size, "section-name string table")?;
    raw.into_iter()
        .enumerate()
        .map(|(index, section)| {
            Ok(Section {
                index: index as u16,
                name: string_at(string_table, section.name_offset)?,
                section_type: section.section_type,
                flags: section.flags,
                address: section.address,
                offset: section.offset,
                size: section.size,
            })
        })
        .collect()
}

#[derive(Debug)]
struct RawSection {
    name_offset: u32,
    section_type: u32,
    flags: u64,
    address: u64,
    offset: u64,
    size: u64,
}

impl RawSection {
    fn read(
        bytes: &[u8],
        offset: usize,
        class: &ElfClass,
        endianness: &Endianness,
    ) -> Result<Self, AppError> {
        let word = |at| match class {
            ElfClass::Elf32 => read_u32(
                bytes,
                offset
                    .checked_add(at)
                    .ok_or_else(|| malformed("integer overflow"))?,
                endianness,
            )
            .map(u64::from),
            ElfClass::Elf64 => read_u64(
                bytes,
                offset
                    .checked_add(at)
                    .ok_or_else(|| malformed("integer overflow"))?,
                endianness,
            ),
        };
        Ok(Self {
            name_offset: read_u32(bytes, offset, endianness)?,
            section_type: read_u32(
                bytes,
                offset
                    .checked_add(4)
                    .ok_or_else(|| malformed("integer overflow"))?,
                endianness,
            )?,
            flags: word(8)?,
            address: word(match class {
                ElfClass::Elf32 => 12,
                ElfClass::Elf64 => 16,
            })?,
            offset: word(match class {
                ElfClass::Elf32 => 16,
                ElfClass::Elf64 => 24,
            })?,
            size: word(match class {
                ElfClass::Elf32 => 20,
                ElfClass::Elf64 => 32,
            })?,
        })
    }
}

fn parse_segments(
    bytes: &[u8],
    class: &ElfClass,
    endianness: &Endianness,
    layout: &Layout,
) -> Result<Vec<Segment>, AppError> {
    if layout.program_count == 0 {
        return Ok(Vec::new());
    }
    let expected_size = match class {
        ElfClass::Elf32 => 32,
        ElfClass::Elf64 => 56,
    };
    validate_table(
        bytes,
        layout.program_offset,
        layout.program_entry_size,
        layout.program_count,
        expected_size,
        "program",
    )?;
    (0..layout.program_count)
        .map(|index| {
            let offset = table_offset(layout.program_offset, layout.program_entry_size, index)?;
            let word = |at| match class {
                ElfClass::Elf32 => read_u32(
                    bytes,
                    offset
                        .checked_add(at)
                        .ok_or_else(|| malformed("integer overflow"))?,
                    endianness,
                )
                .map(u64::from),
                ElfClass::Elf64 => read_u64(
                    bytes,
                    offset
                        .checked_add(at)
                        .ok_or_else(|| malformed("integer overflow"))?,
                    endianness,
                ),
            };
            let segment_type = read_u32(bytes, offset, endianness)?;
            let flags = match class {
                ElfClass::Elf32 => read_u32(
                    bytes,
                    offset
                        .checked_add(24)
                        .ok_or_else(|| malformed("integer overflow"))?,
                    endianness,
                )?,
                ElfClass::Elf64 => read_u32(
                    bytes,
                    offset
                        .checked_add(4)
                        .ok_or_else(|| malformed("integer overflow"))?,
                    endianness,
                )?,
            };
            let file_offset = word(match class {
                ElfClass::Elf32 => 4,
                ElfClass::Elf64 => 8,
            })?;
            let file_size = word(match class {
                ElfClass::Elf32 => 16,
                ElfClass::Elf64 => 32,
            })?;
            if file_size != 0 {
                let _ = file_slice(bytes, file_offset, file_size, "segment contents")?;
            }
            Ok(Segment {
                index,
                segment_type,
                flags,
                offset: file_offset,
                virtual_address: word(match class {
                    ElfClass::Elf32 => 8,
                    ElfClass::Elf64 => 16,
                })?,
                file_size,
                memory_size: word(match class {
                    ElfClass::Elf32 => 20,
                    ElfClass::Elf64 => 40,
                })?,
                alignment: word(match class {
                    ElfClass::Elf32 => 28,
                    ElfClass::Elf64 => 48,
                })?,
            })
        })
        .collect()
}

fn validate_table(
    bytes: &[u8],
    offset: u64,
    entry_size: u16,
    count: u16,
    expected: u16,
    name: &str,
) -> Result<(), AppError> {
    if entry_size < expected {
        return Err(malformed(&format!("invalid {name} entry size")));
    }
    let total = u64::from(entry_size)
        .checked_mul(u64::from(count))
        .ok_or_else(|| malformed("integer overflow"))?;
    let _ = file_slice(bytes, offset, total, name)?;
    Ok(())
}

fn table_offset(base: u64, entry_size: u16, index: u16) -> Result<usize, AppError> {
    let offset = base
        .checked_add(
            u64::from(entry_size)
                .checked_mul(u64::from(index))
                .ok_or_else(|| malformed("integer overflow"))?,
        )
        .ok_or_else(|| malformed("integer overflow"))?;
    usize::try_from(offset).map_err(|_| malformed("offset does not fit this host"))
}

fn file_slice<'a>(
    bytes: &'a [u8],
    offset: u64,
    size: u64,
    what: &str,
) -> Result<&'a [u8], AppError> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| malformed("integer overflow"))?;
    let start = usize::try_from(offset).map_err(|_| malformed("offset does not fit this host"))?;
    let end = usize::try_from(end).map_err(|_| malformed("offset does not fit this host"))?;
    bytes
        .get(start..end)
        .ok_or_else(|| malformed(&format!("{what} is outside the file")))
}

fn string_at(table: &[u8], offset: u32) -> Result<String, AppError> {
    let bytes = table
        .get(
            usize::try_from(offset)
                .map_err(|_| malformed("string offset does not fit this host"))?..,
        )
        .ok_or_else(|| malformed("section name is outside its string table"))?;
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| malformed("unterminated section name"))?;
    Ok(escape_bytes(&bytes[..end]))
}

fn malformed(message: &str) -> AppError {
    AppError::Parse(format!("malformed ELF: {message}"))
}

fn read_u16(bytes: &[u8], offset: usize, endianness: &Endianness) -> Result<u16, AppError> {
    let slice = field(bytes, offset, 2)?;
    Ok(match endianness {
        Endianness::Little => u16::from_le_bytes([slice[0], slice[1]]),
        Endianness::Big => u16::from_be_bytes([slice[0], slice[1]]),
    })
}
fn read_u32(bytes: &[u8], offset: usize, endianness: &Endianness) -> Result<u32, AppError> {
    let slice = field(bytes, offset, 4)?;
    Ok(match endianness {
        Endianness::Little => u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]),
        Endianness::Big => u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]),
    })
}
fn read_u64(bytes: &[u8], offset: usize, endianness: &Endianness) -> Result<u64, AppError> {
    let slice = field(bytes, offset, 8)?;
    Ok(match endianness {
        Endianness::Little => u64::from_le_bytes([
            slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
        ]),
        Endianness::Big => u64::from_be_bytes([
            slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
        ]),
    })
}
fn field(bytes: &[u8], offset: usize, size: usize) -> Result<&[u8], AppError> {
    bytes
        .get(
            offset
                ..offset
                    .checked_add(size)
                    .ok_or_else(|| malformed("integer overflow"))?,
        )
        .ok_or_else(|| malformed("truncated numeric field"))
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
        assert!(binary.sections.is_empty());
    }

    #[test]
    fn rejects_truncated_or_non_elf_data() {
        assert!(parse(&[], 0).is_err());
        assert!(parse(&[0; 16], 16).is_err());
    }

    #[test]
    fn parses_sections_and_escapes_their_names() {
        let mut bytes = vec![0_u8; 200];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4..9].copy_from_slice(&[2, 1, 1, 0, 0]);
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[40..48].copy_from_slice(&64_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[58..60].copy_from_slice(&64_u16.to_le_bytes());
        bytes[60..62].copy_from_slice(&2_u16.to_le_bytes());
        bytes[62..64].copy_from_slice(&1_u16.to_le_bytes());
        bytes[128..132].copy_from_slice(&1_u32.to_le_bytes());
        bytes[128 + 24..128 + 32].copy_from_slice(&192_u64.to_le_bytes());
        bytes[128 + 32..128 + 40].copy_from_slice(&8_u64.to_le_bytes());
        bytes[192..200].copy_from_slice(b"\0.bad\x1b\0\0");

        let binary = parse(&bytes, 200).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(binary.sections.len(), 2);
        assert_eq!(binary.sections[1].name, ".bad\\x1B");
    }
}
