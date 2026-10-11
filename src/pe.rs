//! Safe parsing primitives for Portable Executable (PE/COFF) binary inspection.

use std::collections::HashSet;

use crate::{
    error::{AppError, ParseError},
    hash,
    model::{
        Binary, DynamicInfo, ElfNote, FileFormat, FileHashes, FileMetadata, Hardening,
        PeDataDirectory, PeHeader, PeMachine, PeSubsystem, PieStatus, Relocation, Relro, Section,
        SecurityMitigations, Segment, Symbol, SymbolBinding, SymbolTableKind, SymbolType,
        SymbolVisibility,
    },
    text,
};

/// Maximum sections allowed in a single PE binary to guard against resource exhaustion.
const MAX_SECTIONS: usize = 512;
/// Maximum imports allowed to guard against denial of service.
const MAX_IMPORTS: usize = 10_000;
/// Maximum exports allowed to guard against denial of service.
const MAX_EXPORTS: usize = 10_000;
/// Minimum DOS header length.
const DOS_HEADER_LEN: usize = 64;

/// Parses a regular PE binary file without executing it.
pub fn parse(bytes: &[u8], file_len: u64) -> Result<Binary, AppError> {
    if bytes.len() < DOS_HEADER_LEN {
        return Err(ParseError::FileTooShort {
            actual: bytes.len(),
            expected: DOS_HEADER_LEN,
        }
        .into());
    }

    if &bytes[0..2] != b"MZ" {
        return Err(ParseError::InvalidMagic.into());
    }

    // Offset to PE Header is at 0x3C in DOS header
    let pe_offset = read_u32_le(bytes, 0x3c)? as usize;
    if pe_offset + 24 > bytes.len() {
        return Err(ParseError::OutOfBounds {
            what: "PE header signature",
            offset: pe_offset as u64,
            size: 24,
        }
        .into());
    }

    if &bytes[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return Err(ParseError::InvalidHeader {
            what: "PE signature",
            detail: "file has MZ DOS magic but lacks valid PE\\0\\0 signature".to_string(),
        }
        .into());
    }

    let coff_offset = pe_offset + 4;
    let machine_raw = read_u16_le(bytes, coff_offset)?;
    let machine = match machine_raw {
        0x014c => PeMachine::I386,
        0x8664 => PeMachine::Amd64,
        0x01c0 | 0x01c4 => PeMachine::Arm,
        0xaa64 => PeMachine::Arm64,
        0x0200 => PeMachine::Ia64,
        other => PeMachine::Other(other),
    };

    let number_of_sections = read_u16_le(bytes, coff_offset + 2)? as usize;
    if number_of_sections > MAX_SECTIONS {
        return Err(ParseError::LimitExceeded {
            what: "PE section count exceeds safety limit",
            limit: MAX_SECTIONS,
        }
        .into());
    }

    let time_date_stamp = read_u32_le(bytes, coff_offset + 4)?;
    let size_of_optional_header = read_u16_le(bytes, coff_offset + 16)? as usize;
    let characteristics = read_u16_le(bytes, coff_offset + 18)?;

    let opt_offset = coff_offset + 20;
    if opt_offset + size_of_optional_header > bytes.len() {
        return Err(ParseError::OutOfBounds {
            what: "PE optional header",
            offset: opt_offset as u64,
            size: size_of_optional_header as u64,
        }
        .into());
    }

    let (pe_header, raw_sections_offset) = if size_of_optional_header >= 28 {
        parse_optional_header(
            bytes,
            opt_offset,
            size_of_optional_header,
            machine,
            characteristics,
            time_date_stamp,
        )?
    } else {
        return Err(ParseError::InvalidHeader {
            what: "PE optional header",
            detail: "optional header too short for PE executable".to_string(),
        }
        .into());
    };

    // Parse Sections
    let mut sections = Vec::with_capacity(number_of_sections);
    let mut segments = Vec::with_capacity(number_of_sections);
    let mut raw_sections = Vec::with_capacity(number_of_sections);
    let mut rwx_sections_count = 0;

    for i in 0..number_of_sections {
        let sec_offset = raw_sections_offset + i * 40;
        if sec_offset + 40 > bytes.len() {
            return Err(ParseError::OutOfBounds {
                what: "PE section header",
                offset: sec_offset as u64,
                size: 40,
            }
            .into());
        }

        let name_bytes = &bytes[sec_offset..sec_offset + 8];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        let name = text::escape_bytes(&name_bytes[..name_end]);

        let virtual_size = read_u32_le(bytes, sec_offset + 8)? as u64;
        let virtual_address = read_u32_le(bytes, sec_offset + 12)? as u64;
        let size_of_raw_data = read_u32_le(bytes, sec_offset + 16)? as u64;
        let pointer_to_raw_data = read_u32_le(bytes, sec_offset + 20)? as u64;
        let sec_characteristics = read_u32_le(bytes, sec_offset + 36)?;

        let is_write = sec_characteristics & 0x8000_0000 != 0;
        let is_exec = sec_characteristics & 0x2000_0000 != 0;
        let is_read = sec_characteristics & 0x4000_0000 != 0;

        if is_write && is_exec {
            rwx_sections_count += 1;
        }

        // Calculate entropy on raw data if present
        let entropy = if size_of_raw_data > 0 && pointer_to_raw_data < file_len {
            let start = pointer_to_raw_data as usize;
            let end = (pointer_to_raw_data.saturating_add(size_of_raw_data)).min(file_len) as usize;
            if start < end && end <= bytes.len() {
                Some(hash::calculate_entropy(&bytes[start..end]))
            } else {
                None
            }
        } else {
            None
        };

        raw_sections.push(RawPeSection {
            virtual_address: virtual_address as u32,
            virtual_size: virtual_size as u32,
            raw_data_offset: pointer_to_raw_data as u32,
            raw_data_size: size_of_raw_data as u32,
        });

        sections.push(Section {
            index: i as u16,
            name,
            section_type: sec_characteristics,
            flags: sec_characteristics as u64,
            address: pe_header.image_base.saturating_add(virtual_address),
            offset: pointer_to_raw_data,
            size: size_of_raw_data,
            link: 0,
            info: 0,
            alignment: pe_header.section_alignment as u64,
            entry_size: 0,
            entropy,
        });

        // Also map memory allocations as Segment entries
        let mut seg_flags = 0_u32;
        if is_read {
            seg_flags |= 4; // Read
        }
        if is_write {
            seg_flags |= 2; // Write
        }
        if is_exec {
            seg_flags |= 1; // Execute
        }

        segments.push(Segment {
            index: i as u16,
            segment_type: 1, // PT_LOAD equivalent
            flags: seg_flags,
            offset: pointer_to_raw_data,
            virtual_address: pe_header.image_base.saturating_add(virtual_address),
            file_size: size_of_raw_data,
            memory_size: virtual_size.max(size_of_raw_data),
            alignment: pe_header.section_alignment as u64,
        });
    }

    // Dynamic & Imports parsing
    let mut dynamic = DynamicInfo::default();
    let mut symbols = Vec::new();
    let mut fortified_functions = HashSet::new();
    let mut has_canary = false;

    // Check Data Directories:
    // 0 = Export Directory
    // 1 = Import Directory
    // 5 = Base Relocation Directory
    if let Some(import_dir) = pe_header.data_directories.get(1)
        && import_dir.rva > 0
        && import_dir.size > 0
    {
        parse_imports(
            bytes,
            import_dir.rva,
            &raw_sections,
            &mut dynamic,
            &mut symbols,
            &mut has_canary,
            &mut fortified_functions,
        )?;
    }

    if let Some(export_dir) = pe_header.data_directories.first()
        && export_dir.rva > 0
        && export_dir.size > 0
    {
        parse_exports(
            bytes,
            export_dir.rva,
            &raw_sections,
            &mut dynamic,
            &mut symbols,
        )?;
    }

    // Relocations
    let mut relocations = Vec::new();
    if let Some(reloc_dir) = pe_header.data_directories.get(5)
        && reloc_dir.rva > 0
        && reloc_dir.size > 0
    {
        parse_base_relocations(
            bytes,
            reloc_dir.rva,
            reloc_dir.size,
            &raw_sections,
            &mut relocations,
        )?;
    }

    // Checksec & Security Mitigations for PE
    let is_dll = pe_header.characteristics & 0x2000 != 0;
    let has_dynamic_base = pe_header.dll_characteristics & 0x0040 != 0;
    let has_nx_compat = pe_header.dll_characteristics & 0x0100 != 0;

    let pie = if is_dll {
        PieStatus::Dso
    } else if has_dynamic_base {
        PieStatus::Pie
    } else {
        PieStatus::NoPie
    };

    let nx = if has_nx_compat {
        Hardening::Enabled
    } else {
        Hardening::Disabled
    };

    let stack_canary = if has_canary {
        Hardening::Enabled
    } else {
        Hardening::Disabled
    };

    let fortify = if !fortified_functions.is_empty() {
        Hardening::Enabled
    } else {
        Hardening::Disabled
    };

    let mitigations = SecurityMitigations {
        relro: Relro::Unknown,
        stack_canary,
        nx,
        pie,
        fortify,
        fortified_functions: fortified_functions.into_iter().collect(),
        rwx_segments: rwx_sections_count,
        has_insecure_rpath: false,
    };

    // Notes: Look for Rich Header between 0x80 and pe_offset
    let mut notes = Vec::new();
    if let Some(rich_note) = parse_rich_header(bytes, pe_offset) {
        notes.push(rich_note);
    }

    let hashes = FileHashes {
        sha256: hash::sha256_hex(bytes),
    };

    let strings = crate::strings::extract(bytes, &sections, crate::strings::DEFAULT_MIN_LENGTH);

    Ok(Binary {
        format: FileFormat::Pe,
        file: FileMetadata {
            size_bytes: file_len,
        },
        elf: None,
        pe: Some(pe_header),
        macho: None,
        sections,
        segments,
        dynamic,
        symbols,
        mitigations,
        notes,
        relocations,
        strings,
        hashes,
    })
}

#[derive(Clone, Copy)]
struct RawPeSection {
    virtual_address: u32,
    virtual_size: u32,
    raw_data_offset: u32,
    raw_data_size: u32,
}

fn rva_to_file_offset(rva: u32, sections: &[RawPeSection]) -> Option<usize> {
    for sec in sections {
        let size = sec.virtual_size.max(sec.raw_data_size);
        if rva >= sec.virtual_address && rva < sec.virtual_address.saturating_add(size) {
            let offset_in_sec = rva - sec.virtual_address;
            if offset_in_sec < sec.raw_data_size {
                return Some((sec.raw_data_offset.saturating_add(offset_in_sec)) as usize);
            }
        }
    }
    None
}

fn parse_optional_header(
    bytes: &[u8],
    opt_offset: usize,
    opt_size: usize,
    machine: PeMachine,
    characteristics: u16,
    time_date_stamp: u32,
) -> Result<(PeHeader, usize), ParseError> {
    let magic = read_u16_le(bytes, opt_offset)?;
    let is_pe32_plus = match magic {
        0x10b => false,
        0x20b => true,
        _ => {
            return Err(ParseError::InvalidHeader {
                what: "PE optional header magic",
                detail: format!("unknown optional header magic {magic:#06x}"),
            });
        }
    };

    let major_linker = bytes.get(opt_offset + 2).copied().unwrap_or(0);
    let minor_linker = bytes.get(opt_offset + 3).copied().unwrap_or(0);
    let entry_point = read_u32_le(bytes, opt_offset + 16)?;

    let (
        image_base,
        section_alignment,
        file_alignment,
        subsystem,
        dll_characteristics,
        size_of_image,
        size_of_headers,
        checksum,
        num_dirs,
        dirs_offset,
    ) = if is_pe32_plus {
        if opt_size < 112 {
            return Err(ParseError::InvalidHeader {
                what: "PE32+ optional header",
                detail: "truncated optional header for 64-bit image".to_string(),
            });
        }
        let image_base = read_u64_le(bytes, opt_offset + 24)?;
        let sec_align = read_u32_le(bytes, opt_offset + 32)?;
        let file_align = read_u32_le(bytes, opt_offset + 36)?;
        let size_of_img = read_u32_le(bytes, opt_offset + 56)?;
        let size_of_hdrs = read_u32_le(bytes, opt_offset + 60)?;
        let chksum = read_u32_le(bytes, opt_offset + 64)?;
        let sub = read_u16_le(bytes, opt_offset + 68)?;
        let dll_chars = read_u16_le(bytes, opt_offset + 70)?;
        let dirs = read_u32_le(bytes, opt_offset + 108)?;
        (
            image_base,
            sec_align,
            file_align,
            sub,
            dll_chars,
            size_of_img,
            size_of_hdrs,
            chksum,
            dirs,
            opt_offset + 112,
        )
    } else {
        if opt_size < 96 {
            return Err(ParseError::InvalidHeader {
                what: "PE32 optional header",
                detail: "truncated optional header for 32-bit image".to_string(),
            });
        }
        let image_base = read_u32_le(bytes, opt_offset + 28)? as u64;
        let sec_align = read_u32_le(bytes, opt_offset + 32)?;
        let file_align = read_u32_le(bytes, opt_offset + 36)?;
        let size_of_img = read_u32_le(bytes, opt_offset + 56)?;
        let size_of_hdrs = read_u32_le(bytes, opt_offset + 60)?;
        let chksum = read_u32_le(bytes, opt_offset + 64)?;
        let sub = read_u16_le(bytes, opt_offset + 68)?;
        let dll_chars = read_u16_le(bytes, opt_offset + 70)?;
        let dirs = read_u32_le(bytes, opt_offset + 92)?;
        (
            image_base,
            sec_align,
            file_align,
            sub,
            dll_chars,
            size_of_img,
            size_of_hdrs,
            chksum,
            dirs,
            opt_offset + 96,
        )
    };

    let dir_names = [
        "Export Table",
        "Import Table",
        "Resource Table",
        "Exception Table",
        "Certificate Table (Security)",
        "Base Relocation Table",
        "Debug Table",
        "Architecture Data",
        "Global Pointer",
        "TLS Table",
        "Load Config Table",
        "Bound Import Table",
        "Import Address Table (IAT)",
        "Delay Import Table",
        "CLR Runtime Header",
        "Reserved",
    ];

    let mut data_directories = Vec::new();
    let count = (num_dirs as usize).min(dir_names.len());
    for (i, name) in dir_names.iter().enumerate().take(count) {
        let entry_offset = dirs_offset + i * 8;
        if entry_offset + 8 <= bytes.len() {
            let rva = read_u32_le(bytes, entry_offset)?;
            let size = read_u32_le(bytes, entry_offset + 4)?;
            data_directories.push(PeDataDirectory {
                name: (*name).to_string(),
                rva,
                size,
            });
        }
    }

    let subsystem_typed = match subsystem {
        1 => PeSubsystem::Native,
        2 => PeSubsystem::WindowsGui,
        3 => PeSubsystem::WindowsCui,
        7 => PeSubsystem::PosixCui,
        9 => PeSubsystem::WindowsCeGui,
        10 => PeSubsystem::EfiApplication,
        11 => PeSubsystem::EfiBootServiceDriver,
        12 => PeSubsystem::EfiRuntimeDriver,
        other => PeSubsystem::Other(other),
    };

    let pe_header = PeHeader {
        machine,
        characteristics,
        time_date_stamp,
        is_pe32_plus,
        entry_point,
        image_base,
        section_alignment,
        file_alignment,
        subsystem: subsystem_typed,
        dll_characteristics,
        size_of_image,
        size_of_headers,
        checksum,
        linker_version: (major_linker, minor_linker),
        data_directories,
    };

    let raw_sections_offset = opt_offset + opt_size;
    Ok((pe_header, raw_sections_offset))
}

fn parse_imports(
    bytes: &[u8],
    import_rva: u32,
    sections: &[RawPeSection],
    dynamic: &mut DynamicInfo,
    symbols: &mut Vec<Symbol>,
    has_canary: &mut bool,
    fortified_functions: &mut HashSet<String>,
) -> Result<(), ParseError> {
    let mut descriptor_offset = match rva_to_file_offset(import_rva, sections) {
        Some(offset) => offset,
        None => return Ok(()),
    };

    let mut count = 0;
    while descriptor_offset + 20 <= bytes.len() && count < MAX_IMPORTS {
        let original_first_thunk = read_u32_le(bytes, descriptor_offset)?;
        let name_rva = read_u32_le(bytes, descriptor_offset + 12)?;
        let first_thunk = read_u32_le(bytes, descriptor_offset + 16)?;

        // Terminated by null descriptor
        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }

        if let Some(name_offset) = rva_to_file_offset(name_rva, sections)
            && let Some(dll_name) = read_cstring(bytes, name_offset, 256)
        {
            dynamic.needed.push(dll_name.clone());

            let thunk_rva = if original_first_thunk != 0 {
                original_first_thunk
            } else {
                first_thunk
            };

            if let Some(mut thunk_offset) = rva_to_file_offset(thunk_rva, sections) {
                while thunk_offset + 8 <= bytes.len() && symbols.len() < MAX_IMPORTS {
                    let val = read_u64_le(bytes, thunk_offset)?;
                    if val == 0 {
                        break;
                    }

                    // Highest bit indicates ordinal import, else RVA to hint/name
                    let is_ordinal = val & 0x8000_0000_0000_0000 != 0;
                    if !is_ordinal {
                        let name_entry_rva = (val & 0x7fff_ffff) as u32;
                        if let Some(entry_offset) = rva_to_file_offset(name_entry_rva, sections) {
                            // Skip 2 bytes hint
                            if let Some(func_name) = read_cstring(bytes, entry_offset + 2, 256) {
                                if func_name.contains("__security_check_cookie")
                                    || func_name.contains("__security_cookie")
                                {
                                    *has_canary = true;
                                }
                                if func_name.ends_with("_s") || func_name.contains("_chk") {
                                    fortified_functions.insert(func_name.clone());
                                }

                                symbols.push(Symbol {
                                    index: symbols.len(),
                                    name: format!("{dll_name}!{func_name}"),
                                    value: 0,
                                    size: 0,
                                    sym_type: SymbolType::Func,
                                    binding: SymbolBinding::Global,
                                    visibility: SymbolVisibility::Default,
                                    section_index: None,
                                    is_import: true,
                                    is_export: false,
                                    table: SymbolTableKind::Dynamic,
                                });
                            }
                        }
                    }
                    thunk_offset += 8;
                }
            }
        }

        descriptor_offset += 20;
        count += 1;
    }

    Ok(())
}

fn parse_exports(
    bytes: &[u8],
    export_rva: u32,
    sections: &[RawPeSection],
    dynamic: &mut DynamicInfo,
    symbols: &mut Vec<Symbol>,
) -> Result<(), ParseError> {
    let export_offset = match rva_to_file_offset(export_rva, sections) {
        Some(offset) => offset,
        None => return Ok(()),
    };

    if export_offset + 40 > bytes.len() {
        return Ok(());
    }

    let name_rva = read_u32_le(bytes, export_offset + 12)?;
    if let Some(dll_name_offset) = rva_to_file_offset(name_rva, sections)
        && let Some(dll_name) = read_cstring(bytes, dll_name_offset, 256)
    {
        dynamic.interpreter = Some(dll_name);
    }

    let num_functions = read_u32_le(bytes, export_offset + 20)? as usize;
    let num_names = read_u32_le(bytes, export_offset + 24)? as usize;
    let names_rva = read_u32_le(bytes, export_offset + 32)?;

    if let Some(names_table_offset) = rva_to_file_offset(names_rva, sections) {
        let count = num_names.min(num_functions).min(MAX_EXPORTS);
        for i in 0..count {
            let entry_offset = names_table_offset + i * 4;
            if entry_offset + 4 <= bytes.len() {
                let func_name_rva = read_u32_le(bytes, entry_offset)?;
                if let Some(name_offset) = rva_to_file_offset(func_name_rva, sections)
                    && let Some(func_name) = read_cstring(bytes, name_offset, 256)
                {
                    symbols.push(Symbol {
                        index: symbols.len(),
                        name: func_name,
                        value: 0,
                        size: 0,
                        sym_type: SymbolType::Func,
                        binding: SymbolBinding::Global,
                        visibility: SymbolVisibility::Default,
                        section_index: None,
                        is_import: false,
                        is_export: true,
                        table: SymbolTableKind::Dynamic,
                    });
                }
            }
        }
    }

    Ok(())
}

fn parse_base_relocations(
    bytes: &[u8],
    reloc_rva: u32,
    reloc_size: u32,
    sections: &[RawPeSection],
    relocations: &mut Vec<Relocation>,
) -> Result<(), ParseError> {
    let start_offset = match rva_to_file_offset(reloc_rva, sections) {
        Some(offset) => offset,
        None => return Ok(()),
    };

    let max_len = (reloc_size as usize).min(bytes.len().saturating_sub(start_offset));
    let mut cur = start_offset;
    let end = start_offset + max_len;

    while cur + 8 <= end && relocations.len() < 5000 {
        let page_rva = read_u32_le(bytes, cur)? as u64;
        let block_size = read_u32_le(bytes, cur + 4)? as usize;

        if block_size < 8 || cur + block_size > end {
            break;
        }

        let entries_count = (block_size - 8) / 2;
        for i in 0..entries_count {
            let entry_raw = read_u16_le(bytes, cur + 8 + i * 2)?;
            let rel_type = (entry_raw >> 12) as u32;
            let offset_in_page = (entry_raw & 0x0fff) as u64;

            // Type 0 is IMAGE_REL_BASED_ABSOLUTE (padding)
            if rel_type != 0 {
                relocations.push(Relocation {
                    section_name: ".reloc".to_string(),
                    offset: page_rva.saturating_add(offset_in_page),
                    rel_type,
                    symbol_index: 0,
                    symbol_name: None,
                    addend: None,
                });
            }
        }

        cur += block_size;
    }

    Ok(())
}

fn parse_rich_header(bytes: &[u8], pe_offset: usize) -> Option<ElfNote> {
    if pe_offset < 0x80 {
        return None;
    }

    // Look for b"Rich" in DOS stub
    let stub = &bytes[0x40..pe_offset.min(bytes.len())];
    let rich_pos = stub.windows(4).position(|w| w == b"Rich")?;
    let rich_offset = 0x40 + rich_pos;

    if rich_offset + 8 > bytes.len() {
        return None;
    }

    let xor_key = read_u32_le(bytes, rich_offset + 4).ok()?;

    // Rich header starts with DanS XOR-encrypted with key
    let dans_marker = 0x536e6144_u32 ^ xor_key;
    let mut dans_offset = None;

    let mut scan = 0x40;
    while scan + 4 <= rich_offset {
        if let Ok(val) = read_u32_le(bytes, scan)
            && val == dans_marker
        {
            dans_offset = Some(scan);
            break;
        }
        scan += 4;
    }

    let start = dans_offset.unwrap_or(0x80);
    let mut properties = Vec::new();

    // Entries between DanS+16 and Rich are pairs of [comp_id ^ key, count ^ key]
    let mut entry_offset = start + 16;
    while entry_offset + 8 <= rich_offset {
        if let (Ok(comp_id_enc), Ok(count_enc)) = (
            read_u32_le(bytes, entry_offset),
            read_u32_le(bytes, entry_offset + 4),
        ) {
            let comp_id = comp_id_enc ^ xor_key;
            let count = count_enc ^ xor_key;
            let build_id = comp_id & 0xffff;
            let tool_type = (comp_id >> 16) & 0xffff;
            properties.push(format!(
                "Tool 0x{tool_type:04x} (Build {build_id}): {count} invocations"
            ));
        }
        entry_offset += 8;
    }

    Some(ElfNote {
        name: "Rich Header".to_string(),
        note_type: 0x52696368, // 'Rich'
        description: format!("Rich Header: Decrypted with XOR key {xor_key:#010x}"),
        build_id: Some(format!("{xor_key:#010x}")),
        abi_tag: None,
        properties,
    })
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Result<u16, ParseError> {
    if let Some(slice) = bytes.get(offset..offset + 2) {
        Ok(u16::from_le_bytes([slice[0], slice[1]]))
    } else {
        Err(ParseError::OutOfBounds {
            what: "u16_le",
            offset: offset as u64,
            size: 2,
        })
    }
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32, ParseError> {
    if let Some(slice) = bytes.get(offset..offset + 4) {
        Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
    } else {
        Err(ParseError::OutOfBounds {
            what: "u32_le",
            offset: offset as u64,
            size: 4,
        })
    }
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Result<u64, ParseError> {
    if let Some(slice) = bytes.get(offset..offset + 8) {
        Ok(u64::from_le_bytes([
            slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
        ]))
    } else {
        Err(ParseError::OutOfBounds {
            what: "u64_le",
            offset: offset as u64,
            size: 8,
        })
    }
}

fn read_cstring(bytes: &[u8], offset: usize, max_len: usize) -> Option<String> {
    let mut end = offset;
    let limit = (offset + max_len).min(bytes.len());
    while end < limit && bytes[end] != 0 {
        end += 1;
    }
    if end <= bytes.len() {
        Some(text::escape_bytes(&bytes[offset..end]))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_minimal_pe32_plus_binary() {
        // Construct a synthetic 64-bit PE binary
        let mut bytes = vec![0_u8; 1024];
        // DOS header
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes()); // e_lfanew = 0x80

        // PE signature
        let pe = 0x80;
        bytes[pe..pe + 4].copy_from_slice(b"PE\0\0");

        // COFF header
        let coff = pe + 4;
        bytes[coff..coff + 2].copy_from_slice(&0x8664_u16.to_le_bytes()); // AMD64
        bytes[coff + 2..coff + 4].copy_from_slice(&1_u16.to_le_bytes()); // 1 section
        bytes[coff + 16..coff + 18].copy_from_slice(&240_u16.to_le_bytes()); // size of optional header
        bytes[coff + 18..coff + 20].copy_from_slice(&0x0022_u16.to_le_bytes()); // executable + large address

        // Optional header (PE32+)
        let opt = coff + 20;
        bytes[opt..opt + 2].copy_from_slice(&0x20b_u16.to_le_bytes()); // PE32+
        bytes[opt + 16..opt + 20].copy_from_slice(&0x1000_u32.to_le_bytes()); // EntryPoint RVA = 0x1000
        bytes[opt + 24..opt + 32].copy_from_slice(&0x0000_0001_4000_0000_u64.to_le_bytes()); // ImageBase
        bytes[opt + 32..opt + 36].copy_from_slice(&0x1000_u32.to_le_bytes()); // Section alignment
        bytes[opt + 36..opt + 40].copy_from_slice(&0x200_u32.to_le_bytes()); // File alignment
        bytes[opt + 68..opt + 70].copy_from_slice(&3_u16.to_le_bytes()); // Windows CUI (Console)
        bytes[opt + 70..opt + 72].copy_from_slice(&0x0160_u16.to_le_bytes()); // DynamicBase + NXCompat + HighEntropyVA

        // Data directories count = 16
        bytes[opt + 108..opt + 112].copy_from_slice(&16_u32.to_le_bytes());

        // Section header 1
        let sec = opt + 240;
        bytes[sec..sec + 5].copy_from_slice(b".text");
        bytes[sec + 8..sec + 12].copy_from_slice(&0x500_u32.to_le_bytes()); // virtual size
        bytes[sec + 12..sec + 16].copy_from_slice(&0x1000_u32.to_le_bytes()); // virtual address
        bytes[sec + 16..sec + 20].copy_from_slice(&0x200_u32.to_le_bytes()); // raw data size
        bytes[sec + 20..sec + 24].copy_from_slice(&0x400_u32.to_le_bytes()); // raw data offset
        bytes[sec + 36..sec + 40].copy_from_slice(&0x6000_0020_u32.to_le_bytes()); // Code, Execute, Read

        let binary = parse(&bytes, bytes.len() as u64).expect("valid PE");
        assert_eq!(binary.format, FileFormat::Pe);
        assert!(binary.elf.is_none());
        let pe_hdr = binary.pe.as_ref().expect("PE header present");
        assert_eq!(pe_hdr.machine, PeMachine::Amd64);
        assert!(pe_hdr.is_pe32_plus);
        assert_eq!(pe_hdr.entry_point, 0x1000);
        assert_eq!(pe_hdr.subsystem, PeSubsystem::WindowsCui);

        // Mitigations check
        assert_eq!(binary.mitigations.nx, Hardening::Enabled);
        assert_eq!(binary.mitigations.pie, PieStatus::Pie);
        assert_eq!(binary.mitigations.rwx_segments, 0);

        // Sections
        assert_eq!(binary.sections.len(), 1);
        assert_eq!(binary.sections[0].name, ".text");
    }

    #[test]
    fn rejects_truncated_dos_header() {
        assert!(parse(b"MZ", 2).is_err());
    }

    #[test]
    fn rejects_invalid_pe_magic() {
        let mut bytes = vec![0_u8; 128];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x40_u32.to_le_bytes());
        bytes[0x40..0x44].copy_from_slice(b"NE\0\0"); // Not PE
        assert!(parse(&bytes, 128).is_err());
    }

    #[test]
    fn parses_a_minimal_pe32_32bit_binary() {
        let mut bytes = vec![0_u8; 1024];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());

        let pe = 0x80;
        bytes[pe..pe + 4].copy_from_slice(b"PE\0\0");

        let coff = pe + 4;
        bytes[coff..coff + 2].copy_from_slice(&0x014c_u16.to_le_bytes()); // Intel 386
        bytes[coff + 2..coff + 4].copy_from_slice(&1_u16.to_le_bytes()); // 1 section
        bytes[coff + 16..coff + 18].copy_from_slice(&224_u16.to_le_bytes()); // size of optional header
        bytes[coff + 18..coff + 20].copy_from_slice(&0x0102_u16.to_le_bytes()); // 32bit + executable

        let opt = coff + 20;
        bytes[opt..opt + 2].copy_from_slice(&0x10b_u16.to_le_bytes()); // PE32 (32-bit)
        bytes[opt + 16..opt + 20].copy_from_slice(&0x1000_u32.to_le_bytes()); // EntryPoint
        bytes[opt + 28..opt + 32].copy_from_slice(&0x0040_0000_u32.to_le_bytes()); // ImageBase 32-bit
        bytes[opt + 32..opt + 36].copy_from_slice(&0x1000_u32.to_le_bytes()); // Section alignment
        bytes[opt + 36..opt + 40].copy_from_slice(&0x200_u32.to_le_bytes()); // File alignment
        bytes[opt + 68..opt + 70].copy_from_slice(&2_u16.to_le_bytes()); // Windows GUI
        bytes[opt + 70..opt + 72].copy_from_slice(&0x0100_u16.to_le_bytes()); // NX Compat only (No PIE)
        bytes[opt + 92..opt + 96].copy_from_slice(&16_u32.to_le_bytes()); // num dirs

        let sec = opt + 224;
        bytes[sec..sec + 5].copy_from_slice(b".text");
        bytes[sec + 8..sec + 12].copy_from_slice(&0x200_u32.to_le_bytes());
        bytes[sec + 12..sec + 16].copy_from_slice(&0x1000_u32.to_le_bytes());
        bytes[sec + 16..sec + 20].copy_from_slice(&0x200_u32.to_le_bytes());
        bytes[sec + 20..sec + 24].copy_from_slice(&0x400_u32.to_le_bytes());
        bytes[sec + 36..sec + 40].copy_from_slice(&0x6000_0020_u32.to_le_bytes()); // Code, Exec, Read

        let binary = parse(&bytes, 1024).expect("valid PE32");
        assert_eq!(binary.format, FileFormat::Pe);
        let pe_hdr = binary.pe.as_ref().unwrap();
        assert_eq!(pe_hdr.machine, PeMachine::I386);
        assert!(!pe_hdr.is_pe32_plus);
        assert_eq!(pe_hdr.image_base, 0x0040_0000);
        assert_eq!(pe_hdr.subsystem, PeSubsystem::WindowsGui);

        assert_eq!(binary.mitigations.nx, Hardening::Enabled);
        assert_eq!(binary.mitigations.pie, PieStatus::NoPie);
    }

    #[test]
    fn detects_rwx_sections_in_pe() {
        let mut bytes = vec![0_u8; 1024];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());

        let pe = 0x80;
        bytes[pe..pe + 4].copy_from_slice(b"PE\0\0");
        let coff = pe + 4;
        bytes[coff..coff + 2].copy_from_slice(&0x8664_u16.to_le_bytes());
        bytes[coff + 2..coff + 4].copy_from_slice(&1_u16.to_le_bytes());
        bytes[coff + 16..coff + 18].copy_from_slice(&240_u16.to_le_bytes());

        let opt = coff + 20;
        bytes[opt..opt + 2].copy_from_slice(&0x20b_u16.to_le_bytes());
        bytes[opt + 108..opt + 112].copy_from_slice(&16_u32.to_le_bytes());

        let sec = opt + 240;
        bytes[sec..sec + 7].copy_from_slice(b".rwxsec");
        bytes[sec + 8..sec + 12].copy_from_slice(&0x200_u32.to_le_bytes());
        bytes[sec + 12..sec + 16].copy_from_slice(&0x1000_u32.to_le_bytes());
        bytes[sec + 16..sec + 20].copy_from_slice(&0x200_u32.to_le_bytes());
        bytes[sec + 20..sec + 24].copy_from_slice(&0x400_u32.to_le_bytes());
        // 0xe000_0000 = EXECUTE (0x20) | READ (0x40) | WRITE (0x80)
        bytes[sec + 36..sec + 40].copy_from_slice(&0xe000_0020_u32.to_le_bytes());

        let binary = parse(&bytes, 1024).expect("valid PE");
        assert_eq!(binary.mitigations.rwx_segments, 1);
    }

    #[test]
    fn parses_imports_and_detects_stack_canary() {
        let mut bytes = vec![0_u8; 2048];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());

        let pe = 0x80;
        bytes[pe..pe + 4].copy_from_slice(b"PE\0\0");
        let coff = pe + 4;
        bytes[coff..coff + 2].copy_from_slice(&0x8664_u16.to_le_bytes());
        bytes[coff + 2..coff + 4].copy_from_slice(&1_u16.to_le_bytes()); // 1 section
        bytes[coff + 16..coff + 18].copy_from_slice(&240_u16.to_le_bytes());

        let opt = coff + 20;
        bytes[opt..opt + 2].copy_from_slice(&0x20b_u16.to_le_bytes());
        bytes[opt + 108..opt + 112].copy_from_slice(&16_u32.to_le_bytes());
        // Import directory is index 1 (at offset opt + 112 + 8)
        let imp_dir_offset = opt + 112 + 8;
        bytes[imp_dir_offset..imp_dir_offset + 4].copy_from_slice(&0x1000_u32.to_le_bytes()); // Import RVA = 0x1000
        bytes[imp_dir_offset + 4..imp_dir_offset + 8].copy_from_slice(&40_u32.to_le_bytes()); // Size = 40

        // Section .idata mapped at RVA 0x1000, raw offset 0x400, size 0x600
        let sec = opt + 240;
        bytes[sec..sec + 6].copy_from_slice(b".idata");
        bytes[sec + 8..sec + 12].copy_from_slice(&0x600_u32.to_le_bytes());
        bytes[sec + 12..sec + 16].copy_from_slice(&0x1000_u32.to_le_bytes());
        bytes[sec + 16..sec + 20].copy_from_slice(&0x600_u32.to_le_bytes());
        bytes[sec + 20..sec + 24].copy_from_slice(&0x400_u32.to_le_bytes()); // file offset 0x400

        // Now place IMAGE_IMPORT_DESCRIPTOR at raw offset 0x400
        // Descriptor: OriginalFirstThunk RVA = 0x1040, Name RVA = 0x1060, FirstThunk RVA = 0x1040
        let desc = 0x400;
        bytes[desc..desc + 4].copy_from_slice(&0x1040_u32.to_le_bytes()); // OriginalFirstThunk
        bytes[desc + 12..desc + 16].copy_from_slice(&0x1060_u32.to_le_bytes()); // Name RVA (offset 0x460)
        bytes[desc + 16..desc + 20].copy_from_slice(&0x1040_u32.to_le_bytes()); // FirstThunk

        // DLL name at raw offset 0x460 (RVA 0x1060)
        let dll_name_pos = 0x460;
        bytes[dll_name_pos..dll_name_pos + 13].copy_from_slice(b"VCRUNTIME140\0");

        // Thunk at raw offset 0x440 (RVA 0x1040)
        // Entry 1 points to Name RVA 0x1080 (raw offset 0x480)
        let thunk_pos = 0x440;
        bytes[thunk_pos..thunk_pos + 8].copy_from_slice(&0x1080_u64.to_le_bytes());

        // Function hint/name at raw offset 0x480 (RVA 0x1080): 2 bytes hint (0), then "__security_check_cookie\0"
        let name_pos = 0x480;
        bytes[name_pos + 2..name_pos + 2 + 24].copy_from_slice(b"__security_check_cookie\0");

        let binary = parse(&bytes, 2048).expect("valid PE with imports");
        assert_eq!(binary.dynamic.needed.len(), 1);
        assert_eq!(binary.dynamic.needed[0], "VCRUNTIME140");
        assert_eq!(binary.mitigations.stack_canary, Hardening::Enabled);
        assert_eq!(binary.symbols.len(), 1);
        assert_eq!(
            binary.symbols[0].name,
            "VCRUNTIME140!__security_check_cookie"
        );
    }

    #[test]
    fn inspect_bytes_dispatches_pe_and_elf() {
        let mut pe_bytes = vec![0_u8; 1024];
        pe_bytes[0..2].copy_from_slice(b"MZ");
        pe_bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        let pe = 0x80;
        pe_bytes[pe..pe + 4].copy_from_slice(b"PE\0\0");
        let coff = pe + 4;
        pe_bytes[coff..coff + 2].copy_from_slice(&0x8664_u16.to_le_bytes());
        pe_bytes[coff + 16..coff + 18].copy_from_slice(&240_u16.to_le_bytes());
        let opt = coff + 20;
        pe_bytes[opt..opt + 2].copy_from_slice(&0x20b_u16.to_le_bytes());
        pe_bytes[opt + 108..opt + 112].copy_from_slice(&16_u32.to_le_bytes());

        let res = crate::inspect_bytes(&pe_bytes, 1024).expect("PE parsed");
        assert_eq!(res.format, FileFormat::Pe);

        let mut elf_bytes = [0_u8; 64];
        elf_bytes[..4].copy_from_slice(b"\x7fELF");
        elf_bytes[4..9].copy_from_slice(&[2, 1, 1, 0, 0]);
        elf_bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
        elf_bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        elf_bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        elf_bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        let elf_res = crate::inspect_bytes(&elf_bytes, 64).expect("ELF parsed");
        assert_eq!(elf_res.format, FileFormat::Elf);

        let bad_bytes = [0_u8; 64];
        assert!(crate::inspect_bytes(&bad_bytes, 64).is_err());
    }
}
