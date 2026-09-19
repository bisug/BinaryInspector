//! Bounded decoding of ELF headers, sections, program segments, symbols, notes, relocations, and security mitigations.

use crate::{
    error::AppError,
    hash::{calculate_entropy, sha256_hex},
    model::{
        Binary, DynamicEntry, DynamicInfo, ElfClass, ElfHeader, ElfNote, ElfType, Endianness,
        FileFormat, FileHashes, FileMetadata, Machine, OsAbi, PieStatus, Relocation, Relro,
        Section, SecurityMitigations, Segment, Symbol, SymbolBinding, SymbolTableKind, SymbolType,
        SymbolVisibility,
    },
    text::escape_bytes,
};

const ELF_IDENT_SIZE: usize = 16;
const MAX_TABLE_ENTRIES: u16 = 65_534;
const MAX_DYNAMIC_ENTRIES: usize = 16_384;
const MAX_SYMBOL_ENTRIES: usize = 65_536;
const MAX_RELOC_ENTRIES: usize = 32_768;
const MAX_NOTE_ENTRIES: usize = 8_192;
const MAX_STRING_BYTES: usize = 4_096;
const MAX_TOTAL_TEXT_BYTES: usize = 4 * 1024 * 1024;

/// Parses comprehensive ELF metadata from an owned byte buffer.
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
    let dynamic = dynamic_info(bytes, &class, &endianness, &sections, &segments)?;
    let symbols = parse_symbols(bytes, &class, &endianness, &sections)?;
    let notes = parse_notes(bytes, &class, &endianness, &sections, &segments)?;
    let relocations = parse_relocations(bytes, &class, &endianness, &sections, &symbols)?;

    let elf_header = ElfHeader {
        class,
        endianness,
        elf_type: elf_type(read_u16(bytes, 16, &layout.endianness)?),
        machine: machine(read_u16(bytes, 18, &layout.endianness)?),
        os_abi: os_abi(ident[7]),
        abi_version: ident[8],
        entry_point: layout.entry_point,
        flags: layout.flags,
        section_offset: layout.section_offset,
        section_entry_size: layout.section_entry_size,
        section_count: layout.section_count,
        program_offset: layout.program_offset,
        program_entry_size: layout.program_entry_size,
        program_count: layout.program_count,
    };

    let mitigations = analyze_mitigations(&elf_header, &dynamic, &segments, &symbols);
    let hashes = FileHashes {
        sha256: sha256_hex(bytes),
    };

    Ok(Binary {
        format: FileFormat::Elf,
        file: FileMetadata { size_bytes },
        elf: elf_header,
        dynamic,
        sections,
        segments,
        symbols,
        mitigations,
        notes,
        relocations,
        hashes,
    })
}

fn analyze_mitigations(
    elf: &ElfHeader,
    dynamic: &DynamicInfo,
    segments: &[Segment],
    symbols: &[Symbol],
) -> SecurityMitigations {
    // 1. RELRO
    let has_relro = segments.iter().any(|s| s.segment_type == 0x6474_e552); // PT_GNU_RELRO
    let relro = if has_relro {
        if dynamic.bind_now {
            Relro::Full
        } else {
            Relro::Partial
        }
    } else {
        Relro::None
    };

    // 2. Stack canary
    let stack_canary = symbols.iter().any(|s| {
        s.name == "__stack_chk_fail"
            || s.name == "__stack_chk_fail_local"
            || s.name == "__stack_chk_guard"
    });

    // 3. NX (No-Execute)
    let gnu_stack = segments.iter().find(|s| s.segment_type == 0x6474_e551); // PT_GNU_STACK
    let nx = match gnu_stack {
        Some(seg) => (seg.flags & 1) == 0, // PF_X (1) not set => stack non-executable
        None => false,
    };

    // 4. PIE
    let pie = match elf.elf_type {
        ElfType::Executable => PieStatus::NoPie,
        ElfType::Shared => {
            if dynamic.interpreter.is_some() || dynamic.entries.iter().any(|e| e.tag == 21) {
                PieStatus::Pie
            } else {
                PieStatus::Dso
            }
        }
        _ => PieStatus::NoPie,
    };

    // 5. Fortified functions
    let mut fortified_functions: Vec<String> = symbols
        .iter()
        .filter(|sym| {
            if !sym.is_import {
                return false;
            }
            let base_name = sym.name.split('@').next().unwrap_or("");
            base_name.ends_with("_chk")
        })
        .map(|sym| {
            let base_name = sym.name.split('@').next().unwrap_or(&sym.name);
            base_name.to_string()
        })
        .collect();
    fortified_functions.sort_unstable();
    fortified_functions.dedup();

    // 6. RWX Segments (Write + Execute permission violation)
    let rwx_segments = segments
        .iter()
        .filter(|s| (s.flags & 2 != 0) && (s.flags & 1 != 0))
        .count();

    // 7. Insecure RPATH/RUNPATH
    let is_insecure_path = |path: &str| {
        path.split(':').any(|part| {
            let p = part.trim();
            p.is_empty() || p == "." || p.starts_with("./")
        })
    };
    let has_insecure_rpath = dynamic.rpath.as_deref().is_some_and(is_insecure_path)
        || dynamic.runpath.as_deref().is_some_and(is_insecure_path);

    SecurityMitigations {
        relro,
        stack_canary,
        nx,
        pie,
        fortified_functions,
        rwx_segments,
        has_insecure_rpath,
    }
}

fn dynamic_info(
    bytes: &[u8],
    class: &ElfClass,
    endianness: &Endianness,
    sections: &[Section],
    segments: &[Segment],
) -> Result<DynamicInfo, AppError> {
    let mut info = DynamicInfo::default();
    if let Some(interpreter) = segments.iter().find(|segment| segment.segment_type == 3) {
        let value = file_slice(
            bytes,
            interpreter.offset,
            interpreter.file_size,
            "interpreter",
        )?;
        info.interpreter = Some(c_string(value, "interpreter")?);
    }
    let Some(dynamic) = sections.iter().find(|section| section.section_type == 6) else {
        return Ok(info);
    };
    let strings = sections
        .get(
            usize::try_from(dynamic.link)
                .map_err(|_| malformed("dynamic string-table index is too large"))?,
        )
        .ok_or_else(|| malformed("dynamic string-table index is outside the section table"))?;
    if strings.section_type != 3 {
        return Err(malformed(
            "dynamic string-table link does not reference a string table",
        ));
    }
    let data = file_slice(bytes, dynamic.offset, dynamic.size, "dynamic section")?;
    let width = match class {
        ElfClass::Elf32 => 8,
        ElfClass::Elf64 => 16,
    };
    if data.len() % width != 0 {
        return Err(malformed("dynamic section has an invalid entry size"));
    }
    if data.len() / width > MAX_DYNAMIC_ENTRIES {
        return Err(malformed(
            "dynamic entry count exceeds the inspection limit",
        ));
    }
    let table = file_slice(bytes, strings.offset, strings.size, "dynamic string table")?;
    let mut text_bytes = 0;
    for offset in (0..data.len()).step_by(width) {
        let tag = match class {
            ElfClass::Elf32 => u64::from(read_u32(data, offset, endianness)?),
            ElfClass::Elf64 => read_u64(data, offset, endianness)?,
        };
        let value = match class {
            ElfClass::Elf32 => u64::from(read_u32(data, offset + 4, endianness)?),
            ElfClass::Elf64 => read_u64(data, offset + 8, endianness)?,
        };
        if tag == 0 {
            break;
        }
        let text = || {
            string_at(
                table,
                u32::try_from(value)
                    .map_err(|_| malformed("dynamic string offset is too large"))?,
            )
        };
        let mut string_val = None;
        match tag {
            1 => {
                let s = take_text(text()?, &mut text_bytes)?;
                info.needed.push(s.clone());
                string_val = Some(s);
            }
            14 => {
                // DT_SONAME
                let s = take_text(text()?, &mut text_bytes)?;
                string_val = Some(s);
            }
            15 => {
                let s = take_text(text()?, &mut text_bytes)?;
                info.rpath = Some(s.clone());
                string_val = Some(s);
            }
            29 => {
                let s = take_text(text()?, &mut text_bytes)?;
                info.runpath = Some(s.clone());
                string_val = Some(s);
            }
            24 => info.bind_now = true,
            30 if value & 8 != 0 => info.bind_now = true,
            0x6fff_fffb if value & 1 != 0 => info.bind_now = true,
            _ => {}
        }
        info.entries.push(DynamicEntry {
            tag,
            tag_name: dynamic_tag_name(tag).to_string(),
            value,
            string_value: string_val,
        });
    }
    Ok(info)
}

fn dynamic_tag_name(tag: u64) -> &'static str {
    match tag {
        0 => "DT_NULL",
        1 => "DT_NEEDED",
        2 => "DT_PLTRELSZ",
        3 => "DT_PLTGOT",
        4 => "DT_HASH",
        5 => "DT_STRTAB",
        6 => "DT_SYMTAB",
        7 => "DT_RELA",
        8 => "DT_RELASZ",
        9 => "DT_RELAENT",
        10 => "DT_STRSZ",
        11 => "DT_SYMENT",
        12 => "DT_INIT",
        13 => "DT_FINI",
        14 => "DT_SONAME",
        15 => "DT_RPATH",
        16 => "DT_SYMBOLIC",
        17 => "DT_REL",
        18 => "DT_RELSZ",
        19 => "DT_RELENT",
        20 => "DT_PLTREL",
        21 => "DT_DEBUG",
        22 => "DT_TEXTREL",
        23 => "DT_JMPREL",
        24 => "DT_BIND_NOW",
        25 => "DT_INIT_ARRAY",
        26 => "DT_FINI_ARRAY",
        27 => "DT_INIT_ARRAYSZ",
        28 => "DT_FINI_ARRAYSZ",
        29 => "DT_RUNPATH",
        30 => "DT_FLAGS",
        0x6fff_fffb => "DT_FLAGS_1",
        0x6fff_fef5 => "DT_GNU_HASH",
        0x6fff_fffe => "DT_VERNEED",
        0x6fff_ffff => "DT_VERNEEDNUM",
        0x6fff_fffd => "DT_VERSYM",
        0x6fff_ff00 => "DT_VERSYM",
        _ => "DT_OTHER",
    }
}

fn parse_symbols(
    bytes: &[u8],
    class: &ElfClass,
    endianness: &Endianness,
    sections: &[Section],
) -> Result<Vec<Symbol>, AppError> {
    let mut symbols = Vec::new();
    let mut text_bytes = 0;

    for section in sections {
        if section.section_type != 2 && section.section_type != 11 {
            continue; // Only SHT_SYMTAB (2) and SHT_DYNSYM (11)
        }
        let table_kind = if section.section_type == 2 {
            SymbolTableKind::Static
        } else {
            SymbolTableKind::Dynamic
        };

        let string_table_bytes = if let Some(str_sec) = sections.get(section.link as usize) {
            if str_sec.section_type == 3 {
                Some(file_slice(
                    bytes,
                    str_sec.offset,
                    str_sec.size,
                    "symbol string table",
                )?)
            } else {
                None
            }
        } else {
            None
        };

        let entry_size = match class {
            ElfClass::Elf32 => 16,
            ElfClass::Elf64 => 24,
        };

        let sym_data = file_slice(bytes, section.offset, section.size, "symbol table")?;
        let entry_count = sym_data.len() / entry_size;
        let clamped_count = entry_count.min(MAX_SYMBOL_ENTRIES);

        for i in 0..clamped_count {
            let offset = i * entry_size;
            let (name_offset, value, size, info, other, shndx) = match class {
                ElfClass::Elf32 => {
                    let name = read_u32(sym_data, offset, endianness)?;
                    let val = u64::from(read_u32(sym_data, offset + 4, endianness)?);
                    let sz = u64::from(read_u32(sym_data, offset + 8, endianness)?);
                    let inf = sym_data
                        .get(offset + 12)
                        .copied()
                        .ok_or_else(|| malformed("symbol info truncated"))?;
                    let oth = sym_data
                        .get(offset + 13)
                        .copied()
                        .ok_or_else(|| malformed("symbol other truncated"))?;
                    let sh = read_u16(sym_data, offset + 14, endianness)?;
                    (name, val, sz, inf, oth, sh)
                }
                ElfClass::Elf64 => {
                    let name = read_u32(sym_data, offset, endianness)?;
                    let inf = sym_data
                        .get(offset + 4)
                        .copied()
                        .ok_or_else(|| malformed("symbol info truncated"))?;
                    let oth = sym_data
                        .get(offset + 5)
                        .copied()
                        .ok_or_else(|| malformed("symbol other truncated"))?;
                    let sh = read_u16(sym_data, offset + 6, endianness)?;
                    let val = read_u64(sym_data, offset + 8, endianness)?;
                    let sz = read_u64(sym_data, offset + 16, endianness)?;
                    (name, val, sz, inf, oth, sh)
                }
            };

            let sym_type_raw = info & 0x0f;
            let sym_bind_raw = info >> 4;
            let sym_vis_raw = other & 0x03;

            let sym_type = match sym_type_raw {
                0 => SymbolType::NoType,
                1 => SymbolType::Object,
                2 => SymbolType::Func,
                3 => SymbolType::Section,
                4 => SymbolType::File,
                5 => SymbolType::Common,
                6 => SymbolType::Tls,
                10 => SymbolType::GnuIfunc,
                v => SymbolType::Other(v),
            };

            let binding = match sym_bind_raw {
                0 => SymbolBinding::Local,
                1 => SymbolBinding::Global,
                2 => SymbolBinding::Weak,
                10 => SymbolBinding::GnuUnique,
                v => SymbolBinding::Other(v),
            };

            let visibility = match sym_vis_raw {
                0 => SymbolVisibility::Default,
                1 => SymbolVisibility::Internal,
                2 => SymbolVisibility::Hidden,
                3 => SymbolVisibility::Protected,
                _ => SymbolVisibility::Default,
            };

            let name = if name_offset != 0 {
                if let Some(str_table) = string_table_bytes {
                    match string_at(str_table, name_offset) {
                        Ok(s) => take_text(s, &mut text_bytes)?,
                        Err(_) => String::new(),
                    }
                } else {
                    String::new()
                }
            } else if sym_type_raw == 3 && (shndx as usize) < sections.len() {
                sections[shndx as usize].name.clone()
            } else {
                String::new()
            };

            let is_import = shndx == 0 && !name.is_empty();
            let is_export =
                shndx != 0 && (sym_bind_raw == 1 || sym_bind_raw == 2) && !name.is_empty();
            let section_index = if shndx == 0 || shndx >= 0xff00 {
                None
            } else {
                Some(shndx)
            };

            symbols.push(Symbol {
                index: symbols.len(),
                name,
                value,
                size,
                sym_type,
                binding,
                visibility,
                section_index,
                is_import,
                is_export,
                table: table_kind,
            });
        }
    }

    Ok(symbols)
}

fn parse_notes(
    bytes: &[u8],
    _class: &ElfClass,
    endianness: &Endianness,
    sections: &[Section],
    segments: &[Segment],
) -> Result<Vec<ElfNote>, AppError> {
    let mut notes = Vec::new();

    // Check SHT_NOTE sections first, or PT_NOTE segments if no sections
    let note_slices = sections
        .iter()
        .filter(|s| s.section_type == 7)
        .map(|s| (s.offset, s.size));

    let mut ranges: Vec<(u64, u64)> = note_slices.collect();
    if ranges.is_empty() {
        ranges = segments
            .iter()
            .filter(|s| s.segment_type == 4)
            .map(|s| (s.offset, s.file_size))
            .collect();
    }

    for (offset, size) in ranges {
        if size == 0 {
            continue;
        }
        let Ok(data) = file_slice(bytes, offset, size, "note data") else {
            continue;
        };
        let mut cur = 0;
        while cur + 12 <= data.len() {
            if notes.len() >= MAX_NOTE_ENTRIES {
                break;
            }
            let namesz = match read_u32(data, cur, endianness) {
                Ok(v) => v as usize,
                Err(_) => break,
            };
            let descsz = match read_u32(data, cur + 4, endianness) {
                Ok(v) => v as usize,
                Err(_) => break,
            };
            let note_type = match read_u32(data, cur + 8, endianness) {
                Ok(v) => v,
                Err(_) => break,
            };
            cur += 12;

            let name_padded = match namesz.checked_add(3) {
                Some(v) => v & !3,
                None => break,
            };
            let desc_padded = match descsz.checked_add(3) {
                Some(v) => v & !3,
                None => break,
            };

            let name_end = match cur.checked_add(namesz) {
                Some(end) if end <= data.len() => end,
                _ => break,
            };
            let next_cur = match cur.checked_add(name_padded) {
                Some(next) if next <= data.len() => next,
                _ => break,
            };
            let name_raw = &data[cur..name_end];
            cur = next_cur;

            let desc_end = match cur.checked_add(descsz) {
                Some(end) if end <= data.len() => end,
                _ => break,
            };
            let next_cur = match cur.checked_add(desc_padded) {
                Some(next) if next <= data.len() => next,
                _ => break,
            };
            let desc_raw = &data[cur..desc_end];
            cur = next_cur;

            let clean_name = escape_bytes(if let Some(&0) = name_raw.last() {
                &name_raw[..name_raw.len() - 1]
            } else {
                name_raw
            });

            let mut build_id = None;
            let mut abi_tag = None;
            let mut properties = Vec::new();
            let mut description = format!("Note type {note_type:#x}");

            if clean_name == "GNU" {
                match note_type {
                    1 => {
                        // NT_GNU_ABI_TAG: OS (4B), Major (4B), Minor (4B), Subminor (4B)
                        if desc_raw.len() >= 16 {
                            let os = read_u32(desc_raw, 0, endianness).unwrap_or(0);
                            let major = read_u32(desc_raw, 4, endianness).unwrap_or(0);
                            let minor = read_u32(desc_raw, 8, endianness).unwrap_or(0);
                            let subminor = read_u32(desc_raw, 12, endianness).unwrap_or(0);
                            let os_str = match os {
                                0 => "Linux",
                                1 => "GNU/Hurd",
                                2 => "Solaris",
                                3 => "FreeBSD",
                                _ => "OS",
                            };
                            let tag = format!("{os_str} {major}.{minor}.{subminor}");
                            description = format!("ABI requirement: {tag}");
                            abi_tag = Some(tag);
                        }
                    }
                    3 => {
                        // NT_GNU_BUILD_ID: SHA-1 or MD5 hash bytes
                        const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
                        let id_bytes = if desc_raw.len() > 64 {
                            &desc_raw[..64]
                        } else {
                            desc_raw
                        };
                        let mut hex = String::with_capacity(id_bytes.len() * 2);
                        for &b in id_bytes {
                            hex.push(HEX_LOWER[(b >> 4) as usize] as char);
                            hex.push(HEX_LOWER[(b & 0x0f) as usize] as char);
                        }
                        description = format!("Build ID: {hex}");
                        build_id = Some(hex);
                    }
                    5 => {
                        // NT_GNU_PROPERTY_TYPE_0
                        description = "GNU Properties".to_string();
                        let mut prop_offset = 0;
                        while prop_offset + 8 <= desc_raw.len() {
                            let pr_type = read_u32(desc_raw, prop_offset, endianness).unwrap_or(0);
                            let pr_datasz = read_u32(desc_raw, prop_offset + 4, endianness)
                                .unwrap_or(0) as usize;
                            prop_offset += 8;
                            if prop_offset + pr_datasz > desc_raw.len() {
                                break;
                            }
                            let pr_data = &desc_raw[prop_offset..prop_offset + pr_datasz];
                            let pr_padded = (pr_datasz + 7) & !7;
                            prop_offset += pr_padded;

                            match pr_type {
                                0xc000_0002 => {
                                    // GNU_PROPERTY_X86_FEATURE_1_AND
                                    if let Ok(bits) = read_u32(pr_data, 0, endianness) {
                                        if bits & 1 != 0 {
                                            properties.push(
                                                "x86 IBT (Indirect Branch Tracking)".to_string(),
                                            );
                                        }
                                        if bits & 2 != 0 {
                                            properties.push("x86 SHSTK (Shadow Stack)".to_string());
                                        }
                                    }
                                }
                                0xc000_0000 => {
                                    // GNU_PROPERTY_AARCH64_FEATURE_1_AND
                                    if let Ok(bits) = read_u32(pr_data, 0, endianness) {
                                        if bits & 1 != 0 {
                                            properties.push(
                                                "ARM BTI (Branch Target Identification)"
                                                    .to_string(),
                                            );
                                        }
                                        if bits & 2 != 0 {
                                            properties.push(
                                                "ARM PAC (Pointer Authentication)".to_string(),
                                            );
                                        }
                                    }
                                }
                                other => {
                                    properties.push(format!("Property {other:#x}"));
                                }
                            }
                        }
                    }
                    _ => {}
                }
            } else if clean_name == "Go" && note_type == 4 {
                description = format!("Go Build ID: {}", escape_bytes(desc_raw));
            }

            notes.push(ElfNote {
                name: clean_name,
                note_type,
                description,
                build_id,
                abi_tag,
                properties,
            });
        }
    }

    Ok(notes)
}

fn parse_relocations(
    bytes: &[u8],
    class: &ElfClass,
    endianness: &Endianness,
    sections: &[Section],
    symbols: &[Symbol],
) -> Result<Vec<Relocation>, AppError> {
    let mut relocations = Vec::new();

    let static_syms: Vec<&str> = symbols
        .iter()
        .filter(|s| s.table == SymbolTableKind::Static)
        .map(|s| s.name.as_str())
        .collect();
    let dynamic_syms: Vec<&str> = symbols
        .iter()
        .filter(|s| s.table == SymbolTableKind::Dynamic)
        .map(|s| s.name.as_str())
        .collect();

    for section in sections {
        let is_rela = section.section_type == 4; // SHT_RELA
        let is_rel = section.section_type == 9; // SHT_REL
        if !is_rela && !is_rel {
            continue;
        }

        let entry_size = match (class, is_rela) {
            (ElfClass::Elf32, false) => 8,
            (ElfClass::Elf32, true) => 12,
            (ElfClass::Elf64, false) => 16,
            (ElfClass::Elf64, true) => 24,
        };

        let Ok(data) = file_slice(bytes, section.offset, section.size, "relocation table") else {
            continue;
        };

        let target_kind = sections
            .get(section.link as usize)
            .and_then(|s| match s.section_type {
                2 => Some(SymbolTableKind::Static),
                11 => Some(SymbolTableKind::Dynamic),
                _ => None,
            });

        let sym_lookup: Option<&[&str]> = target_kind.map(|kind| match kind {
            SymbolTableKind::Static => static_syms.as_slice(),
            SymbolTableKind::Dynamic => dynamic_syms.as_slice(),
        });

        let count = (data.len() / entry_size).min(MAX_RELOC_ENTRIES);
        for i in 0..count {
            if relocations.len() >= MAX_RELOC_ENTRIES {
                break;
            }
            let offset = i * entry_size;
            let (rel_offset, rel_type, sym_index, addend) = match (class, is_rela) {
                (ElfClass::Elf32, false) => {
                    let r_offset = u64::from(read_u32(data, offset, endianness)?);
                    let r_info = read_u32(data, offset + 4, endianness)?;
                    (r_offset, r_info & 0xff, r_info >> 8, None)
                }
                (ElfClass::Elf32, true) => {
                    let r_offset = u64::from(read_u32(data, offset, endianness)?);
                    let r_info = read_u32(data, offset + 4, endianness)?;
                    let r_addend = i64::from(read_i32(data, offset + 8, endianness)?);
                    (r_offset, r_info & 0xff, r_info >> 8, Some(r_addend))
                }
                (ElfClass::Elf64, false) => {
                    let r_offset = read_u64(data, offset, endianness)?;
                    let r_info = read_u64(data, offset + 8, endianness)?;
                    (
                        r_offset,
                        (r_info & 0xffff_ffff) as u32,
                        (r_info >> 32) as u32,
                        None,
                    )
                }
                (ElfClass::Elf64, true) => {
                    let r_offset = read_u64(data, offset, endianness)?;
                    let r_info = read_u64(data, offset + 8, endianness)?;
                    let r_addend = read_i64(data, offset + 16, endianness)?;
                    (
                        r_offset,
                        (r_info & 0xffff_ffff) as u32,
                        (r_info >> 32) as u32,
                        Some(r_addend),
                    )
                }
            };

            let symbol_name = sym_lookup
                .and_then(|list| list.get(sym_index as usize).copied())
                .filter(|name| !name.is_empty())
                .map(String::from);

            relocations.push(Relocation {
                section_name: section.name.clone(),
                offset: rel_offset,
                rel_type,
                symbol_index: sym_index,
                symbol_name,
                addend,
            });
        }
    }

    Ok(relocations)
}

#[derive(Debug)]
struct Layout {
    endianness: Endianness,
    entry_point: u64,
    flags: u32,
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
            flags_at,
            program_size_at,
            program_count_at,
            section_size_at,
            section_count_at,
            names_at,
        ) = match class {
            ElfClass::Elf32 => (52, 28, 32, 36, 42, 44, 46, 48, 50),
            ElfClass::Elf64 => (64, 32, 40, 48, 54, 56, 58, 60, 62),
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
        let flags = read_u32(bytes, flags_at, endianness)?;
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
            flags,
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
    if names.section_type != 3 {
        return Err(malformed("section-name table is not a string table"));
    }
    let string_table = file_slice(bytes, names.offset, names.size, "section-name string table")?;
    let mut text_bytes = 0;
    let mut sections = Vec::with_capacity(raw.len());
    for (index, section) in raw.into_iter().enumerate() {
        let entropy = if section.section_type != 8 && section.size > 0 {
            let data = file_slice(bytes, section.offset, section.size, "section contents")?;
            calculate_entropy(data)
        } else {
            0.0
        };

        sections.push(Section {
            index: index as u16,
            name: take_text(
                string_at(string_table, section.name_offset)?,
                &mut text_bytes,
            )?,
            section_type: section.section_type,
            flags: section.flags,
            address: section.address,
            offset: section.offset,
            size: section.size,
            link: section.link,
            info: section.info,
            alignment: section.alignment,
            entry_size: section.entry_size,
            entropy,
        });
    }
    Ok(sections)
}

#[derive(Debug)]
struct RawSection {
    name_offset: u32,
    section_type: u32,
    flags: u64,
    address: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    alignment: u64,
    entry_size: u64,
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
            link: read_u32(
                bytes,
                offset
                    .checked_add(match class {
                        ElfClass::Elf32 => 24,
                        ElfClass::Elf64 => 40,
                    })
                    .ok_or_else(|| malformed("integer overflow"))?,
                endianness,
            )?,
            info: read_u32(
                bytes,
                offset
                    .checked_add(match class {
                        ElfClass::Elf32 => 28,
                        ElfClass::Elf64 => 44,
                    })
                    .ok_or_else(|| malformed("integer overflow"))?,
                endianness,
            )?,
            alignment: word(match class {
                ElfClass::Elf32 => 32,
                ElfClass::Elf64 => 48,
            })?,
            entry_size: word(match class {
                ElfClass::Elf32 => 36,
                ElfClass::Elf64 => 56,
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
        .take(MAX_STRING_BYTES + 1)
        .position(|byte| *byte == 0)
        .ok_or_else(|| malformed("string is unterminated or exceeds the inspection limit"))?;
    Ok(escape_bytes(&bytes[..end]))
}

fn c_string(bytes: &[u8], what: &str) -> Result<String, AppError> {
    let end = bytes
        .iter()
        .take(MAX_STRING_BYTES + 1)
        .position(|byte| *byte == 0)
        .ok_or_else(|| {
            malformed(&format!(
                "{what} is unterminated or exceeds the inspection limit"
            ))
        })?;
    Ok(escape_bytes(&bytes[..end]))
}

fn take_text(text: String, total: &mut usize) -> Result<String, AppError> {
    *total = total
        .checked_add(text.len())
        .ok_or_else(|| malformed("text size overflow"))?;
    if *total > MAX_TOTAL_TEXT_BYTES {
        return Err(malformed("decoded text exceeds the inspection limit"));
    }
    Ok(text)
}

fn malformed(message: &str) -> AppError {
    AppError::Parse(format!("malformed ELF: {message}"))
}

fn read_u16(bytes: &[u8], offset: usize, endianness: &Endianness) -> Result<u16, AppError> {
    let arr: [u8; 2] = field(bytes, offset, 2)?
        .try_into()
        .expect("field ensures 2 bytes");
    Ok(match endianness {
        Endianness::Little => u16::from_le_bytes(arr),
        Endianness::Big => u16::from_be_bytes(arr),
    })
}
fn read_u32(bytes: &[u8], offset: usize, endianness: &Endianness) -> Result<u32, AppError> {
    let arr: [u8; 4] = field(bytes, offset, 4)?
        .try_into()
        .expect("field ensures 4 bytes");
    Ok(match endianness {
        Endianness::Little => u32::from_le_bytes(arr),
        Endianness::Big => u32::from_be_bytes(arr),
    })
}
fn read_i32(bytes: &[u8], offset: usize, endianness: &Endianness) -> Result<i32, AppError> {
    let arr: [u8; 4] = field(bytes, offset, 4)?
        .try_into()
        .expect("field ensures 4 bytes");
    Ok(match endianness {
        Endianness::Little => i32::from_le_bytes(arr),
        Endianness::Big => i32::from_be_bytes(arr),
    })
}
fn read_u64(bytes: &[u8], offset: usize, endianness: &Endianness) -> Result<u64, AppError> {
    let arr: [u8; 8] = field(bytes, offset, 8)?
        .try_into()
        .expect("field ensures 8 bytes");
    Ok(match endianness {
        Endianness::Little => u64::from_le_bytes(arr),
        Endianness::Big => u64::from_be_bytes(arr),
    })
}
fn read_i64(bytes: &[u8], offset: usize, endianness: &Endianness) -> Result<i64, AppError> {
    let arr: [u8; 8] = field(bytes, offset, 8)?
        .try_into()
        .expect("field ensures 8 bytes");
    Ok(match endianness {
        Endianness::Little => i64::from_le_bytes(arr),
        Endianness::Big => i64::from_be_bytes(arr),
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
    use super::{parse, string_at, MAX_STRING_BYTES};
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
        assert!(!binary.hashes.sha256.is_empty());
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
        bytes[132..136].copy_from_slice(&3_u32.to_le_bytes());
        bytes[128 + 24..128 + 32].copy_from_slice(&192_u64.to_le_bytes());
        bytes[128 + 32..128 + 40].copy_from_slice(&8_u64.to_le_bytes());
        bytes[192..200].copy_from_slice(b"\0.bad\x1b\0\0");

        let binary = parse(&bytes, 200).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(binary.sections.len(), 2);
        assert_eq!(binary.sections[1].name, ".bad\\x1B");
    }

    #[test]
    fn rejects_a_section_outside_the_file() {
        let mut bytes = vec![0_u8; 200];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4..9].copy_from_slice(&[2, 1, 1, 0, 0]);
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[40..48].copy_from_slice(&64_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[58..60].copy_from_slice(&64_u16.to_le_bytes());
        bytes[60..62].copy_from_slice(&2_u16.to_le_bytes());
        bytes[62..64].copy_from_slice(&1_u16.to_le_bytes());
        bytes[68..72].copy_from_slice(&1_u32.to_le_bytes());
        bytes[88..96].copy_from_slice(&200_u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&1_u64.to_le_bytes());
        bytes[132..136].copy_from_slice(&3_u32.to_le_bytes());
        bytes[128 + 24..128 + 32].copy_from_slice(&192_u64.to_le_bytes());
        bytes[128 + 32..128 + 40].copy_from_slice(&1_u64.to_le_bytes());
        bytes[192] = 0;

        assert!(parse(&bytes, 200).is_err());
    }

    #[test]
    fn rejects_an_oversized_string() {
        assert!(string_at(&vec![b'a'; MAX_STRING_BYTES + 1], 0).is_err());
    }

    #[test]
    fn test_dt_bind_now_and_stack_chk_fail_local() {
        use super::analyze_mitigations;
        use crate::model::{
            DynamicInfo, ElfHeader, ElfType, OsAbi, Relro, Segment, Symbol, SymbolBinding,
            SymbolTableKind, SymbolType, SymbolVisibility,
        };

        let elf = ElfHeader {
            class: ElfClass::Elf64,
            endianness: Endianness::Little,
            elf_type: ElfType::Shared,
            machine: Machine::X86_64,
            os_abi: OsAbi::SystemV,
            abi_version: 0,
            entry_point: 0x1000,
            flags: 0,
            section_offset: 0,
            section_entry_size: 64,
            section_count: 0,
            program_offset: 64,
            program_entry_size: 56,
            program_count: 1,
        };

        let dynamic = DynamicInfo {
            bind_now: true,
            ..Default::default()
        };

        let segments = vec![Segment {
            index: 0,
            segment_type: 0x6474_e552, // PT_GNU_RELRO
            flags: 4,
            offset: 0,
            virtual_address: 0,
            file_size: 0,
            memory_size: 0,
            alignment: 8,
        }];

        let symbols = vec![
            Symbol {
                index: 0,
                name: "__stack_chk_fail_local".to_string(),
                value: 0,
                size: 0,
                sym_type: SymbolType::Func,
                binding: SymbolBinding::Global,
                visibility: SymbolVisibility::Default,
                section_index: None,
                is_import: true,
                is_export: false,
                table: SymbolTableKind::Dynamic,
            },
            Symbol {
                index: 1,
                name: "__printf_chk@GLIBC_2.3.4".to_string(),
                value: 0,
                size: 0,
                sym_type: SymbolType::Func,
                binding: SymbolBinding::Global,
                visibility: SymbolVisibility::Default,
                section_index: None,
                is_import: true,
                is_export: false,
                table: SymbolTableKind::Dynamic,
            },
        ];

        let mit = analyze_mitigations(&elf, &dynamic, &segments, &symbols);
        assert_eq!(mit.relro, Relro::Full);
        assert!(mit.stack_canary);
        assert_eq!(mit.fortified_functions, vec!["__printf_chk".to_string()]);
    }
}
