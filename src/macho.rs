//! Safe parsing primitives for Apple Mach-O binary inspection.
//!
//! Supports 32-bit and 64-bit Mach-O binaries, as well as Universal / Fat
//! binary containers across x86, x86_64, ARM, and ARM64 / ARM64E architectures.

use std::collections::HashSet;

use crate::{
    error::{AppError, ParseError},
    hash,
    model::{
        Binary, DynamicInfo, ElfNote, FileFormat, FileHashes, FileMetadata, Hardening, MachOHeader,
        PieStatus, Relocation, Relro, Section, SecurityMitigations, Segment, Symbol, SymbolBinding,
        SymbolTableKind, SymbolType, SymbolVisibility,
    },
    text,
};

/// Maximum load commands to inspect to guard against resource exhaustion.
const MAX_COMMANDS: usize = 1024;
/// Maximum sections allowed in a single Mach-O binary.
const MAX_SECTIONS: usize = 512;
/// Maximum symbols allowed to guard against denial of service.
const MAX_SYMBOLS: usize = 50_000;
/// Maximum relocations allowed.
const MAX_RELOCATIONS: usize = 50_000;

// Magic numbers
const MH_MAGIC: u32 = 0xfeed_face;
const MH_CIGAM: u32 = 0xcefa_edfe;
const MH_MAGIC_64: u32 = 0xfeed_facf;
const MH_CIGAM_64: u32 = 0xcffa_edfe;
const FAT_MAGIC: u32 = 0xcafe_babe;
const FAT_CIGAM: u32 = 0xbeba_feca;
const FAT_MAGIC_64: u32 = 0xcafe_babf;
const FAT_CIGAM_64: u32 = 0xbfba_feca;

// CPU Types
const CPU_TYPE_X86: u32 = 7;
const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const CPU_TYPE_ARM: u32 = 12;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const CPU_TYPE_ARM64_32: u32 = 0x0200_000c;
const CPU_TYPE_POWERPC: u32 = 18;
const CPU_TYPE_POWERPC64: u32 = 0x0100_0012;

// CPU Subtypes
const CPU_SUBTYPE_ARM64E: u32 = 2;
const CPU_SUBTYPE_X86_64_H: u32 = 8;

// File Types
const MH_OBJECT: u32 = 0x1;
const MH_EXECUTE: u32 = 0x2;
const MH_FVMLIB: u32 = 0x3;
const MH_CORE: u32 = 0x4;
const MH_PRELOAD: u32 = 0x5;
const MH_DYLIB: u32 = 0x6;
const MH_DYLINKER: u32 = 0x7;
const MH_BUNDLE: u32 = 0x8;
const MH_DSYM: u32 = 0xa;
const MH_KEXT_BUNDLE: u32 = 0xb;

// Flags
const MH_NOUNDEFS: u32 = 0x1;
const MH_INCRLINK: u32 = 0x2;
const MH_DYLDLINK: u32 = 0x4;
const MH_BINDATLOAD: u32 = 0x8;
const MH_PREBOUND: u32 = 0x10;
const MH_SPLIT_SEGS: u32 = 0x20;
const MH_TWOLEVEL: u32 = 0x80;
const MH_FORCE_FLAT: u32 = 0x100;
const MH_WEAK_DEFINES: u32 = 0x8000;
const MH_BINDS_TO_WEAK: u32 = 0x10000;
const MH_ALLOW_STACK_EXECUTION: u32 = 0x20000;
const MH_ROOT_SAFE: u32 = 0x40000;
const MH_SETUID_SAFE: u32 = 0x80000;
const MH_PIE: u32 = 0x200000;
const MH_DEAD_STRIPPABLE_DYLIB: u32 = 0x400000;
const MH_NO_HEAP_EXECUTION: u32 = 0x1000000;
const MH_APP_EXTENSION_SAFE: u32 = 0x2000000;

// Load Commands
const LC_REQ_DYLD: u32 = 0x8000_0000;
const LC_SEGMENT: u32 = 0x1;
const LC_SYMTAB: u32 = 0x2;
const LC_UNIXTHREAD: u32 = 0x5;
const LC_DYSYMTAB: u32 = 0xb;
const LC_LOAD_DYLIB: u32 = 0xc;
const LC_ID_DYLIB: u32 = 0xd;
const LC_LOAD_DYLINKER: u32 = 0xe;
const LC_LOAD_WEAK_DYLIB: u32 = 0x18 | LC_REQ_DYLD;
const LC_SEGMENT_64: u32 = 0x19;
const LC_UUID: u32 = 0x1b;
const LC_RPATH: u32 = 0x1c | LC_REQ_DYLD;
const LC_CODE_SIGNATURE: u32 = 0x1d;
const LC_REEXPORT_DYLIB: u32 = 0x1f | LC_REQ_DYLD;
const LC_VERSION_MIN_MACOSX: u32 = 0x24;
const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
const LC_MAIN: u32 = 0x28 | LC_REQ_DYLD;
const LC_VERSION_MIN_TVOS: u32 = 0x2f;
const LC_VERSION_MIN_WATCHOS: u32 = 0x30;
const LC_BUILD_VERSION: u32 = 0x32;

/// Parses a regular Mach-O or Universal Fat binary file without executing it.
pub fn parse(bytes: &[u8], file_len: u64) -> Result<Binary, AppError> {
    if bytes.len() < 4 {
        return Err(ParseError::FileTooShort {
            actual: bytes.len(),
            expected: 4,
        }
        .into());
    }

    let initial_magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let mut is_fat_universal = false;
    let mut fat_architectures = Vec::new();

    // Sliced sub-slice to parse if inside a Universal container
    let (slice_bytes, slice_offset) = match initial_magic {
        FAT_MAGIC | FAT_CIGAM | FAT_MAGIC_64 | FAT_CIGAM_64 => {
            let is_fat_le = initial_magic == FAT_CIGAM || initial_magic == FAT_CIGAM_64;
            let is_fat_64 = initial_magic == FAT_MAGIC_64 || initial_magic == FAT_CIGAM_64;

            let (chosen_slice, archs) = extract_fat_slice(bytes, is_fat_le, is_fat_64)?;
            is_fat_universal = true;
            fat_architectures = archs;
            chosen_slice
        }
        _ => (bytes, 0),
    };

    if slice_bytes.len() < 28 {
        return Err(ParseError::FileTooShort {
            actual: slice_bytes.len(),
            expected: 28,
        }
        .into());
    }

    let magic_raw = u32::from_be_bytes([
        slice_bytes[0],
        slice_bytes[1],
        slice_bytes[2],
        slice_bytes[3],
    ]);

    let (is_64_bit, is_little_endian) = match magic_raw {
        MH_MAGIC => (false, false),
        MH_CIGAM => (false, true),
        MH_MAGIC_64 => (true, false),
        MH_CIGAM_64 => (true, true),
        _ => return Err(ParseError::InvalidMagic.into()),
    };

    let header_size = if is_64_bit { 32 } else { 28 };
    if slice_bytes.len() < header_size {
        return Err(ParseError::FileTooShort {
            actual: slice_bytes.len(),
            expected: header_size,
        }
        .into());
    }

    let cpu_type = read_u32(slice_bytes, 4, is_little_endian)?;
    let cpu_subtype = read_u32(slice_bytes, 8, is_little_endian)?;
    let file_type_raw = read_u32(slice_bytes, 12, is_little_endian)?;
    let ncmds = read_u32(slice_bytes, 16, is_little_endian)?;
    let sizeofcmds = read_u32(slice_bytes, 20, is_little_endian)?;
    let flags = read_u32(slice_bytes, 24, is_little_endian)?;

    let cpu_arch = format_cpu_arch(cpu_type, cpu_subtype);
    let file_type = format_file_type(file_type_raw);
    let flags_desc = decode_flags(flags);

    let mut sections = Vec::new();
    let mut segments = Vec::new();
    let mut dynamic = DynamicInfo::default();
    let mut symbols = Vec::new();
    let mut notes = Vec::new();
    let mut relocations = Vec::new();

    let mut entry_point: Option<u64> = None;
    let mut min_os: Option<String> = None;
    let mut uuid_str: Option<String> = None;
    let mut has_stack_canary = false;
    let mut fortified_functions = HashSet::new();
    let mut rwx_segments = 0usize;
    let mut has_insecure_rpath = false;
    let mut text_vmaddr: Option<u64> = None;

    // Load Commands traversal
    let mut cmd_offset = header_size;
    let cmd_limit = (ncmds as usize).min(MAX_COMMANDS);

    for _ in 0..cmd_limit {
        if cmd_offset + 8 > slice_bytes.len() {
            break;
        }

        let cmd = read_u32(slice_bytes, cmd_offset, is_little_endian)?;
        let cmdsize = read_u32(slice_bytes, cmd_offset + 4, is_little_endian)? as usize;

        if cmdsize < 8 || cmd_offset + cmdsize > slice_bytes.len() {
            return Err(ParseError::OutOfBounds {
                what: "load command payload",
                offset: (slice_offset + cmd_offset) as u64,
                size: cmdsize as u64,
            }
            .into());
        }

        let cmd_payload = &slice_bytes[cmd_offset..cmd_offset + cmdsize];

        match cmd {
            LC_SEGMENT_64 => {
                if cmd_payload.len() >= 72 {
                    let seg_name = read_fixed_str(&cmd_payload[8..24]);
                    let vmaddr = read_u64(cmd_payload, 24, is_little_endian)?;
                    let vmsize = read_u64(cmd_payload, 32, is_little_endian)?;
                    let fileoff = read_u64(cmd_payload, 40, is_little_endian)?;
                    let filesize = read_u64(cmd_payload, 48, is_little_endian)?;
                    let initprot = read_u32(cmd_payload, 60, is_little_endian)?;
                    let nsects = read_u32(cmd_payload, 64, is_little_endian)? as usize;

                    if seg_name == "__TEXT" {
                        text_vmaddr = Some(vmaddr);
                    }

                    let is_rwx = (initprot & 0x6) == 0x6; // VM_PROT_WRITE (2) | VM_PROT_EXECUTE (4)
                    if is_rwx && filesize > 0 {
                        rwx_segments += 1;
                    }

                    let mut seg_flags = 0_u32;
                    if (initprot & 1) != 0 {
                        seg_flags |= 4; // Read
                    }
                    if (initprot & 2) != 0 {
                        seg_flags |= 2; // Write
                    }
                    if (initprot & 4) != 0 {
                        seg_flags |= 1; // Execute
                    }

                    let seg_idx = segments.len() as u16;
                    segments.push(Segment {
                        index: seg_idx,
                        segment_type: 1, // PT_LOAD equivalent
                        flags: seg_flags,
                        offset: fileoff,
                        virtual_address: vmaddr,
                        file_size: filesize,
                        memory_size: vmsize,
                        alignment: 4096,
                    });

                    // Parse inner sections
                    let mut sect_offset = 72;
                    for _ in 0..nsects.min(MAX_SECTIONS) {
                        if sect_offset + 80 > cmd_payload.len() {
                            break;
                        }

                        let sect_name = read_fixed_str(&cmd_payload[sect_offset..sect_offset + 16]);
                        let s_seg_name =
                            read_fixed_str(&cmd_payload[sect_offset + 16..sect_offset + 32]);
                        let s_addr = read_u64(cmd_payload, sect_offset + 32, is_little_endian)?;
                        let s_size = read_u64(cmd_payload, sect_offset + 40, is_little_endian)?;
                        let s_off =
                            read_u32(cmd_payload, sect_offset + 48, is_little_endian)? as u64;
                        let s_align =
                            1u64 << read_u32(cmd_payload, sect_offset + 52, is_little_endian)?;
                        let _s_reloff =
                            read_u32(cmd_payload, sect_offset + 56, is_little_endian)? as u64;
                        let s_nreloc = read_u32(cmd_payload, sect_offset + 60, is_little_endian)?;
                        let s_flags = read_u32(cmd_payload, sect_offset + 64, is_little_endian)?;

                        let full_sect_name = format!("{s_seg_name},{sect_name}");
                        let sect_entropy =
                            if s_off + s_size <= slice_bytes.len() as u64 && s_size > 0 {
                                let sect_slice =
                                    &slice_bytes[s_off as usize..(s_off + s_size) as usize];
                                Some(hash::calculate_entropy(sect_slice))
                            } else {
                                None
                            };

                        let s_idx = sections.len() as u16;
                        sections.push(Section {
                            index: s_idx,
                            name: full_sect_name,
                            section_type: s_flags & 0xff,
                            flags: s_flags as u64,
                            address: s_addr,
                            offset: s_off,
                            size: s_size,
                            link: 0,
                            info: s_nreloc,
                            alignment: s_align,
                            entry_size: 0,
                            entropy: sect_entropy,
                        });

                        sect_offset += 80;
                    }
                }
            }
            LC_SEGMENT => {
                if cmd_payload.len() >= 56 {
                    let seg_name = read_fixed_str(&cmd_payload[8..24]);
                    let vmaddr = read_u32(cmd_payload, 24, is_little_endian)? as u64;
                    let vmsize = read_u32(cmd_payload, 28, is_little_endian)? as u64;
                    let fileoff = read_u32(cmd_payload, 32, is_little_endian)? as u64;
                    let filesize = read_u32(cmd_payload, 36, is_little_endian)? as u64;
                    let initprot = read_u32(cmd_payload, 44, is_little_endian)?;
                    let nsects = read_u32(cmd_payload, 48, is_little_endian)? as usize;

                    if seg_name == "__TEXT" {
                        text_vmaddr = Some(vmaddr);
                    }

                    let is_rwx = (initprot & 0x6) == 0x6;
                    if is_rwx && filesize > 0 {
                        rwx_segments += 1;
                    }

                    let mut seg_flags = 0_u32;
                    if (initprot & 1) != 0 {
                        seg_flags |= 4;
                    }
                    if (initprot & 2) != 0 {
                        seg_flags |= 2;
                    }
                    if (initprot & 4) != 0 {
                        seg_flags |= 1;
                    }

                    let seg_idx = segments.len() as u16;
                    segments.push(Segment {
                        index: seg_idx,
                        segment_type: 1,
                        flags: seg_flags,
                        offset: fileoff,
                        virtual_address: vmaddr,
                        file_size: filesize,
                        memory_size: vmsize,
                        alignment: 4096,
                    });

                    let mut sect_offset = 56;
                    for _ in 0..nsects.min(MAX_SECTIONS) {
                        if sect_offset + 68 > cmd_payload.len() {
                            break;
                        }

                        let sect_name = read_fixed_str(&cmd_payload[sect_offset..sect_offset + 16]);
                        let s_seg_name =
                            read_fixed_str(&cmd_payload[sect_offset + 16..sect_offset + 32]);
                        let s_addr =
                            read_u32(cmd_payload, sect_offset + 32, is_little_endian)? as u64;
                        let s_size =
                            read_u32(cmd_payload, sect_offset + 36, is_little_endian)? as u64;
                        let s_off =
                            read_u32(cmd_payload, sect_offset + 40, is_little_endian)? as u64;
                        let s_align =
                            1u64 << read_u32(cmd_payload, sect_offset + 44, is_little_endian)?;
                        let _s_reloff =
                            read_u32(cmd_payload, sect_offset + 48, is_little_endian)? as u64;
                        let s_nreloc = read_u32(cmd_payload, sect_offset + 52, is_little_endian)?;
                        let s_flags = read_u32(cmd_payload, sect_offset + 56, is_little_endian)?;

                        let full_sect_name = format!("{s_seg_name},{sect_name}");
                        let sect_entropy =
                            if s_off + s_size <= slice_bytes.len() as u64 && s_size > 0 {
                                let sect_slice =
                                    &slice_bytes[s_off as usize..(s_off + s_size) as usize];
                                Some(hash::calculate_entropy(sect_slice))
                            } else {
                                None
                            };

                        let s_idx = sections.len() as u16;
                        sections.push(Section {
                            index: s_idx,
                            name: full_sect_name,
                            section_type: s_flags & 0xff,
                            flags: s_flags as u64,
                            address: s_addr,
                            offset: s_off,
                            size: s_size,
                            link: 0,
                            info: s_nreloc,
                            alignment: s_align,
                            entry_size: 0,
                            entropy: sect_entropy,
                        });

                        sect_offset += 68;
                    }
                }
            }
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB => {
                if cmd_payload.len() >= 24 {
                    let name_offset = read_u32(cmd_payload, 8, is_little_endian)? as usize;
                    if name_offset < cmd_payload.len()
                        && let Some(dylib_path) =
                            read_cstring(cmd_payload, name_offset, cmd_payload.len() - name_offset)
                    {
                        let escaped = text::escape_bytes(dylib_path.as_bytes());
                        dynamic.needed.push(escaped.clone());
                        dynamic.entries.push(crate::model::DynamicEntry {
                            tag: cmd as u64,
                            tag_name: if cmd == LC_LOAD_WEAK_DYLIB {
                                "LC_LOAD_WEAK_DYLIB".to_string()
                            } else if cmd == LC_REEXPORT_DYLIB {
                                "LC_REEXPORT_DYLIB".to_string()
                            } else {
                                "LC_LOAD_DYLIB".to_string()
                            },
                            value: 0,
                            string_value: Some(escaped),
                        });
                    }
                }
            }
            LC_ID_DYLIB => {
                if cmd_payload.len() >= 24 {
                    let name_offset = read_u32(cmd_payload, 8, is_little_endian)? as usize;
                    if name_offset < cmd_payload.len()
                        && let Some(install_name) =
                            read_cstring(cmd_payload, name_offset, cmd_payload.len() - name_offset)
                    {
                        let escaped = text::escape_bytes(install_name.as_bytes());
                        if dynamic.interpreter.is_none() {
                            dynamic.interpreter = Some(escaped.clone());
                        }
                        dynamic.entries.push(crate::model::DynamicEntry {
                            tag: cmd as u64,
                            tag_name: "LC_ID_DYLIB (Install Name)".to_string(),
                            value: 0,
                            string_value: Some(escaped),
                        });
                    }
                }
            }
            LC_LOAD_DYLINKER => {
                if cmd_payload.len() >= 12 {
                    let name_offset = read_u32(cmd_payload, 8, is_little_endian)? as usize;
                    if name_offset < cmd_payload.len()
                        && let Some(dylinker) =
                            read_cstring(cmd_payload, name_offset, cmd_payload.len() - name_offset)
                    {
                        let escaped = text::escape_bytes(dylinker.as_bytes());
                        dynamic.interpreter = Some(escaped.clone());
                        dynamic.entries.push(crate::model::DynamicEntry {
                            tag: cmd as u64,
                            tag_name: "LC_LOAD_DYLINKER (Dynamic Linker)".to_string(),
                            value: 0,
                            string_value: Some(escaped),
                        });
                    }
                }
            }
            LC_RPATH => {
                if cmd_payload.len() >= 12 {
                    let path_offset = read_u32(cmd_payload, 8, is_little_endian)? as usize;
                    if path_offset < cmd_payload.len()
                        && let Some(rpath_val) =
                            read_cstring(cmd_payload, path_offset, cmd_payload.len() - path_offset)
                    {
                        let escaped = text::escape_bytes(rpath_val.as_bytes());
                        if escaped.starts_with("./")
                            || escaped.is_empty()
                            || escaped.contains("/tmp")
                        {
                            has_insecure_rpath = true;
                        }
                        if dynamic.rpath.is_none() {
                            dynamic.rpath = Some(escaped.clone());
                        }
                        dynamic.entries.push(crate::model::DynamicEntry {
                            tag: cmd as u64,
                            tag_name: "LC_RPATH".to_string(),
                            value: 0,
                            string_value: Some(escaped),
                        });
                    }
                }
            }
            LC_MAIN => {
                if cmd_payload.len() >= 24 {
                    let entryoff = read_u64(cmd_payload, 8, is_little_endian)?;
                    let full_ep = text_vmaddr.map(|t| t + entryoff).unwrap_or(entryoff);
                    entry_point = Some(full_ep);
                }
            }
            LC_UNIXTHREAD => {
                // Thread state: 8 bytes header (cmd, cmdsize), 4 bytes flavor, 4 bytes count, register state
                if entry_point.is_none() && cmd_payload.len() >= 24 {
                    // x86_64: x86_THREAD_STATE64 flavor is 4. RIP register is at offset 16 + 16*8 = 144
                    if (cpu_type == CPU_TYPE_X86_64 || cpu_type == CPU_TYPE_X86)
                        && cmd_payload.len() >= 152
                    {
                        if let Ok(rip) = read_u64(cmd_payload, 144, is_little_endian) {
                            entry_point = Some(rip);
                        }
                    } else if (cpu_type == CPU_TYPE_ARM64 || cpu_type == CPU_TYPE_ARM64_32)
                        && cmd_payload.len() >= 280
                    {
                        // ARM64_THREAD_STATE flavor is 6. PC is at offset 16 + 32*8 = 272
                        if let Ok(pc) = read_u64(cmd_payload, 272, is_little_endian) {
                            entry_point = Some(pc);
                        }
                    }
                }
            }
            LC_BUILD_VERSION => {
                if cmd_payload.len() >= 24 {
                    let platform = read_u32(cmd_payload, 8, is_little_endian)?;
                    let minos = read_u32(cmd_payload, 12, is_little_endian)?;
                    let sdk = read_u32(cmd_payload, 16, is_little_endian)?;

                    let platform_str = match platform {
                        1 => "macOS",
                        2 => "iOS",
                        3 => "tvOS",
                        4 => "watchOS",
                        5 => "bridgeOS",
                        6 => "Mac Catalyst",
                        7 => "iOS Simulator",
                        8 => "tvOS Simulator",
                        9 => "watchOS Simulator",
                        11 => "visionOS",
                        _ => "Apple OS",
                    };
                    let minos_str =
                        format!("{}.{}.{}", minos >> 16, (minos >> 8) & 0xff, minos & 0xff);
                    let sdk_str = format!("{}.{}.{}", sdk >> 16, (sdk >> 8) & 0xff, sdk & 0xff);
                    min_os = Some(format!("{platform_str} {minos_str} (SDK {sdk_str})"));
                }
            }
            LC_VERSION_MIN_MACOSX
            | LC_VERSION_MIN_IPHONEOS
            | LC_VERSION_MIN_TVOS
            | LC_VERSION_MIN_WATCHOS => {
                if min_os.is_none() && cmd_payload.len() >= 16 {
                    let version = read_u32(cmd_payload, 8, is_little_endian)?;
                    let sdk = read_u32(cmd_payload, 12, is_little_endian)?;
                    let name = match cmd {
                        LC_VERSION_MIN_MACOSX => "macOS",
                        LC_VERSION_MIN_IPHONEOS => "iOS",
                        LC_VERSION_MIN_TVOS => "tvOS",
                        LC_VERSION_MIN_WATCHOS => "watchOS",
                        _ => "macOS",
                    };
                    let ver_str = format!(
                        "{}.{}.{}",
                        version >> 16,
                        (version >> 8) & 0xff,
                        version & 0xff
                    );
                    let sdk_str = format!("{}.{}.{}", sdk >> 16, (sdk >> 8) & 0xff, sdk & 0xff);
                    min_os = Some(format!("{name} {ver_str} (SDK {sdk_str})"));
                }
            }
            LC_UUID => {
                if cmd_payload.len() >= 24 {
                    let uuid_bytes = &cmd_payload[8..24];
                    let formatted = format!(
                        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                        uuid_bytes[0],
                        uuid_bytes[1],
                        uuid_bytes[2],
                        uuid_bytes[3],
                        uuid_bytes[4],
                        uuid_bytes[5],
                        uuid_bytes[6],
                        uuid_bytes[7],
                        uuid_bytes[8],
                        uuid_bytes[9],
                        uuid_bytes[10],
                        uuid_bytes[11],
                        uuid_bytes[12],
                        uuid_bytes[13],
                        uuid_bytes[14],
                        uuid_bytes[15]
                    );
                    uuid_str = Some(formatted.clone());
                    notes.push(ElfNote {
                        name: "Mach-O UUID".to_string(),
                        note_type: 1,
                        description: formatted.clone(),
                        build_id: Some(formatted),
                        abi_tag: None,
                        properties: Vec::new(),
                    });
                }
            }
            LC_CODE_SIGNATURE => {
                if cmd_payload.len() >= 16 {
                    let dataoff = read_u32(cmd_payload, 8, is_little_endian)?;
                    let datasize = read_u32(cmd_payload, 12, is_little_endian)?;
                    notes.push(ElfNote {
                        name: "Code Signature".to_string(),
                        note_type: 0x1d,
                        description: format!("Offset {dataoff:#x}, Size {datasize} bytes"),
                        build_id: None,
                        abi_tag: None,
                        properties: vec!["Embedded digital signature present".to_string()],
                    });
                }
            }
            LC_SYMTAB => {
                if cmd_payload.len() >= 24 {
                    let symoff = read_u32(cmd_payload, 8, is_little_endian)? as usize;
                    let nsyms = read_u32(cmd_payload, 12, is_little_endian)? as usize;
                    let stroff = read_u32(cmd_payload, 16, is_little_endian)? as usize;
                    let strsize = read_u32(cmd_payload, 20, is_little_endian)? as usize;

                    parse_symtab(
                        slice_bytes,
                        symoff,
                        nsyms,
                        stroff,
                        strsize,
                        is_64_bit,
                        is_little_endian,
                        &mut symbols,
                        &mut has_stack_canary,
                        &mut fortified_functions,
                    )?;
                }
            }
            LC_DYSYMTAB if cmd_payload.len() >= 80 => {
                let extreloff = read_u32(cmd_payload, 56, is_little_endian)? as usize;
                let nextrel = read_u32(cmd_payload, 60, is_little_endian)? as usize;
                let locreloff = read_u32(cmd_payload, 64, is_little_endian)? as usize;
                let nlocrel = read_u32(cmd_payload, 68, is_little_endian)? as usize;

                parse_relocs(
                    slice_bytes,
                    extreloff,
                    nextrel,
                    is_little_endian,
                    "External",
                    &mut relocations,
                )?;
                parse_relocs(
                    slice_bytes,
                    locreloff,
                    nlocrel,
                    is_little_endian,
                    "Local",
                    &mut relocations,
                )?;
            }
            _ => {}
        }

        cmd_offset += cmdsize;
    }

    // Security Mitigations (checksec for Mach-O)
    let is_dylib = file_type_raw == MH_DYLIB;
    let has_pie_flag = flags & MH_PIE != 0;
    let pie = if is_dylib {
        PieStatus::Dso
    } else if has_pie_flag {
        PieStatus::Pie
    } else {
        PieStatus::NoPie
    };

    let stack_canary = if has_stack_canary {
        Hardening::Enabled
    } else {
        Hardening::Disabled
    };

    let allow_stack_exec = flags & MH_ALLOW_STACK_EXECUTION != 0;
    let nx = if allow_stack_exec || rwx_segments > 0 {
        Hardening::Disabled
    } else {
        Hardening::Enabled
    };

    let relro = if flags & MH_BINDATLOAD != 0 {
        Relro::Full
    } else if flags & MH_TWOLEVEL != 0 {
        Relro::Partial
    } else {
        Relro::Unknown
    };

    let fortify = if !fortified_functions.is_empty() {
        Hardening::Enabled
    } else {
        Hardening::Disabled
    };

    let mitigations = SecurityMitigations {
        relro,
        stack_canary,
        nx,
        pie,
        fortify,
        fortified_functions: fortified_functions.into_iter().collect(),
        rwx_segments,
        has_insecure_rpath,
    };

    let macho_header = MachOHeader {
        cpu_arch,
        cpu_type,
        cpu_subtype,
        file_type,
        file_type_raw,
        ncmds,
        sizeofcmds,
        flags,
        flags_desc,
        is_64_bit,
        is_little_endian,
        entry_point,
        min_os,
        uuid: uuid_str,
        is_fat_universal,
        fat_architectures,
    };

    let hashes = FileHashes {
        sha256: hash::sha256_hex(bytes),
    };

    let strings =
        crate::strings::extract(slice_bytes, &sections, crate::strings::DEFAULT_MIN_LENGTH);

    Ok(Binary {
        format: FileFormat::MachO,
        file: FileMetadata {
            size_bytes: file_len,
        },
        elf: None,
        pe: None,
        macho: Some(macho_header),
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

type FatSlice<'a> = ((&'a [u8], usize), Vec<String>);

/// Slices a Fat / Universal container, preferring ARM64/ARM64E or x86_64 slices.
fn extract_fat_slice<'a>(
    bytes: &'a [u8],
    is_little_endian: bool,
    is_64_bit: bool,
) -> Result<FatSlice<'a>, AppError> {
    if bytes.len() < 8 {
        return Err(ParseError::FileTooShort {
            actual: bytes.len(),
            expected: 8,
        }
        .into());
    }

    let nfat_arch = read_u32(bytes, 4, is_little_endian)? as usize;
    if nfat_arch == 0 || nfat_arch > 32 {
        return Err(ParseError::Malformed(format!(
            "invalid fat_header nfat_arch count: {nfat_arch}"
        ))
        .into());
    }

    let entry_size = if is_64_bit { 32 } else { 20 };
    let required_len = 8 + nfat_arch * entry_size;
    if bytes.len() < required_len {
        return Err(ParseError::OutOfBounds {
            what: "fat_arch header array",
            offset: 8,
            size: (nfat_arch * entry_size) as u64,
        }
        .into());
    }

    let mut arch_names = Vec::new();
    let mut chosen_slice: Option<(&'a [u8], usize)> = None;
    let mut chosen_rank = 0usize;

    for i in 0..nfat_arch {
        let entry_offset = 8 + i * entry_size;
        let cputype = read_u32(bytes, entry_offset, is_little_endian)?;
        let cpusubtype = read_u32(bytes, entry_offset + 4, is_little_endian)?;

        let (slice_offset, slice_size) = if is_64_bit {
            let off = read_u64(bytes, entry_offset + 8, is_little_endian)? as usize;
            let sz = read_u64(bytes, entry_offset + 16, is_little_endian)? as usize;
            (off, sz)
        } else {
            let off = read_u32(bytes, entry_offset + 8, is_little_endian)? as usize;
            let sz = read_u32(bytes, entry_offset + 12, is_little_endian)? as usize;
            (off, sz)
        };

        let arch_label = format_cpu_arch(cputype, cpusubtype);
        arch_names.push(arch_label);

        if slice_offset + slice_size <= bytes.len() {
            // Prioritize ARM64E (rank 4), ARM64 (rank 3), x86_64 (rank 2), other 64-bit (rank 1)
            let rank = if cputype == CPU_TYPE_ARM64 && cpusubtype == CPU_SUBTYPE_ARM64E {
                4
            } else if cputype == CPU_TYPE_ARM64 {
                3
            } else if cputype == CPU_TYPE_X86_64 {
                2
            } else {
                1
            };

            if rank > chosen_rank || chosen_slice.is_none() {
                chosen_rank = rank;
                chosen_slice = Some((
                    &bytes[slice_offset..slice_offset + slice_size],
                    slice_offset,
                ));
            }
        }
    }

    let slice = chosen_slice.ok_or_else(|| {
        ParseError::Malformed("no valid architecture slice found in fat binary".to_string())
    })?;

    Ok((slice, arch_names))
}

#[allow(clippy::too_many_arguments)]
fn parse_symtab(
    bytes: &[u8],
    symoff: usize,
    nsyms: usize,
    stroff: usize,
    strsize: usize,
    is_64_bit: bool,
    is_little_endian: bool,
    symbols: &mut Vec<Symbol>,
    has_canary: &mut bool,
    fortified_functions: &mut HashSet<String>,
) -> Result<(), ParseError> {
    let entry_size = if is_64_bit { 16 } else { 12 };
    let total_syms_len = nsyms.saturating_mul(entry_size);

    if symoff + total_syms_len > bytes.len() || stroff + strsize > bytes.len() {
        return Ok(()); // Lenient for truncated debug symbols
    }

    let string_table = &bytes[stroff..stroff + strsize];
    let limit = nsyms.min(MAX_SYMBOLS);

    for i in 0..limit {
        let entry_off = symoff + i * entry_size;
        let strx = read_u32(bytes, entry_off, is_little_endian)? as usize;
        let n_type = bytes[entry_off + 4];
        let n_sect = bytes[entry_off + 5];
        let n_value = if is_64_bit {
            read_u64(bytes, entry_off + 8, is_little_endian)?
        } else {
            read_u32(bytes, entry_off + 8, is_little_endian)? as u64
        };

        let sym_name = if strx < string_table.len() {
            read_cstring(string_table, strx, string_table.len() - strx).unwrap_or_default()
        } else {
            String::new()
        };

        // Check for stack canary & fortified functions
        if sym_name == "___stack_chk_fail" || sym_name == "___stack_chk_guard" {
            *has_canary = true;
        }
        if is_fortified_symbol(&sym_name) {
            fortified_functions.insert(sym_name.clone());
        }

        let is_external = n_type & 0x01 != 0;
        let is_undefined = (n_type & 0x0e) == 0x0;

        let binding = if is_external {
            SymbolBinding::Global
        } else {
            SymbolBinding::Local
        };

        let sym_type = if is_undefined {
            SymbolType::NoType
        } else {
            SymbolType::Func
        };

        let escaped_name = text::escape_bytes(sym_name.as_bytes());

        symbols.push(Symbol {
            index: symbols.len(),
            name: escaped_name,
            value: n_value,
            size: 0,
            sym_type,
            binding,
            visibility: SymbolVisibility::Default,
            section_index: if n_sect > 0 {
                Some(n_sect as u16)
            } else {
                None
            },
            is_import: is_undefined,
            is_export: is_external && !is_undefined,
            table: SymbolTableKind::Dynamic,
        });
    }

    Ok(())
}

fn parse_relocs(
    bytes: &[u8],
    reloff: usize,
    nreloc: usize,
    is_little_endian: bool,
    section_name: &'static str,
    relocations: &mut Vec<Relocation>,
) -> Result<(), ParseError> {
    if reloff + nreloc.saturating_mul(8) > bytes.len() {
        return Ok(());
    }

    let limit = nreloc.min(MAX_RELOCATIONS);
    for i in 0..limit {
        let off = reloff + i * 8;
        let r_address = read_u32(bytes, off, is_little_endian)? as u64;
        let r_info = read_u32(bytes, off + 4, is_little_endian)?;
        let r_type = r_info >> 28;

        relocations.push(Relocation {
            section_name: section_name.to_string(),
            offset: r_address,
            rel_type: r_type,
            symbol_index: 0,
            symbol_name: None,
            addend: None,
        });
    }

    Ok(())
}

fn is_fortified_symbol(name: &str) -> bool {
    let clean = name.strip_prefix('_').unwrap_or(name);
    clean.ends_with("_chk")
        && (clean.starts_with("memcpy")
            || clean.starts_with("memmove")
            || clean.starts_with("memset")
            || clean.starts_with("strcpy")
            || clean.starts_with("strncpy")
            || clean.starts_with("strcat")
            || clean.starts_with("strncat")
            || clean.starts_with("sprintf")
            || clean.starts_with("snprintf")
            || clean.starts_with("printf"))
}

fn format_cpu_arch(cputype: u32, cpusubtype: u32) -> String {
    match cputype {
        CPU_TYPE_X86_64 => {
            if cpusubtype == CPU_SUBTYPE_X86_64_H {
                "x86_64 (Haswell)".to_string()
            } else {
                "x86_64".to_string()
            }
        }
        CPU_TYPE_ARM64 => {
            if cpusubtype == CPU_SUBTYPE_ARM64E {
                "arm64e (Apple Silicon PAC)".to_string()
            } else {
                "arm64".to_string()
            }
        }
        CPU_TYPE_ARM64_32 => "arm64_32 (Apple Watch)".to_string(),
        CPU_TYPE_X86 => "x86 (32-bit)".to_string(),
        CPU_TYPE_ARM => "arm (32-bit)".to_string(),
        CPU_TYPE_POWERPC64 => "ppc64".to_string(),
        CPU_TYPE_POWERPC => "ppc".to_string(),
        other => format!("Unknown CPU ({other:#010x})"),
    }
}

fn format_file_type(filetype: u32) -> String {
    match filetype {
        MH_OBJECT => "Relocatable Object".to_string(),
        MH_EXECUTE => "Executable (MH_EXECUTE)".to_string(),
        MH_FVMLIB => "Fixed VM Library".to_string(),
        MH_CORE => "Core Dump".to_string(),
        MH_PRELOAD => "Preloaded Executable".to_string(),
        MH_DYLIB => "Dynamic Library (MH_DYLIB)".to_string(),
        MH_DYLINKER => "Dynamic Linker".to_string(),
        MH_BUNDLE => "Bundle (MH_BUNDLE)".to_string(),
        MH_DSYM => "dSYM Companion".to_string(),
        MH_KEXT_BUNDLE => "Kernel Extension (kext)".to_string(),
        other => format!("Type {other:#x}"),
    }
}

fn decode_flags(flags: u32) -> Vec<String> {
    let mut descs = Vec::new();
    if flags & MH_PIE != 0 {
        descs.push("MH_PIE (ASLR enabled)".to_string());
    }
    if flags & MH_TWOLEVEL != 0 {
        descs.push("MH_TWOLEVEL (Two-level namespace)".to_string());
    }
    if flags & MH_BINDATLOAD != 0 {
        descs.push("MH_BINDATLOAD (Immediate binding)".to_string());
    }
    if flags & MH_NOUNDEFS != 0 {
        descs.push("MH_NOUNDEFS".to_string());
    }
    if flags & MH_INCRLINK != 0 {
        descs.push("MH_INCRLINK (Incremental link)".to_string());
    }
    if flags & MH_PREBOUND != 0 {
        descs.push("MH_PREBOUND".to_string());
    }
    if flags & MH_SPLIT_SEGS != 0 {
        descs.push("MH_SPLIT_SEGS".to_string());
    }
    if flags & MH_FORCE_FLAT != 0 {
        descs.push("MH_FORCE_FLAT (Flat namespace)".to_string());
    }
    if flags & MH_WEAK_DEFINES != 0 {
        descs.push("MH_WEAK_DEFINES".to_string());
    }
    if flags & MH_BINDS_TO_WEAK != 0 {
        descs.push("MH_BINDS_TO_WEAK".to_string());
    }
    if flags & MH_DYLDLINK != 0 {
        descs.push("MH_DYLDLINK".to_string());
    }
    if flags & MH_ALLOW_STACK_EXECUTION != 0 {
        descs.push("MH_ALLOW_STACK_EXECUTION (Executable Stack)".to_string());
    }
    if flags & MH_ROOT_SAFE != 0 {
        descs.push("MH_ROOT_SAFE".to_string());
    }
    if flags & MH_SETUID_SAFE != 0 {
        descs.push("MH_SETUID_SAFE".to_string());
    }
    if flags & MH_DEAD_STRIPPABLE_DYLIB != 0 {
        descs.push("MH_DEAD_STRIPPABLE_DYLIB".to_string());
    }
    if flags & MH_NO_HEAP_EXECUTION != 0 {
        descs.push("MH_NO_HEAP_EXECUTION (DEP Heap)".to_string());
    }
    if flags & MH_APP_EXTENSION_SAFE != 0 {
        descs.push("MH_APP_EXTENSION_SAFE".to_string());
    }
    descs
}

fn read_u32(bytes: &[u8], offset: usize, is_le: bool) -> Result<u32, ParseError> {
    if offset + 4 > bytes.len() {
        return Err(ParseError::OutOfBounds {
            what: "u32 field",
            offset: offset as u64,
            size: 4,
        });
    }
    let slice = [
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ];
    Ok(if is_le {
        u32::from_le_bytes(slice)
    } else {
        u32::from_be_bytes(slice)
    })
}

fn read_u64(bytes: &[u8], offset: usize, is_le: bool) -> Result<u64, ParseError> {
    if offset + 8 > bytes.len() {
        return Err(ParseError::OutOfBounds {
            what: "u64 field",
            offset: offset as u64,
            size: 8,
        });
    }
    let slice = [
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ];
    Ok(if is_le {
        u64::from_le_bytes(slice)
    } else {
        u64::from_be_bytes(slice)
    })
}

fn read_fixed_str(slice: &[u8]) -> String {
    let nul_pos = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..nul_pos])
        .trim()
        .to_string()
}

fn read_cstring(bytes: &[u8], offset: usize, max_len: usize) -> Option<String> {
    if offset >= bytes.len() {
        return None;
    }
    let end = (offset + max_len).min(bytes.len());
    let slice = &bytes[offset..end];
    let nul_pos = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    Some(String::from_utf8_lossy(&slice[..nul_pos]).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_minimal_macho_64_binary() {
        let mut bytes = vec![0u8; 512];
        // MH_CIGAM_64 magic
        bytes[0..4].copy_from_slice(&MH_CIGAM_64.to_be_bytes());
        // CPU_TYPE_ARM64
        bytes[4..8].copy_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
        // CPU_SUBTYPE_ARM64E
        bytes[8..12].copy_from_slice(&CPU_SUBTYPE_ARM64E.to_le_bytes());
        // MH_EXECUTE
        bytes[12..16].copy_from_slice(&MH_EXECUTE.to_le_bytes());
        // ncmds = 1
        bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
        // sizeofcmds = 72
        bytes[20..24].copy_from_slice(&72u32.to_le_bytes());
        // flags = MH_PIE | MH_TWOLEVEL
        let flags = MH_PIE | MH_TWOLEVEL;
        bytes[24..28].copy_from_slice(&flags.to_le_bytes());

        // Command 1: LC_SEGMENT_64 "__TEXT"
        let cmd_off = 32;
        bytes[cmd_off..cmd_off + 4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
        bytes[cmd_off + 4..cmd_off + 8].copy_from_slice(&72u32.to_le_bytes());
        bytes[cmd_off + 8..cmd_off + 14].copy_from_slice(b"__TEXT");
        // vmaddr = 0x100000000
        bytes[cmd_off + 24..cmd_off + 32].copy_from_slice(&0x100000000u64.to_le_bytes());
        // vmsize = 0x4000
        bytes[cmd_off + 32..cmd_off + 40].copy_from_slice(&0x4000u64.to_le_bytes());
        // fileoff = 0
        bytes[cmd_off + 40..cmd_off + 48].copy_from_slice(&0u64.to_le_bytes());
        // filesize = 512
        bytes[cmd_off + 48..cmd_off + 56].copy_from_slice(&512u64.to_le_bytes());
        // initprot = 5 (Read | Execute)
        bytes[cmd_off + 60..cmd_off + 64].copy_from_slice(&5u32.to_le_bytes());

        let binary = parse(&bytes, 512).expect("valid Mach-O 64-bit binary");
        assert_eq!(binary.format, FileFormat::MachO);
        let macho = binary.macho.expect("macho header present");
        assert_eq!(macho.cpu_arch, "arm64e (Apple Silicon PAC)");
        assert!(macho.is_64_bit);
        assert!(macho.is_little_endian);
        assert_eq!(binary.mitigations.pie, PieStatus::Pie);
        assert_eq!(binary.mitigations.nx, Hardening::Enabled);
        assert_eq!(binary.mitigations.rwx_segments, 0);
        assert_eq!(binary.segments.len(), 1);
        assert_eq!(binary.segments[0].virtual_address, 0x100000000);
    }

    #[test]
    fn parses_fat_universal_binary() {
        let mut bytes = vec![0u8; 1024];
        // FAT_MAGIC (big endian)
        bytes[0..4].copy_from_slice(&FAT_MAGIC.to_be_bytes());
        // nfat_arch = 2
        bytes[4..8].copy_from_slice(&2u32.to_be_bytes());

        // Arch 1: x86_64 at offset 256, size 256
        bytes[8..12].copy_from_slice(&CPU_TYPE_X86_64.to_be_bytes());
        bytes[12..16].copy_from_slice(&3u32.to_be_bytes()); // ALL
        bytes[16..20].copy_from_slice(&256u32.to_be_bytes()); // offset
        bytes[20..24].copy_from_slice(&256u32.to_be_bytes()); // size

        // Arch 2: arm64 at offset 512, size 256
        bytes[28..32].copy_from_slice(&CPU_TYPE_ARM64.to_be_bytes());
        bytes[32..36].copy_from_slice(&0u32.to_be_bytes()); // ALL
        bytes[36..40].copy_from_slice(&512u32.to_be_bytes()); // offset
        bytes[40..44].copy_from_slice(&256u32.to_be_bytes()); // size

        // Write Mach-O header for ARM64 slice at offset 512
        let arm_off = 512;
        bytes[arm_off..arm_off + 4].copy_from_slice(&MH_CIGAM_64.to_be_bytes());
        bytes[arm_off + 4..arm_off + 8].copy_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
        bytes[arm_off + 8..arm_off + 12].copy_from_slice(&0u32.to_le_bytes());
        bytes[arm_off + 12..arm_off + 16].copy_from_slice(&MH_EXECUTE.to_le_bytes());
        bytes[arm_off + 16..arm_off + 20].copy_from_slice(&0u32.to_le_bytes()); // 0 cmds

        let binary = parse(&bytes, 1024).expect("valid fat binary");
        let macho = binary.macho.expect("macho header present");
        assert!(macho.is_fat_universal);
        assert_eq!(macho.fat_architectures.len(), 2);
        assert_eq!(macho.cpu_arch, "arm64");
    }

    #[test]
    fn detects_rwx_segments_in_macho() {
        let mut bytes = vec![0u8; 512];
        bytes[0..4].copy_from_slice(&MH_CIGAM_64.to_be_bytes());
        bytes[4..8].copy_from_slice(&CPU_TYPE_X86_64.to_le_bytes());
        bytes[12..16].copy_from_slice(&MH_EXECUTE.to_le_bytes());
        bytes[16..20].copy_from_slice(&1u32.to_le_bytes()); // 1 cmd
        bytes[20..24].copy_from_slice(&72u32.to_le_bytes());

        // Command 1: LC_SEGMENT_64 with initprot = 7 (Read | Write | Execute)
        let cmd_off = 32;
        bytes[cmd_off..cmd_off + 4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
        bytes[cmd_off + 4..cmd_off + 8].copy_from_slice(&72u32.to_le_bytes());
        bytes[cmd_off + 8..cmd_off + 15].copy_from_slice(b"__BADRW");
        bytes[cmd_off + 48..cmd_off + 56].copy_from_slice(&512u64.to_le_bytes()); // filesize
        bytes[cmd_off + 60..cmd_off + 64].copy_from_slice(&7u32.to_le_bytes()); // RWX

        let binary = parse(&bytes, 512).expect("valid Mach-O binary");
        assert_eq!(binary.mitigations.rwx_segments, 1);
        assert_eq!(binary.mitigations.nx, Hardening::Disabled);
    }

    #[test]
    fn inspect_bytes_dispatches_macho() {
        let mut bytes = vec![0u8; 512];
        bytes[0..4].copy_from_slice(&MH_CIGAM_64.to_be_bytes());
        bytes[4..8].copy_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
        bytes[12..16].copy_from_slice(&MH_EXECUTE.to_le_bytes());

        let binary = crate::inspect_bytes(&bytes, 512).expect("dispatches Mach-O");
        assert_eq!(binary.format, FileFormat::MachO);
        assert!(binary.macho.is_some());
    }

    #[test]
    fn rejects_truncated_macho() {
        let bytes = vec![0u8; 10];
        assert!(parse(&bytes, 10).is_err());
    }
}
