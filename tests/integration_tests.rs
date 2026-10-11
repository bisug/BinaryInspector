//! End-to-end integration tests for BinaryInspector.

#![forbid(unsafe_code)]

use std::{
    fs::{self, File},
    io::Write,
    path::PathBuf,
    process::Command,
};

use binary_inspector::{
    error::{AppError, ParseError},
    inspect, inspect_bytes,
    model::{FileFormat, Hardening, PieStatus, StringCategory},
    report::{self, ReportOptions},
};

fn create_temp_file(prefix: &str, content: &[u8]) -> PathBuf {
    let mut path = std::env::temp_dir();
    let unique = format!(
        "{prefix}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    path.push(unique);
    let mut file = File::create(&path).expect("failed to create temp file");
    file.write_all(content).expect("failed to write temp file");
    path
}

fn minimal_elf64_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 128];
    // Magic
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2; // ELFCLASS64
    bytes[5] = 1; // ELFDATA2LSB (little endian)
    bytes[6] = 1; // EV_CURRENT
    bytes[7] = 0; // ELFOSABI_NONE
    // Type: ET_EXEC (2)
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    // Machine: EM_X86_64 (62)
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
    // Version (1)
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    // Entry: 0x400000
    bytes[24..32].copy_from_slice(&0x400000u64.to_le_bytes());
    // Header size: 64
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes
}

fn minimal_pe32_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 512];
    // DOS Header
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew = 128

    // PE Header signature at offset 128
    let pe_off = 128;
    bytes[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");

    // COFF Header
    let coff_off = pe_off + 4;
    bytes[coff_off..coff_off + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // IMAGE_FILE_MACHINE_AMD64
    bytes[coff_off + 2..coff_off + 4].copy_from_slice(&0u16.to_le_bytes()); // 0 sections
    bytes[coff_off + 16..coff_off + 18].copy_from_slice(&240u16.to_le_bytes()); // opt header size

    // Optional Header (PE32+ 64-bit)
    let opt_off = coff_off + 20;
    bytes[opt_off..opt_off + 2].copy_from_slice(&0x020bu16.to_le_bytes()); // PE32+
    bytes[opt_off + 16..opt_off + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry point
    bytes[opt_off + 24..opt_off + 32].copy_from_slice(&0x140000000u64.to_le_bytes()); // image base

    // DllCharacteristics: DYNAMIC_BASE (0x40) | NX_COMPAT (0x100)
    bytes[opt_off + 70..opt_off + 72].copy_from_slice(&(0x0040u16 | 0x0100u16).to_le_bytes());

    bytes
}

fn minimal_macho64_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 256];
    // MH_MAGIC_64 (0xfeedfacf) little endian
    bytes[0..4].copy_from_slice(&0xfeedfacfu32.to_le_bytes());
    // CPU_TYPE_X86_64 (0x01000007)
    bytes[4..8].copy_from_slice(&0x01000007u32.to_le_bytes());
    // CPU_SUBTYPE_LIB64 (0x80000003)
    bytes[8..12].copy_from_slice(&0x80000003u32.to_le_bytes());
    // MH_EXECUTE (2)
    bytes[12..16].copy_from_slice(&2u32.to_le_bytes());
    // ncmds = 0
    bytes[16..20].copy_from_slice(&0u32.to_le_bytes());
    // sizeofcmds = 0
    bytes[20..24].copy_from_slice(&0u32.to_le_bytes());
    // flags: MH_PIE (0x00200000)
    bytes[24..28].copy_from_slice(&0x00200000u32.to_le_bytes());
    bytes
}

fn minimal_fat_macho_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 512];
    // FAT_MAGIC (0xcafebabe) big endian
    bytes[0..4].copy_from_slice(&0xcafebabeu32.to_be_bytes());
    // nfat_arch = 1
    bytes[4..8].copy_from_slice(&1u32.to_be_bytes());

    // Slice 1: x86_64
    bytes[8..12].copy_from_slice(&0x01000007u32.to_be_bytes()); // cputype
    bytes[12..16].copy_from_slice(&3u32.to_be_bytes()); // cpusubtype
    bytes[16..20].copy_from_slice(&64u32.to_be_bytes()); // offset = 64
    bytes[20..24].copy_from_slice(&128u32.to_be_bytes()); // size = 128
    bytes[24..28].copy_from_slice(&3u32.to_be_bytes()); // align

    // Slice content at offset 64: Mach-O 64-bit header
    let slice_off = 64;
    bytes[slice_off..slice_off + 4].copy_from_slice(&0xfeedfacfu32.to_le_bytes());
    bytes[slice_off + 4..slice_off + 8].copy_from_slice(&0x01000007u32.to_le_bytes());
    bytes[slice_off + 8..slice_off + 12].copy_from_slice(&0x80000003u32.to_le_bytes());
    bytes[slice_off + 12..slice_off + 16].copy_from_slice(&2u32.to_le_bytes()); // MH_EXECUTE
    bytes[slice_off + 24..slice_off + 28].copy_from_slice(&0x00200000u32.to_le_bytes()); // MH_PIE

    bytes
}

#[test]
fn test_inspect_bytes_elf64_lifecycle() {
    let bytes = minimal_elf64_bytes();
    let binary = inspect_bytes(&bytes, bytes.len() as u64).expect("ELF64 parsing failed");

    assert_eq!(binary.format, FileFormat::Elf);
    assert!(binary.elf.is_some());
    let elf = binary.elf.as_ref().unwrap();
    assert_eq!(elf.entry_point, 0x400000);
    assert_eq!(elf.machine.to_string(), "x86-64");

    // Report generation
    let human = report::report_human(&binary, ReportOptions::default());
    assert!(human.contains("Format: ELF"));
    assert!(human.contains("SHA-256:"));

    let json = report::report_json(&binary).expect("JSON serialization failed");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("Invalid JSON emitted");
    assert_eq!(parsed["format"], "Elf");
    assert_eq!(parsed["schema_version"], 1);
}

#[test]
fn test_inspect_bytes_pe32_plus_lifecycle() {
    let bytes = minimal_pe32_bytes();
    let binary = inspect_bytes(&bytes, bytes.len() as u64).expect("PE32+ parsing failed");

    assert_eq!(binary.format, FileFormat::Pe);
    assert!(binary.pe.is_some());
    let pe = binary.pe.as_ref().unwrap();
    assert!(pe.is_pe32_plus);
    assert_eq!(pe.entry_point, 0x1000);
    assert_eq!(binary.mitigations.pie, PieStatus::Pie);
    assert_eq!(binary.mitigations.nx, Hardening::Enabled);

    let json = report::report_json(&binary).expect("JSON serialization failed");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("Invalid JSON emitted");
    assert_eq!(parsed["format"], "Pe");
    assert_eq!(parsed["pe"]["is_pe32_plus"], true);
}

#[test]
fn test_inspect_bytes_macho64_lifecycle() {
    let bytes = minimal_macho64_bytes();
    let binary = inspect_bytes(&bytes, bytes.len() as u64).expect("Mach-O parsing failed");

    assert_eq!(binary.format, FileFormat::MachO);
    assert!(binary.macho.is_some());
    let macho = binary.macho.as_ref().unwrap();
    assert!(macho.is_64_bit);
    assert_eq!(macho.cpu_arch, "x86_64");
    assert_eq!(binary.mitigations.pie, PieStatus::Pie);

    let json = report::report_json(&binary).expect("JSON serialization failed");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("Invalid JSON emitted");
    assert_eq!(parsed["format"], "MachO");
    assert_eq!(parsed["macho"]["cpu_arch"], "x86_64");
}

#[test]
fn test_inspect_bytes_fat_universal_macho() {
    let bytes = minimal_fat_macho_bytes();
    let binary =
        inspect_bytes(&bytes, bytes.len() as u64).expect("Fat Mach-O container parsing failed");

    assert_eq!(binary.format, FileFormat::MachO);
    assert!(binary.macho.is_some());
    let macho = binary.macho.as_ref().unwrap();
    assert!(macho.is_fat_universal);
    assert_eq!(macho.fat_architectures.len(), 1);

    let json = report::report_json(&binary).expect("JSON serialization failed");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("Invalid JSON emitted");
    assert_eq!(parsed["macho"]["is_fat_universal"], true);
}

#[test]
fn test_rejects_invalid_magic_and_empty_file() {
    let empty: [u8; 0] = [];
    assert!(matches!(
        inspect_bytes(&empty, 0),
        Err(AppError::Parse(ParseError::InvalidMagic))
    ));

    let text = b"#!/usr/bin/env python3\nprint('hello')\n";
    assert!(matches!(
        inspect_bytes(text, text.len() as u64),
        Err(AppError::Parse(ParseError::InvalidMagic))
    ));
}

#[test]
fn test_rejects_truncated_binaries_gracefully() {
    // Truncated ELF
    assert!(matches!(
        inspect_bytes(b"\x7fELF\x02", 5),
        Err(AppError::Parse(ParseError::FileTooShort { .. }))
    ));

    // Truncated PE DOS
    assert!(matches!(
        inspect_bytes(b"MZ\x00\x00", 4),
        Err(AppError::Parse(ParseError::FileTooShort { .. }))
    ));

    // Truncated Mach-O
    assert!(matches!(
        inspect_bytes(&0xfeedfacfu32.to_le_bytes(), 4),
        Err(AppError::Parse(ParseError::FileTooShort { .. }))
    ));
}

#[test]
fn test_file_inspect_negative_cases() {
    // Non-existent path
    let non_existent = PathBuf::from("/non_existent_binary_inspector_target_12345");
    assert!(matches!(inspect(&non_existent), Err(AppError::Io(_))));

    // Directory
    let temp_dir = std::env::temp_dir();
    assert!(matches!(
        inspect(&temp_dir),
        Err(AppError::InvalidFileType(_))
    ));

    // Text file
    let tmp = create_temp_file("plain_text", b"hello world this is plain text\n");
    let res = inspect(&tmp);
    let _ = fs::remove_file(&tmp);
    assert!(matches!(
        res,
        Err(AppError::Parse(ParseError::InvalidMagic))
    ));
}

#[test]
fn test_string_extraction_categories() {
    let mut payload = minimal_elf64_bytes();
    // Inject test strings
    payload.extend_from_slice(b"https://api.github.com/v1/repos\0");
    payload.extend_from_slice(b"192.168.1.100\0");
    payload.extend_from_slice(b"/var/log/syslog\0");
    payload.extend_from_slice(b"contact@antigravity.dev\0");
    payload.extend_from_slice(b"4a2c5e88-0000-41d4-a716-446655440000\0");
    payload.extend_from_slice(b"STANDARD_GENERAL_STRING\0");

    let binary = inspect_bytes(&payload, payload.len() as u64).unwrap();

    let has_url = binary
        .strings
        .iter()
        .any(|s| s.category == StringCategory::Url && s.value.contains("api.github.com"));
    let has_ip = binary
        .strings
        .iter()
        .any(|s| s.category == StringCategory::Ip && s.value == "192.168.1.100");
    let has_path = binary
        .strings
        .iter()
        .any(|s| s.category == StringCategory::FilePath && s.value == "/var/log/syslog");
    let has_email = binary
        .strings
        .iter()
        .any(|s| s.category == StringCategory::Email && s.value == "contact@antigravity.dev");
    let has_crypto = binary.strings.iter().any(|s| {
        s.category == StringCategory::Crypto && s.value == "4a2c5e88-0000-41d4-a716-446655440000"
    });
    let has_gen = binary
        .strings
        .iter()
        .any(|s| s.category == StringCategory::General && s.value == "STANDARD_GENERAL_STRING");

    assert!(has_url, "Expected URL category string");
    assert!(has_ip, "Expected IP category string");
    assert!(has_path, "Expected FilePath category string");
    assert!(has_email, "Expected Email category string");
    assert!(has_crypto, "Expected Crypto category string");
    assert!(has_gen, "Expected General category string");
}

#[test]
fn test_cli_exit_codes_via_subprocesses() {
    // Locate the built binary
    let target_bin = env!("CARGO_BIN_EXE_binary-inspector");

    // Case 1: Valid execution on itself
    let status_self = Command::new(target_bin)
        .arg(target_bin)
        .arg("--json")
        .output()
        .expect("failed to execute binary-inspector");
    assert!(
        status_self.status.success(),
        "CLI failed on itself: {:?}",
        status_self
    );

    // Case 2: Usage error (unknown argument) -> ExitCode 1
    let status_usage = Command::new(target_bin)
        .arg("--invalid-flag-xyz")
        .output()
        .expect("failed to execute binary-inspector");
    assert_eq!(
        status_usage.status.code(),
        Some(1),
        "Expected exit code 1 for invalid argument"
    );

    // Case 3: File not found -> ExitCode 2
    let status_not_found = Command::new(target_bin)
        .arg("/non_existent_file_path_12345")
        .output()
        .expect("failed to execute binary-inspector");
    assert_eq!(
        status_not_found.status.code(),
        Some(2),
        "Expected exit code 2 for non-existent file"
    );

    // Case 4: Directory -> ExitCode 2
    let status_dir = Command::new(target_bin)
        .arg(std::env::temp_dir())
        .output()
        .expect("failed to execute binary-inspector");
    assert_eq!(
        status_dir.status.code(),
        Some(2),
        "Expected exit code 2 for directory"
    );

    // Case 5: Non-executable plain text file -> ExitCode 3
    let tmp = create_temp_file("cli_test_text", b"non-binary text content");
    let status_text = Command::new(target_bin)
        .arg(&tmp)
        .output()
        .expect("failed to execute binary-inspector");
    let _ = fs::remove_file(&tmp);
    assert_eq!(
        status_text.status.code(),
        Some(3),
        "Expected exit code 3 for non-executable file"
    );
}
