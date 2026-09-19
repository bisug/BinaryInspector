//! Deterministic human-readable Phase 1 reporting.

use std::fmt::Write;

use crate::model::Binary;

/// Formats the currently available human-readable report.
pub fn human(binary: &Binary) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "Format: ELF");
    let _ = writeln!(output, "File size: {} bytes", binary.file.size_bytes);
    let _ = writeln!(output, "Class: {}", binary.elf.class);
    let _ = writeln!(output, "Endianness: {}", binary.elf.endianness);
    let _ = writeln!(output, "Type: {}", binary.elf.elf_type);
    let _ = writeln!(output, "Machine: {}", binary.elf.machine);
    let _ = writeln!(output, "OS ABI: {}", binary.elf.os_abi);
    let _ = writeln!(output, "ABI version: {}", binary.elf.abi_version);
    let _ = writeln!(output, "Entry point: {:#x}", binary.elf.entry_point);
    output
}
