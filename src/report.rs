//! Deterministic human-readable Phase 1 reporting.

use std::fmt::Write;

use crate::model::Binary;

/// Formats the currently available human-readable report.
pub fn human(binary: &Binary, sections: bool, segments: bool, dependencies: bool) -> String {
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
    if sections {
        let _ = writeln!(output, "\nSections:");
        for section in &binary.sections {
            let _ = writeln!(
                output,
                "  [{:>2}] {:<20} type={:#x} flags={} address={:#x} offset={:#x} size={:#x}",
                section.index,
                section.name,
                section.section_type,
                section_flags(section.flags),
                section.address,
                section.offset,
                section.size
            );
        }
    }
    if segments {
        let _ = writeln!(output, "\nSegments:");
        for segment in &binary.segments {
            let _ = writeln!(
                output,
                "  [{:>2}] type={:#x} flags={} offset={:#x} vaddr={:#x} filesz={:#x} memsz={:#x} align={:#x}",
                segment.index,
                segment.segment_type,
                segment_flags(segment.flags),
                segment.offset,
                segment.virtual_address,
                segment.file_size,
                segment.memory_size,
                segment.alignment
            );
        }
    }
    if dependencies {
        let _ = writeln!(output, "\nDependencies:");
        if let Some(interpreter) = &binary.dynamic.interpreter {
            let _ = writeln!(output, "  Interpreter: {interpreter}");
        }
        if let Some(rpath) = &binary.dynamic.rpath {
            let _ = writeln!(output, "  RPATH: {rpath}");
        }
        if let Some(runpath) = &binary.dynamic.runpath {
            let _ = writeln!(output, "  RUNPATH: {runpath}");
        }
        for needed in &binary.dynamic.needed {
            let _ = writeln!(output, "  Needed: {needed}");
        }
        if binary.dynamic.needed.is_empty() && binary.dynamic.interpreter.is_none() {
            let _ = writeln!(output, "  None");
        }
    }
    output
}

fn section_flags(flags: u64) -> String {
    let mut output = String::new();
    if flags & 0x1 != 0 {
        output.push('W');
    }
    if flags & 0x2 != 0 {
        output.push('A');
    }
    if flags & 0x4 != 0 {
        output.push('X');
    }
    if output.is_empty() {
        output.push('-');
    }
    output
}

fn segment_flags(flags: u32) -> String {
    let mut output = String::new();
    if flags & 0x4 != 0 {
        output.push('R');
    }
    if flags & 0x2 != 0 {
        output.push('W');
    }
    if flags & 0x1 != 0 {
        output.push('E');
    }
    if output.is_empty() {
        output.push('-');
    }
    output
}
