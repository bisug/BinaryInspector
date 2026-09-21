//! Deterministic human-readable reporting.

use std::fmt::Write;

use crate::model::{Binary, Hardening, SecurityMitigations};

/// Options selecting which categories to display in human-readable output.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReportOptions {
    /// Show sections.
    pub sections: bool,
    /// Show program segments.
    pub segments: bool,
    /// Show dynamic dependencies and loader metadata.
    pub dependencies: bool,
    /// Show symbols.
    pub symbols: bool,
    /// Show security hardening mitigations.
    pub mitigations: bool,
    /// Show ELF notes and build info.
    pub notes: bool,
    /// Show relocations.
    pub relocations: bool,
}

/// Versioned JSON report envelope (schema version 1).
#[derive(Debug, serde::Serialize)]
struct JsonReport<'a> {
    /// Schema version of this document.
    schema_version: u32,
    /// The full inspection result. Flattened so its fields appear at the top level.
    #[serde(flatten)]
    binary: &'a Binary,
}

/// Serializes the full inspection result as pretty-printed JSON (schema version 1).
pub fn report_json(binary: &Binary) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&JsonReport {
        schema_version: 1,
        binary,
    })
}

/// Formats the legacy human-readable report for backwards compatibility.
pub fn human(binary: &Binary, sections: bool, segments: bool, dependencies: bool) -> String {
    report_human(
        binary,
        ReportOptions {
            sections,
            segments,
            dependencies,
            symbols: false,
            mitigations: false,
            notes: false,
            relocations: false,
        },
    )
}

/// Formats a comprehensive human-readable report.
pub fn report_human(binary: &Binary, options: ReportOptions) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "Format: ELF");
    let _ = writeln!(output, "File size: {} bytes", binary.file.size_bytes);
    let _ = writeln!(output, "SHA-256: {}", binary.hashes.sha256);
    let _ = writeln!(output, "Class: {}", binary.elf.class);
    let _ = writeln!(output, "Endianness: {}", binary.elf.endianness);
    let _ = writeln!(output, "Type: {}", binary.elf.elf_type);
    let _ = writeln!(output, "Machine: {}", binary.elf.machine);
    let _ = writeln!(output, "OS ABI: {}", binary.elf.os_abi);
    let _ = writeln!(output, "ABI version: {}", binary.elf.abi_version);
    let _ = writeln!(output, "Entry point: {:#x}", binary.elf.entry_point);
    let _ = writeln!(output, "Flags: {:#x}", binary.elf.flags);

    if options.mitigations {
        format_mitigations(&mut output, &binary.mitigations);
    }

    if options.sections {
        let _ = writeln!(output, "\nSections ({}):", binary.sections.len());
        for section in &binary.sections {
            let _ = writeln!(
                output,
                "  [{:>2}] {:<22} type={:<10} flags={:<4} addr={:#010x} offset={:#08x} size={:<8} entropy={}",
                section.index,
                section.name,
                format!("{:#x}", section.section_type),
                section_flags(section.flags),
                section.address,
                section.offset,
                section.size,
                section
                    .entropy
                    .map_or_else(|| "-".to_string(), |entropy| format!("{entropy:.2}"))
            );
        }
    }

    if options.segments {
        let _ = writeln!(output, "\nSegments ({}):", binary.segments.len());
        for segment in &binary.segments {
            let _ = writeln!(
                output,
                "  [{:>2}] type={:#010x} flags={} offset={:#08x} vaddr={:#010x} filesz={:<8} memsz={:<8} align={:#x}",
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

    if options.dependencies {
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

    if options.notes {
        let _ = writeln!(output, "\nNotes ({}):", binary.notes.len());
        if binary.notes.is_empty() {
            let _ = writeln!(output, "  None");
        } else {
            for note in &binary.notes {
                let _ = writeln!(output, "  [{}] {}", note.name, note.description);
                for prop in &note.properties {
                    let _ = writeln!(output, "    - Property: {prop}");
                }
            }
        }
    }

    if options.symbols {
        let imports = binary.symbols.iter().filter(|s| s.is_import).count();
        let exports = binary.symbols.iter().filter(|s| s.is_export).count();
        let _ = writeln!(
            output,
            "\nSymbols ({} total, {} imports, {} exports):",
            binary.symbols.len(),
            imports,
            exports
        );
        for sym in binary.symbols.iter().take(200) {
            let _ = writeln!(
                output,
                "  [{:>4}] {:<32} type={:<10} bind={:<8} vis={:<8} value={:#010x} size={:<6} {}",
                sym.index,
                sym.name,
                sym.sym_type.to_string(),
                sym.binding.to_string(),
                sym.visibility.to_string(),
                sym.value,
                sym.size,
                if sym.is_import {
                    "[import]"
                } else if sym.is_export {
                    "[export]"
                } else {
                    ""
                }
            );
        }
        if binary.symbols.len() > 200 {
            let _ = writeln!(
                output,
                "  ... ({} additional symbols omitted from summary)",
                binary.symbols.len() - 200
            );
        }
    }

    if options.relocations {
        let _ = writeln!(output, "\nRelocations ({}):", binary.relocations.len());
        for rel in binary.relocations.iter().take(200) {
            let target = rel.symbol_name.as_deref().unwrap_or("<none>");
            let _ = writeln!(
                output,
                "  offset={:#010x} type={:<4} sym={:<24} section={}",
                rel.offset, rel.rel_type, target, rel.section_name
            );
        }
        if binary.relocations.len() > 200 {
            let _ = writeln!(
                output,
                "  ... ({} additional relocations omitted)",
                binary.relocations.len() - 200
            );
        }
    }

    output
}

fn format_mitigations(output: &mut String, mit: &SecurityMitigations) {
    let _ = writeln!(output, "\nSecurity Hardening (checksec):");
    let _ = writeln!(output, "  RELRO:          {}", mit.relro);
    let _ = writeln!(
        output,
        "  Stack Canary:   {}",
        match mit.stack_canary {
            Hardening::Enabled => "Yes",
            Hardening::Disabled => "No (vulnerable)",
            Hardening::Unknown => "Unknown (no symbol table)",
        }
    );
    let _ = writeln!(
        output,
        "  NX Stack:       {}",
        match mit.nx {
            Hardening::Enabled => "Yes (non-executable)",
            Hardening::Disabled => "No (executable stack)",
            Hardening::Unknown => "Unknown (no PT_GNU_STACK)",
        }
    );
    let _ = writeln!(output, "  PIE:            {}", mit.pie);
    let _ = writeln!(
        output,
        "  Fortify Source: {}",
        match mit.fortify {
            Hardening::Enabled => format!("Yes ({} functions)", mit.fortified_functions.len()),
            Hardening::Disabled => "No".to_string(),
            Hardening::Unknown => "Unknown (no symbol table)".to_string(),
        }
    );
    let _ = writeln!(
        output,
        "  RWX Segments:   {}",
        if mit.rwx_segments == 0 {
            "0 (None)".to_string()
        } else {
            format!("{} (WARNING: W^X violation)", mit.rwx_segments)
        }
    );
    let _ = writeln!(
        output,
        "  Insecure RPATH: {}",
        if mit.has_insecure_rpath {
            "Yes (Warning)"
        } else {
            "No"
        }
    );
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
