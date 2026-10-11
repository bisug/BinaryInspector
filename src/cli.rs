//! Command-line argument definitions.

use std::path::PathBuf;

use clap::Parser;

/// Inspect metadata in an executable binary without executing it.
///
/// Supported formats:
///   - ELF (Linux, BSD, Android): ELF32 & ELF64
///   - PE/COFF (Windows): PE32 & PE32+ (.exe, .dll, .sys, .efi)
///   - Mach-O (macOS, iOS): 32-bit, 64-bit & Universal / Fat multi-architecture containers
#[derive(Debug, Parser)]
#[command(
    version,
    about = "Inspect executable binary metadata (ELF, PE/COFF, Mach-O) safely without execution",
    after_help = "Supported Formats:\n  - ELF: Linux / Unix / BSD executables, shared objects (.so), relocatable objects (.o)\n  - PE/COFF: Windows executables (.exe), dynamic-link libraries (.dll), drivers (.sys), EFI (.efi)\n  - Mach-O: macOS / iOS binaries, dynamic libraries (.dylib), bundles, and Universal Fat archives\n\nExamples:\n  binary-inspector /bin/ls\n  binary-inspector ./app.exe -m\n  binary-inspector ./libtarget.dylib -t\n  binary-inspector ./app -S -l\n  binary-inspector /bin/ls --json\n\nExit codes:\n  0  success\n  1  usage error\n  2  I/O error, or the target is not a regular file\n  3  the input was rejected: not a valid executable binary, the file exceeds the size limit,\n     or the report could not be serialized"
)]
pub struct Cli {
    /// Executable file to inspect (ELF, PE/COFF, Mach-O, Universal Fat).
    pub file: PathBuf,
    /// Include section information.
    #[arg(short = 'S', long)]
    pub sections: bool,
    /// Include program segments.
    #[arg(short = 'l', long)]
    pub segments: bool,
    /// Include dynamic dependencies and loader metadata.
    #[arg(short = 'd', long)]
    pub dependencies: bool,
    /// Include symbol tables.
    #[arg(short = 's', long)]
    pub symbols: bool,
    /// Include security hardening mitigations (checksec).
    #[arg(short = 'm', long)]
    pub mitigations: bool,
    /// Include ELF notes and build information.
    #[arg(short = 'n', long)]
    pub notes: bool,
    /// Include relocation entries.
    #[arg(short = 'r', long)]
    pub relocations: bool,
    /// Include extracted strings and embedded artifacts.
    #[arg(short = 't', long)]
    pub strings: bool,
    /// Minimum string length when filtering (default: 4).
    #[arg(long, default_value = "4")]
    pub string_min_len: usize,
    /// Filter extracted strings by category (url, ip, file-path, crypto, email, general).
    #[arg(long)]
    pub string_category: Option<String>,
    /// Include every available category (the default).
    #[arg(short, long)]
    pub all: bool,
    /// Emit versioned JSON (schema 1) to stdout instead of human text.
    #[arg(long)]
    pub json: bool,
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::Cli;

    #[test]
    fn accepts_short_category_flags() {
        let cli = Cli::try_parse_from(["binary-inspector", "fixture", "-Sld"])
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(cli.sections && cli.segments && cli.dependencies);
    }

    #[test]
    fn accepts_extended_category_flags() {
        let cli = Cli::try_parse_from(["binary-inspector", "fixture", "-smnrt"])
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(cli.symbols && cli.mitigations && cli.notes && cli.relocations && cli.strings);
    }

    #[test]
    fn accepts_string_filter_flags() {
        let cli = Cli::try_parse_from([
            "binary-inspector",
            "fixture",
            "--strings",
            "--string-min-len",
            "8",
            "--string-category",
            "url",
        ])
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(cli.strings);
        assert_eq!(cli.string_min_len, 8);
        assert_eq!(cli.string_category.as_deref(), Some("url"));
    }
}
