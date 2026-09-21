//! Command-line argument definitions.

use std::path::PathBuf;

use clap::Parser;

/// Inspect metadata in an ELF binary without executing it.
#[derive(Debug, Parser)]
#[command(
    version,
    after_help = "Examples:\n  binary-inspector /bin/ls\n  binary-inspector /bin/ls -m\n  binary-inspector /bin/ls -s -n\n  binary-inspector ./app -S -l\n  binary-inspector /bin/ls --json\n\nExit codes: 0 success; 1 usage; 2 I/O; 3 parse error."
)]
pub struct Cli {
    /// ELF file to inspect.
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
    /// Include every available category (the default).
    #[arg(short, long)]
    pub all: bool,
    /// Emit versioned JSON (schema 1) to stdout instead of human text.
    #[arg(long)]
    pub json: bool,
    /// Disable color (human output is currently uncolored).
    #[arg(long)]
    pub no_color: bool,
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
        let cli = Cli::try_parse_from(["binary-inspector", "fixture", "-smnr"])
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(cli.symbols && cli.mitigations && cli.notes && cli.relocations);
    }
}
