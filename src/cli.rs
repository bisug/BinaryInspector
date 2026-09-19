//! Command-line argument definitions.

use std::path::PathBuf;

use clap::Parser;

/// Inspect metadata in an ELF binary without executing it.
#[derive(Debug, Parser)]
#[command(
    version,
    after_help = "Examples:\n  binary-inspector /bin/ls\n  binary-inspector /bin/ls -d\n  binary-inspector ./app -S -l\n\nExit codes: 0 success; 1 usage; 2 I/O; 3 parse error."
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
    /// Include every available category (the default).
    #[arg(short, long)]
    pub all: bool,
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
}
