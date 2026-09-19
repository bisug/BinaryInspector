//! Command-line argument definitions.

use std::path::PathBuf;

use clap::Parser;

/// Inspect metadata in an ELF binary without executing it.
#[derive(Debug, Parser)]
#[command(
    version,
    after_help = "Exit codes: 0 success; 1 usage; 2 I/O; 3 parse error."
)]
pub struct Cli {
    /// ELF file to inspect.
    pub file: PathBuf,
    /// Include section information.
    #[arg(long)]
    pub sections: bool,
    /// Include program segments.
    #[arg(long)]
    pub segments: bool,
    /// Include dynamic dependencies and loader metadata.
    #[arg(long)]
    pub dependencies: bool,
    /// Disable color (human output is currently uncolored).
    #[arg(long)]
    pub no_color: bool,
}
