//! BinaryInspector command-line entry point.

use std::process::ExitCode;

use clap::{error::ErrorKind, Parser};

use binary_inspector::{
    cli::Cli,
    inspect,
    report::{self, ReportOptions},
};

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let success = matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            );
            let _ = error.print();
            return if success {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            };
        }
    };

    let any_selected = cli.sections
        || cli.segments
        || cli.dependencies
        || cli.symbols
        || cli.mitigations
        || cli.notes
        || cli.relocations;
    let all = cli.all || !any_selected;

    match inspect(&cli.file) {
        Ok(binary) => {
            let options = ReportOptions {
                sections: all || cli.sections,
                segments: all || cli.segments,
                dependencies: all || cli.dependencies,
                symbols: all || cli.symbols,
                mitigations: all || cli.mitigations,
                notes: all || cli.notes,
                relocations: all || cli.relocations,
            };
            print!("{}", report::report_human(&binary, options));
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("binary-inspector: {error}");
            ExitCode::from(error.exit_code() as u8)
        }
    }
}
