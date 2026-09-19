//! BinaryInspector command-line entry point.

use std::process::ExitCode;

use clap::{error::ErrorKind, Parser};

use binary_inspector::{cli::Cli, inspect, report};

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
    let all_categories = cli.all || (!cli.sections && !cli.segments && !cli.dependencies);
    match inspect(&cli.file) {
        Ok(binary) => {
            print!(
                "{}",
                report::human(
                    &binary,
                    all_categories || cli.sections,
                    all_categories || cli.segments,
                    all_categories || cli.dependencies
                )
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("binary-inspector: {error}");
            ExitCode::from(error.exit_code() as u8)
        }
    }
}
