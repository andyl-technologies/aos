//! Explicit private-prefix provider experiments on the operator's machine.
//!
//! Credentials and selected provider coordinates are read from files. The
//! report contains observations for independent review; it does not configure
//! or accept a Worker. Unknown journal effects have no dispatch/resume command.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "aos-hub-provider-conformance")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Run {
        /// Read the explicit operator target and protected input file paths.
        #[arg(long)]
        config_file: PathBuf,
        /// Create a new private journal before the first provider mutation.
        #[arg(long)]
        journal_directory: PathBuf,
        /// Create a new credential-free closed observation report.
        #[arg(long)]
        output: PathBuf,
    },
    Status {
        /// Read retained originals and outcomes without provider requests.
        #[arg(long)]
        journal_directory: PathBuf,
    },
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let result = match Cli::parse().command {
        Command::Run {
            config_file,
            journal_directory,
            output,
        } => {
            aos_hub::provider_conformance::run_provider_conformance(
                &config_file,
                &journal_directory,
                &output,
            )
            .await
        }
        Command::Status { journal_directory } => {
            aos_hub::provider_conformance::provider_conformance_status(&journal_directory)
        }
    };
    match result {
        Ok(value) => {
            println!("{value}");
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}
