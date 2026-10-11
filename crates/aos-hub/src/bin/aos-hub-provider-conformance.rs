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
    ProfileDigest {
        /// Read the exact closed canonical external profile; no authentication is granted.
        #[arg(long)]
        profile_file: PathBuf,
    },
    CopyCapacity {
        /// Read the actual signed Direct runtime qualification artifact.
        #[arg(long)]
        artifact_file: PathBuf,
        /// Read the independently selected reviewer public key as 64 lowercase hex bytes.
        #[arg(long)]
        reviewer_public_key_file: PathBuf,
        /// Read the private canonical audience and domain ceiling declaration.
        #[arg(long)]
        declaration_file: PathBuf,
        /// Create a new private initial capacity projection.
        #[arg(long)]
        output: PathBuf,
    },
    CopyContract {
        /// Read the actual complete bounded provider observation report.
        #[arg(long)]
        report_file: PathBuf,
        /// Read the matching retained private original and phase journal.
        #[arg(long)]
        journal_directory: PathBuf,
        /// Create a new private copy transport-facts document.
        #[arg(long)]
        output: PathBuf,
    },
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
        Command::ProfileDigest { profile_file } => {
            aos_hub::provider_conformance::export_provider_profile_digest(&profile_file)
        }
        Command::CopyCapacity {
            artifact_file,
            reviewer_public_key_file,
            declaration_file,
            output,
        } => aos_hub::provider_conformance::export_provider_copy_capacity(
            &artifact_file,
            &reviewer_public_key_file,
            &declaration_file,
            &output,
        ),
        Command::CopyContract {
            report_file,
            journal_directory,
            output,
        } => aos_hub::provider_conformance::export_provider_copy_contract(
            &report_file,
            &journal_directory,
            &output,
        ),
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
