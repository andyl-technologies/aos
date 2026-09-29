//! Loads configuration and dispatches one Terrane process role.
//!
//! Arguments and file loading live here; configuration semantics and role
//! behavior live in the `terrane` library (CRATE-16). This T0 binary supports
//! syntax checking, but reports unavailable runtimes instead of starting a
//! service. Roles follow specification 03 and 37, and TOML follows 11 and 26.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use terrane::config::Config;
use terrane::role::Role;

#[derive(Parser)]
#[command(
    name = "terrane",
    version,
    about = "Content-addressed, branchable filesystem store"
)]
struct Arguments {
    /// Load one process role and store expression from TOML.
    #[arg(long)]
    config: PathBuf,
    /// Select the process role named in configuration.
    #[arg(long)]
    role: Option<Role>,
    /// Check configuration syntax without opening stores or starting services.
    #[arg(long)]
    check_config: bool,
}

fn main() -> ExitCode {
    let arguments = Arguments::parse();
    match run(arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("terrane: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(arguments: Arguments) -> Result<(), Box<dyn std::error::Error>> {
    let input = std::fs::read_to_string(&arguments.config)?;
    let config = Config::parse(&input)?;
    let role = config.select_role(arguments.role)?;
    if arguments.check_config {
        println!(
            "configuration syntax valid for role {}; backend, token, and schema checks are pending",
            role
        );
        return Ok(());
    }

    role.run()?;
    Ok(())
}
