//! Dispatches local repository commands and one configured Terrane process role.
//!
//! Arguments and file loading live here; configuration semantics and role
//! behavior live in library crates (CRATE-16). [`local`] calls the T1
//! repository SDK and registered checkout surface (CRATE-22 to CRATE-24).
//! Linux configured SDK snapshots run through `terrane-linux`; other configured
//! runtimes remain unavailable. Syntax checking starts no runtime.
//! Roles follow specifications 03 and 37, and TOML follows 11 and 26.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use terrane_sdk::config::Config;
use terrane_sdk::role::Role;

mod local;

#[derive(Parser)]
#[command(
    name = "terrane",
    version,
    about = "Content-addressed, branchable filesystem store",
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true
)]
struct Arguments {
    /// Load one process role and store expression from TOML.
    #[arg(long, required = true)]
    config: Option<PathBuf>,
    /// Select a process role, agreeing with configuration when it names one.
    #[arg(long)]
    role: Option<Role>,
    /// Check configuration syntax without opening stores or starting services.
    #[arg(long)]
    check_config: bool,
    #[command(subcommand)]
    command: Option<local::Command>,
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
    if let Some(command) = arguments.command {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        return runtime.block_on(command.run());
    }

    let config_path = arguments
        .config
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing --config"))?;
    let input = std::fs::read_to_string(config_path)?;
    let config = Config::parse(&input)?;
    let role = config.select_role(arguments.role)?;
    if arguments.check_config {
        println!(
            "configuration syntax valid for role {}; backend, token, and schema checks are pending",
            role
        );
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    if role == Role::Serve && !config.exposures().is_empty() {
        use std::io::Write;

        // The library performs whole-config preflight and installs confinement
        // before its executor. Keep completion custody through status reporting.
        let completed = terrane_linux::configured_sdk::run(&config, role)?;
        let mut output = std::io::stdout().lock();
        for snapshot in completed.snapshots()? {
            let status = snapshot.status();
            write!(
                output,
                "completed SDK snapshot {:?}: commit ",
                snapshot.id()
            )?;
            for byte in status.commit {
                write!(output, "{byte:02x}")?;
            }
            writeln!(
                output,
                ", state {:?}, endpoint {:?}",
                status.state,
                snapshot.endpoint()
            )?;
        }
        output.flush()?;
        return Ok(());
    }

    role.run()?;
    Ok(())
}
