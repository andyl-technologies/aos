//! Dispatches local repository commands and one configured Terrane process role.
//!
//! Arguments and file loading live here; configuration semantics and role
//! behavior live in library crates (CRATE-16). [`local`] calls the T1
//! repository SDK and registered checkout surface (CRATE-22 to CRATE-24).
//! Linux configured SDK snapshots, local collection, native cache maintenance
//! and publisher startup run through `terrane-linux`;
//! other configured runtimes remain unavailable. Syntax checking starts no runtime.
//! Roles follow specifications 03 and 37, and TOML follows 11 and 26.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use terrane_sdk::config::Config;
use terrane_sdk::role::Role;

mod local;
#[cfg(target_os = "linux")]
mod service_ready;

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
    if let (Role::Publish, Some(host)) = (role, config.host_tier()) {
        // Pass only host-tier inputs: this role must not open repository
        // authority or resolve exposure credentials before native startup.
        terrane_linux::configured::run_configured_publisher(host)?;
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    if role == Role::Serve && !config.exposures().is_empty() {
        // The library performs whole-config preflight and installs confinement
        // before its executor. Native workers remain active after SDK completion.
        if config.host_tier().is_some() {
            terrane_linux::configured_sdk::run_service(&config, role, report_snapshots)?;
            return Ok(());
        }
        let completed = terrane_linux::configured_sdk::run(&config, role)?;
        report_snapshots(completed.snapshots()?)?;
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    if role == Role::Gc {
        if let Some(host) = config.host_tier() {
            if config.gc().is_some() {
                return Err(
                    "host maintenance cannot also select local repository collection".into(),
                );
            }
            let responses = terrane_linux::configured_maintenance::run_configured_gc(host)?;
            for response in responses {
                let counts = response.reconciliation;
                println!(
                    "domain {}: checked {}, completed {}, blocked {} draining exposures",
                    response.domain, counts.checked, counts.completed, counts.blocked,
                );
            }
            return Ok(());
        }
        // The library checks the complete supported local configuration before
        // installing confinement, creating its executor or reopening authority.
        terrane_linux::configured_gc::run_service(&config, role, report_collector_ready)?;
        return Ok(());
    }

    role.run()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn report_collector_ready() -> std::io::Result<()> {
    use std::io::Write;

    let mut output = std::io::stdout().lock();
    writeln!(output, "collector ready: initial marking complete")?;
    output.flush()
}

#[cfg(target_os = "linux")]
fn report_snapshots(
    snapshots: &[terrane_linux::configured_sdk::CompletedSnapshot],
) -> std::io::Result<()> {
    use std::io::Write;

    let mut output = std::io::stdout().lock();
    for snapshot in snapshots {
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
    service_ready::notify()
}
