mod cli;
mod commands;
mod error;
mod nix;
mod output;

use std::process;

use anyhow::Result;
use clap::Parser;

use cli::{Cli, Commands};
use error::AosError;
use nix::NixRunner;
use output::Printer;

fn main() {
    // Set up a human-friendly panic handler that suppresses the default
    // backtrace noise and instead prints a short, actionable message.
    std::panic::set_hook(Box::new(|info| {
        let message = if let Some(msg) = info.payload().downcast_ref::<&str>() {
            (*msg).to_string()
        } else if let Some(msg) = info.payload().downcast_ref::<String>() {
            msg.clone()
        } else {
            "unexpected internal error".to_string()
        };

        let location = info
            .location()
            .map(|loc| format!(" ({}:{})", loc.file(), loc.line()))
            .unwrap_or_default();

        eprintln!("aos: internal error: {message}{location}");
        eprintln!("This is a bug. Please report it.");
    }));

    let cli = Cli::parse();

    let exit_code = match run(&cli) {
        Ok(()) => 0,
        Err(err) => handle_error(&cli, err),
    };

    process::exit(exit_code);
}

fn run(cli: &Cli) -> Result<()> {
    let printer = Printer::new(cli.verbose, cli.quiet, cli.json);

    // Shell completions can be generated without a Nix installation or
    // project root, so handle them before constructing the NixRunner.
    if let Commands::Completions { shell } = &cli.command {
        commands::completions::run(*shell);
        return Ok(());
    }

    let nix = NixRunner::new(cli.verbose, cli.quiet)?;

    match &cli.command {
        Commands::Build { package, all } => {
            commands::build::run(&nix, &printer, package.as_deref(), *all)
        }
        Commands::System { command } => commands::system::run(&nix, &printer, command),
        Commands::Show { package } => commands::show::run(&nix, &printer, package),
        Commands::Graph { package, dot } => commands::graph::run(&nix, &printer, package, *dot),
        Commands::Lint { package } => commands::lint::run(&nix, &printer, package.as_deref()),
        Commands::Test { command } => commands::test::run(&nix, &printer, command),
        Commands::Shell => commands::shell::run(&nix, &printer),
        Commands::Repl => commands::repl::run(&nix, &printer),
        Commands::Gc {
            list_generations,
        } => commands::gc::run(&nix, &printer, *list_generations),
        Commands::WhyDepends {
            package,
            dependency,
        } => commands::why_depends::run(&nix, &printer, package, dependency),
        Commands::Describe => commands::describe::run(&nix, &printer),
        // Already handled above, but the match must be exhaustive.
        Commands::Completions { .. } => unreachable!(),
    }
}

/// Map an `anyhow::Error` to an appropriate exit code while printing a
/// user-facing message.  The exit-code conventions are:
///
///   0 — success
///   1 — build / test failure
///   2 — user error (bad arguments, unknown variant, etc.)
///   3 — nix not found
fn handle_error(cli: &Cli, err: anyhow::Error) -> i32 {
    let printer = Printer::new(cli.verbose, cli.quiet, cli.json);

    // Walk the error chain looking for a typed AosError so we can pick the
    // right exit code.
    if let Some(aos_err) = err.downcast_ref::<AosError>() {
        let code = aos_err.exit_code();
        printer.error(&format!("{err:#}"));
        return code;
    }

    // Fallback: unknown error type — treat as build failure.
    printer.error(&format!("{err:#}"));
    1
}
