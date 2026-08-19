//! Shared process entrypoint for the AOS multicall binaries.

use std::process;

use anyhow::Result;
use clap::Parser;

use crate::cli::{Cli, Commands};
use crate::commands;
use aos_core::error::AosError;
use aos_core::nix::NixRunner;
use aos_core::output::{Printer, ProgressMode};

/// Installs process hooks, parses the multicall command line, and exits.
pub(crate) async fn main() {
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

    // Detect argv[0]:
    // - "apm" -> implicitly prepend "package"
    // - "apr" -> implicitly prepend "package registry"
    let cli = {
        // Normalisation (strip leading '.' and trailing '-unwrapped') lives in
        // `aos_core::invocation` so that hint messages can derive the same name.
        let bin_name = aos_core::invocation::binary_name();

        if bin_name == "apr" {
            let mut args: Vec<String> = std::env::args().collect();
            args.insert(1, "package".to_string());
            args.insert(2, "registry".to_string());
            Cli::parse_from(args)
        } else if bin_name == "apm" {
            let mut args: Vec<String> = std::env::args().collect();
            args.insert(1, "package".to_string());
            Cli::parse_from(args)
        } else {
            Cli::parse()
        }
    };

    let exit_code = match run(&cli).await {
        Ok(()) => 0,
        Err(err) => handle_error(&cli, err),
    };

    process::exit(exit_code);
}

/// Dispatch the parsed CLI to the matching command implementation.
///
/// Commands that need no Nix installation (`completions`, `serve`, `token`,
/// `package`, `cache`) are handled before the [`NixRunner`] is constructed, so
/// they work even when `nix` is absent or the working directory is not a repo
/// root.
async fn run(cli: &Cli) -> Result<()> {
    let progress_mode = match cli.progress {
        crate::cli::ProgressChoice::Auto => ProgressMode::Auto,
        crate::cli::ProgressChoice::Tty => ProgressMode::Tty,
        crate::cli::ProgressChoice::Plain => ProgressMode::Plain,
        crate::cli::ProgressChoice::Off => ProgressMode::Off,
    };
    let printer = Printer::new(cli.verbose, cli.quiet, cli.json).with_progress_mode(progress_mode);

    // Shell completions can be generated without a Nix installation or
    // project root, so handle them before constructing the NixRunner.
    if let Commands::Completions { shell } = &cli.command {
        commands::completions::run(*shell);
        return Ok(());
    }

    // The server command doesn't need NixRunner, handle it before construction.
    if let Commands::Serve { config } = &cli.command {
        return commands::serve::run(&printer, config).await;
    }

    // Token management connects to the bootstrap socket -- no NixRunner needed.
    if let Commands::Token { command } = &cli.command {
        let socket_path = aos_server::aos_root().join("run/bootstrap.sock");
        return commands::token::run(&printer, command, &socket_path).await;
    }

    // Package management (apm) has its own infrastructure -- no NixRunner needed.
    if let Commands::Package(args) = &cli.command {
        return commands::package::run(args, &printer).await;
    }

    // Cache commands use NixCli (classic nix commands), not NixRunner.
    if let Commands::Cache { command } = &cli.command {
        return commands::cache::run(&printer, command).await;
    }

    // The metadata agent does not need a repository or NixRunner.
    if let Commands::Metadata { command } = &cli.command {
        return commands::metadata::run(command).await;
    }

    // Hub commands talk to the public API and do not need NixRunner.
    if let Commands::Hub { command } = &cli.command {
        return commands::hub::run(&printer, command).await;
    }

    // Signed image discovery and downloads use only the Hub API.
    if let Commands::Image { command } = &cli.command {
        return commands::image::run(command, &printer).await;
    }

    let nix = NixRunner::new(cli.verbose, cli.quiet)?;

    match &cli.command {
        Commands::Build {
            package,
            all,
            remote,
            view,
            token,
        } => {
            if let Some(url) = remote {
                return commands::build::run_remote(
                    &nix,
                    &printer,
                    package.as_deref(),
                    url,
                    view,
                    token.as_deref(),
                )
                .await;
            }
            commands::build::run(&nix, &printer, package.as_deref(), *all)
        }
        Commands::System { command } => commands::system::run(&nix, &printer, command),
        Commands::Show { package } => commands::show::run(&nix, &printer, package),
        Commands::Graph { package, dot } => commands::graph::run(&nix, &printer, package, *dot),
        Commands::Lint { package } => commands::lint::run(&nix, &printer, package.as_deref()),
        Commands::Test { command, jobs } => commands::test::run(&nix, &printer, command, *jobs),
        Commands::Repl => commands::repl::run(&nix, &printer),
        Commands::Gc {
            list_generations,
            remote,
            view,
            token,
            collect,
            dry_run,
            all,
            pin,
        } => {
            commands::gc::run(
                &nix,
                &printer,
                *list_generations,
                remote.as_deref(),
                view.as_deref(),
                token.as_deref(),
                *collect,
                *dry_run,
                *all,
                pin.as_deref(),
            )
            .await
        }
        Commands::WhyDepends {
            package,
            dependency,
        } => commands::why_depends::run(&nix, &printer, package, dependency),
        Commands::Profile { command } => commands::profile::run(&nix, &printer, command),
        Commands::Describe { package } => {
            if let Some(package) = package {
                commands::show::run(&nix, &printer, package)
            } else {
                commands::describe::run(&nix, &printer)
            }
        }
        Commands::Prefetch {
            package,
            all,
            update,
            jobs,
            connect_timeout,
            min_speed,
        } => commands::prefetch::run(
            &nix,
            &printer,
            package,
            *all,
            *update,
            *jobs,
            *connect_timeout,
            *min_speed,
        ),
        Commands::Fmt { check, files } => commands::fmt::run(&nix, &printer, *check, files),
        Commands::Doc {
            source,
            path,
            search,
            list,
            rebuild,
        } => aos_doc::run(&nix, &printer, source, path, search, list, *rebuild).await,
        // These commands are handled in the early-return block above (before
        // NixRunner construction) and will never reach this match arm. The
        // arms exist only to satisfy exhaustiveness checking.
        Commands::Completions { .. } => unreachable!(),
        Commands::Serve { .. } => unreachable!(),
        Commands::Token { .. } => unreachable!(),
        Commands::Package { .. } => unreachable!(),
        Commands::Cache { .. } => unreachable!(),
        Commands::Metadata { .. } => unreachable!(),
        Commands::Hub { .. } => unreachable!(),
        Commands::Image { .. } => unreachable!(),
    }
}

/// Maps an `anyhow::Error` to an appropriate exit code while printing a
/// user-facing message.
fn handle_error(cli: &Cli, err: anyhow::Error) -> i32 {
    let printer = Printer::new(cli.verbose, cli.quiet, cli.json);

    // Walk the error chain looking for a typed AosError so we can pick the
    // right exit code.
    if let Some(aos_err) = err.downcast_ref::<AosError>() {
        let code = aos_err.exit_code();
        printer.error(&format!("{err:#}"));
        return code;
    }

    // Fallback: unknown error type -- treat as build failure.
    printer.error(&format!("{err:#}"));
    1
}
