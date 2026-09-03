//! Process entry points shared by the AOS command-line programs.

use std::process;
use std::{ffi::OsString, io::Write};

use anyhow::Result;
use clap::Parser;

use crate::cli::{ApmCli, AprCli, Cli, ColorChoice, Commands, ProgressChoice};
use crate::commands;
use aos_core::error::AosError;
use aos_core::nix::NixRunner;
use aos_core::output::{Printer, ProgressMode};

/// Parses and runs the `aos` repository and system-development CLI.
pub async fn aos_main() {
    install_panic_hook("aos");
    let cli = Cli::parse();
    let printer = printer(cli.verbose, cli.quiet, cli.json, cli.progress, cli.color);
    exit_with_result(run(&cli, &printer).await, &printer);
}

/// Parses and runs the `apm` package-consumer CLI.
pub async fn apm_main() {
    install_panic_hook("apm");
    let args = std::env::args_os().collect::<Vec<_>>();
    if internal_package_command(&args).is_some() {
        exit_surface_error("apm", "internal package runtime command");
    }
    let cli = ApmCli::parse_from(args);
    let printer = printer(cli.verbose, cli.quiet, cli.json, cli.progress, cli.color);
    exit_with_result(
        aos_package::run(&cli.command, cli.dry_run, cli.yes, &printer).await,
        &printer,
    );
}

/// Parses and runs the private on-host package lifecycle helper.
pub async fn package_runtime_main() {
    install_panic_hook("aos-package-runtime");
    let mut args = std::env::args_os().collect::<Vec<_>>();
    if internal_package_command(&args).is_none() {
        exit_surface_error("aos-package-runtime", "public package-consumer command");
    }
    if let Some(program) = args.first_mut() {
        *program = OsString::from("apm");
    }

    let cli = ApmCli::parse_from(args);
    if !cli.command.is_runtime_internal() {
        exit_surface_error("aos-package-runtime", "public package-consumer command");
    }
    let printer = printer(cli.verbose, cli.quiet, cli.json, cli.progress, cli.color);
    exit_with_result(
        aos_package::run(&cli.command, cli.dry_run, cli.yes, &printer).await,
        &printer,
    );
}

/// Parses and runs the `apr` registry-authoring CLI.
pub async fn apr_main() {
    install_panic_hook("apr");
    let cli = AprCli::parse();
    let printer = printer(cli.verbose, cli.quiet, cli.json, cli.progress, cli.color);
    exit_with_result(
        aos_package::run_apr(&cli.command, cli.system, cli.dry_run, &printer).await,
        &printer,
    );
}

/// Installs a concise process panic hook for a public CLI name.
fn install_panic_hook(program: &'static str) {
    // Set up a human-friendly panic handler that suppresses the default
    // backtrace noise and instead prints a short, actionable message.
    std::panic::set_hook(Box::new(move |info| {
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

        eprintln!("{program}: internal error: {message}{location}");
        eprintln!("This is a bug. Please report it.");
    }));
}

/// Returns the private runtime command name present in an argument vector.
fn internal_package_command(arguments: &[OsString]) -> Option<&str> {
    const COMMANDS: &[&str] = &[
        "activate-pre-etc-swap",
        "activate-post-etc-swap",
        "activate-restore-routed-sources",
        "recover-credential-transactions",
        "_test-systemd-client",
        "_test-reconcile-exposed-units",
        "_test-verify-package-attestation",
        "_test-produce-package-attestation-quote",
        "__verify-boot-commit",
        "_load-ebpf-lsm-policies",
        "__eval",
        "__eval-retained",
        "__materialize",
        "__activate-config",
        "fetch",
        "render-one",
        "__graph-compile",
    ];

    arguments.iter().find_map(|argument| {
        let argument = argument.to_str()?;
        COMMANDS.contains(&argument).then_some(argument)
    })
}

/// Reports a command-surface violation with clap's user-error exit status.
fn exit_surface_error(program: &str, rejected: &str) -> ! {
    let _ = writeln!(
        std::io::stderr(),
        "error: {program} does not accept {rejected}"
    );
    process::exit(2);
}

/// Terminates with the exit status represented by a command result.
fn exit_with_result(result: Result<()>, printer: &Printer) -> ! {
    let exit_code = match result {
        Ok(()) => 0,
        Err(err) => handle_error(printer, err),
    };

    process::exit(exit_code);
}

/// Constructs a printer and applies the shared color/progress policy.
fn printer(
    verbose: u8,
    quiet: bool,
    json: bool,
    progress: ProgressChoice,
    color: ColorChoice,
) -> Printer {
    match color {
        ColorChoice::Auto if std::env::var_os("NO_COLOR").is_some() => {
            console::set_colors_enabled_stderr(false);
        }
        ColorChoice::Auto => {}
        ColorChoice::Always => console::set_colors_enabled_stderr(true),
        ColorChoice::Never => console::set_colors_enabled_stderr(false),
    }
    let progress_mode = match progress {
        ProgressChoice::Auto => ProgressMode::Auto,
        ProgressChoice::Tty => ProgressMode::Tty,
        ProgressChoice::Plain => ProgressMode::Plain,
        ProgressChoice::Off => ProgressMode::Off,
    };

    Printer::new(verbose, quiet, json).with_progress_mode(progress_mode)
}

/// Dispatch the parsed CLI to the matching command implementation.
///
/// Commands that need no Nix installation (`completions`, `serve`, `token`,
/// `package`, `cache`) are handled before the [`NixRunner`] is constructed, so
/// they work even when `nix` is absent or the working directory is not a repo
/// root.
async fn run(cli: &Cli, printer: &Printer) -> Result<()> {
    // Shell completions can be generated without a Nix installation or
    // project root, so handle them before constructing the NixRunner.
    if let Commands::Completions { shell } = &cli.command {
        commands::completions::run(*shell);
        return Ok(());
    }

    // The server command doesn't need NixRunner, handle it before construction.
    if let Commands::Serve { config } = &cli.command {
        return commands::serve::run(printer, config).await;
    }

    // Token management connects to the bootstrap socket -- no NixRunner needed.
    if let Commands::Token { command } = &cli.command {
        let socket_path = aos_server::aos_root().join("run/bootstrap.sock");
        return commands::token::run(printer, command, &socket_path).await;
    }

    if let Commands::LanguageServer { system, documents } = &cli.command {
        return aos_package::run(
            &aos_package::PackageCommand::Docs {
                command: aos_package::DocumentationCommand::Lsp {
                    system: *system,
                    documents: documents.clone(),
                },
            },
            false,
            false,
            printer,
        )
        .await;
    }

    if let Commands::Doc {
        source: Some(mode),
        path,
        search,
        system,
        hub,
        registry,
        token,
        version,
        platform,
        ..
    } = &cli.command
        && matches!(mode.as_str(), "package" | "hub")
    {
        let command = if mode == "hub" || search.is_some() {
            aos_package::DocumentationCommand::Search {
                query: search
                    .clone()
                    .or_else(|| path.clone())
                    .ok_or_else(|| anyhow::anyhow!("aos doc hub requires a search query"))?,
                kind: None,
                limit: 25,
                hub: hub.clone(),
                registry: registry.clone(),
                token: token.clone(),
                system: *system,
            }
        } else {
            aos_package::DocumentationCommand::Show {
                package: path
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("aos doc package requires a package name"))?,
                version: version.clone(),
                platform: platform.clone(),
                format: None,
                output: None,
                hub: hub.clone(),
                registry: registry.clone(),
                token: token.clone(),
                system: *system,
            }
        };
        return aos_package::run(
            &aos_package::PackageCommand::Docs { command },
            false,
            false,
            printer,
        )
        .await;
    }

    // Cache commands use NixCli (classic nix commands), not NixRunner.
    if let Commands::Cache { command } = &cli.command {
        return commands::cache::run(printer, command).await;
    }

    // The metadata agent does not need a repository or NixRunner.
    if let Commands::Metadata { command } = &cli.command {
        return commands::metadata::run(command).await;
    }

    // Hub commands talk to the public API and do not need NixRunner.
    if let Commands::Hub { command } = &cli.command {
        return commands::hub::run(printer, command).await;
    }

    // Signed image discovery and downloads use only the Hub API.
    if let Commands::Image { command } = &cli.command {
        return commands::image::run(command, printer).await;
    }

    // Offline release verification uses captured files and public keys only.
    if let Commands::Release {
        command: crate::cli::ReleaseCommand::Verify(args),
    } = &cli.command
    {
        return commands::release::verify_offline(args, printer);
    }
    if let Commands::Release {
        command: crate::cli::ReleaseCommand::Status(args),
    } = &cli.command
    {
        return commands::release::status_offline(args, printer);
    }
    if let Commands::Release {
        command: crate::cli::ReleaseCommand::Signer { command },
    } = &cli.command
    {
        return commands::release::signer_offline(command, printer).await;
    }
    if let Commands::Release {
        command: crate::cli::ReleaseCommand::Stage(args),
    } = &cli.command
    {
        return commands::release::stage_offline(args, printer).await;
    }
    if let Commands::Release {
        command: crate::cli::ReleaseCommand::Qualify(args),
    } = &cli.command
    {
        return commands::release::qualify_offline(args, printer).await;
    }
    if let Commands::Release {
        command: crate::cli::ReleaseCommand::Timestamp { command },
    } = &cli.command
    {
        return commands::release::timestamp_offline(command, printer).await;
    }

    // Local VM runs use downloaded artifacts and host-side QEMU tools.
    if let Commands::Vm { command } = &cli.command {
        return commands::vm::run(command, printer);
    }

    let nix = NixRunner::new(cli.verbose, cli.quiet)?;

    if let Commands::Release {
        command: crate::cli::ReleaseCommand::FinalizeImage(args),
    } = &cli.command
    {
        return commands::release::finalize_image(args, &nix, printer).await;
    }

    match &cli.command {
        Commands::Build {
            package,
            all,
            target,
            remote,
            view,
            token,
        } => {
            if let Some(url) = remote {
                return commands::build::run_remote(
                    &nix,
                    printer,
                    package.as_deref(),
                    target.as_deref(),
                    url,
                    view,
                    token.as_deref(),
                )
                .await;
            }
            commands::build::run(&nix, printer, package.as_deref(), *all, target.as_deref())
        }
        Commands::System { command } => commands::system::run(&nix, printer, command),
        Commands::Show { package } => commands::show::run(&nix, printer, package),
        Commands::Graph { package, dot } => commands::graph::run(&nix, printer, package, *dot),
        Commands::Lint { package } => commands::lint::run(&nix, printer, package.as_deref()),
        Commands::Test { command, jobs } => commands::test::run(&nix, printer, command, *jobs),
        Commands::Repl => commands::repl::run(&nix, printer),
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
                printer,
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
        } => commands::why_depends::run(&nix, printer, package, dependency),
        Commands::Profile { command } => commands::profile::run(&nix, printer, command),
        Commands::Describe { package } => {
            if let Some(package) = package {
                commands::show::run(&nix, printer, package)
            } else {
                commands::describe::run(&nix, printer)
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
            printer,
            package,
            *all,
            *update,
            *jobs,
            *connect_timeout,
            *min_speed,
        ),
        Commands::Fmt { check, files } => commands::fmt::run(&nix, printer, *check, files),
        Commands::Release { command } => commands::release::run(command, &nix, printer),
        Commands::Doc {
            source,
            path,
            search,
            list,
            rebuild,
            ..
        } => aos_doc::run(&nix, printer, source, path, search, list, *rebuild).await,
        // These commands are handled in the early-return block above (before
        // NixRunner construction) and will never reach this match arm. The
        // arms exist only to satisfy exhaustiveness checking.
        Commands::Completions { .. } => unreachable!(),
        Commands::Serve { .. } => unreachable!(),
        Commands::Token { .. } => unreachable!(),
        Commands::Cache { .. } => unreachable!(),
        Commands::Metadata { .. } => unreachable!(),
        Commands::Hub { .. } => unreachable!(),
        Commands::Image { .. } => unreachable!(),
        Commands::Vm { .. } => unreachable!(),
        Commands::LanguageServer { .. } => unreachable!(),
    }
}

/// Maps an `anyhow::Error` to an appropriate exit code while printing a
/// user-facing message.
fn handle_error(printer: &Printer, err: anyhow::Error) -> i32 {
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
