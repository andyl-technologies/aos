//! Process entry points shared by the AOS command-line programs.

use std::process;
use std::{ffi::OsStr, ffi::OsString, io::Write};

use anyhow::{Result, bail};
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
    let (progress, color) = maintenance_output_policy(&cli);
    let printer = printer(cli.verbose, cli.quiet, cli.json, progress, color);
    if let Commands::Maintain(args) = &cli.command {
        let result = tokio::select! {
            result = commands::maintain::run(&cli, args, &printer) => result,
            signal = tokio::signal::ctrl_c() => match signal {
                Ok(()) => commands::maintain::interrupted("maintain"),
                Err(error) => Err(error.into()),
            },
        };
        let exit_code = match result {
            Ok(completion) => {
                let exit_code = i32::from(completion.exit_code());
                if let Err(error) = commands::maintain::render(&cli, args, &completion, &printer) {
                    exit_with_result(Err(error), &printer);
                }
                exit_code
            }
            Err(error) => handle_error(&printer, error),
        };
        process::exit(exit_code);
    }
    exit_with_result(run(&cli, &printer).await, &printer);
}

/// Resolves accessibility and machine-output modes before constructing a printer.
fn maintenance_output_policy(cli: &Cli) -> (ProgressChoice, ColorChoice) {
    let Commands::Maintain(args) = &cli.command else {
        return (cli.progress, cli.color);
    };

    if cli.json || args.jsonl {
        return (ProgressChoice::Off, ColorChoice::Never);
    }
    if args.screen_reader || std::env::var("TERM").is_ok_and(|term| term == "dumb") {
        let progress = match cli.progress {
            ProgressChoice::Off => ProgressChoice::Off,
            _ => ProgressChoice::Plain,
        };
        return (progress, ColorChoice::Never);
    }

    (cli.progress, cli.color)
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
    validate_container_runtime(&cli.command)?;
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

    if let Some(command) = cli.command.documentation_command()? {
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

    // Container transfers and local inspection are daemon-free. The handler
    // constructs Nix lazily only for definition list/show/build operations.
    if let Commands::Container { command } = &cli.command {
        return commands::container::run(command, printer).await;
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
        command: crate::cli::ReleaseCommand::ComposeSurface(args),
    } = &cli.command
    {
        return commands::release::compose_surface_offline(args, printer);
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
        command: crate::cli::ReleaseCommand::Qualification { command },
    } = &cli.command
    {
        return commands::release::qualification_offline(command, printer).await;
    }
    if let Commands::Release {
        command: crate::cli::ReleaseCommand::QualifyRun(args),
    } = &cli.command
    {
        return commands::release::qualification_run_offline(args, printer).await;
    }
    if let Commands::Release {
        command: crate::cli::ReleaseCommand::Promote(args),
    } = &cli.command
    {
        return commands::release::promote_offline(args, printer).await;
    }
    if let Commands::Release {
        command: crate::cli::ReleaseCommand::Bootstrap(args),
    } = &cli.command
    {
        return commands::release::bootstrap_offline(args, printer).await;
    }
    if let Commands::Release {
        command: crate::cli::ReleaseCommand::Channel { command },
    } = &cli.command
    {
        return commands::release::channel_offline(command, printer).await;
    }
    if let Commands::Release {
        command: crate::cli::ReleaseCommand::Timestamp { command },
    } = &cli.command
    {
        return commands::release::timestamp_offline(command, printer).await;
    }
    if let Commands::Release {
        command: crate::cli::ReleaseCommand::Tuf(args),
    } = &cli.command
    {
        return commands::release::tuf_offline(args, printer).await;
    }
    if let Commands::Release {
        command: crate::cli::ReleaseCommand::FinalizeRegistry(args),
    } = &cli.command
    {
        return commands::release::finalize_registry(args, printer).await;
    }
    if let Commands::Release {
        command: crate::cli::ReleaseCommand::Finalize(args),
    } = &cli.command
    {
        return commands::release::finalize(args, printer).await;
    }
    if let Commands::Release {
        command: crate::cli::ReleaseCommand::FinalizeCache(args),
    } = &cli.command
    {
        return commands::release::finalize_cache(args, printer).await;
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
        Commands::Maintain(_) => unreachable!(),
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
        Commands::Container { .. } => unreachable!(),
        Commands::Vm { .. } => unreachable!(),
        Commands::LanguageServer { .. } => unreachable!(),
    }
}

/// Rejects entrypoints that necessarily operate on host boot or device state.
///
/// Package-manager and registry-authoring paths are guarded within
/// `aos-package`, where their complete command shapes are available. This
/// top-level guard owns the repository CLI: the QEMU lifecycle and boot
/// metadata agent are rejected, while portable builds, signed image downloads,
/// and container publication remain available.
fn validate_container_runtime(command: &Commands) -> Result<()> {
    let runtime = std::env::var_os("AOS_RUNTIME");
    validate_runtime(command, runtime.as_deref())?;

    // The independent apm/apr processes synchronize inside `aos-package`.
    // Every admitted repository command waits here so `docker exec aos ...`
    // cannot race PID-1 setup.
    if runtime.as_deref() == Some(OsStr::new("container")) {
        aos_core::container_runtime::synchronize()?;
    }

    Ok(())
}

/// Applies the runtime boundary using an explicit value so tests do not mutate
/// the process environment.
fn validate_runtime(command: &Commands, runtime: Option<&OsStr>) -> Result<()> {
    if runtime == Some(OsStr::new("container"))
        && matches!(command, Commands::Vm { .. } | Commands::Metadata { .. })
    {
        bail!(
            "this command requires host boot, virtualization, or device access unavailable in an AOS container; run it on an AOS machine or VM"
        );
    }

    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("test command line should parse")
    }

    #[test]
    fn container_rejects_vm_and_boot_metadata_entrypoints() {
        for args in [
            ["aos", "vm", "run", "aos.qcow2"].as_slice(),
            ["aos", "metadata", "detect"].as_slice(),
        ] {
            let cli = parse(args);
            let error = validate_runtime(&cli.command, Some(OsStr::new("container")))
                .expect_err("host command should be rejected");

            assert_eq!(
                error.to_string(),
                "this command requires host boot, virtualization, or device access unavailable in an AOS container; run it on an AOS machine or VM"
            );
        }
    }

    #[test]
    fn container_allows_image_downloads_and_repository_builds() {
        for args in [
            ["aos", "image", "list", "--registry", "core"].as_slice(),
            ["aos", "build", "bash"].as_slice(),
            ["aos", "system", "image"].as_slice(),
        ] {
            let cli = parse(args);
            assert!(
                validate_runtime(&cli.command, Some(OsStr::new("container"))).is_ok(),
                "portable command should remain available: {args:?}"
            );
        }
    }

    #[test]
    fn non_container_runtime_preserves_host_command_admission() {
        let cli = parse(&["aos", "vm", "run", "aos.qcow2"]);

        assert!(validate_runtime(&cli.command, None).is_ok());
        assert!(validate_runtime(&cli.command, Some(OsStr::new("Container"))).is_ok());
    }
}
