//! `aos` — the command-line tool for working with the AOS repository.
//!
//! This binary is a *multicall* executable: behaviour depends on the name
//! it is invoked as (`argv[0]`, normalised by `aos_core::invocation`):
//!
//! - `aos` — the full CLI, dispatching on the first argument.
//! - `apm` — alias for `aos package ...` (the package manager).
//! - `apr` — alias for `aos package registry ...` (registry operations).
//!
//! # Subcommand families
//!
//! The clap definitions live in `cli` and the implementations in
//! `commands`, one module per subcommand:
//!
//! - **Nix workflows** (need a `NixRunner`): `build`, `system`, `show`,
//!   `graph`, `lint`, `test`, `repl`, `gc`, `why-depends`, `describe`,
//!   `prefetch`, `fmt`, and `doc` (implemented in the `aos-doc` crate).
//! - **Server-side**: `serve` (the HTTP binary cache server, implemented
//!   in `aos-server`) and `token` (provisioning-token management over the
//!   server's bootstrap socket).
//! - **Client-side**: `cache` (binary cache push/pull/prefetch/list,
//!   implemented in `aos-cache`) and the `--remote` modes of `build` and
//!   `gc` (via `aos-remote`).
//! - **Package management**: `package` / `apm` / `apr` (implemented in
//!   `aos-package`).
//! - **Misc**: `completions` (shell completion scripts).
//!
//! # Exit codes
//!
//! `0` success; `1` build/test failure (and unknown errors); `2` user
//! error; `3` Nix not found — see `handle_error` and
//! `aos_core::error::AosError::exit_code`.

mod cli;
mod commands;
mod logging;

use std::path::PathBuf;
use std::process;

use anyhow::{Context, Result};
use clap::Parser;

use aos_core::error::AosError;
use aos_core::nix::{NixEvalConfig, NixEvalMode, NixRunner};
use aos_core::output::Printer;
use aos_nix_harness::diff::DiffMode;
use cli::{Cli, Commands};

/// Process entry point: installs the panic hook, applies the multicall
/// `argv[0]` rewrite (`apm`/`apr`), parses the CLI, runs the selected
/// command, and exits with the mapped exit code.
#[tokio::main]
async fn main() {
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
/// Commands that need no Nix installation (`completions`, `serve`,
/// `token`, `package`, `cache`) are handled before the [`NixRunner`] is
/// constructed, so they work even when `nix` is absent or the working
/// directory is not a repo root.
async fn run(cli: &Cli) -> Result<()> {
    let printer = Printer::new(cli.verbose, cli.quiet, cli.json);
    let eval_config = eval_config_from_cli(cli)?;

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

    // Token management connects to the bootstrap socket — no NixRunner needed.
    if let Commands::Token { command } = &cli.command {
        let socket_path = aos_server::aos_root().join("run/bootstrap.sock");
        return commands::token::run(&printer, command, &socket_path).await;
    }

    // Package management (apm) has its own infrastructure — no NixRunner needed.
    if let Commands::Package(args) = &cli.command {
        return commands::package::run(args, &printer).await;
    }

    // Cache commands use NixCli (classic nix commands), not NixRunner.
    if let Commands::Cache { command } = &cli.command {
        return commands::cache::run(&printer, command, &eval_config).await;
    }

    if let Commands::NixDiff {
        attr,
        smoke,
        all,
        systems,
        eval_json,
        expr,
        eval_json_corpus,
        time_budget,
        file,
        mode,
        oracle_stats,
        cache_validation,
        oracle_drv,
        candidate_drv,
        oracle_drv_bundle,
        candidate_drv_bundle,
    } = &cli.command
    {
        match (oracle_drv, candidate_drv) {
            (Some(oracle_drv), Some(candidate_drv)) => {
                return run_nix_diff_pair_threaded(
                    printer,
                    oracle_drv.clone(),
                    candidate_drv.clone(),
                    oracle_drv_bundle.clone(),
                    candidate_drv_bundle.clone(),
                    (*mode).into(),
                );
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(AosError::InvalidArgument {
                    message: "provide both --oracle-drv and --candidate-drv".to_string(),
                }
                .into());
            }
            (None, None) => {}
        }
        let file = if *eval_json {
            PathBuf::new()
        } else {
            match file {
                Some(file) => file.clone(),
                None => NixRunner::find_root()?.join("default.nix"),
            }
        };
        return run_nix_diff_threaded(
            printer,
            cli.verbose,
            eval_config,
            file,
            attr.clone(),
            *smoke,
            *all,
            *systems,
            *eval_json,
            expr.clone(),
            eval_json_corpus.clone(),
            time_budget.map(std::time::Duration::from_secs),
            (*mode).into(),
            *oracle_stats,
            *cache_validation,
        );
    }

    if let Commands::NixBench {
        attr,
        file,
        samples,
        history,
        no_record,
        fail_on_regression,
        require_perf_win,
        regression_threshold,
        memory_regression_threshold,
    } = &cli.command
    {
        return run_nix_bench_threaded(
            printer,
            cli.verbose,
            eval_config,
            file.clone(),
            attr.clone(),
            *samples,
            history.clone(),
            *no_record,
            *fail_on_regression,
            *require_perf_win,
            *regression_threshold,
            *memory_regression_threshold,
        );
    }

    if let Commands::NixFuzzCorpus {
        attr,
        exclude,
        file,
        output_dir,
        clean,
    } = &cli.command
    {
        return run_nix_fuzz_corpus_threaded(
            printer,
            cli.verbose,
            eval_config,
            attr.clone(),
            exclude.clone(),
            file.clone(),
            output_dir.clone(),
            *clean,
        );
    }

    if let Commands::NixMeasure {
        attr,
        file,
        history,
        no_record,
        min_eval_fraction,
        fail_on_stop,
    } = &cli.command
    {
        return run_nix_measure_threaded(
            printer,
            cli.verbose,
            eval_config,
            file.clone(),
            attr.clone(),
            history.clone(),
            *no_record,
            *min_eval_fraction,
            *fail_on_stop,
        );
    }

    let nix = NixRunner::with_eval_config(cli.verbose, cli.quiet, eval_config)?;

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
        Commands::Describe => commands::describe::run(&nix, &printer),
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
        // NixRunner construction) and will never reach this match arm.  The
        // arms exist only to satisfy exhaustiveness checking.
        Commands::Completions { .. } => unreachable!(),
        Commands::Serve { .. } => unreachable!(),
        Commands::Token { .. } => unreachable!(),
        Commands::Package { .. } => unreachable!(),
        Commands::Cache { .. } => unreachable!(),
        Commands::NixDiff { .. } => unreachable!(),
        Commands::NixBench { .. } => unreachable!(),
        Commands::NixFuzzCorpus { .. } => unreachable!(),
        Commands::NixMeasure { .. } => unreachable!(),
    }
}

fn run_nix_diff_pair_threaded(
    printer: Printer,
    oracle_drv: PathBuf,
    candidate_drv: PathBuf,
    oracle_bundle: Option<PathBuf>,
    candidate_bundle: Option<PathBuf>,
    mode: DiffMode,
) -> Result<()> {
    const NIX_DIFF_STACK_SIZE: usize = 32 * 1024 * 1024;

    let handle = std::thread::Builder::new()
        .name("aos-nix-diff".to_string())
        .stack_size(NIX_DIFF_STACK_SIZE)
        .spawn(move || {
            commands::nix_diff::run_pair(
                &printer,
                &oracle_drv,
                &candidate_drv,
                oracle_bundle.as_deref(),
                candidate_bundle.as_deref(),
                mode,
            )
        })
        .context("spawning nix-diff worker thread")?;

    match handle.join() {
        Ok(result) => result,
        Err(_) => anyhow::bail!("nix-diff worker thread panicked"),
    }
}

fn run_nix_diff_threaded(
    printer: Printer,
    verbose: u8,
    eval_config: NixEvalConfig,
    file: PathBuf,
    attr: Option<String>,
    smoke: bool,
    all: bool,
    systems: bool,
    eval_json: bool,
    exprs: Vec<String>,
    eval_json_corpus: Vec<PathBuf>,
    time_budget: Option<std::time::Duration>,
    mode: DiffMode,
    oracle_stats: bool,
    cache_validation: bool,
) -> Result<()> {
    const NIX_DIFF_STACK_SIZE: usize = 32 * 1024 * 1024;

    // `aos` runs under Tokio, while nix-diff is a synchronous harness that may
    // instantiate libraries owning their own runtimes. Run it on a plain thread
    // so those runtimes are not dropped from inside Tokio's async context.
    let handle = std::thread::Builder::new()
        .name("aos-nix-diff".to_string())
        .stack_size(NIX_DIFF_STACK_SIZE)
        .spawn(move || {
            commands::nix_diff::run(
                &printer,
                verbose,
                eval_config,
                &file,
                attr.as_deref(),
                smoke,
                all,
                systems,
                eval_json,
                &exprs,
                &eval_json_corpus,
                time_budget,
                mode,
                oracle_stats,
                cache_validation,
            )
        })
        .context("spawning nix-diff worker thread")?;

    match handle.join() {
        Ok(result) => result,
        Err(_) => anyhow::bail!("nix-diff worker thread panicked"),
    }
}

#[allow(clippy::too_many_arguments)]
fn run_nix_bench_threaded(
    printer: Printer,
    verbose: u8,
    eval_config: NixEvalConfig,
    file: Option<PathBuf>,
    attrs: Vec<String>,
    samples: usize,
    history: Option<PathBuf>,
    no_record: bool,
    fail_on_regression: bool,
    require_perf_win: bool,
    regression_threshold: f64,
    memory_regression_threshold: f64,
) -> Result<()> {
    const NIX_BENCH_STACK_SIZE: usize = 32 * 1024 * 1024;

    let handle = std::thread::Builder::new()
        .name("aos-nix-bench".to_string())
        .stack_size(NIX_BENCH_STACK_SIZE)
        .spawn(move || {
            commands::nix_bench::run(
                &printer,
                verbose,
                eval_config,
                file.as_deref(),
                &attrs,
                samples,
                history.as_deref(),
                no_record,
                fail_on_regression,
                require_perf_win,
                regression_threshold,
                memory_regression_threshold,
            )
        })
        .context("spawning nix-bench worker thread")?;

    match handle.join() {
        Ok(result) => result,
        Err(_) => anyhow::bail!("nix-bench worker thread panicked"),
    }
}

fn run_nix_fuzz_corpus_threaded(
    printer: Printer,
    verbose: u8,
    eval_config: NixEvalConfig,
    attrs: Vec<String>,
    excludes: Vec<String>,
    file: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    clean: bool,
) -> Result<()> {
    const NIX_FUZZ_CORPUS_STACK_SIZE: usize = 32 * 1024 * 1024;

    let handle = std::thread::Builder::new()
        .name("aos-nix-fuzz-corpus".to_string())
        .stack_size(NIX_FUZZ_CORPUS_STACK_SIZE)
        .spawn(move || {
            commands::nix_fuzz_corpus::run(
                &printer,
                verbose,
                eval_config,
                &attrs,
                &excludes,
                file.as_deref(),
                output_dir.as_deref(),
                clean,
            )
        })
        .context("spawning nix-fuzz-corpus worker thread")?;

    match handle.join() {
        Ok(result) => result,
        Err(_) => anyhow::bail!("nix-fuzz-corpus worker thread panicked"),
    }
}

fn run_nix_measure_threaded(
    printer: Printer,
    verbose: u8,
    eval_config: NixEvalConfig,
    file: Option<PathBuf>,
    attrs: Vec<String>,
    history: Option<PathBuf>,
    no_record: bool,
    min_eval_fraction: f64,
    fail_on_stop: bool,
) -> Result<()> {
    const NIX_MEASURE_STACK_SIZE: usize = 32 * 1024 * 1024;

    let handle = std::thread::Builder::new()
        .name("aos-nix-measure".to_string())
        .stack_size(NIX_MEASURE_STACK_SIZE)
        .spawn(move || {
            commands::nix_measure::run(
                &printer,
                verbose,
                eval_config,
                file.as_deref(),
                &attrs,
                history.as_deref(),
                no_record,
                min_eval_fraction,
                fail_on_stop,
            )
        })
        .context("spawning nix-measure worker thread")?;

    match handle.join() {
        Ok(result) => result,
        Err(_) => anyhow::bail!("nix-measure worker thread panicked"),
    }
}

fn eval_config_from_cli(cli: &Cli) -> Result<NixEvalConfig> {
    let mut eval_config = NixEvalConfig::new();
    if cli.impure_eval {
        eval_config.set_eval_mode(NixEvalMode::Impure);
    } else if cli.pure_eval {
        eval_config.set_eval_mode(NixEvalMode::Pure);
    } else if cli.restrict_eval {
        eval_config.set_eval_mode(NixEvalMode::Restricted);
    }
    if let Some(system) = &cli.eval_system {
        eval_config.set_current_system(system)?;
    }
    if let Some(max_rss) = cli.max_rss {
        eval_config.set_heap_memory_budget_bytes(max_rss)?;
    }
    for path in &cli.eval_allowed_paths {
        eval_config.add_allowed_path(path.clone())?;
    }
    for uri in &cli.eval_allowed_uris {
        eval_config.add_allowed_uri(uri.clone())?;
    }
    eval_config.set_trace_verbose(cli.trace_verbose);
    Ok(eval_config)
}

/// Map an `anyhow::Error` to an appropriate exit code while printing a
/// user-facing message.  The exit-code conventions are:
///
/// - `0` — success
/// - `1` — build / test failure
/// - `2` — user error (bad arguments, unknown variant, etc.)
/// - `3` — nix not found
fn handle_error(cli: &Cli, err: anyhow::Error) -> i32 {
    let printer = Printer::new(cli.verbose, cli.quiet, cli.json);

    // `aos nix-diff` renders the full divergence report before returning this
    // sentinel error. Preserve the failing exit code without printing a second
    // generic error object, especially in `--json` mode.
    if err
        .downcast_ref::<commands::nix_diff::NixDiffReportedFailure>()
        .is_some()
        || err
            .downcast_ref::<commands::nix_bench::NixBenchRegressionFailure>()
            .is_some()
        || err
            .downcast_ref::<commands::nix_bench::NixBenchAdmissibilityFailure>()
            .is_some()
        || err
            .downcast_ref::<commands::nix_measure::NixMeasureStopFailure>()
            .is_some()
    {
        return 1;
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eval_config_from_cli_sets_explicit_impure_mode() -> Result<()> {
        let cli = Cli {
            impure_eval: true,
            ..base_nix_diff_cli()
        };

        let config = eval_config_from_cli(&cli)?;

        assert_eq!(config.eval_mode(), NixEvalMode::Impure);
        Ok(())
    }

    #[test]
    fn eval_config_from_cli_sets_pure_mode() -> Result<()> {
        let cli = Cli {
            pure_eval: true,
            ..base_nix_diff_cli()
        };

        let config = eval_config_from_cli(&cli)?;

        assert_eq!(config.eval_mode(), NixEvalMode::Pure);
        Ok(())
    }

    #[test]
    fn eval_config_from_cli_sets_restricted_mode_options() -> Result<()> {
        let cli = Cli {
            restrict_eval: true,
            eval_system: Some("aos-test-target".to_string()),
            max_rss: Some(4096),
            trace_verbose: true,
            eval_allowed_paths: vec!["/aos/src".to_string()],
            eval_allowed_uris: vec!["https://cache.example/".to_string()],
            ..base_nix_diff_cli()
        };

        let config = eval_config_from_cli(&cli)?;

        assert_eq!(config.eval_mode(), NixEvalMode::Restricted);
        assert_eq!(config.current_system(), Some("aos-test-target"));
        assert_eq!(config.heap_memory_budget_bytes(), Some(4096));
        assert_eq!(config.allowed_paths(), ["/aos/src"]);
        assert_eq!(config.allowed_uris(), ["https://cache.example/"]);
        assert!(config.trace_verbose());
        Ok(())
    }

    #[test]
    fn eval_config_from_cli_keeps_ambient_mode_without_policy_flags() -> Result<()> {
        let config = eval_config_from_cli(&base_nix_diff_cli())?;

        assert_eq!(config.eval_mode(), NixEvalMode::Ambient);
        Ok(())
    }

    #[test]
    fn eval_config_from_cli_rejects_zero_max_rss() {
        let cli = Cli {
            max_rss: Some(0),
            ..base_nix_diff_cli()
        };

        let error = eval_config_from_cli(&cli).expect_err("zero max rss should be invalid");
        assert!(error.to_string().contains("greater than zero"));
    }

    #[test]
    fn handle_error_suppresses_rendered_nix_diff_divergence() {
        let cli = base_nix_diff_cli();
        let error: anyhow::Error = commands::nix_diff::NixDiffReportedFailure::diverged(1).into();

        assert_eq!(handle_error(&cli, error), 1);
    }

    fn base_nix_diff_cli() -> Cli {
        Cli {
            command: Commands::NixDiff {
                attr: Some("pkgs.hello".to_string()),
                smoke: false,
                all: false,
                systems: false,
                eval_json: false,
                expr: Vec::new(),
                eval_json_corpus: Vec::new(),
                time_budget: None,
                file: None,
                mode: crate::cli::NixDiffMode::Byte,
                oracle_stats: false,
                cache_validation: false,
                oracle_drv: None,
                candidate_drv: None,
                oracle_drv_bundle: None,
                candidate_drv_bundle: None,
            },
            verbose: 0,
            quiet: false,
            json: true,
            trace_verbose: false,
            eval_system: None,
            max_rss: None,
            impure_eval: false,
            pure_eval: false,
            restrict_eval: false,
            eval_allowed_paths: Vec::new(),
            eval_allowed_uris: Vec::new(),
        }
    }
}
