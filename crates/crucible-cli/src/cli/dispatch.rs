//! Process entrypoint, CLI dispatch, selftest, and savepoint export.

use super::*;

#[cfg(any(test, feature = "test-double"))]
pub(super) const BUILT_IN_CORPUS_SELFTEST_GATES: &[&str] = &[
    "gate:layer0-determinism",
    "gate:content-address",
    "gate:layer1-injection",
    "gate:replay-oracle",
    "gate:scheduler-liveness",
    "gate:control-responsive",
];

// crucible-lint: allow rust-allow -- the test harness builds the binary root without invoking its imported entrypoint.
#[cfg_attr(test, allow(dead_code))]
pub(super) fn main() {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let exit_code = cli_parse_error_exit_code(&error);
            if let Err(print_error) = error.print() {
                eprintln!("crucible: {print_error}");
                std::process::exit(CliError::Io(print_error).exit_code());
            }
            std::process::exit(exit_code);
        }
    };
    if let Err(error) = dispatch(&cli) {
        eprintln!("crucible: {error}");
        std::process::exit(error.exit_code());
    }
}

pub(super) fn cli_parse_error_exit_code(error: &clap::Error) -> i32 {
    match error.kind() {
        clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => 0,
        _ => CliError::Usage(error.to_string()).exit_code(),
    }
}

pub(super) fn dispatch(cli: &Cli) -> Result<(), CliError> {
    let thin_plan = plan_cli_invocation(cli);
    execute_cli_dispatch_plan(&thin_plan, &mut NullOperationRecorder)?;
    let mut seed_entropy = OsSeedEntropySource;
    let ergonomics_plan =
        plan_determinism_ergonomics(cli, &ProcessSeedEnvironment, &mut seed_entropy)?;
    let run_store_root = default_run_store_root(cli);
    let run_identity_seed = ergonomics_plan
        .as_ref()
        .map(|plan| crucible::Seed::from_u64(plan.seed.value));
    let run_plan = match &cli.command {
        Commands::Run(args) => {
            let mut plan = plan_run_invocation(args, &run_store_root)?;
            if let Some(seed) = run_identity_seed {
                pin_run_invocation_seed(&mut plan, seed)?;
            }
            Some(plan)
        }
        _ => None,
    };
    let verify_plan = match &cli.command {
        Commands::Verify(args) => Some(plan_verify_invocation(args, &run_store_root)?),
        _ => None,
    };
    let save_plan = match &cli.command {
        Commands::Save(args) => {
            let mut plan = plan_save_invocation(args, &run_store_root, &cli.artifact_dir)?;
            if let Some(seed) = run_identity_seed {
                pin_run_invocation_seed(&mut plan.run_plan, seed)?;
            }
            Some(plan)
        }
        _ => None,
    };
    let resume_plan = match &cli.command {
        Commands::Resume(args) => Some(plan_resume_invocation(args, &run_store_root)?),
        _ => None,
    };
    let fork_plan = match &cli.command {
        Commands::Fork(args) => {
            let fork_seed = if cli.seed.is_some() {
                Some(
                    ergonomics_plan
                        .as_ref()
                        .ok_or_else(|| backend_error("fork requires a resolved explicit seed"))?
                        .seed
                        .value,
                )
            } else {
                None
            };
            Some(plan_fork_invocation(
                args,
                fork_seed,
                &cli.artifact_dir,
                &run_store_root,
            )?)
        }
        _ => None,
    };
    let search_plan = match &cli.command {
        Commands::Search(args) => {
            let mut plan =
                plan_search_invocation_with_artifact_dir(args, &run_store_root, &cli.artifact_dir)?;
            if let Some(seed) = run_identity_seed {
                pin_search_invocation_seed(&mut plan, seed)?;
            }
            Some(plan)
        }
        _ => None,
    };
    let fuzz_plan = match &cli.command {
        Commands::Fuzz(args) => {
            let seed = ergonomics_plan.as_ref().ok_or_else(|| {
                backend_error("fuzz requires a resolved deterministic campaign seed")
            })?;
            Some(plan_fuzz_invocation_with_artifact_dir(
                args,
                seed,
                &run_store_root,
                &cli.artifact_dir,
            )?)
        }
        _ => None,
    };
    let emit_human = should_emit_human_dispatch_output(cli);
    if let Some(plan) = &ergonomics_plan {
        execute_determinism_ergonomics_plan(plan, &mut NullDeterminismErgonomicsRecorder)?;
        if emit_human {
            println!("{}", plan.seed_announcement());
        }
    }
    if let Commands::Serve(args) = &cli.command {
        return run_serve_invocation(cli, args);
    }
    if let Some(backend_plan) = plan_backend_selection(cli)? {
        execute_backend_selection_plan(&backend_plan, cli.quiet, &mut NullBackendRouteRecorder)?;
        if let Some(resume_plan) = &resume_plan {
            if backend_plan.target == BackendExecutionTarget::Local {
                let outcome = match backend_plan.resolved_backend.as_ref() {
                    #[cfg(any(test, feature = "test-double"))]
                    Some(ResolvedLocalBackend::Double) => run_local_double_resume_workflow(
                        &thin_plan,
                        &backend_plan,
                        ergonomics_plan.as_ref(),
                        resume_plan,
                    ),
                    Some(ResolvedLocalBackend::Qemu { .. }) => run_local_qemu_resume_workflow(
                        &thin_plan,
                        &backend_plan,
                        ergonomics_plan.as_ref(),
                        resume_plan,
                    ),
                    None => Err(unsupported_resume_backend_error(resume_plan)),
                }?;
                let backend = backend_plan.resolved_backend.as_ref().ok_or_else(|| {
                    backend_error("local resume completed without a resolved backend")
                })?;
                let evidence = observe_local_backend_execution(backend)?;
                validate_backend_execution_evidence(&backend_plan, &evidence)?;
                if emit_human && backend_plan.should_announce(cli.quiet) {
                    println!("{}", backend_plan.announcement());
                }
                emit_backend_command_output(cli, &outcome)?;
                if outcome.status.is_non_passing() {
                    return Err(CliError::Outcome(outcome.status));
                }
                return Ok(());
            }
            if backend_plan.target == BackendExecutionTarget::RemoteDaemon
                && let Some(daemon) = backend_plan.daemon.as_deref()
            {
                let outcome = run_remote_resume_workflow(
                    daemon,
                    &thin_plan,
                    &backend_plan,
                    ergonomics_plan.as_ref(),
                    resume_plan,
                )?;
                emit_backend_command_output(cli, &outcome)?;
                if outcome.status.is_non_passing() {
                    return Err(CliError::Outcome(outcome.status));
                }
                return Ok(());
            }
            return Err(unsupported_resume_backend_error(resume_plan));
        }
        if let Some(fork_plan) = &fork_plan {
            if backend_plan.target == BackendExecutionTarget::Local {
                let outcome = match backend_plan.resolved_backend.as_ref() {
                    #[cfg(any(test, feature = "test-double"))]
                    Some(ResolvedLocalBackend::Double) => run_local_double_fork_workflow(
                        &thin_plan,
                        &backend_plan,
                        ergonomics_plan.as_ref(),
                        fork_plan,
                    ),
                    Some(ResolvedLocalBackend::Qemu { .. }) => run_local_qemu_fork_workflow(
                        &thin_plan,
                        &backend_plan,
                        ergonomics_plan.as_ref(),
                        fork_plan,
                    ),
                    None => Err(unsupported_fork_backend_error(fork_plan)),
                }?;
                let backend = backend_plan.resolved_backend.as_ref().ok_or_else(|| {
                    backend_error("local fork completed without a resolved backend")
                })?;
                let evidence = observe_local_backend_execution(backend)?;
                validate_backend_execution_evidence(&backend_plan, &evidence)?;
                if emit_human && backend_plan.should_announce(cli.quiet) {
                    println!("{}", backend_plan.announcement());
                }
                emit_backend_command_output(cli, &outcome)?;
                if outcome.status.is_non_passing() {
                    return Err(CliError::Outcome(outcome.status));
                }
                return Ok(());
            }
            return Err(unsupported_fork_backend_error(fork_plan));
        }
        if let Some(search_plan) = &search_plan {
            if backend_plan.target == BackendExecutionTarget::Local {
                let outcome = match backend_plan.resolved_backend.as_ref() {
                    #[cfg(any(test, feature = "test-double"))]
                    Some(ResolvedLocalBackend::Double) => run_local_double_search_workflow(
                        &thin_plan,
                        &backend_plan,
                        ergonomics_plan.as_ref(),
                        search_plan,
                    ),
                    Some(ResolvedLocalBackend::Qemu { .. }) => run_local_qemu_search_workflow(
                        &thin_plan,
                        &backend_plan,
                        ergonomics_plan.as_ref(),
                        search_plan,
                    ),
                    None => Err(unsupported_search_backend_error(search_plan)),
                }?;
                let backend = backend_plan.resolved_backend.as_ref().ok_or_else(|| {
                    backend_error("local search completed without a resolved backend")
                })?;
                let evidence = observe_local_backend_execution(backend)?;
                validate_backend_execution_evidence(&backend_plan, &evidence)?;
                if emit_human && backend_plan.should_announce(cli.quiet) {
                    println!("{}", backend_plan.announcement());
                }
                emit_backend_command_output(cli, &outcome)?;
                if outcome.status.is_non_passing() {
                    return Err(CliError::Outcome(outcome.status));
                }
                return Ok(());
            }
            return Err(unsupported_search_backend_error(search_plan));
        }
        if let Some(fuzz_plan) = &fuzz_plan {
            match fuzz_dispatch_route(&backend_plan, fuzz_plan) {
                Some(FuzzDispatchRoute::BuiltInFaultCampaignProof) => {
                    run_builtin_fault_campaign_fuzz(cli, fuzz_plan)?;
                    return Ok(());
                }
                #[cfg(any(test, feature = "test-double"))]
                Some(FuzzDispatchRoute::LocalDouble) => {
                    let outcome = run_local_double_fuzz_workflow(
                        &thin_plan,
                        &backend_plan,
                        ergonomics_plan.as_ref(),
                        fuzz_plan,
                    )?;
                    let backend = backend_plan.resolved_backend.as_ref().ok_or_else(|| {
                        backend_error("local fuzz completed without a resolved backend")
                    })?;
                    let evidence = observe_local_backend_execution(backend)?;
                    validate_backend_execution_evidence(&backend_plan, &evidence)?;
                    if emit_human && backend_plan.should_announce(cli.quiet) {
                        println!("{}", backend_plan.announcement());
                    }
                    emit_backend_command_output(cli, &outcome)?;
                    if outcome.status.is_non_passing() {
                        return Err(CliError::Outcome(outcome.status));
                    }
                    return Ok(());
                }
                Some(FuzzDispatchRoute::LocalPackagedBackend) => {
                    let outcome = run_local_qemu_fuzz_workflow(
                        &thin_plan,
                        &backend_plan,
                        ergonomics_plan.as_ref(),
                        fuzz_plan,
                    )?;
                    let backend = backend_plan.resolved_backend.as_ref().ok_or_else(|| {
                        backend_error("local fuzz completed without a resolved backend")
                    })?;
                    let evidence = observe_local_backend_execution(backend)?;
                    validate_backend_execution_evidence(&backend_plan, &evidence)?;
                    if emit_human && backend_plan.should_announce(cli.quiet) {
                        println!("{}", backend_plan.announcement());
                    }
                    emit_backend_command_output(cli, &outcome)?;
                    if outcome.status.is_non_passing() {
                        return Err(CliError::Outcome(outcome.status));
                    }
                    return Ok(());
                }
                None => return Err(unsupported_fuzz_backend_error(fuzz_plan)),
            }
        }
        let mut outcome = execute_backend_routed_command(
            &thin_plan,
            &backend_plan,
            ergonomics_plan.as_ref(),
            run_plan
                .as_ref()
                .or_else(|| save_plan.as_ref().map(|plan| &plan.run_plan)),
            verify_plan.as_ref(),
            save_plan.as_ref(),
            &mut NullBackendCommandRunner,
        )?;
        #[cfg(any(test, feature = "test-double"))]
        if matches!(
            &cli.command,
            Commands::Run(RunArgs {
                emit_mock_failure_artifact: true,
                ..
            })
        ) {
            mark_mock_failure_outcome(cli, &backend_plan, &mut outcome, ergonomics_plan.as_ref())?;
        }
        if emit_human && backend_plan.should_announce(cli.quiet) {
            println!("{}", backend_plan.announcement());
        }
        if let Some(save_plan) = &save_plan {
            export_savepoint_handle(save_plan, &mut outcome)?;
        }
        emit_backend_command_output(cli, &outcome)?;
        if outcome.status.is_non_passing() {
            return Err(CliError::Outcome(outcome.status));
        }
    }

    match &cli.command {
        Commands::Replay(args) => {
            let report = replay_reproduction_artifact(cli, args)?;
            emit_replay_report_output(cli, &report)?;
            if let Some(check) = &report.check
                && let Some(mismatch) = &check.mismatch
            {
                return Err(replay_check_mismatch_error(check, mismatch));
            }
            if let Some(bisect) = &report.bisect
                && let Some(divergence) = &bisect.divergence
            {
                return Err(replay_bisect_error(&report.path, bisect, divergence));
            }
            Ok(())
        }
        Commands::Run(_) => Ok(()),
        Commands::Selftest(args) => {
            let report = run_selftest(cli, args)?;
            if !cli.quiet {
                for gate in &report.gates {
                    println!(
                        "crucible: selftest gate={} status={} runner={} corpus={} runs-per-entry={} qemu={} live-icount={} live-fingerprint={}",
                        gate.name,
                        gate.status.label(),
                        gate.runner.label(),
                        gate.corpus_entries,
                        gate.runs_per_entry,
                        gate.qemu_build_id.as_deref().unwrap_or("none"),
                        gate.live_qemu_icount
                            .map_or_else(|| String::from("none"), |value| value.to_string()),
                        gate.live_qemu_fingerprint.as_deref().unwrap_or("none")
                    );
                }
                for verified in report.verified {
                    println!(
                        "crucible: selftest {} PASS runs={}",
                        verified.scenario_name, verified.runs
                    );
                }
            }
            Ok(())
        }
        Commands::Verify(_)
        | Commands::Save(_)
        | Commands::Resume(_)
        | Commands::Fork(_)
        | Commands::Search(_)
        | Commands::Fuzz(_)
        | Commands::Serve(_) => Ok(()),
        Commands::Completions(args) => {
            write_completions(args.shell, &mut io::stdout());
            Ok(())
        }
        Commands::Triage(args) => {
            let report = run_triage_invocation(cli, args)?;
            if !cli.quiet {
                println!(
                    "crucible: triage findings={} findings_count={} ledger={} ledger_cache_hit={} policy={} minimize={} clusters={} report={} format={} store={} result={} cache_hit={} compare={}",
                    report.plan.findings.label(),
                    report.ledger.artifact_count(),
                    format_content_hash_ref(report.stored_ledger.key),
                    report.stored_ledger.cache_hit,
                    report.plan.policy_label(),
                    report.plan.minimize_label(),
                    report.result.clustering.cluster_count(),
                    report.report_path.display(),
                    report.plan.format_label(),
                    report.plan.store_root.display(),
                    format_content_hash_ref(report.stored_result.key),
                    report.stored_result.cache_hit,
                    report
                        .compare
                        .as_ref()
                        .map(|diff| diff.status_label())
                        .unwrap_or("none")
                );
                if let Some(diff) = &report.compare {
                    println!("{}", diff.content_diff());
                }
            }
            Ok(())
        }
        Commands::Debug(args) => {
            let plan = plan_debug_invocation(cli, args)?;
            if cli.daemon.is_some() {
                return run_remote_debug_relay(cli, &plan);
            }
            let backend = require_selftest_qemu_backend(cli)?;
            for line in run_local_qemu_debug_workflow(&backend, &plan)? {
                println!("{line}");
            }
            Ok(())
        }
    }
}

#[path = "dispatch/support.rs"]
mod support;

pub(super) use support::*;
