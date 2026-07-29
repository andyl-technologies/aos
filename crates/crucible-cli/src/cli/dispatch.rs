//! Process entrypoint, CLI dispatch, selftest, and savepoint export.

use super::*;
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
    let run_plan = match &cli.command {
        Commands::Run(args) => Some(plan_run_invocation(args, &run_store_root)?),
        _ => None,
    };
    let verify_plan = match &cli.command {
        Commands::Verify(args) => Some(plan_verify_invocation(args, &run_store_root)?),
        _ => None,
    };
    let save_plan = match &cli.command {
        Commands::Save(args) => Some(plan_save_invocation(
            args,
            &run_store_root,
            &cli.artifact_dir,
        )?),
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
        Commands::Search(args) => Some(plan_search_invocation(args, &run_store_root)?),
        _ => None,
    };
    let fuzz_plan = match &cli.command {
        Commands::Fuzz(args) => {
            let seed = ergonomics_plan.as_ref().ok_or_else(|| {
                backend_error("fuzz requires a resolved deterministic campaign seed")
            })?;
            Some(plan_fuzz_invocation(args, seed, &run_store_root)?)
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
            let _plan = plan_debug_invocation(cli, args)?;
            let backend = require_selftest_qemu_backend(cli)?;
            reject_unwired_qemu_workflow(&backend, "debug").map(|_| ())
        }
    }
}

pub(super) fn write_replay_report_human(
    output: &mut impl Write,
    report: &ReplayArtifactReport,
) -> io::Result<()> {
    writeln!(
        output,
        "crucible: replay artifact {} ({}) seed={} scenario={} digest={}",
        report.path.display(),
        REPRODUCTION_ARTIFACT_MEDIA_TYPE,
        report.seed,
        report.scenario_digest,
        report.digest
    )?;
    if let Some(check) = &report.check {
        match &check.mismatch {
            Some(mismatch) => {
                writeln!(
                    output,
                    "crucible: replay check {} status=mismatch expected={} replayed={} first_diff_byte={} original_len={} replayed_len={}",
                    check.path.display(),
                    mismatch.original_digest,
                    mismatch.replayed_digest,
                    mismatch.first_diff_byte,
                    mismatch.original_len,
                    mismatch.replayed_len
                )?;
            }
            None => {
                writeln!(
                    output,
                    "crucible: replay check {} status=byte-identical digest={}",
                    check.path.display(),
                    check.digest
                )?;
            }
        }
    }
    if let Some(target) = &report.to_savepoint {
        writeln!(output, "{}", replay_to_savepoint_status_line(target))?;
    }
    if let Some(bisect) = &report.bisect {
        match &bisect.divergence {
            Some(divergence) => {
                writeln!(
                    output,
                    "crucible: replay bisect {} status=diverged mismatch={} first_decision={} first_fingerprint_sample={} first_instruction={} node={} byte={} left_state={} right_state={}",
                    bisect.other_path.display(),
                    divergence.mismatch.label(),
                    divergence
                        .first_different_decision
                        .map(|decision| decision.to_string())
                        .unwrap_or_else(|| String::from("unknown")),
                    divergence
                        .first_different_fingerprint_sample
                        .map(|sample| sample.to_string())
                        .unwrap_or_else(|| String::from("unknown")),
                    divergence.first_different_instruction,
                    divergence.node.as_deref().unwrap_or("unknown"),
                    divergence.first_different_byte,
                    divergence.left_state_digest,
                    divergence.right_state_digest
                )?;
            }
            None => {
                writeln!(
                    output,
                    "crucible: replay bisect {} status=byte-identical digest={}",
                    bisect.other_path.display(),
                    bisect.other_digest
                )?;
            }
        }
    }
    Ok(())
}

pub(super) fn default_run_store_root(cli: &Cli) -> PathBuf {
    cli.store
        .clone()
        .unwrap_or_else(|| cli.artifact_dir.join("store"))
}

pub(super) fn plan_selftest_gates(args: &SelftestArgs) -> Result<Vec<String>, CliError> {
    let requested = match args.gates.as_deref() {
        Some(raw) => raw.split(',').map(str::trim).collect::<Vec<_>>(),
        #[cfg(any(test, feature = "test-double"))]
        None => BUILT_IN_CORPUS_SELFTEST_GATES.to_vec(),
        #[cfg(not(any(test, feature = "test-double")))]
        None => REAL_QEMU_SELFTEST_GATES.to_vec(),
    };
    #[cfg(any(test, feature = "test-double"))]
    let mut requested = requested;
    #[cfg(any(test, feature = "test-double"))]
    if args.gates.is_none() && args.with_qemu {
        requested.extend(REAL_QEMU_SELFTEST_GATES.iter().copied());
    }
    if requested.is_empty() || requested.iter().any(|gate| gate.is_empty()) {
        return Err(usage_error(
            "--gates must name one or more comma-separated canonical gates",
        ));
    }

    let mut seen = BTreeSet::new();
    for gate in &requested {
        if !seen.insert(*gate) {
            return Err(usage_error(format!(
                "duplicate selftest gate `{gate}` in --gates"
            )));
        }
        if !CANONICAL_GATE_NAMES.contains(gate) {
            return Err(usage_error(format!(
                "unknown selftest gate `{gate}`; use canonical gate names from RFC-0010 file 24"
            )));
        }
        #[cfg(any(test, feature = "test-double"))]
        if BUILT_IN_CORPUS_SELFTEST_GATES.contains(gate) {
            continue;
        }
        if REAL_QEMU_SELFTEST_GATES.contains(gate) {
            if !args.with_qemu {
                return Err(usage_error(format!(
                    "selftest gate `{gate}` requires --with-qemu"
                )));
            }
            continue;
        }
        {
            return Err(usage_error(format!(
                "selftest gate `{gate}` is not supported by the built-in corpus or real-QEMU selftest runners"
            )));
        }
    }

    Ok(requested.into_iter().map(ToOwned::to_owned).collect())
}

pub(super) fn selftest_gate_uses_real_backend(gate: &str) -> bool {
    REAL_QEMU_SELFTEST_GATES.contains(&gate)
}

pub(super) fn verify_selftest_corpus(
    args: &SelftestArgs,
) -> Result<Vec<crucible::ExampleScenarioVerifyReport>, CliError> {
    match &args.corpus {
        Some(path) => verify_selftest_corpus_manifest(path),
        None => verify_selftest_builtin_corpus(),
    }
}

pub(super) fn verify_selftest_builtin_corpus()
-> Result<Vec<crucible::ExampleScenarioVerifyReport>, CliError> {
    let corpus = crucible::built_in_example_corpus().map_err(CliError::Selftest)?;
    let mut verified = Vec::with_capacity(corpus.len());
    for fixture in corpus {
        verified.push(
            crucible::verify_example_scenario_runs(&fixture, DEFAULT_SELFTEST_RUNS)
                .map_err(CliError::Selftest)?,
        );
    }
    Ok(verified)
}

pub(super) fn verify_selftest_corpus_manifest(
    path: &Path,
) -> Result<Vec<crucible::ExampleScenarioVerifyReport>, CliError> {
    if !path.is_file() {
        return Err(usage_error(format!(
            "selftest --corpus `{}` must be a manifest file",
            path.display()
        )));
    }
    let text = fs::read_to_string(path).map_err(|error| {
        usage_error(format!(
            "selftest --corpus `{}` could not be read: {error}",
            path.display()
        ))
    })?;
    let mut verified = Vec::new();
    for (index, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        verified.push(verify_selftest_fixture_by_name(line).map_err(|message| {
            usage_error(format!(
                "selftest --corpus `{}` line {}: {message}",
                path.display(),
                index + 1
            ))
        })?);
    }
    if verified.is_empty() {
        return Err(usage_error(format!(
            "selftest --corpus `{}` must list at least one built-in scenario name",
            path.display()
        )));
    }
    Ok(verified)
}

pub(super) fn verify_selftest_fixture_by_name(
    raw_name: &str,
) -> Result<crucible::ExampleScenarioVerifyReport, String> {
    let name = raw_name.strip_prefix("builtin:").unwrap_or(raw_name);
    let fixture = match name {
        crucible::HAPPY_PATH_SCENARIO_NAME => {
            crucible::happy_path_scenario().map_err(|error| error.to_string())
        }
        crucible::PARTITION_RECOVERY_SCENARIO_NAME => {
            crucible::partition_recovery_scenario().map_err(|error| error.to_string())
        }
        crucible::CRASH_RESTART_SCENARIO_NAME => {
            crucible::crash_restart_scenario().map_err(|error| error.to_string())
        }
        _ => Err(format!(
            "unknown built-in scenario `{raw_name}`; expected {}, {}, or {}",
            crucible::HAPPY_PATH_SCENARIO_NAME,
            crucible::PARTITION_RECOVERY_SCENARIO_NAME,
            crucible::CRASH_RESTART_SCENARIO_NAME
        )),
    }?;
    crucible::verify_example_scenario_runs(&fixture, DEFAULT_SELFTEST_RUNS)
        .map_err(|error| error.to_string())
}

pub(super) fn write_completions<W: Write>(shell: Shell, writer: &mut W) {
    let mut command = Cli::command();
    let name = command.get_name().to_string();
    clap_complete::generate(shell, &mut command, name, writer);
}

pub(super) fn mark_mock_failure_outcome(
    _cli: &Cli,
    backend_plan: &BackendSelectionPlan,
    outcome: &mut BackendCommandOutcome,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
) -> Result<(), CliError> {
    let Some(plan) = ergonomics_plan else {
        return Err(CliError::Backend(
            "run requires a resolved seed before emitting a reproduction artifact".to_string(),
        ));
    };
    if backend_plan.target == BackendExecutionTarget::RemoteDaemon {
        return Err(CliError::Backend(
            "mock failure reproduction artifacts require local producer provenance; remote daemon provenance is not available".to_string(),
        ));
    }
    let artifact = mock_failure_reproduction_artifact_bytes_for_backend(
        plan.seed.value,
        backend_plan.resolved_backend.as_ref(),
    )?;
    outcome.status = BackendCommandStatus::Failed;
    outcome.exit_code = 1;
    outcome.stderr.push(String::from(
        "crucible: mock non-passing outcome requested for gate testing",
    ));
    outcome.canonical_log.push(CanonicalLogEntry {
        sequence: outcome.canonical_log.len() as u64,
        virtual_time_ticks: outcome.canonical_log.len() as u64,
        node: String::from("session"),
        kind: String::from("outcome"),
        summary: String::from("Failed"),
    });
    outcome.canonical_log_digest = canonical_log_digest(&outcome.canonical_log);
    outcome.artifact_digest = content_address_bytes(&artifact);
    outcome.reproduction_artifact = Some(artifact);
    Ok(())
}

pub(super) fn export_savepoint_handle(
    plan: &SaveInvocationPlan,
    outcome: &mut BackendCommandOutcome,
) -> Result<(), CliError> {
    if outcome.status.is_non_passing() {
        return Ok(());
    }
    let savepoint = outcome.terminal_savepoint.ok_or_else(|| {
        backend_error("save completed without a validated create-savepoint reply")
    })?;
    let oracle = outcome
        .savepoint_oracle
        .as_ref()
        .ok_or_else(|| backend_error("save completed without replay-oracle proof"))?;
    let store_report = persist_savepoint_closure_artifact(plan, savepoint, oracle)?;
    let checkpoint = format_content_hash_ref(savepoint);
    let handle = savepoint_handle_bytes(plan, &checkpoint, outcome, oracle);
    let handle_digest = content_address_bytes(&handle);
    let path = plan.output.resolve(&plan.label, &handle_digest);
    if let Some(parent) = path.parent().filter(|path| !path.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, handle)?;
    outcome.stdout.push(format!(
        "save-handle\tcheckpoint={checkpoint}\tlabel={}\tout={}\tdigest={handle_digest}",
        plan.label,
        path.display()
    ));
    outcome.stdout.push(format!(
        "save-store\tcheckpoint={checkpoint}\tartifact={}\tindex={}\tstore={}",
        format_content_hash_ref(store_report.artifact),
        format_content_hash_ref(store_report.index),
        plan.store_root.display()
    ));
    outcome.canonical_log.push(CanonicalLogEntry {
        sequence: outcome.canonical_log.len() as u64,
        virtual_time_ticks: outcome.canonical_log.len() as u64,
        node: String::from("cli"),
        kind: String::from("save_export"),
        summary: format!(
            "at={} checkpoint={} label={} out={} digest={}",
            plan.at.label(),
            checkpoint,
            plan.label,
            path.display(),
            handle_digest
        ),
    });
    outcome.canonical_log_digest = canonical_log_digest(&outcome.canonical_log);
    outcome.canonical_log.push(CanonicalLogEntry {
        sequence: outcome.canonical_log.len() as u64,
        virtual_time_ticks: outcome.canonical_log.len() as u64,
        node: String::from("cli"),
        kind: String::from("save_store_index"),
        summary: format!(
            "checkpoint={} artifact={} index={} store={}",
            checkpoint,
            format_content_hash_ref(store_report.artifact),
            format_content_hash_ref(store_report.index),
            plan.store_root.display()
        ),
    });
    outcome.canonical_log_digest = canonical_log_digest(&outcome.canonical_log);
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SavepointClosureStoreReport {
    pub(super) artifact: crucible::ContentHash,
    pub(super) index: crucible::ContentHash,
}

pub(super) fn persist_savepoint_closure_artifact(
    plan: &SaveInvocationPlan,
    savepoint: crucible::ContentHash,
    oracle: &SavepointOracleProof,
) -> Result<SavepointClosureStoreReport, CliError> {
    if oracle.configuration != savepoint || oracle.fat_checkpoint != savepoint {
        return Err(CliError::Identity(format!(
            "savepoint closure checkpoint {} did not match oracle configuration {} and fat checkpoint {}",
            format_content_hash_ref(savepoint),
            format_content_hash_ref(oracle.configuration),
            format_content_hash_ref(oracle.fat_checkpoint)
        )));
    }
    let artifact = crucible::ReproductionArtifact::capture(
        plan.run_plan.scenario.scenario_form(),
        &oracle.schedule,
    )
    .map_err(|error| {
        artifact_error(format!(
            "savepoint closure artifact capture failed for {}: {error}",
            format_content_hash_ref(savepoint)
        ))
    })?;
    let configuration = crucible::Configuration {
        def: artifact.scenario_def(),
        schedule: artifact.schedule().clone(),
    };
    if configuration.id() != savepoint {
        return Err(CliError::Identity(format!(
            "savepoint closure artifact reconstructed {}, expected {}",
            format_content_hash_ref(configuration.id()),
            format_content_hash_ref(savepoint)
        )));
    }
    let store = crucible::LocalDagStore::new(plan.store_root.clone());
    let artifact_key = store
        .put(&artifact.to_compact_binary())
        .map_err(CliError::Store)?;
    let index_key = store
        .write_checkpoint_closure_index(savepoint, artifact_key)
        .map_err(CliError::Store)?;
    Ok(SavepointClosureStoreReport {
        artifact: artifact_key,
        index: index_key,
    })
}

pub(super) fn savepoint_handle_bytes(
    plan: &SaveInvocationPlan,
    checkpoint: &str,
    outcome: &BackendCommandOutcome,
    oracle: &SavepointOracleProof,
) -> Vec<u8> {
    let mut text = String::new();
    let scenario_payload = plan.run_plan.scenario.scenario_form().to_compact_binary();
    let scenario_payload_digest = content_address_bytes(&scenario_payload);
    let schedule_payload = oracle.schedule.to_compact_binary();
    let frontier_ticks = oracle.frontier.ticks;
    let schedule_payload_digest = content_address_bytes(&schedule_payload);
    artifact_line(&mut text, &["schema", SAVEPOINT_HANDLE_SCHEMA]);
    artifact_line(&mut text, &["label", &plan.label]);
    artifact_line(&mut text, &["checkpoint", checkpoint]);
    artifact_line(
        &mut text,
        &[
            "scenario",
            &plan.run_plan.scenario.scenario_id().to_hex(),
            &plan.run_plan.scenario.label(),
        ],
    );
    artifact_line(
        &mut text,
        &[
            "scenario-payload",
            &scenario_payload_digest,
            &hex_bytes(&scenario_payload),
        ],
    );
    artifact_line(
        &mut text,
        &[
            "schedule-payload",
            &schedule_payload_digest,
            &hex_bytes(&schedule_payload),
        ],
    );
    artifact_line(&mut text, &["frontier", &frontier_ticks.to_string()]);
    artifact_line(&mut text, &["at", plan.at.label()]);
    artifact_line(
        &mut text,
        &[
            "terminal-condition",
            plan.run_plan.terminal_condition.label(),
        ],
    );
    artifact_line(&mut text, &["materialization", "create-savepoint", "reply"]);
    let oracle_status = oracle.status_label();
    artifact_line(&mut text, &["oracle", oracle_status]);
    artifact_line(&mut text, &["canonical-log", &outcome.canonical_log_digest]);
    text.into_bytes()
}

pub(super) fn unsupported_resume_backend_error(plan: &ResumeInvocationPlan) -> CliError {
    backend_error(format!(
        "resume from checkpoint {} ({}) requires remaining resume runner coverage tracked by T-CLI-10",
        format_content_hash_ref(plan.savepoint.checkpoint()),
        plan.savepoint.label()
    ))
}

pub(super) fn unsupported_fork_backend_error(plan: &ForkInvocationPlan) -> CliError {
    backend_error(format!(
        "fork from checkpoint {} ({}) as branch `{}` requires the independent child checkpoint-instantiation runner tracked by T-CLI-11",
        format_content_hash_ref(plan.source.checkpoint()),
        plan.source.label(),
        plan.label
    ))
}
