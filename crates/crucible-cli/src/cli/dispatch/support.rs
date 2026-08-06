//! Dispatch reporting, selftest planning, and savepoint export helpers.

use super::*;

pub(crate) fn write_replay_report_human(
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
    if let Some(reduction) = &report.reduction {
        writeln!(
            output,
            "crucible: replay reduction status=reexecuted artifact={} scenario={} schedule={} state={} reconstructed_decisions={}",
            format_content_hash_ref(reduction.artifact),
            format_content_hash_ref(reduction.scenario),
            format_content_hash_ref(reduction.schedule),
            format_content_hash_ref(reduction.state),
            reduction.reconstructed_decisions
        )?;
    }
    if let Some(live) = &report.live_qemu {
        writeln!(
            output,
            "crucible: replay live-qemu status=validated producer={} terminal_configuration={} event_stream={} fingerprint_stream={} controls={}",
            live.producer,
            live.terminal_configuration,
            live.event_stream_digest,
            live.fingerprint_stream_digest,
            live.controls
        )?;
    }
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

pub(crate) fn default_run_store_root(cli: &Cli) -> PathBuf {
    cli.store
        .clone()
        .unwrap_or_else(|| cli.artifact_dir.join("store"))
}

pub(crate) fn plan_selftest_gates(args: &SelftestArgs) -> Result<Vec<String>, CliError> {
    let qemu_enabled = args.with_qemu || !cfg!(any(test, feature = "test-double"));
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
                "unknown selftest gate `{gate}`; run selftest without --gates to use the supported default set"
            )));
        }
        #[cfg(any(test, feature = "test-double"))]
        if BUILT_IN_CORPUS_SELFTEST_GATES.contains(gate) {
            continue;
        }
        if REAL_QEMU_SELFTEST_GATES.contains(gate) {
            if !qemu_enabled {
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

pub(crate) fn selftest_gate_uses_real_backend(gate: &str) -> bool {
    REAL_QEMU_SELFTEST_GATES.contains(&gate)
}

#[cfg(any(test, feature = "test-double"))]
pub(crate) fn verify_selftest_corpus(
    args: &SelftestArgs,
) -> Result<Vec<crucible::ExampleScenarioVerifyReport>, CliError> {
    match &args.corpus {
        Some(path) => verify_selftest_corpus_manifest(path),
        None => verify_selftest_builtin_corpus(),
    }
}

#[cfg(any(test, feature = "test-double"))]
pub(crate) fn verify_selftest_builtin_corpus(
) -> Result<Vec<crucible::ExampleScenarioVerifyReport>, CliError> {
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

#[cfg(any(test, feature = "test-double"))]
pub(crate) fn verify_selftest_corpus_manifest(
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

#[cfg(any(test, feature = "test-double"))]
pub(crate) fn verify_selftest_fixture_by_name(
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

pub(crate) fn write_completions<W: Write>(shell: Shell, writer: &mut W) {
    let mut command = Cli::command();
    let name = command.get_name().to_string();
    clap_complete::generate(shell, &mut command, name, writer);
}

#[cfg(any(test, feature = "test-double"))]
pub(crate) fn mark_mock_failure_outcome(
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

pub(crate) fn export_savepoint_handle(
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
pub(crate) struct SavepointClosureStoreReport {
    pub(crate) artifact: crucible::ContentHash,
    pub(crate) index: crucible::ContentHash,
}

pub(crate) fn persist_savepoint_closure_artifact(
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
        .write_checkpoint_closure_index(savepoint, artifact_key, oracle.frontier)
        .map_err(CliError::Store)?;
    Ok(SavepointClosureStoreReport {
        artifact: artifact_key,
        index: index_key,
    })
}

pub(crate) fn savepoint_handle_bytes(
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

pub(crate) fn unsupported_resume_backend_error(plan: &ResumeInvocationPlan) -> CliError {
    backend_error(format!(
        "resume from checkpoint {} ({}) requires remaining resume runner coverage tracked by T-CLI-10",
        format_content_hash_ref(plan.savepoint.checkpoint()),
        plan.savepoint.label()
    ))
}

pub(crate) fn unsupported_fork_backend_error(plan: &ForkInvocationPlan) -> CliError {
    backend_error(format!(
        "fork from checkpoint {} ({}) as branch `{}` requires the independent child checkpoint-instantiation runner tracked by T-CLI-11",
        format_content_hash_ref(plan.source.checkpoint()),
        plan.source.label(),
        plan.label
    ))
}
