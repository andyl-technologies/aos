//! Replay execution, schedule-prefix proof, and bisection.

use super::*;
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct TraceRenderReport {
    pub(super) format: OutputFormat,
    pub(super) path: Option<PathBuf>,
    pub(super) bytes: Vec<u8>,
    pub(super) entry_count: usize,
    pub(super) streamed_entries: usize,
    pub(super) canonical_digest: String,
}

pub(super) fn emit_canonical_trace(
    format: OutputFormat,
    entries: &[CanonicalLogEntry],
    trace_path: Option<&Path>,
    stdout: bool,
) -> Result<TraceRenderReport, CliError> {
    if format == OutputFormat::Markdown {
        return Err(usage_error(
            "--format markdown is reserved for triage reports, not canonical event-log traces",
        ));
    }

    let mut bytes = Vec::new();
    let mut streamed_entries = 0usize;
    match format {
        OutputFormat::Jsonl => {
            let mut trace_file = trace_path.map(fs::File::create).transpose()?;
            for entry in entries {
                let line = json_for_canonical_log_entry(entry);
                if stdout {
                    println!("{line}");
                }
                if let Some(file) = trace_file.as_mut() {
                    writeln!(file, "{line}")?;
                }
                writeln!(&mut bytes, "{line}")?;
                streamed_entries += 1;
            }
        }
        OutputFormat::Json | OutputFormat::Table => {
            let rendered = render_canonical_event_log(format, entries)?;
            if stdout {
                println!("{}", String::from_utf8_lossy(&rendered.bytes));
            }
            if let Some(path) = trace_path {
                fs::write(path, &rendered.bytes)?;
            }
            bytes = rendered.bytes;
        }
        OutputFormat::Markdown => unreachable!("markdown rejected above"),
    }

    Ok(TraceRenderReport {
        format,
        path: trace_path.map(Path::to_path_buf),
        bytes,
        entry_count: entries.len(),
        streamed_entries,
        canonical_digest: canonical_log_digest(entries),
    })
}

pub(super) fn replay_reproduction_artifact(
    cli: &Cli,
    args: &ReplayArgs,
) -> Result<ReplayArtifactReport, CliError> {
    let bytes = fs::read(&args.artifact)?;
    let artifact = validate_replayable_reproduction_artifact(cli, &bytes)?;
    let seed = artifact.seed;
    let scenario_digest = artifact.scenario.digest.clone();
    let reduction = replay_embedded_model_artifact(&artifact)?;
    let live_qemu = if replay_uses_live_qemu(cli)? {
        if reduction.is_none() {
            return Err(artifact_error(
                "v3 replay requires an embedded pure model reproduction proof",
            ));
        }
        Some(replay_live_qemu_evidence(cli, &artifact)?)
    } else {
        None
    };
    let to_savepoint = args
        .to
        .as_deref()
        .map(|target| replay_to_savepoint(cli, target, &artifact))
        .transpose()?;
    let check = if let Some(path) = &args.check {
        let replayed = canonical_log_entry_bytes(&canonical_log_entries_from_artifact(&artifact)?);
        let original = fs::read(path)?;
        let mismatch = (original != replayed).then(|| ReplayCheckMismatchReport {
            original_digest: content_address_bytes(&original),
            replayed_digest: content_address_bytes(&replayed),
            first_diff_byte: bisect_first_different_byte(&original, &replayed),
            original_len: original.len(),
            replayed_len: replayed.len(),
        });
        Some(ReplayCheckReport {
            path: path.clone(),
            digest: content_address_bytes(&replayed),
            mismatch,
        })
    } else {
        None
    };
    let bisect = if check
        .as_ref()
        .and_then(|check| check.mismatch.as_ref())
        .is_some()
    {
        None
    } else {
        args.bisect
            .as_ref()
            .map(|other| replay_bisect_artifacts(cli, other, &artifact, &bytes))
            .transpose()?
    };
    Ok(ReplayArtifactReport {
        path: args.artifact.clone(),
        digest: content_address_bytes(&bytes),
        seed,
        scenario_digest,
        reduction,
        live_qemu,
        to_savepoint,
        check,
        bisect,
    })
}

fn replay_uses_live_qemu(cli: &Cli) -> Result<bool, CliError> {
    let plan = plan_backend_selection(cli)?;
    Ok(matches!(
        plan.as_ref()
            .and_then(|plan| plan.resolved_backend.as_ref()),
        Some(ResolvedLocalBackend::Qemu { .. })
    ))
}

fn replay_live_qemu_evidence(
    cli: &Cli,
    artifact: &CliReproductionArtifact,
) -> Result<ReplayLiveQemuProof, CliError> {
    let contract_bytes = required_single_component_payload(
        artifact,
        LIVE_QEMU_REPLAY_CONTRACT_MEDIA_TYPE,
        "live QEMU replay contract",
    )?;
    let expected_events = required_single_component_payload(
        artifact,
        LIVE_QEMU_EVENT_STREAM_MEDIA_TYPE,
        "live QEMU event stream",
    )?;
    let expected_fingerprints = required_single_component_payload(
        artifact,
        LIVE_QEMU_FINGERPRINT_STREAM_MEDIA_TYPE,
        "live QEMU fingerprint stream",
    )?;
    let resolved_effect_trace_bytes = optional_single_component_payload(
        artifact,
        LIVE_QEMU_RESOLVED_EFFECT_TRACE_MEDIA_TYPE,
        "live QEMU resolved-effect trace",
    )?;
    let contract = LiveQemuReplayContract::decode(contract_bytes)?;
    let top_level_fingerprints =
        verify_fingerprint_stream_bytes(&artifact_fingerprint_samples(artifact));
    if top_level_fingerprints != expected_fingerprints {
        return Err(artifact_error(
            "live-QEMU fingerprint component does not match top-level artifact samples",
        ));
    }
    if artifact.scenario.media_type != "application/vnd.crucible.scenario.compact-binary" {
        return Err(artifact_error(
            "v3 live-QEMU replay requires a compact binary scenario component",
        ));
    }
    let scenario = crucible::ScenarioDefForm::from_compact_binary(resolved_component_payload(
        artifact,
        &artifact.scenario,
    )?)
    .map_err(|error| artifact_error(format!("decode live-QEMU replay scenario: {error}")))?;
    let resolved_effect_trace = resolved_effect_trace_bytes
        .map(|bytes| {
            crucible::model::ResolvedEffectTrace::from_canonical_bytes(
                bytes,
                scenario.plan().fault_signals().resource_limits(),
            )
            .map_err(|error| artifact_error(format!("decode resolved-effect trace: {error}")))
        })
        .transpose()?;
    match (
        scenario.plan().fault_signals().programs().is_empty(),
        resolved_effect_trace.is_some(),
    ) {
        (false, false) => {
            return Err(artifact_error(
                "live-QEMU replay of a signal fault plan requires a resolved-effect trace",
            ));
        }
        (true, true) => {
            return Err(artifact_error(
                "live-QEMU replay artifact carries a resolved-effect trace for an inert fault plan",
            ));
        }
        (true, false) | (false, true) => {}
    }
    let model_bytes = required_single_component_payload(
        artifact,
        MODEL_REPRODUCTION_ARTIFACT_MEDIA_TYPE,
        "model reproduction",
    )?;
    let model = crucible::ReproductionArtifact::from_compact_binary(model_bytes)
        .map_err(|error| artifact_error(format!("decode live-QEMU replay model: {error}")))?;
    if model.scenario_def().id() != scenario.id() {
        return Err(CliError::Identity(format!(
            "live-QEMU model scenario {} did not match artifact scenario {}",
            model.scenario_def().id().to_hex(),
            scenario.id().to_hex()
        )));
    }
    let terminal_configuration = crucible::Configuration {
        def: scenario.scenario_def(),
        schedule: model.schedule().clone(),
    };
    if format_content_hash_ref(terminal_configuration.id()) != contract.terminal_configuration {
        return Err(CliError::Identity(format!(
            "live-QEMU contract terminal configuration {} did not match model configuration {}",
            contract.terminal_configuration,
            format_content_hash_ref(terminal_configuration.id())
        )));
    }
    let backend_plan = plan_backend_selection(cli)?.ok_or_else(|| {
        backend_error("live-QEMU artifact replay requires a resolved local backend")
    })?;
    if backend_plan.target != BackendExecutionTarget::Local {
        return Err(backend_error(
            "live-QEMU artifact replay does not support a remote daemon",
        ));
    }
    let backend = backend_plan.resolved_backend.as_ref().ok_or_else(|| {
        backend_error("live-QEMU artifact replay requires a resolved local QEMU backend")
    })?;
    if !matches!(backend, ResolvedLocalBackend::Qemu { .. }) {
        return Err(backend_error(
            "v3 reproduction artifacts replay only through the packaged QEMU backend",
        ));
    }
    let terminal_node_count = scenario.world().vm_nodes().len();
    let scenario_nodes = scenario
        .world()
        .vm_nodes()
        .iter()
        .map(|node| node.id.name.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let (_run_plan, report) = run_live_qemu_artifact_replay(
        backend,
        scenario,
        model.schedule(),
        &contract,
        resolved_effect_trace,
    )?;
    let replay_events = canonical_verify_log_stream_bytes(&[], &report.streamed_event_frames);
    let replay_samples = match contract.fingerprint_scope {
        LiveQemuFingerprintScope::FullExecution => run_fingerprint_samples(&report),
        LiveQemuFingerprintScope::TerminalAllNodes => {
            let expected_samples = artifact.fingerprints.len();
            if expected_samples != terminal_node_count {
                return Err(artifact_error(format!(
                    "terminal fingerprint scope contains {expected_samples} samples for {terminal_node_count} VM nodes"
                )));
            }
            let artifact_nodes = artifact
                .fingerprints
                .iter()
                .map(|sample| sample.node.clone())
                .collect::<std::collections::BTreeSet<_>>();
            if artifact_nodes != scenario_nodes {
                return Err(artifact_error(format!(
                    "terminal fingerprint scope nodes {artifact_nodes:?} did not match scenario VM nodes {scenario_nodes:?}"
                )));
            }
            let mut samples = run_fingerprint_samples(&report);
            if samples.len() < expected_samples {
                return Err(CliError::ReplayCheck(format!(
                    "live QEMU replay produced {} fingerprint samples, expected a terminal all-node snapshot of {expected_samples}",
                    samples.len()
                )));
            }
            let mut terminal = samples.split_off(samples.len() - expected_samples);
            let terminal_nodes = terminal
                .iter()
                .map(|sample| sample.node.clone())
                .collect::<std::collections::BTreeSet<_>>();
            if terminal_nodes != scenario_nodes {
                return Err(CliError::ReplayCheck(format!(
                    "live QEMU replay terminal fingerprint nodes {terminal_nodes:?} did not match scenario VM nodes {scenario_nodes:?}"
                )));
            }
            for (index, sample) in terminal.iter_mut().enumerate() {
                sample.index = index as u64;
            }
            terminal
        }
    };
    let replay_fingerprints = verify_fingerprint_stream_bytes(&replay_samples);
    validate_live_qemu_terminal(&contract, model.schedule(), &report)?;
    if replay_events != expected_events {
        return Err(CliError::ReplayCheck(format!(
            "live QEMU event stream diverged at byte {} (expected {} bytes, replayed {})",
            bisect_first_different_byte(expected_events, &replay_events),
            expected_events.len(),
            replay_events.len()
        )));
    }
    if replay_fingerprints != expected_fingerprints {
        return Err(CliError::ReplayCheck(format!(
            "live QEMU fingerprint stream diverged at byte {} (expected {} bytes, replayed {})",
            bisect_first_different_byte(expected_fingerprints, &replay_fingerprints),
            expected_fingerprints.len(),
            replay_fingerprints.len()
        )));
    }
    if matches!(
        contract.producer.as_str(),
        "run" | "verify" | "fuzz" | "fork"
    ) {
        let actual_controls = report
            .acknowledged_commands
            .iter()
            .map(|command| session_command_name(*command))
            .collect::<Vec<_>>();
        let expected_controls = contract
            .controls
            .iter()
            .map(|control| control.command.as_str())
            .collect::<Vec<_>>();
        if actual_controls != expected_controls {
            return Err(CliError::ReplayCheck(format!(
                "live QEMU control sequence diverged: expected {expected_controls:?}, got {actual_controls:?}"
            )));
        }
    }
    Ok(ReplayLiveQemuProof {
        producer: contract.producer,
        terminal_status: contract.terminal_status,
        terminal_outcome: contract.terminal_outcome,
        terminal_configuration: contract.terminal_configuration,
        event_stream_digest: content_address_bytes(expected_events),
        fingerprint_stream_digest: content_address_bytes(expected_fingerprints),
        controls: contract.controls.len(),
    })
}

fn required_single_component_payload<'a>(
    artifact: &'a CliReproductionArtifact,
    media_type: &str,
    label: &str,
) -> Result<&'a [u8], CliError> {
    let components = artifact
        .components
        .iter()
        .filter(|component| component.media_type == media_type)
        .collect::<Vec<_>>();
    if components.len() != 1 {
        return Err(artifact_error(format!(
            "v3 replay requires exactly one {label} component, found {}",
            components.len()
        )));
    }
    resolved_component_payload(artifact, components[0])
}

fn optional_single_component_payload<'a>(
    artifact: &'a CliReproductionArtifact,
    media_type: &str,
    label: &str,
) -> Result<Option<&'a [u8]>, CliError> {
    let components = artifact
        .components
        .iter()
        .filter(|component| component.media_type == media_type)
        .collect::<Vec<_>>();
    match components.as_slice() {
        [] => Ok(None),
        [component] => resolved_component_payload(artifact, component).map(Some),
        _ => Err(artifact_error(format!(
            "v3 replay accepts at most one {label} component, found {}",
            components.len()
        ))),
    }
}

fn validate_live_qemu_terminal(
    contract: &LiveQemuReplayContract,
    expected_schedule: &crucible::Schedule,
    report: &RunWorkflowReport,
) -> Result<(), CliError> {
    let actual_configuration = report
        .terminal_configuration
        .as_ref()
        .map(|configuration| format_content_hash_ref(configuration.id()))
        .ok_or_else(|| artifact_error("live QEMU replay omitted its terminal configuration"))?;
    let actual_outcome = terminal_outcome_label(report.outcome);
    if report.status.label() != contract.terminal_status
        || actual_outcome != contract.terminal_outcome
        || actual_configuration != contract.terminal_configuration
        || report.final_frontier_ticks != contract.final_frontier_ticks
        || report.final_quanta != contract.final_quanta
        || report.budget_timed_out != contract.budget_timed_out
    {
        let actual_schedule = report
            .terminal_configuration
            .as_ref()
            .map(|configuration| &configuration.schedule);
        let first_different_decision = actual_schedule.and_then(|actual| {
            expected_schedule
                .decisions()
                .iter()
                .zip(actual.decisions())
                .position(|(expected, actual)| expected != actual)
                .or_else(|| {
                    (expected_schedule.len() != actual.len())
                        .then_some(expected_schedule.len().min(actual.len()))
                })
        });
        let expected_decision = first_different_decision
            .and_then(|index| expected_schedule.decisions().get(index))
            .map_or_else(|| String::from("none"), |decision| format!("{decision:?}"));
        let actual_decision = first_different_decision
            .and_then(|index| actual_schedule.and_then(|schedule| schedule.decisions().get(index)))
            .map_or_else(|| String::from("none"), |decision| format!("{decision:?}"));
        return Err(CliError::ReplayCheck(format!(
            "live QEMU terminal tuple diverged: expected status={} outcome={} configuration={} frontier={} quanta={} budget_timeout={} decisions={}, got status={} outcome={} configuration={} frontier={} quanta={} budget_timeout={} decisions={} first_different_decision={} expected_decision={} actual_decision={}",
            contract.terminal_status,
            contract.terminal_outcome,
            contract.terminal_configuration,
            contract.final_frontier_ticks,
            contract.final_quanta,
            contract.budget_timed_out,
            expected_schedule.len(),
            report.status.label(),
            actual_outcome,
            actual_configuration,
            report.final_frontier_ticks,
            report.final_quanta,
            report.budget_timed_out,
            actual_schedule.map_or(0, crucible::Schedule::len),
            first_different_decision
                .map_or_else(|| String::from("none"), |index| index.to_string()),
            expected_decision,
            actual_decision
        )));
    }
    Ok(())
}

pub(super) fn replay_embedded_model_artifact(
    artifact: &CliReproductionArtifact,
) -> Result<Option<ReplayReductionProof>, CliError> {
    let model_components = artifact
        .components
        .iter()
        .filter(|component| component.media_type == MODEL_REPRODUCTION_ARTIFACT_MEDIA_TYPE)
        .collect::<Vec<_>>();
    let state_components = artifact
        .components
        .iter()
        .filter(|component| component.media_type == MODEL_REPLAY_STATE_MEDIA_TYPE)
        .collect::<Vec<_>>();
    if model_components.is_empty() && state_components.is_empty() {
        return Ok(None);
    }
    if model_components.len() != 1 || state_components.len() != 1 {
        return Err(artifact_error(
            "replay requires exactly one paired model reproduction and replay-state component",
        ));
    }
    let model_bytes = resolved_component_payload(artifact, model_components[0])?;
    let expected_state_bytes = resolved_component_payload(artifact, state_components[0])?;
    let model =
        crucible::ReproductionArtifact::from_compact_binary(model_bytes).map_err(|error| {
            artifact_error(format!(
                "model reproduction component could not be decoded: {error}"
            ))
        })?;
    if seed_to_u64(model.seed()) != artifact.seed {
        return Err(CliError::Identity(format!(
            "model reproduction seed {} does not match CLI artifact seed {}",
            seed_to_u64(model.seed()),
            artifact.seed
        )));
    }
    validate_embedded_scenario_identity("model reproduction", &model.scenario_def(), artifact)?;
    let replay = model.replay().map_err(|error| {
        CliError::ReplayCheck(format!(
            "pure reduce(ScenarioDef, Schedule) replay failed: {error}"
        ))
    })?;
    let expected_state = std::str::from_utf8(expected_state_bytes).map_err(|error| {
        artifact_error(format!(
            "model replay-state component is not UTF-8: {error}"
        ))
    })?;
    if expected_state != format_content_hash_ref(replay.state) {
        return Err(CliError::ReplayCheck(format!(
            "pure reduction reached {}, expected {}",
            format_content_hash_ref(replay.state),
            expected_state
        )));
    }
    let reconstructed_decisions = model.schedule().len();
    Ok(Some(ReplayReductionProof {
        artifact: replay.artifact,
        scenario: replay.scenario,
        schedule: replay.schedule,
        state: replay.state,
        reconstructed_decisions,
    }))
}

fn resolved_component_payload<'a>(
    artifact: &'a CliReproductionArtifact,
    component: &CliComponent,
) -> Result<&'a [u8], CliError> {
    artifact
        .payloads
        .iter()
        .find(|payload| payload.digest == component.digest)
        .map(|payload| payload.bytes.as_slice())
        .ok_or_else(|| {
            artifact_error(format!(
                "component `{}` payload `{}` is unresolved",
                component.name, component.digest
            ))
        })
}

fn validate_embedded_scenario_identity(
    context: &str,
    scenario: &crucible::ScenarioDef,
    artifact: &CliReproductionArtifact,
) -> Result<(), CliError> {
    if artifact.scenario.media_type == "application/vnd.crucible.scenario.compact-binary" {
        let bytes = resolved_component_payload(artifact, &artifact.scenario)?;
        let captured = crucible::ScenarioDefForm::from_compact_binary(bytes).map_err(|error| {
            artifact_error(format!(
                "{context} CLI scenario component could not be decoded: {error}"
            ))
        })?;
        if captured.id() != scenario.id() {
            return Err(CliError::Identity(format!(
                "{context} scenario {} did not match artifact scenario {}",
                scenario.id().to_hex(),
                captured.id().to_hex()
            )));
        }
        return Ok(());
    }

    let scenario_digest = content_address_bytes(&scenario_identity_bytes(scenario));
    if scenario_digest != artifact.scenario.digest {
        return Err(CliError::Identity(format!(
            "{context} scenario {} did not match artifact scenario {}",
            scenario_digest, artifact.scenario.digest
        )));
    }
    Ok(())
}

pub(super) fn replay_to_savepoint(
    cli: &Cli,
    target: &str,
    artifact: &CliReproductionArtifact,
) -> Result<ReplayToSavepointReport, CliError> {
    let savepoint = resolve_savepoint_ref("replay --to", Some(target))?;
    let evidence = match savepoint_evidence("replay --to", &savepoint, &default_run_store_root(cli))
    {
        Ok(evidence) => evidence,
        Err(store_error) => {
            embedded_terminal_savepoint_evidence(artifact, &savepoint)?.ok_or(store_error)?
        }
    };
    validate_embedded_scenario_identity("replay --to savepoint", &evidence.scenario, artifact)
        .map_err(|error| match error {
            CliError::Identity(message) => CliError::Artifact(message),
            other => other,
        })?;
    let schedule_prefix = prove_replay_schedule_prefix(artifact, &evidence.schedule)?;
    let oracle = validate_checkpoint_with_replay_oracle(
        "replay --to",
        &evidence.scenario,
        &evidence.configuration,
        &evidence.checkpoint,
        evidence.checkpoint.virtual_time,
    )?;
    let materialization =
        materialize_replay_to_savepoint(&evidence.scenario, &evidence.configuration, &oracle)?;
    Ok(ReplayToSavepointReport {
        target_label: savepoint.label(),
        checkpoint: evidence.checkpoint.id,
        frontier_ticks: evidence.checkpoint.virtual_time.ticks,
        schedule_prefix,
        oracle,
        materialization,
    })
}

fn embedded_terminal_savepoint_evidence(
    artifact: &CliReproductionArtifact,
    savepoint: &ResumeSavepointRef,
) -> Result<Option<ResumeHandleEvidence>, CliError> {
    let ResumeSavepointRef::CheckpointHash(target) = savepoint else {
        return Ok(None);
    };
    let contract_bytes = required_single_component_payload(
        artifact,
        LIVE_QEMU_REPLAY_CONTRACT_MEDIA_TYPE,
        "live QEMU replay contract",
    )?;
    let contract = LiveQemuReplayContract::decode(contract_bytes)?;
    if contract.terminal_configuration != format_content_hash_ref(*target) {
        return Ok(None);
    }
    let model_bytes = required_single_component_payload(
        artifact,
        MODEL_REPRODUCTION_ARTIFACT_MEDIA_TYPE,
        "model reproduction",
    )?;
    let model = crucible::ReproductionArtifact::from_compact_binary(model_bytes)
        .map_err(|error| artifact_error(format!("decode replay --to embedded model: {error}")))?;
    let scenario_form = model.scenario_form().clone();
    let scenario = model.scenario_def();
    let schedule = model.schedule().clone();
    let configuration = crucible::Configuration {
        def: scenario.clone(),
        schedule: schedule.clone(),
    };
    if configuration.id() != *target {
        return Err(CliError::Identity(format!(
            "replay --to embedded terminal configuration {} did not match target {}",
            format_content_hash_ref(configuration.id()),
            format_content_hash_ref(*target)
        )));
    }
    let frontier = validate_resume_handle_frontier(&schedule, contract.final_frontier_ticks)?;
    let checkpoint = checkpoint_for_resume_configuration(&configuration, frontier)?;
    Ok(Some(ResumeHandleEvidence {
        scenario_form,
        scenario,
        schedule,
        configuration,
        checkpoint,
    }))
}

pub(super) fn prove_replay_schedule_prefix(
    artifact: &CliReproductionArtifact,
    target_schedule: &Schedule,
) -> Result<ReplaySchedulePrefixProof, CliError> {
    let target_decisions = target_schedule.len();
    if target_decisions > artifact.decisions.len() {
        return Err(CliError::ReplayCheck(format!(
            "replay --to savepoint frontier has {target_decisions} decisions, but artifact encodes only {} decisions",
            artifact.decisions.len()
        )));
    }

    let expected = replay_schedule_prefix_decisions(target_schedule);
    for (index, expected_decision) in expected.iter().enumerate() {
        let actual = &artifact.decisions[index];
        let actual_payload_summary = decision_payload_summary(artifact, actual)?;
        if !replay_schedule_prefix_decision_matches(
            actual,
            &actual_payload_summary,
            expected_decision,
        ) {
            return Err(CliError::ReplayCheck(format!(
                "replay --to schedule-prefix mismatch at decision {index}: expected sequence={} virtual_time={} kind={} payload={}, got sequence={} virtual_time={} kind={} payload={}",
                expected_decision.sequence,
                expected_decision.virtual_time_ticks,
                expected_decision.kind,
                expected_decision.payload_digest,
                actual.sequence,
                actual.virtual_time_ticks,
                actual.kind,
                actual.payload_digest
            )));
        }
    }

    Ok(ReplaySchedulePrefixProof {
        target_decisions,
        artifact_decisions: artifact.decisions.len(),
        matched_decisions: expected.len(),
        typed_prefix_digest: typed_schedule_prefix_digest(&expected),
        artifact_prefix_digest: schedule_digest(&artifact.decisions[..target_decisions]),
    })
}

pub(super) fn replay_schedule_prefix_decisions(
    schedule: &Schedule,
) -> Vec<ReplaySchedulePrefixDecisionProof> {
    schedule
        .decisions()
        .iter()
        .enumerate()
        .map(|(index, decision)| {
            let payload_summary = format!("{decision:?}");
            ReplaySchedulePrefixDecisionProof {
                sequence: index as u64,
                virtual_time_ticks: index as u64 + 1,
                kind: engine_decision_kind(decision).to_string(),
                payload_digest: content_address_bytes(payload_summary.as_bytes()),
                payload_summary,
            }
        })
        .collect()
}

pub(super) fn replay_schedule_prefix_decision_matches(
    actual: &CliDecision,
    actual_payload_summary: &str,
    expected: &ReplaySchedulePrefixDecisionProof,
) -> bool {
    actual.sequence == expected.sequence
        && actual.virtual_time_ticks == expected.virtual_time_ticks
        && replay_schedule_prefix_kind_matches(&actual.kind, &expected.kind)
        && actual.payload_digest == expected.payload_digest
        && actual_payload_summary == expected.payload_summary
}

pub(super) fn replay_schedule_prefix_kind_matches(actual: &str, expected: &str) -> bool {
    actual == expected || actual == expected.replace('-', "_")
}

pub(super) fn typed_schedule_prefix_digest(
    decisions: &[ReplaySchedulePrefixDecisionProof],
) -> String {
    let mut material = String::new();
    artifact_line(
        &mut material,
        &["schema", REPLAY_SCHEDULE_PREFIX_PROOF_SCHEMA],
    );
    for decision in decisions {
        artifact_line(
            &mut material,
            &[
                "typed-decision",
                &decision.sequence.to_string(),
                &decision.virtual_time_ticks.to_string(),
                &decision.kind,
                &decision.payload_digest,
            ],
        );
    }
    content_address_bytes(material.as_bytes())
}

pub(super) fn replay_to_savepoint_status_line(target: &ReplayToSavepointReport) -> String {
    format!(
        "crucible: replay --to {} status=target-validated schedule_prefix=typed materialization={} unified_operation={} checkpoint={} frontier_ticks={} target_decisions={} artifact_decisions={} matched_decisions={} typed_prefix_digest={} artifact_prefix_digest={} materialized_configuration={} materialized_schedule={} materialized_checkpoint={} runtime_state={} reduced_state={} single_vm_fingerprint={} graph={} replay_fat={} replay_thin={} oracle={} store_objects={}",
        target.target_label,
        target.materialization.materialization,
        target.materialization.operation,
        format_content_hash_ref(target.checkpoint),
        target.frontier_ticks,
        target.schedule_prefix.target_decisions,
        target.schedule_prefix.artifact_decisions,
        target.schedule_prefix.matched_decisions,
        target.schedule_prefix.typed_prefix_digest,
        target.schedule_prefix.artifact_prefix_digest,
        format_content_hash_ref(target.materialization.configuration),
        format_content_hash_ref(target.materialization.schedule),
        format_content_hash_ref(target.materialization.checkpoint),
        format_content_hash_ref(target.materialization.runtime_state),
        format_content_hash_ref(target.materialization.reduced_state),
        format_content_hash_ref(target.materialization.single_vm_fingerprint),
        format_content_hash_ref(target.materialization.graph),
        format_content_hash_ref(target.materialization.replay_fat_checkpoint),
        format_content_hash_ref(target.materialization.replay_thin_checkpoint),
        target.oracle.status_label(),
        target.oracle.store_objects
    )
}

pub(super) fn materialize_replay_to_savepoint(
    scenario: &crucible::ScenarioDef,
    configuration: &crucible::Configuration,
    oracle: &SavepointOracleProof,
) -> Result<ReplayToSavepointMaterializationProof, CliError> {
    let mut graph = save_validation_graph(scenario)?;
    let replay = crucible::ReplayOracleCheck {
        configuration: oracle.configuration,
        fat_checkpoint: oracle.fat_checkpoint,
        thin_checkpoint: oracle.thin_checkpoint,
    };
    let report = graph
        .validate_unified_operation(&crucible::UnifiedGraphOperationEvidence::Replay {
            configuration: configuration.clone(),
            replay,
        })
        .map_err(|error| {
            CliError::Identity(format!(
                "replay --to materialized temporal-graph replay failed: {error}"
            ))
        })?;
    if report.operation != crucible::UnifiedGraphOperationKind::Replay {
        return Err(CliError::Identity(format!(
            "replay --to materialized unexpected unified operation {:?}",
            report.operation
        )));
    }
    Ok(ReplayToSavepointMaterializationProof::from_report(report))
}

pub(super) fn replay_bisect_artifacts(
    cli: &Cli,
    other_path: &Path,
    artifact: &CliReproductionArtifact,
    artifact_bytes: &[u8],
) -> Result<ReplayBisectionReport, CliError> {
    let other_bytes = fs::read(other_path)?;
    let other_artifact = validate_replayable_reproduction_artifact(cli, &other_bytes)?;
    if replay_uses_live_qemu(cli)? {
        replay_embedded_model_artifact(&other_artifact)?.ok_or_else(|| {
            artifact_error("replay --bisect requires a model proof in the other v3 artifact")
        })?;
        replay_live_qemu_evidence(cli, &other_artifact)?;
    }
    verify_compare_artifact_inputs_match("replay --bisect", artifact, &other_artifact)?;
    let mode = VerifyMode::CompareArtifacts {
        left: PathBuf::from("replay-left"),
        right: other_path.to_path_buf(),
    };
    let reductions = verify_reduction_plans(2, false, &mode);
    let mut reductions = reductions.into_iter();
    let left_reduction = reductions
        .next()
        .ok_or_else(|| backend_error("replay bisection omitted left reduction"))?;
    let right_reduction = reductions
        .next()
        .ok_or_else(|| backend_error("replay bisection omitted right reduction"))?;
    let witnesses = vec![
        verify_witness_from_artifact(left_reduction, artifact.clone(), artifact_bytes.to_vec())?,
        verify_witness_from_artifact(right_reduction, other_artifact, other_bytes.clone())?,
    ];
    let divergence = compare_verify_witnesses(&witnesses);
    Ok(ReplayBisectionReport {
        other_path: other_path.to_path_buf(),
        other_digest: content_address_bytes(&other_bytes),
        divergence,
    })
}

pub(super) fn replay_bisect_error(
    left_path: &Path,
    bisect: &ReplayBisectionReport,
    divergence: &VerifyDivergenceReport,
) -> CliError {
    CliError::ReplayCheck(format!(
        "replay --bisect divergence between `{}` and `{}`: mismatch={}, first_decision={}, first_fingerprint_sample={}, first_virtual_time={}, first_virtual_time_node={}, first_instruction={}, first_instruction_node={}, first_diff_byte={}, left_state={}, right_state={}",
        left_path.display(),
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
        divergence
            .first_different_virtual_time
            .map(|ticks| ticks.to_string())
            .unwrap_or_else(|| String::from("unknown")),
        divergence
            .first_different_virtual_time_node
            .as_deref()
            .unwrap_or("unknown"),
        divergence
            .first_different_instruction
            .map(|instruction| instruction.to_string())
            .unwrap_or_else(|| String::from("unknown")),
        divergence
            .first_different_instruction_node
            .as_deref()
            .unwrap_or("unknown"),
        divergence.first_different_byte,
        divergence.left_state_digest,
        divergence.right_state_digest
    ))
}

pub(super) fn replay_check_mismatch_error(
    check: &ReplayCheckReport,
    mismatch: &ReplayCheckMismatchReport,
) -> CliError {
    CliError::ReplayCheck(format!(
        "replay --check mismatch for `{}`: expected {}, replayed {}, first_diff_byte={}, original_len={}, replayed_len={}",
        check.path.display(),
        mismatch.original_digest,
        mismatch.replayed_digest,
        mismatch.first_diff_byte,
        mismatch.original_len,
        mismatch.replayed_len
    ))
}

#[path = "replay/artifact.rs"]
mod artifact;

pub(super) use artifact::*;
