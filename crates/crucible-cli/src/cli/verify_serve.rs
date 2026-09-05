//! Verification comparison, canonical witnesses, and daemon service entrypoints.

use super::*;

use std::os::unix::net::UnixStream;

#[path = "artifact_capture.rs"]
mod artifact_capture;
pub(super) use artifact_capture::*;

#[path = "verify_serve/packaged_executor.rs"]
mod packaged_executor;
use packaged_executor::prepare_cli_packaged_executor;

use super::cli_campaign_import::apply_campaign_import_manifests;
use super::cli_campaign_store::load_campaign_repository_store;

const DEFAULT_CAMPAIGN_MAINTENANCE_WRITE_BACK_TRANSFERS: u32 = 64;
const DEFAULT_CAMPAIGN_MAINTENANCE_S3_NODES: u16 = 8;
const DEFAULT_CAMPAIGN_MAINTENANCE_S3_UPLOADS: u16 = 128;

pub(super) async fn run_control_client_verify_workflow_async<C>(
    client: &C,
    verify_plan: &VerifyInvocationPlan,
    backend: Option<&ResolvedLocalBackend>,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
) -> Result<VerifyWorkflowReport, CliError>
where
    C: ControlClient + Sync,
{
    let Some(scenario) = verify_plan.scenario() else {
        return Err(backend_error(
            "verify compare mode must not enter the live control-client workflow",
        ));
    };
    let mut witnesses = Vec::with_capacity(verify_plan.reductions.len());
    let request_seed = ergonomics_plan
        .map(|plan| crucible::Seed::from_u64(plan.seed.value))
        .unwrap_or_else(|| scenario.scenario_def().seed());
    let seeded_scenario = reseed_run_scenario_ref(scenario, request_seed)?;
    for reduction in &verify_plan.reductions {
        let run_plan =
            verify_run_invocation_plan(seeded_scenario.clone(), request_seed, reduction.clone());
        let report = run_control_client_workflow_async(client, &run_plan, &[]).await?;
        // Determinism applies to failing and budget-terminated executions too.
        // A completed reduction remains comparable; transport/backend errors
        // have already returned above without producing a report.
        witnesses.push(verify_witness_from_run_report(
            reduction.clone(),
            &run_plan,
            &report,
            backend,
            ergonomics_plan,
        )?);
    }
    let divergence = compare_verify_witnesses(&witnesses);
    Ok(VerifyWorkflowReport {
        witnesses,
        divergence,
    })
}

pub(super) fn verify_compare_artifacts(
    verify_plan: &VerifyInvocationPlan,
) -> Result<VerifyWorkflowReport, CliError> {
    let VerifyMode::CompareArtifacts { left, right } = &verify_plan.mode else {
        return Err(backend_error(
            "verify run mode must use the live control-client workflow",
        ));
    };
    let left_bytes = fs::read(left)?;
    let right_bytes = fs::read(right)?;
    let left_artifact = decode_reproduction_artifact(&left_bytes)?;
    let right_artifact = decode_reproduction_artifact(&right_bytes)?;
    verify_replay_identity(&right_artifact.identity, &left_artifact.identity)?;
    verify_compare_artifact_inputs_match("verify --compare", &left_artifact, &right_artifact)?;
    let witnesses = vec![
        verify_witness_from_artifact(verify_plan.reductions[0].clone(), left_artifact, left_bytes)?,
        verify_witness_from_artifact(
            verify_plan.reductions[1].clone(),
            right_artifact,
            right_bytes,
        )?,
    ];
    let divergence = compare_verify_witnesses(&witnesses);
    Ok(VerifyWorkflowReport {
        witnesses,
        divergence,
    })
}

pub(super) fn verify_compare_artifact_inputs_match(
    command: &str,
    left: &CliReproductionArtifact,
    right: &CliReproductionArtifact,
) -> Result<(), CliError> {
    if left.seed != right.seed {
        return Err(artifact_error(format!(
            "{command} requires matching seeds, got left={} right={}",
            left.seed, right.seed
        )));
    }
    if left.scenario.digest != right.scenario.digest {
        return Err(artifact_error(format!(
            "{command} requires matching scenario digests, got left={} right={}",
            left.scenario.digest, right.scenario.digest
        )));
    }
    if left.scenario.media_type != right.scenario.media_type {
        return Err(artifact_error(format!(
            "{command} requires matching scenario media types, got left={} right={}",
            left.scenario.media_type, right.scenario.media_type
        )));
    }
    Ok(())
}

pub(super) fn verify_run_invocation_plan(
    scenario: RunScenarioRef,
    request_seed: crucible::Seed,
    reduction: VerifyReductionPlan,
) -> RunInvocationPlan {
    RunInvocationPlan {
        scenario,
        save_store_root: None,
        request_seed: Some(request_seed),
        terminal_condition: RunTerminalCondition::Quiescence,
        max_virtual_time: None,
        max_virtual_time_ticks: None,
        max_quanta: None,
        execution_mode: RunExecutionMode::ToCompletion,
        save_policy: RunSavePolicy::Never,
        watch_streams_live_status: false,
        startup_commands: vec![
            SessionCommandKind::Start,
            SessionCommandKind::StepQuantum,
            SessionCommandKind::Continue,
        ],
        initial_control_commands: vec![SessionCommandKind::Query, SessionCommandKind::Query],
        accepted_interactive_commands: Vec::new(),
        observer_profile: reduction.host_profile,
        collect_execution_fingerprints: true,
        bounded_ack_quanta: RUN_INTERACTIVE_ACK_QUANTA_BOUND,
        outcome_exit_codes: vec![
            (
                BackendCommandStatus::Passed,
                CliError::Outcome(BackendCommandStatus::Passed).exit_code(),
            ),
            (
                BackendCommandStatus::Failed,
                CliError::Outcome(BackendCommandStatus::Failed).exit_code(),
            ),
            (
                BackendCommandStatus::Timeout,
                CliError::Outcome(BackendCommandStatus::Timeout).exit_code(),
            ),
            (
                BackendCommandStatus::Crashed,
                CliError::Outcome(BackendCommandStatus::Crashed).exit_code(),
            ),
        ],
        invalid_scenario_exit_code: CliError::InvalidScenario(String::new()).exit_code(),
    }
}

pub(super) fn verify_witness_from_run_report(
    reduction: VerifyReductionPlan,
    run_plan: &RunInvocationPlan,
    report: &RunWorkflowReport,
    backend: Option<&ResolvedLocalBackend>,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
) -> Result<VerifyRunWitness, CliError> {
    let canonical_log = canonical_run_log_entries(run_plan, report);
    let canonical_log_bytes =
        canonical_verify_log_stream_bytes(&canonical_log, &report.streamed_event_frames);
    let fingerprint_samples = verify_fingerprint_samples(report)?;
    let fingerprint_stream = verify_fingerprint_stream_bytes(&fingerprint_samples);
    let request_seed = run_plan
        .request_seed
        .unwrap_or_else(|| run_plan.scenario.scenario_def().seed());
    let seed = ergonomics_plan
        .map(|plan| plan.seed.value)
        .unwrap_or_else(|| seed_to_u64(request_seed));
    let state_dump = verify_state_dump(run_plan, report);
    let artifact = backend
        .map(|backend| {
            if !matches!(backend, ResolvedLocalBackend::Qemu { .. }) {
                return verify_reproduction_artifact_bytes(
                    seed,
                    Some(backend),
                    run_plan.scenario.scenario_def(),
                    &canonical_log,
                    &fingerprint_samples,
                );
            }
            let scenario = run_plan.scenario.scenario_form();
            let terminal = report.terminal_configuration.as_ref().ok_or_else(|| {
                artifact_error("verify artifact capture requires a terminal configuration")
            })?;
            let model = crucible::ReproductionArtifact::capture(scenario, &terminal.schedule)
                .map_err(|error| {
                    artifact_error(format!("verify model reproduction capture failed: {error}"))
                })?;
            let replay = model.replay().map_err(|error| {
                artifact_error(format!("verify model reproduction replay failed: {error}"))
            })?;
            let live = live_qemu_artifact_evidence_from_run(
                LiveQemuArtifactRecipe {
                    producer: "verify",
                    terminal_condition: run_plan.terminal_condition,
                    max_virtual_time_ticks: run_plan.max_virtual_time_ticks,
                    max_quanta: run_plan.max_quanta,
                    coverage: false,
                    execution_mode: run_plan.execution_mode,
                    startup_commands: &run_plan.startup_commands,
                    initial_control_commands: &run_plan.initial_control_commands,
                    branch: LiveQemuReplayBranch::None,
                },
                scenario,
                report,
            )?;
            let mut payloads = model_reproduction_artifact_payloads(&model, replay.state);
            payloads.extend(live_qemu_artifact_payloads(&live));
            let scenario_bytes = scenario.to_compact_binary();
            reproduction_artifact_bytes_with_scenario_payload(
                seed,
                Some(backend),
                ReproductionScenarioPayload {
                    name: "verify-scenario.crucible-scenario",
                    media_type: "application/vnd.crucible.scenario.compact-binary",
                    bytes: &scenario_bytes,
                },
                &canonical_log,
                &fingerprint_samples,
                &payloads,
            )
        })
        .transpose()?;
    Ok(VerifyRunWitness {
        reduction,
        canonical_log,
        canonical_log_bytes,
        fingerprint_samples,
        fingerprint_stream,
        state_dump,
        artifact,
    })
}

pub(super) fn verify_witness_from_artifact(
    reduction: VerifyReductionPlan,
    artifact: CliReproductionArtifact,
    bytes: Vec<u8>,
) -> Result<VerifyRunWitness, CliError> {
    let canonical_log = canonical_log_entries_from_artifact(&artifact)?;
    let canonical_log_bytes = canonical_log_entry_bytes(&canonical_log);
    let fingerprint_samples = artifact_fingerprint_samples(&artifact);
    let fingerprint_stream = verify_fingerprint_stream_bytes(&fingerprint_samples);
    let state_dump = artifact_state_dump(&artifact);
    Ok(VerifyRunWitness {
        reduction,
        canonical_log,
        canonical_log_bytes,
        fingerprint_samples,
        fingerprint_stream,
        state_dump,
        artifact: Some(bytes),
    })
}

pub(super) fn canonical_run_log_entries(
    run_plan: &RunInvocationPlan,
    report: &RunWorkflowReport,
) -> Vec<CanonicalLogEntry> {
    let mut outcome = BackendCommandOutcome {
        subcommand: CliSubcommand::Run,
        status: BackendCommandStatus::Passed,
        exit_code: 0,
        stdout: Vec::new(),
        stderr: Vec::new(),
        canonical_log: Vec::new(),
        canonical_log_digest: content_address_bytes(b"empty"),
        artifact_digest: content_address_bytes(b"empty"),
        terminal_savepoint: None,
        savepoint_oracle: None,
        save_boundary_evidence: None,
        reproduction_artifact: None,
        side_reproduction_artifacts: Vec::new(),
    };
    append_local_double_run_entries(&mut outcome, run_plan, report);
    outcome.canonical_log
}

pub(super) fn canonical_log_entry_bytes(entries: &[CanonicalLogEntry]) -> Vec<u8> {
    jsonl_for_canonical_log_entries(entries).into_bytes()
}

pub(super) fn canonical_verify_log_stream_bytes(
    entries: &[CanonicalLogEntry],
    event_frames: &[Vec<u8>],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"crucible.verify.canonical-log-stream.v1\n");
    bytes.extend_from_slice(&canonical_log_entry_bytes(entries));
    bytes.extend_from_slice(b"\ncrucible.verify.api-event-frames.v1\n");
    for frame in event_frames {
        bytes.extend_from_slice(frame);
        if !frame.ends_with(b"\n") {
            bytes.push(b'\n');
        }
    }
    bytes
}

pub(super) fn canonical_streaming_event_frame_bytes(
    frame: &crucible_api::StreamingEventFrame,
) -> Vec<u8> {
    let mut output = String::from("crucible.rpc/event-frame\n");
    push_canonical_wire_line(&mut output, "generation", &frame.generation.to_string());
    push_canonical_wire_line(
        &mut output,
        "cursor",
        &frame.cursor.next_sequence.to_string(),
    );
    push_canonical_wire_line(
        &mut output,
        "next-cursor",
        &frame.next_cursor.next_sequence.to_string(),
    );
    push_canonical_wire_line(&mut output, "sequence", &frame.event.sequence.to_string());
    push_canonical_wire_line(
        &mut output,
        "virtual-time-ticks",
        &frame.event.at.virtual_time_ticks.to_string(),
    );
    push_canonical_wire_line(
        &mut output,
        "icount-retired",
        &frame.event.at.icount_retired.to_string(),
    );
    push_canonical_wire_line(
        &mut output,
        "icount-node",
        &optional_string_canonical_wire(frame.event.at.icount_node.as_deref()),
    );
    push_canonical_wire_line(
        &mut output,
        "source",
        &event_source_canonical_wire(&frame.event.source),
    );
    push_canonical_wire_line(
        &mut output,
        "level",
        event_level_canonical_wire(frame.event.level),
    );
    push_canonical_wire_line(
        &mut output,
        "observational",
        if frame.event.observational {
            "true"
        } else {
            "false"
        },
    );
    push_canonical_wire_line(&mut output, "kind", &frame.event.payload.kind);
    for (name, value) in &frame.event.payload.attributes {
        push_canonical_wire_line(
            &mut output,
            "attribute",
            &format!(
                "{}|{}",
                hex_bytes(name.as_bytes()),
                attribute_canonical_wire(value)
            ),
        );
    }
    output.into_bytes()
}

pub(super) fn optional_string_canonical_wire(value: Option<&str>) -> String {
    value
        .map(|value| hex_bytes(value.as_bytes()))
        .unwrap_or_else(|| String::from("none"))
}

pub(super) fn event_source_canonical_wire(source: &crucible_api::OpenSetEventSource) -> String {
    match source {
        crucible_api::OpenSetEventSource::Scenario { event } => {
            format!("scenario|{}", hex_bytes(event.as_bytes()))
        }
        crucible_api::OpenSetEventSource::Engine => String::from("engine"),
        crucible_api::OpenSetEventSource::Node { node } => {
            format!("node|{}", hex_bytes(node.as_bytes()))
        }
        crucible_api::OpenSetEventSource::Guest { node } => {
            format!("guest|{}", hex_bytes(node.as_bytes()))
        }
        crucible_api::OpenSetEventSource::Command { command_id } => {
            format!("command|{command_id}")
        }
    }
}

pub(super) fn event_level_canonical_wire(level: crucible::EventLevel) -> &'static str {
    match level {
        crucible::EventLevel::Trace => "trace",
        crucible::EventLevel::Debug => "debug",
        crucible::EventLevel::Info => "info",
        crucible::EventLevel::Warn => "warn",
        crucible::EventLevel::Error => "error",
    }
}

pub(super) fn attribute_canonical_wire(value: &crucible_api::OpenSetAttributeValue) -> String {
    match value {
        crucible_api::OpenSetAttributeValue::Bool(value) => {
            format!("bool|{}", if *value { "true" } else { "false" })
        }
        crucible_api::OpenSetAttributeValue::Int(value) => format!("int|{value}"),
        crucible_api::OpenSetAttributeValue::Uint(value) => format!("uint|{value}"),
        crucible_api::OpenSetAttributeValue::Uint128(value) => format!("uint128|{value}"),
        crucible_api::OpenSetAttributeValue::Float64Bits(value) => {
            format!("float64bits|{value}")
        }
        crucible_api::OpenSetAttributeValue::String(value) => {
            format!("string|{}", hex_bytes(value.as_bytes()))
        }
        crucible_api::OpenSetAttributeValue::Bytes(value) => format!("bytes|{}", hex_bytes(value)),
    }
}

pub(super) fn push_canonical_wire_line(output: &mut String, key: &str, value: &str) {
    output.push_str(key);
    output.push('=');
    output.push_str(value);
    output.push('\n');
}

pub(super) fn verify_fingerprint_samples(
    report: &RunWorkflowReport,
) -> Result<Vec<VerifyFingerprintSample>, CliError> {
    let samples = run_fingerprint_samples(report);
    if samples.is_empty() {
        return Err(backend_error(
            "verify did not collect any backend execution fingerprint samples",
        ));
    }
    Ok(samples)
}

pub(super) fn run_fingerprint_samples(report: &RunWorkflowReport) -> Vec<VerifyFingerprintSample> {
    let mut samples = Vec::new();
    for (index, sample) in report.execution_fingerprints.iter().enumerate() {
        let index = u64::try_from(index).unwrap_or(u64::MAX);
        samples.push(VerifyFingerprintSample {
            index,
            instruction: sample.at.ticks,
            node: sample.node.name.clone(),
            digest: format!(
                "{}{}",
                CONTENT_ADDRESS_PREFIX,
                sample.fingerprint.hash.to_hex()
            ),
        });
    }
    samples
}

pub(super) fn verify_fingerprint_stream_bytes(samples: &[VerifyFingerprintSample]) -> Vec<u8> {
    let mut text = String::from("crucible.verify.execution-fingerprint-stream.v1\n");
    for sample in samples {
        artifact_line(
            &mut text,
            &[
                "sample",
                &sample.index.to_string(),
                &sample.instruction.to_string(),
                &sample.node,
                &sample.digest,
            ],
        );
    }
    text.into_bytes()
}

pub(super) fn verify_state_dump(
    run_plan: &RunInvocationPlan,
    report: &RunWorkflowReport,
) -> String {
    let seed = run_plan
        .request_seed
        .unwrap_or_else(|| run_plan.scenario.scenario_def().seed());
    format!(
        "scenario={} seed={} final_state={} outcome={} frontier_ticks={} quanta={} savepoint={} events={} frames={}",
        run_plan.scenario.scenario_id().to_hex(),
        seed.to_hex(),
        report.final_state,
        terminal_outcome_label(report.outcome),
        report.final_frontier_ticks,
        report.final_quanta,
        report
            .terminal_savepoint
            .map(format_content_hash_ref)
            .unwrap_or_else(|| String::from("none")),
        report.streamed_events.len(),
        report.streamed_event_frames.len()
    )
}

pub(super) fn canonical_log_entries_from_artifact(
    artifact: &CliReproductionArtifact,
) -> Result<Vec<CanonicalLogEntry>, CliError> {
    if artifact.decisions.is_empty() {
        return Err(artifact_error(
            "verify comparison artifact contains no canonical decisions",
        ));
    }
    artifact
        .decisions
        .iter()
        .map(|decision| {
            Ok(CanonicalLogEntry {
                sequence: decision.sequence,
                virtual_time_ticks: decision.virtual_time_ticks,
                node: decision.node.clone(),
                kind: decision.kind.clone(),
                summary: decision_payload_summary(artifact, decision)?,
            })
        })
        .collect()
}

pub(super) fn decision_payload_summary(
    artifact: &CliReproductionArtifact,
    decision: &CliDecision,
) -> Result<String, CliError> {
    let payload = artifact
        .payloads
        .iter()
        .find(|payload| payload.digest == decision.payload_digest)
        .ok_or_else(|| {
            artifact_error(format!(
                "decision payload `{}` is missing from artifact payloads",
                decision.payload_digest
            ))
        })?;
    String::from_utf8(payload.bytes.clone()).map_err(|error| {
        artifact_error(format!(
            "decision payload `{}` is not UTF-8: {error}",
            decision.payload_digest
        ))
    })
}

pub(super) fn artifact_fingerprint_samples(
    artifact: &CliReproductionArtifact,
) -> Vec<VerifyFingerprintSample> {
    artifact
        .fingerprints
        .iter()
        .map(|fingerprint| VerifyFingerprintSample {
            index: fingerprint.index,
            instruction: fingerprint.instruction,
            node: fingerprint.node.clone(),
            digest: fingerprint.digest.clone(),
        })
        .collect()
}

pub(super) fn artifact_state_dump(artifact: &CliReproductionArtifact) -> String {
    format!(
        "scenario={} seed={} decisions={} fingerprints={} schedule={}",
        artifact.scenario.digest,
        artifact.seed,
        artifact.decisions.len(),
        artifact.fingerprints.len(),
        artifact.schedule_digest
    )
}

pub(super) fn compare_verify_witnesses(
    witnesses: &[VerifyRunWitness],
) -> Option<VerifyDivergenceReport> {
    for left_index in 0..witnesses.len() {
        for right_index in left_index + 1..witnesses.len() {
            let left = &witnesses[left_index];
            let right = &witnesses[right_index];
            let canonical_log_differs = left.canonical_log_bytes != right.canonical_log_bytes;
            let fingerprint_differs = left.fingerprint_stream != right.fingerprint_stream;
            if canonical_log_differs || fingerprint_differs {
                let mismatch = match (canonical_log_differs, fingerprint_differs) {
                    (true, true) => VerifyMismatchKind::CanonicalLogAndFingerprintStream,
                    (true, false) => VerifyMismatchKind::CanonicalLog,
                    (false, true) => VerifyMismatchKind::FingerprintStream,
                    (false, false) => unreachable!("guarded by difference check"),
                };
                return Some(localize_verify_divergence(
                    left_index,
                    right_index,
                    mismatch,
                    left,
                    right,
                ));
            }
        }
    }
    None
}

pub(super) fn localize_verify_divergence(
    left_index: usize,
    right_index: usize,
    mismatch: VerifyMismatchKind,
    left: &VerifyRunWitness,
    right: &VerifyRunWitness,
) -> VerifyDivergenceReport {
    let first_different_decision =
        first_different_canonical_entry(&left.canonical_log, &right.canonical_log);
    let first_different_sample =
        first_different_fingerprint_sample(&left.fingerprint_samples, &right.fingerprint_samples);
    let entry = first_different_decision.and_then(|index| {
        left.canonical_log
            .get(index)
            .or_else(|| right.canonical_log.get(index))
    });
    let sample = first_different_sample.and_then(|index| {
        left.fingerprint_samples
            .get(index)
            .or_else(|| right.fingerprint_samples.get(index))
    });
    let first_different_byte = bisect_first_different_byte(
        bytes_for_mismatch(mismatch, left),
        bytes_for_mismatch(mismatch, right),
    );
    VerifyDivergenceReport {
        left: left_index,
        right: right_index,
        mismatch,
        first_different_decision,
        first_different_fingerprint_sample: first_different_sample,
        first_different_virtual_time: entry.map(|entry| entry.virtual_time_ticks),
        first_different_virtual_time_node: entry.map(|entry| entry.node.clone()),
        first_different_instruction: sample.map(|sample| sample.instruction),
        first_different_instruction_node: sample.map(|sample| sample.node.clone()),
        first_different_byte,
        left_state_digest: verify_witness_state_digest(left),
        right_state_digest: verify_witness_state_digest(right),
        left_state_dump: left.state_dump.clone(),
        right_state_dump: right.state_dump.clone(),
    }
}

pub(super) fn verify_witness_state_digest(witness: &VerifyRunWitness) -> String {
    if let Some(artifact) = witness.artifact.as_ref() {
        return content_address_bytes(artifact);
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&witness.canonical_log_bytes);
    bytes.extend_from_slice(&witness.fingerprint_stream);
    bytes.extend_from_slice(witness.state_dump.as_bytes());
    content_address_bytes(&bytes)
}

pub(super) fn bytes_for_mismatch(
    mismatch: VerifyMismatchKind,
    witness: &VerifyRunWitness,
) -> &[u8] {
    match mismatch {
        VerifyMismatchKind::CanonicalLog | VerifyMismatchKind::CanonicalLogAndFingerprintStream => {
            &witness.canonical_log_bytes
        }
        VerifyMismatchKind::FingerprintStream => &witness.fingerprint_stream,
    }
}

pub(super) fn first_different_canonical_entry(
    left: &[CanonicalLogEntry],
    right: &[CanonicalLogEntry],
) -> Option<usize> {
    for (index, (left_entry, right_entry)) in left.iter().zip(right.iter()).enumerate() {
        if json_for_canonical_log_entry(left_entry) != json_for_canonical_log_entry(right_entry) {
            return Some(index);
        }
    }
    (left.len() != right.len()).then_some(left.len().min(right.len()))
}

pub(super) fn first_different_fingerprint_sample(
    left: &[VerifyFingerprintSample],
    right: &[VerifyFingerprintSample],
) -> Option<usize> {
    for (index, (left_sample, right_sample)) in left.iter().zip(right.iter()).enumerate() {
        if left_sample != right_sample {
            return Some(index);
        }
    }
    (left.len() != right.len()).then_some(left.len().min(right.len()))
}

pub(super) fn bisect_first_different_byte(left: &[u8], right: &[u8]) -> usize {
    let max_len = left.len().max(right.len());
    if max_len == 0 || left == right {
        return 0;
    }
    let mut low = 0usize;
    let mut high = max_len;
    while low < high {
        let midpoint = low + ((high - low) / 2);
        if prefixes_match(left, right, midpoint.saturating_add(1)) {
            low = midpoint.saturating_add(1);
        } else {
            high = midpoint;
        }
    }
    low
}

pub(super) fn prefixes_match(left: &[u8], right: &[u8], len: usize) -> bool {
    left.get(..len) == right.get(..len)
}

/// Encodes a self-contained reproduction artifact around an explicit scenario payload.
///
/// # Errors
///
/// Returns [`CliError`] when component identity, decision payload, or canonical
/// artifact encoding validation fails.
pub(crate) fn reproduction_artifact_bytes_with_scenario_payload(
    seed: u64,
    backend: Option<&ResolvedLocalBackend>,
    scenario: ReproductionScenarioPayload<'_>,
    canonical_log: &[CanonicalLogEntry],
    fingerprint_samples: &[VerifyFingerprintSample],
    extra_payloads: &[ReproductionArtifactComponentPayload],
) -> Result<Vec<u8>, CliError> {
    let scenario_digest = content_address_bytes(scenario.bytes);
    let store_uri = format!("cas:{scenario_digest}");
    let identity = expected_replay_identity_for_backend(backend);
    let decisions = cli_decisions_from_canonical_log(canonical_log);
    let extra_components = extra_payloads
        .iter()
        .map(|payload| CliComponent {
            kind: payload.kind.clone(),
            name: payload.name.clone(),
            digest: content_address_bytes(&payload.bytes),
            store_uri: format!("cas:{}", content_address_bytes(&payload.bytes)),
            media_type: payload.media_type.clone(),
            size_bytes: payload.bytes.len() as u64,
        })
        .collect::<Vec<_>>();
    let schedule_digest = schedule_digest(&decisions);
    let mut text = String::new();

    artifact_line(&mut text, &["schema", REPRODUCTION_ARTIFACT_SCHEMA]);
    artifact_line(&mut text, &["seed", &seed.to_string()]);
    artifact_line(
        &mut text,
        &[
            "identity",
            &identity.engine_version,
            &identity.engine_abi,
            &identity.artifact_abi,
            &identity.qemu_build_id,
            &identity.qemu_patch_series_hash,
            &identity.shmem_abi_version,
            &identity.guest_host_protocol_version,
            &identity.rpc_abi_version,
            &identity.rpc_abi_build,
            &identity.plugin_abi,
        ],
    );
    artifact_line(
        &mut text,
        &[
            "scenario",
            "scenario_def",
            scenario.name,
            &scenario_digest,
            &store_uri,
            scenario.media_type,
            &scenario.bytes.len().to_string(),
        ],
    );
    artifact_line(
        &mut text,
        &[
            "component",
            "scenario_def",
            scenario.name,
            &scenario_digest,
            &store_uri,
            scenario.media_type,
            &scenario.bytes.len().to_string(),
        ],
    );
    for component in &extra_components {
        artifact_component_line(&mut text, "component", component);
    }
    for decision in &decisions {
        let payload = canonical_log
            .get(decision.sequence as usize)
            .ok_or_else(|| artifact_error("decision payload is missing from canonical log"))?
            .summary
            .as_bytes();
        artifact_line(
            &mut text,
            &[
                "component",
                "other",
                &format!("decision-{}-payload", decision.sequence),
                &decision.payload_digest,
                &format!("cas:{}", decision.payload_digest),
                RECORDED_DECISION_PAYLOAD_MEDIA_TYPE,
                &payload.len().to_string(),
            ],
        );
    }
    artifact_line(
        &mut text,
        &["payload", &scenario_digest, &hex_bytes(scenario.bytes)],
    );
    for (component, payload) in extra_components.iter().zip(extra_payloads) {
        artifact_line(
            &mut text,
            &["payload", &component.digest, &hex_bytes(&payload.bytes)],
        );
    }
    for decision in &decisions {
        let payload = canonical_log
            .get(decision.sequence as usize)
            .ok_or_else(|| artifact_error("decision payload is missing from canonical log"))?
            .summary
            .as_bytes();
        artifact_line(
            &mut text,
            &["payload", &decision.payload_digest, &hex_bytes(payload)],
        );
    }
    artifact_line(
        &mut text,
        &["schedule", &schedule_digest, &decisions.len().to_string()],
    );
    for decision in &decisions {
        artifact_line(
            &mut text,
            &[
                "decision",
                &decision.sequence.to_string(),
                &decision.virtual_time_ticks.to_string(),
                &decision.node,
                &decision.kind,
                &decision.payload_digest,
            ],
        );
    }
    for sample in fingerprint_samples {
        artifact_line(
            &mut text,
            &[
                "fingerprint",
                &sample.index.to_string(),
                &sample.instruction.to_string(),
                &sample.node,
                &sample.digest,
            ],
        );
    }
    artifact_line(
        &mut text,
        &[
            "sampling",
            "every-fingerprint-sample",
            "final",
            "1",
            "execution-fingerprint-stream",
        ],
    );

    let bytes = text.into_bytes();
    let artifact = decode_reproduction_artifact(&bytes)?;
    verify_replay_identity(&artifact.identity, &identity)?;
    Ok(bytes)
}

pub(super) fn seed_to_u64(seed: crucible::Seed) -> u64 {
    let bytes = seed.bytes();
    let mut low = [0u8; 8];
    low.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(low)
}

pub(super) fn scenario_identity_bytes(scenario: &crucible::ScenarioDef) -> Vec<u8> {
    format!(
        "scenario_id={}\nseed={}\napp_random_draw_cap={}\n",
        scenario.id().to_hex(),
        scenario.seed().to_hex(),
        scenario.app_random_draw_cap()
    )
    .into_bytes()
}

#[cfg(any(test, feature = "test-double"))]
pub(super) async fn run_local_double_workflow_async(
    run_plan: &RunInvocationPlan,
    _ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    interactive_commands: &[SessionCommandKind],
) -> Result<RunWorkflowReport, CliError> {
    let control_plane = LifecycleControlPlane::new(
        "crucible-cli-double",
        Vec::new(),
        |_scenario: &crucible::ScenarioDef, _seed| QuiescentLifecycleLoop::new(),
    );
    let client = InProcessLifecycleClient::new(control_plane);
    run_control_client_workflow_async(&client, run_plan, interactive_commands).await
}

#[cfg(any(test, feature = "test-double"))]
pub(super) async fn run_local_double_workflow_stdin_async(
    run_plan: &RunInvocationPlan,
    _ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
) -> Result<RunWorkflowReport, CliError> {
    let control_plane = LifecycleControlPlane::new(
        "crucible-cli-double",
        Vec::new(),
        |_scenario: &crucible::ScenarioDef, _seed| QuiescentLifecycleLoop::new(),
    );
    let client = InProcessLifecycleClient::new(control_plane);
    run_control_client_workflow_stdin_async(&client, run_plan, false).await
}

pub(super) fn run_serve_invocation(cli: &Cli, args: &ServeArgs) -> Result<(), CliError> {
    if cli.daemon.is_some() {
        return Err(usage_error(
            "serve hosts the daemon and cannot itself use --daemon",
        ));
    }
    validate_serve_invocation(args)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| serve_error(format!("serve runtime error: {error}")))?;
    runtime.block_on(run_serve_invocation_until_shutdown(
        cli,
        args,
        serve_shutdown_signal(),
    ))
}

pub(super) async fn run_serve_invocation_until_shutdown<S>(
    cli: &Cli,
    args: &ServeArgs,
    shutdown: S,
) -> Result<(), CliError>
where
    S: Future<Output = Result<(), CliError>> + Send + 'static,
{
    let debug_authorization = debug_authorization_policy(args)?;
    let tls_acceptor = match (&args.tls_cert, &args.tls_key, &args.client_ca) {
        (Some(certificate), Some(private_key), Some(client_ca)) => Some(
            mutual_tls_acceptor_from_pem(certificate, private_key, client_ca)
                .map_err(|error| serve_error(format!("serve mutual-TLS error: {error}")))?,
        ),
        _ => None,
    };
    let mut production_config = if args.production_qemu {
        let backend = require_selftest_qemu_backend(cli)?;
        let mut config = production_qemu_lifecycle_config(&backend)?;
        if let Some(interval) = packaged_executor::production_rendezvous_interval(
            args.qemu_rendezvous_icount,
            args.campaign_packaged_executor.is_some(),
        ) {
            config = config.with_rendezvous_interval_icount(interval);
        }
        Some(config.with_debug_gdbstubs_for_all_nodes("127.0.0.1:0"))
    } else {
        None
    };
    let campaign_service = open_local_campaign_service(args, production_config.as_ref())?;
    let listener = tokio::net::TcpListener::bind(&args.listen)
        .await
        .map_err(|error| serve_error(format!("serve bind error: {error}")))?;
    let address = listener
        .local_addr()
        .map_err(|error| serve_error(format!("serve bind error: {error}")))?;
    if !cli.quiet {
        let mode = if args.read_only {
            "read-only"
        } else {
            "read-write"
        };
        let scheme = if tls_acceptor.is_some() {
            "https"
        } else {
            "http"
        };
        println!("crucible: serving API daemon at {scheme}://{address} mode={mode}");
        if let Some(service) = campaign_service.as_ref() {
            println!(
                "crucible: serving local campaign service at {}",
                service.socket_path().display()
            );
        }
    }
    let mode = if args.read_only {
        LifecycleServerMode::read_only()
    } else {
        LifecycleServerMode::read_write()
    };
    if args.production_qemu {
        let config = production_config
            .take()
            .ok_or_else(|| serve_error("production QEMU configuration disappeared"))?;
        let resume_config = config.clone();
        let mut control_plane = LifecycleControlPlane::new_with_fallible_source_factory(
            "crucible-cli-qemu-daemon",
            Vec::new(),
            move |scenario, source, _seed| {
                let source =
                    source.ok_or_else(|| crucible_api::LifecycleApiError::LoopFactory {
                        message: String::from(
                            "production QEMU daemon requires an inline scenario definition",
                        ),
                    })?;
                crucible_api::build_production_vm_lifecycle_loop(scenario, source, &config)
            },
        )
        .with_fat_checkpoint_resume_factory(move |scenario, source, _seed, checkpoint| {
            crucible_api::build_production_vm_lifecycle_loop_from_checkpoint(
                scenario,
                source,
                &resume_config,
                checkpoint,
            )
        });
        if let Some(max_sessions) = args.max_sessions {
            control_plane = control_plane.with_max_sessions(max_sessions);
        }
        return run_bound_daemon_services(
            listener,
            control_plane,
            mode,
            tls_acceptor,
            debug_authorization,
            shutdown,
            campaign_service,
        )
        .await;
    }
    let mut control_plane = LifecycleControlPlane::new(
        "crucible-cli-daemon",
        Vec::new(),
        |_scenario: &crucible::ScenarioDef, _seed| QuiescentLifecycleLoop::new(),
    );
    if let Some(max_sessions) = args.max_sessions {
        control_plane = control_plane.with_max_sessions(max_sessions);
    }
    run_bound_daemon_services(
        listener,
        control_plane,
        mode,
        tls_acceptor,
        debug_authorization,
        shutdown,
        campaign_service,
    )
    .await
}

pub(super) struct PreparedLocalCampaignService {
    service: crucible_daemon::CampaignLocalService,
    socket_path: PathBuf,
}

impl PreparedLocalCampaignService {
    fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

pub(super) fn open_local_campaign_service(
    args: &ServeArgs,
    production_qemu: Option<&crucible_api::ProductionVmLifecycleConfig>,
) -> Result<Option<PreparedLocalCampaignService>, CliError> {
    validate_campaign_runtime_attachments(args)?;
    let (Some(socket), Some(state), Some(policy)) = (
        args.campaign_socket.as_ref(),
        args.campaign_state.as_ref(),
        args.campaign_policy.as_ref(),
    ) else {
        return Ok(None);
    };
    let endpoint = crucible_daemon::CampaignLoopbackEndpointConfig::new(
        socket,
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
        args.campaign_socket_mode,
    )
    .map_err(|error| serve_error(format!("campaign endpoint configuration error: {error}")))?;
    let mut config = crucible_daemon::CampaignLocalServiceConfig::new(
        endpoint,
        state,
        policy,
        if args.read_only {
            crucible_daemon::CampaignLocalServiceMode::ReadOnly
        } else {
            crucible_daemon::CampaignLocalServiceMode::ReadWrite
        },
        crucible_daemon::CampaignLoopbackServerConfig::default(),
    )
    .map_err(|error| serve_error(format!("campaign service configuration error: {error}")))?;
    if let Some(path) = args.campaign_component_authority.as_ref() {
        config = config
            .with_component_authority_path(path)
            .map_err(|error| {
                serve_error(format!("campaign service configuration error: {error}"))
            })?;
    }
    let mut prepared = match args.campaign_store.as_deref() {
        Some(path) => config.prepare_with_store(load_campaign_repository_store(path)?),
        None => config.prepare(),
    }
    .map_err(|error| serve_error(format!("campaign service bootstrap error: {error}")))?;
    if let Some(maintenance) = campaign_store_maintenance_config(args)? {
        prepared = prepared
            .with_store_maintenance(maintenance)
            .map_err(|error| serve_error(format!("campaign maintenance error: {error}")))?;
    }
    let runtime_control_planner = if args.campaign_component_authority.is_some() && !args.read_only
    {
        Some(
            crucible_daemon::CanonicalPlannerProcessConfig::for_current_executable(
                Duration::from_secs(30),
            )
            .map_err(|error| {
                serve_error(format!("campaign planner configuration error: {error}"))
            })?,
        )
    } else {
        None
    };
    apply_campaign_import_manifests(&prepared, &args.campaign_import_manifest)?;
    let selected_campaigns = if args.campaign_runtime_all {
        prepared
            .discover_packaged_campaigns()
            .map_err(|error| serve_error(format!("campaign runtime discovery error: {error}")))?
    } else {
        args.campaign_runtime
            .iter()
            .map(|campaign| {
                crucible_campaign::CampaignName::new(campaign)
                    .map_err(|error| serve_error(format!("campaign runtime name error: {error}")))
            })
            .collect::<Result<std::collections::BTreeSet<_>, _>>()?
    };
    let packaged_executor = match args.campaign_packaged_executor.as_deref() {
        Some(deployment) => {
            let executor_socket = args.campaign_executor_socket.first().ok_or_else(|| {
                usage_error("--campaign-packaged-executor requires one executor socket")
            })?;
            Some(prepare_cli_packaged_executor(
                &prepared,
                args,
                selected_campaigns.clone(),
                executor_socket,
                deployment,
                production_qemu.ok_or_else(|| {
                    serve_error("--campaign-packaged-executor requires --production-qemu")
                })?,
            )?)
        }
        None => None,
    };
    let runtime_targets = if packaged_executor.is_some() {
        let executor_socket = args.campaign_executor_socket.first().ok_or_else(|| {
            usage_error("--campaign-packaged-executor requires one executor socket")
        })?;
        selected_campaigns
            .iter()
            .cloned()
            .map(|campaign| (campaign, executor_socket.as_path()))
            .collect::<Vec<_>>()
    } else {
        args.campaign_runtime
            .iter()
            .zip(&args.campaign_executor_socket)
            .map(|(campaign, executor_socket)| {
                crucible_campaign::CampaignName::new(campaign)
                    .map(|campaign| (campaign, executor_socket.as_path()))
                    .map_err(|error| serve_error(format!("campaign runtime name error: {error}")))
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    let mut runtimes = Vec::with_capacity(runtime_targets.len());
    for (index, (campaign, executor_socket)) in runtime_targets.into_iter().enumerate() {
        let stream = connect_campaign_executor(executor_socket)?;
        let planner = runtime_control_planner.clone().ok_or_else(|| {
            serve_error("campaign runtime attachment requires the planner control profile")
        })?;
        let runtime_config =
            crucible_daemon::CanonicalCampaignRuntimeConfig::canonical_defaults(campaign, planner)
                .map_err(|error| {
                    serve_error(format!("campaign runtime configuration error: {error}"))
                })?;
        runtimes.push(
            prepared
                .prepare_runtime(stream, &runtime_config)
                .map_err(|error| {
                    serve_error(format!(
                        "campaign runtime {index} attachment error: {error}"
                    ))
                })?,
        );
    }
    let prepared = match runtime_control_planner {
        Some(planner) => prepared
            .with_runtime_control(planner)
            .map_err(|error| serve_error(format!("campaign runtime control error: {error}")))?,
        None => prepared,
    };
    let service = if let Some(executor) = packaged_executor {
        prepared.bind_with_runtimes_and_executor(runtimes, executor)
    } else if runtimes.is_empty() {
        prepared.bind()
    } else {
        prepared.bind_with_runtimes(runtimes)
    }
    .map_err(|error| serve_error(format!("campaign service bind error: {error}")))?;
    Ok(Some(PreparedLocalCampaignService {
        service,
        socket_path: socket.clone(),
    }))
}

pub(super) fn connect_campaign_executor(path: &Path) -> Result<UnixStream, CliError> {
    let user_id = rustix::process::geteuid().as_raw();
    let group_id = rustix::process::getegid().as_raw();
    let endpoint = crucible_daemon::ExecutorLoopbackEndpointConfig::new(
        path.to_owned(),
        user_id,
        group_id,
        0o600,
    )
    .map_err(|error| serve_error(format!("campaign executor endpoint error: {error}")))?;
    endpoint
        .connect()
        .map_err(|error| serve_error(format!("campaign executor connection error: {error}")))
}

struct RunningLocalCampaignService {
    shutdown: crucible_daemon::CampaignLoopbackServerShutdown,
    thread: std::thread::JoinHandle<
        Result<
            crucible_daemon::CampaignLoopbackServerReport,
            crucible_daemon::CampaignLocalServiceError,
        >,
    >,
    done: tokio::sync::oneshot::Receiver<()>,
}

fn start_local_campaign_service(
    prepared: PreparedLocalCampaignService,
) -> Result<RunningLocalCampaignService, CliError> {
    let shutdown = prepared.service.shutdown_handle();
    let (done_sender, done) = tokio::sync::oneshot::channel();
    let thread = std::thread::Builder::new()
        .name(String::from("crucible-campaign-service"))
        .spawn(move || {
            let result = prepared.service.serve();
            let _ = done_sender.send(());
            result
        })
        .map_err(|error| serve_error(format!("campaign service thread error: {error}")))?;
    Ok(RunningLocalCampaignService {
        shutdown,
        thread,
        done,
    })
}

async fn run_bound_daemon_services<L, F, S>(
    listener: tokio::net::TcpListener,
    control_plane: LifecycleControlPlane<L, F>,
    mode: LifecycleServerMode,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    debug_authorization: DebugAuthorizationPolicy,
    shutdown: S,
    campaign: Option<PreparedLocalCampaignService>,
) -> Result<(), CliError>
where
    L: crucible::QuantumLoop + Send + 'static,
    F: Fn(
            &crucible::ScenarioDef,
            Option<&crucible::ScenarioDefForm>,
            crucible::Seed,
        ) -> Result<L, crucible_api::LifecycleApiError>
        + Send
        + Sync
        + 'static,
    S: Future<Output = Result<(), CliError>> + Send + 'static,
{
    let Some(campaign) = campaign else {
        return run_bound_lifecycle_server(
            listener,
            control_plane,
            mode,
            tls_acceptor,
            debug_authorization,
            shutdown,
        )
        .await;
    };
    let RunningLocalCampaignService {
        shutdown: campaign_shutdown,
        thread: campaign_thread,
        mut done,
    } = start_local_campaign_service(campaign)?;
    let wait_shutdown = campaign_shutdown.clone();
    let combined_shutdown = async move {
        // crucible-lint: allow unordered-select -- either daemon service ending stops the process.
        tokio::select! {
            result = shutdown => {
                wait_shutdown.shutdown();
                result
            }
            _ = &mut done => Err(serve_error("campaign service stopped unexpectedly")),
        }
    };
    let lifecycle_result = run_bound_lifecycle_server(
        listener,
        control_plane,
        mode,
        tls_acceptor,
        debug_authorization,
        combined_shutdown,
    )
    .await;
    campaign_shutdown.shutdown();
    let campaign_result = tokio::task::spawn_blocking(move || campaign_thread.join())
        .await
        .map_err(|error| serve_error(format!("campaign service join error: {error}")))?
        .map_err(|_| serve_error("campaign service thread panicked"))?
        .map_err(|error| serve_error(format!("campaign service error: {error}")));
    lifecycle_result.and(campaign_result.map(|_| ()))
}

async fn run_bound_lifecycle_server<L, F, S>(
    listener: tokio::net::TcpListener,
    control_plane: LifecycleControlPlane<L, F>,
    mode: LifecycleServerMode,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    debug_authorization: DebugAuthorizationPolicy,
    shutdown: S,
) -> Result<(), CliError>
where
    L: crucible::QuantumLoop + Send + 'static,
    F: Fn(
            &crucible::ScenarioDef,
            Option<&crucible::ScenarioDefForm>,
            crucible::Seed,
        ) -> Result<L, crucible_api::LifecycleApiError>
        + Send
        + Sync
        + 'static,
    S: Future<Output = Result<(), CliError>> + Send + 'static,
{
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
    let server: Pin<Box<dyn Future<Output = Result<(), std::io::Error>> + Send>> =
        if let Some(tls_acceptor) = tls_acceptor {
            Box::pin(serve_lifecycle_http2_mtls_with_mode_until_shutdown(
                listener,
                control_plane,
                mode,
                tls_acceptor,
                debug_authorization,
                async move {
                    let _ = shutdown_receiver.await;
                },
            ))
        } else {
            Box::pin(serve_lifecycle_http2_with_debug_policy_until_shutdown(
                listener,
                control_plane,
                mode,
                debug_authorization,
                async move {
                    let _ = shutdown_receiver.await;
                },
            ))
        };
    tokio::pin!(server);
    tokio::pin!(shutdown);
    // crucible-lint: allow unordered-select -- serve shutdown races only with host daemon drainage.
    tokio::select! {
        result = &mut server => {
            result.map_err(|error| serve_error(format!("serve backend error: {error}")))?;
            Ok(())
        }
        signal = &mut shutdown => {
            signal?;
            let _ = shutdown_sender.send(());
            if let Ok(result) = tokio::time::timeout(SERVE_SHUTDOWN_DRAIN_TIMEOUT, server).await {
                result.map_err(|error| serve_error(format!("serve backend error: {error}")))?;
            }
            Ok(())
        }
    }
}

#[cfg(unix)]
pub(super) async fn serve_shutdown_signal() -> Result<(), CliError> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut interrupt = signal(SignalKind::interrupt())
        .map_err(|error| serve_error(format!("serve shutdown signal error: {error}")))?;
    let mut terminate = signal(SignalKind::terminate())
        .map_err(|error| serve_error(format!("serve shutdown signal error: {error}")))?;
    // crucible-lint: allow unordered-select -- signal choice is host shutdown policy, not replay state.
    tokio::select! {
        _ = interrupt.recv() => Ok(()),
        _ = terminate.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
pub(super) async fn serve_shutdown_signal() -> Result<(), CliError> {
    tokio::signal::ctrl_c()
        .await
        .map_err(|error| serve_error(format!("serve shutdown signal error: {error}")))
}

pub(super) fn validate_serve_invocation(args: &ServeArgs) -> Result<(), CliError> {
    if args.max_sessions == Some(0) {
        return Err(usage_error("--max-sessions must be greater than zero"));
    }
    if args.qemu_rendezvous_icount == Some(0) {
        return Err(usage_error(
            "--qemu-rendezvous-icount must be greater than zero",
        ));
    }
    if args.qemu_rendezvous_icount.is_some() && !args.production_qemu {
        return Err(usage_error(
            "--qemu-rendezvous-icount requires --production-qemu",
        ));
    }
    let campaign_fields = [
        args.campaign_socket.is_some(),
        args.campaign_state.is_some(),
        args.campaign_policy.is_some(),
    ];
    let campaign_field_count = campaign_fields
        .into_iter()
        .filter(|present| *present)
        .count();
    if campaign_field_count != 0 && campaign_field_count != campaign_fields.len() {
        return Err(usage_error(
            "--campaign-socket, --campaign-state, and --campaign-policy must be provided together",
        ));
    }
    let _ = campaign_store_maintenance_config(args)?;
    validate_campaign_runtime_attachments(args)?;
    if args.campaign_packaged_executor.is_some() && !args.production_qemu {
        return Err(usage_error(
            "--campaign-packaged-executor requires --production-qemu",
        ));
    }
    if args.campaign_socket.is_some()
        && (args.campaign_socket_mode == 0
            || args.campaign_socket_mode & !0o777 != 0
            || args.campaign_socket_mode & 0o222 == 0)
    {
        return Err(usage_error(
            "--campaign-socket-mode must grant write access and contain only permission bits",
        ));
    }
    let tls_file_count = [
        args.tls_cert.is_some(),
        args.tls_key.is_some(),
        args.client_ca.is_some(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if tls_file_count != 0 && tls_file_count != 3 {
        return Err(usage_error(
            "--tls-cert, --tls-key, and --client-ca must be supplied together",
        ));
    }
    if tls_file_count == 3 && args.trusted_unauthenticated_bind {
        return Err(usage_error(
            "--trusted-unauthenticated-bind cannot be combined with mutual TLS",
        ));
    }
    if tls_file_count == 0 && !args.trusted_unauthenticated_bind {
        return Err(usage_error(
            "serve requires mutual TLS or explicit --trusted-unauthenticated-bind",
        ));
    }
    let _ = debug_authorization_policy(args)?;
    Ok(())
}

fn campaign_store_maintenance_config(
    args: &ServeArgs,
) -> Result<Option<crucible_daemon::CampaignStoreMaintenanceConfig>, CliError> {
    let bounds_present = args.campaign_maintenance_write_back_transfers.is_some()
        || args.campaign_maintenance_s3_nodes.is_some()
        || args.campaign_maintenance_s3_uploads.is_some();
    let Some(interval_ms) = args.campaign_maintenance_interval_ms else {
        if bounds_present {
            return Err(usage_error(
                "campaign maintenance bounds require --campaign-maintenance-interval-ms",
            ));
        }
        return Ok(None);
    };
    if args.campaign_store.is_none() {
        return Err(usage_error(
            "--campaign-maintenance-interval-ms requires --campaign-store",
        ));
    }
    if args.read_only {
        return Err(usage_error(
            "--campaign-maintenance-interval-ms conflicts with --read-only",
        ));
    }
    crucible_daemon::CampaignStoreMaintenanceConfig::new(
        Duration::from_millis(interval_ms),
        args.campaign_maintenance_write_back_transfers
            .unwrap_or(DEFAULT_CAMPAIGN_MAINTENANCE_WRITE_BACK_TRANSFERS),
        args.campaign_maintenance_s3_nodes
            .unwrap_or(DEFAULT_CAMPAIGN_MAINTENANCE_S3_NODES),
        args.campaign_maintenance_s3_uploads
            .unwrap_or(DEFAULT_CAMPAIGN_MAINTENANCE_S3_UPLOADS),
    )
    .map(Some)
    .map_err(|error| usage_error(error.to_string()))
}

fn validate_campaign_runtime_attachments(args: &ServeArgs) -> Result<(), CliError> {
    let packaged = args.campaign_packaged_executor.is_some();
    if packaged {
        if args.campaign_executor_socket.is_empty()
            || args
                .campaign_executor_socket
                .windows(2)
                .any(|pair| pair[0] != pair[1])
        {
            return Err(usage_error(
                "--campaign-packaged-executor requires one shared executor socket value",
            ));
        }
    } else if args.campaign_runtime.len() != args.campaign_executor_socket.len() {
        return Err(usage_error(
            "--campaign-runtime and --campaign-executor-socket must be repeated the same number of times",
        ));
    }
    if args.campaign_runtime.len() > crucible_daemon::MAX_ATTACHED_CANONICAL_CAMPAIGN_RUNTIMES {
        return Err(usage_error(format!(
            "--campaign-runtime exceeds the {}-runtime daemon ceiling",
            crucible_daemon::MAX_ATTACHED_CANONICAL_CAMPAIGN_RUNTIMES
        )));
    }
    if args.campaign_runtime.is_empty() && !args.campaign_runtime_all {
        if packaged {
            return Err(usage_error(
                "--campaign-packaged-executor requires --campaign-runtime or --campaign-runtime-all",
            ));
        }
        if !args.campaign_executor_socket.is_empty() {
            return Err(usage_error(
                "--campaign-executor-socket requires a campaign runtime",
            ));
        }
        return Ok(());
    }
    if args.campaign_socket.is_none() || args.campaign_component_authority.is_none() {
        return Err(usage_error(
            "--campaign-runtime requires the complete campaign profile and --campaign-component-authority",
        ));
    }
    if args.read_only {
        return Err(usage_error(
            "--campaign-runtime cannot be combined with --read-only",
        ));
    }

    let mut campaigns = std::collections::BTreeSet::new();
    for campaign in &args.campaign_runtime {
        let campaign = crucible_campaign::CampaignName::new(campaign)
            .map_err(|error| usage_error(format!("--campaign-runtime is invalid: {error}")))?;
        if !campaigns.insert(campaign) {
            return Err(usage_error(
                "--campaign-runtime cannot attach the same campaign twice",
            ));
        }
    }
    Ok(())
}

fn debug_authorization_policy(args: &ServeArgs) -> Result<DebugAuthorizationPolicy, CliError> {
    let mut policy = DebugAuthorizationPolicy::deny_all();
    if args.trusted_unauthenticated_bind {
        policy.grant_trusted_unauthenticated_role(DebugRole::new([
            DebugCapability::Observe,
            DebugCapability::Control,
            DebugCapability::Mutate,
            DebugCapability::Shell,
            DebugCapability::Admin,
        ]));
    }
    for mapping in &args.debug_role {
        let (fingerprint, capabilities) = mapping
            .split_once('=')
            .ok_or_else(|| usage_error("--debug-role must use sha256=capability,... syntax"))?;
        let mut parsed = Vec::new();
        for capability in capabilities.split(',') {
            parsed.push(match capability {
                "observe" => DebugCapability::Observe,
                "control" => DebugCapability::Control,
                "mutate" => DebugCapability::Mutate,
                "shell" => DebugCapability::Shell,
                "admin" => DebugCapability::Admin,
                _ => {
                    return Err(usage_error(format!(
                        "unknown debugger capability `{capability}`"
                    )));
                }
            });
        }
        if parsed.is_empty() {
            return Err(usage_error(
                "--debug-role must grant at least one capability",
            ));
        }
        policy
            .grant_certificate_role(fingerprint, DebugRole::new(parsed))
            .map_err(|error| usage_error(error.to_string()))?;
    }
    Ok(policy)
}

pub(super) async fn run_control_client_workflow_async<C>(
    client: &C,
    run_plan: &RunInvocationPlan,
    interactive_commands: &[SessionCommandKind],
) -> Result<RunWorkflowReport, CliError>
where
    C: ControlClient + Sync,
{
    run_control_client_workflow_with_interactive_driver(
        client,
        run_plan,
        InteractiveCommandDriver::Preparsed(interactive_commands),
        false,
        false,
    )
    .await
}

pub(super) async fn run_control_client_save_workflow_async<C>(
    client: &C,
    save_plan: &SaveInvocationPlan,
) -> Result<SaveWorkflowReport, CliError>
where
    C: ControlClient + Sync,
{
    let run_plan = &save_plan.run_plan;
    let seed = run_plan
        .request_seed
        .unwrap_or_else(|| run_plan.scenario.scenario_def().seed());
    let request =
        CreateSessionRequest::inline_form(run_plan.scenario.scenario_form().clone(), seed)
            .with_start_paused(true);
    let created = client
        .create_session(request)
        .await
        .map_err(save_control_client_error)?;
    let mut acknowledged_commands = Vec::new();
    let mut state_updates = Vec::new();
    let mut command_id = 1;

    let (boundary, breakpoint_firing) = match save_plan.at {
        SaveAtArg::Quiescence => {
            let predicate = crucible::Predicate::quiescent();
            let (boundary, breakpoint_id) = run_save_predicate_to_boundary(
                client,
                created.session,
                BreakpointSpec::suspend_once(predicate.clone()),
                &mut command_id,
                &mut acknowledged_commands,
                &mut state_updates,
                "paused quiescence save boundary",
                false,
            )
            .await?;
            let firings = query_save_breakpoint_firings(
                client,
                created.session,
                &mut command_id,
                &mut acknowledged_commands,
                &mut state_updates,
            )
            .await?;
            let firing = validate_save_breakpoint_firing(
                "quiescence",
                &predicate,
                breakpoint_id,
                &boundary,
                &firings,
            )?;
            (boundary, Some(firing))
        }
        SaveAtArg::VirtualTime => {
            let budget = run_plan.max_virtual_time_ticks.ok_or_else(|| {
                usage_error("save --at virtual-time requires --max-virtual-time <dur>")
            })?;
            let boundary = drive_save_to_virtual_time_boundary(
                client,
                created.session,
                budget,
                &mut command_id,
                &mut acknowledged_commands,
                &mut state_updates,
                "",
            )
            .await?;
            (boundary, None)
        }
        SaveAtArg::Property | SaveAtArg::Marker => {
            let (boundary, firing) = run_save_selector_to_boundary(
                client,
                created.session,
                save_plan,
                &mut command_id,
                &mut acknowledged_commands,
                &mut state_updates,
            )
            .await?;
            (boundary, Some(firing))
        }
    };

    let snapshot_response = send_save_workflow_command(
        client,
        created.session,
        &mut command_id,
        SessionCommand::query_snapshot(),
        &mut acknowledged_commands,
        &mut state_updates,
    )
    .await?;
    let snapshot = match snapshot_response.query_result {
        Some(QueryResult::Snapshot(snapshot)) => *snapshot,
        Some(other) => {
            return Err(save_backend_error(format!(
                "save boundary snapshot returned unexpected query payload: {other:?}"
            )));
        }
        None => {
            return Err(save_backend_error(
                "save boundary snapshot returned no query payload",
            ));
        }
    };
    let savepoint_response = send_save_workflow_command(
        client,
        created.session,
        &mut command_id,
        SessionCommand::CreateSavepoint {
            label: save_plan.label.clone(),
            reply: CommandReply::discard(),
        },
        &mut acknowledged_commands,
        &mut state_updates,
    )
    .await?;
    let savepoint = savepoint_response
        .savepoint_info
        .ok_or_else(|| save_backend_error("savepoint command returned no savepoint payload"))?;
    if savepoint.label != save_plan.label {
        return Err(CliError::Identity(format!(
            "savepoint label mismatch: expected `{}`, got `{}`",
            save_plan.label, savepoint.label
        )));
    }
    let configuration = snapshot.configuration.id();
    if savepoint.configuration != configuration {
        return Err(CliError::Identity(format!(
            "savepoint configuration {} did not match boundary snapshot {}",
            format_content_hash_ref(savepoint.configuration),
            format_content_hash_ref(configuration)
        )));
    }
    let oracle = validate_savepoint_checkpoint(
        save_plan,
        &snapshot.configuration,
        &savepoint.checkpoint,
        boundary.frontier,
    )?;
    send_save_workflow_command(
        client,
        created.session,
        &mut command_id,
        SessionCommand::Stop,
        &mut acknowledged_commands,
        &mut state_updates,
    )
    .await?;
    let stopped = client
        .list_sessions()
        .await
        .map_err(control_client_error)?
        .sessions
        .into_iter()
        .find(|summary| summary.session == created.session);
    if let Some(summary) = &stopped
        && let Some(terminal) = summary.terminal_savepoint
        && terminal != oracle.fat_checkpoint
    {
        return Err(CliError::Identity(format!(
            "save terminal checkpoint {} did not match validated checkpoint {}",
            format_content_hash_ref(terminal),
            format_content_hash_ref(oracle.fat_checkpoint)
        )));
    }

    let final_state = match save_plan.at {
        SaveAtArg::Quiescence => String::from("quiescent"),
        SaveAtArg::VirtualTime => String::from("virtual-time"),
        SaveAtArg::Property => String::from("property"),
        SaveAtArg::Marker => String::from("marker"),
    };
    if state_updates.last() != Some(&final_state) {
        state_updates.push(final_state.clone());
    }

    Ok(SaveWorkflowReport {
        run: RunWorkflowReport {
            status: BackendCommandStatus::Passed,
            created_state: format!("{:?}", created.state).to_ascii_lowercase(),
            final_state,
            outcome: Some(OutcomeKind::Passed),
            terminal_savepoint: Some(oracle.fat_checkpoint),
            terminal_configuration: Some(snapshot.configuration.clone()),
            final_frontier_ticks: stopped
                .as_ref()
                .map(|summary| summary.frontier.ticks)
                .unwrap_or(boundary.frontier.ticks)
                .max(boundary.frontier.ticks),
            final_quanta: stopped
                .as_ref()
                .map(|summary| summary.quanta_stepped)
                .unwrap_or(boundary.quanta_stepped)
                .max(boundary.quanta_stepped),
            budget_timed_out: false,
            state_updates,
            streamed_events: Vec::new(),
            streamed_event_frames: Vec::new(),
            coverage_feedback: crucible::EventLogCoverageFeedback::from_event_log(&[]),
            execution_fingerprints: Vec::new(),
            resolved_effect_trace: None,
            acknowledged_commands,
            watch_statuses: Vec::new(),
        },
        oracle,
        boundary_evidence: SaveBoundaryEvidence {
            at: save_plan.at,
            selector: save_plan.selector.clone(),
            frontier_ticks: boundary.frontier.ticks,
            quanta: boundary.quanta_stepped,
            breakpoint_firing,
        },
    })
}
