//! Encodes and compares deterministic CLI verification evidence.

use super::*;

pub(crate) fn canonical_run_log_entries(
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
        savepoint_replay_closure: None,
        reproduction_artifact: None,
        side_reproduction_artifacts: Vec::new(),
        host_scheduler_preemption: Vec::new(),
    };
    append_local_double_run_entries(&mut outcome, run_plan, report);
    outcome.canonical_log
}

pub(crate) fn canonical_log_entry_bytes(entries: &[CanonicalLogEntry]) -> Vec<u8> {
    jsonl_for_canonical_log_entries(entries).into_bytes()
}

pub(crate) fn canonical_verify_log_stream_bytes(
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

pub(crate) fn canonical_streaming_event_frame_bytes(
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
        "stamp-tick",
        &frame.event.at.stamp_tick.to_string(),
    );
    push_canonical_wire_line(
        &mut output,
        "stamp-retired",
        &frame
            .event
            .at
            .stamp_retired
            .map_or_else(|| String::from("none"), |retired| retired.to_string()),
    );
    push_canonical_wire_line(
        &mut output,
        "stamp-node",
        &optional_string_canonical_wire(frame.event.at.stamp_node.as_deref()),
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

pub(crate) fn optional_string_canonical_wire(value: Option<&str>) -> String {
    value
        .map(|value| hex_bytes(value.as_bytes()))
        .unwrap_or_else(|| String::from("none"))
}

pub(crate) fn event_source_canonical_wire(source: &crucible_api::OpenSetEventSource) -> String {
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

pub(crate) fn event_level_canonical_wire(level: crucible::EventLevel) -> &'static str {
    match level {
        crucible::EventLevel::Trace => "trace",
        crucible::EventLevel::Debug => "debug",
        crucible::EventLevel::Info => "info",
        crucible::EventLevel::Warn => "warn",
        crucible::EventLevel::Error => "error",
    }
}

pub(crate) fn attribute_canonical_wire(value: &crucible_api::OpenSetAttributeValue) -> String {
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

pub(crate) fn push_canonical_wire_line(output: &mut String, key: &str, value: &str) {
    output.push_str(key);
    output.push('=');
    output.push_str(value);
    output.push('\n');
}

pub(crate) fn verify_fingerprint_samples(
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

pub(crate) fn run_fingerprint_samples(report: &RunWorkflowReport) -> Vec<VerifyFingerprintSample> {
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

pub(crate) fn verify_fingerprint_stream_bytes(samples: &[VerifyFingerprintSample]) -> Vec<u8> {
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

pub(crate) fn verify_state_dump(
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

pub(crate) fn canonical_log_entries_from_artifact(
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

pub(crate) fn decision_payload_summary(
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

pub(crate) fn artifact_fingerprint_samples(
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

pub(crate) fn artifact_state_dump(artifact: &CliReproductionArtifact) -> String {
    format!(
        "scenario={} seed={} decisions={} fingerprints={} schedule={}",
        artifact.scenario.digest,
        artifact.seed,
        artifact.decisions.len(),
        artifact.fingerprints.len(),
        artifact.schedule_digest
    )
}

pub(crate) fn compare_verify_witnesses(
    witnesses: &[VerifyRunWitness],
) -> Option<VerifyDivergenceReport> {
    for left_index in 0..witnesses.len() {
        for right_index in left_index + 1..witnesses.len() {
            let left = &witnesses[left_index];
            let right = &witnesses[right_index];
            let canonical_log_differs = left.canonical_log_bytes != right.canonical_log_bytes;
            let fingerprint_differs = left.fingerprint_stream != right.fingerprint_stream;
            if let Some(mismatch) = verify_mismatch_kind(canonical_log_differs, fingerprint_differs)
            {
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

pub(crate) const fn verify_mismatch_kind(
    canonical_log_differs: bool,
    fingerprint_differs: bool,
) -> Option<VerifyMismatchKind> {
    match (canonical_log_differs, fingerprint_differs) {
        (true, true) => Some(VerifyMismatchKind::CanonicalLogAndFingerprintStream),
        (true, false) => Some(VerifyMismatchKind::CanonicalLog),
        (false, true) => Some(VerifyMismatchKind::FingerprintStream),
        (false, false) => None,
    }
}

pub(crate) fn localize_verify_divergence(
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

pub(crate) fn verify_witness_state_digest(witness: &VerifyRunWitness) -> String {
    if let Some(artifact) = witness.artifact.as_ref() {
        return content_address_bytes(artifact);
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&witness.canonical_log_bytes);
    bytes.extend_from_slice(&witness.fingerprint_stream);
    bytes.extend_from_slice(witness.state_dump.as_bytes());
    content_address_bytes(&bytes)
}

pub(crate) fn bytes_for_mismatch(
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

pub(crate) fn first_different_canonical_entry(
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

pub(crate) fn first_different_fingerprint_sample(
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

pub(crate) fn bisect_first_different_byte(left: &[u8], right: &[u8]) -> usize {
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

pub(crate) fn prefixes_match(left: &[u8], right: &[u8], len: usize) -> bool {
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
            &identity.qemu_atomic_patch_hash,
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

pub(crate) fn seed_to_u64(seed: crucible::Seed) -> u64 {
    let bytes = seed.bytes();
    let mut low = [0u8; 8];
    low.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(low)
}

pub(crate) fn scenario_identity_bytes(scenario: &crucible::ScenarioDef) -> Vec<u8> {
    format!(
        "scenario_id={}\nseed={}\napp_random_draw_cap={}\n",
        scenario.id().to_hex(),
        scenario.seed().to_hex(),
        scenario.app_random_draw_cap()
    )
    .into_bytes()
}
