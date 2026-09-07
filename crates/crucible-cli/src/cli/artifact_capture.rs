//! Failure and verification artifact capture from observed execution evidence.

use super::*;

/// Borrowed scenario component embedded in a reproduction artifact.
pub(crate) struct ReproductionScenarioPayload<'a> {
    /// Stable component name recorded in the artifact.
    pub(crate) name: &'a str,
    /// Media type describing the encoded scenario bytes.
    pub(crate) media_type: &'a str,
    /// Self-contained scenario payload.
    pub(crate) bytes: &'a [u8],
}

/// Exact producer evidence required to replay one v3 artifact through QEMU.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LiveQemuArtifactEvidence {
    /// Canonical execution recipe and terminal target.
    pub(crate) contract: LiveQemuReplayContract,
    /// Canonical producer event stream compared with the replay.
    pub(crate) event_stream: Vec<u8>,
    /// Canonical producer fingerprint stream compared with the replay.
    pub(crate) fingerprint_stream: Vec<u8>,
    /// Exact resolved-effect work items, including pass outcomes.
    pub(crate) resolved_effect_trace: Option<Vec<u8>>,
    /// Authenticated choice records required by a campaign-owned replay.
    pub(crate) campaign_replay_closure: Option<Vec<u8>>,
    /// Typed samples encoded into both the component and top-level artifact.
    pub(crate) fingerprint_samples: Vec<VerifyFingerprintSample>,
}

/// Exact producer recipe recorded beside observed live-QEMU evidence.
pub(crate) struct LiveQemuArtifactRecipe<'a> {
    /// Closed producer name that selects replay semantics.
    pub(crate) producer: &'a str,
    /// Terminal predicate used by the producer.
    pub(crate) terminal_condition: RunTerminalCondition,
    /// Optional virtual-time ceiling used by the producer.
    pub(crate) max_virtual_time_ticks: Option<u64>,
    /// Optional quantum ceiling used by the producer.
    pub(crate) max_quanta: Option<u64>,
    /// Whether the run collected coverage observations.
    pub(crate) coverage: bool,
    /// Batch or interactive producer execution mode.
    pub(crate) execution_mode: RunExecutionMode,
    /// Commands issued to start producer execution.
    pub(crate) startup_commands: &'a [SessionCommandKind],
    /// Commands issued immediately after startup.
    pub(crate) initial_control_commands: &'a [SessionCommandKind],
    /// Optional retained-prefix branch recipe.
    pub(crate) branch: LiveQemuReplayBranch,
}

/// Builds the required v3 live-QEMU components from one completed run.
pub(crate) fn live_qemu_artifact_evidence_from_run(
    recipe: LiveQemuArtifactRecipe<'_>,
    scenario: &crucible::ScenarioDefForm,
    report: &RunWorkflowReport,
) -> Result<LiveQemuArtifactEvidence, CliError> {
    if recipe.execution_mode == RunExecutionMode::Interactive {
        return Err(artifact_error(
            "live-QEMU reproduction artifacts do not yet support interactive control recipes",
        ));
    }
    let campaign_replay_closure = match (
        recipe.producer,
        report.execution_owner,
        report.campaign_replay_closure.as_ref(),
    ) {
        ("campaign-run", RunExecutionOwner::Campaign, Some(closure)) => Some(closure.clone()),
        ("campaign-run", _, _) => {
            return Err(artifact_error(
                "campaign-run artifact capture requires campaign-owned execution and its authenticated replay closure",
            ));
        }
        (_, RunExecutionOwner::Session, None) => None,
        (_, _, _) => {
            return Err(artifact_error(
                "session-owned artifact producers cannot carry a campaign replay closure",
            ));
        }
    };
    let terminal = report.terminal_configuration.as_ref().ok_or_else(|| {
        artifact_error("live-QEMU artifact capture requires a terminal configuration")
    })?;
    let all_fingerprint_samples = run_fingerprint_samples(report);
    let fingerprint_scope = if recipe.producer == "fork" {
        LiveQemuFingerprintScope::TerminalAllNodes
    } else {
        LiveQemuFingerprintScope::FullExecution
    };
    let fingerprint_samples = select_live_qemu_artifact_fingerprints(
        scenario.world().vm_nodes(),
        all_fingerprint_samples,
        fingerprint_scope,
    )?;
    if fingerprint_samples.is_empty() {
        return Err(artifact_error(
            "live-QEMU artifact capture requires execution fingerprint samples",
        ));
    }
    let mut network_choice_indices = replay_choice_indices(&terminal.schedule);
    let branch_start = match &recipe.branch {
        LiveQemuReplayBranch::None => 0,
        LiveQemuReplayBranch::Resume { base_decisions, .. }
        | LiveQemuReplayBranch::Reseed { base_decisions, .. }
        | LiveQemuReplayBranch::PrefixOverrides { base_decisions, .. } => *base_decisions,
    };
    network_choice_indices.retain(|index| *index >= branch_start);
    let controls = report
        .acknowledged_commands
        .iter()
        .enumerate()
        .map(|(sequence, command)| LiveQemuReplayControl {
            sequence: sequence as u64,
            command: session_command_name(*command).to_string(),
        })
        .collect();
    let encode_plan_controls = |commands: &[SessionCommandKind]| {
        commands
            .iter()
            .enumerate()
            .map(|(sequence, command)| LiveQemuReplayControl {
                sequence: sequence as u64,
                command: session_command_name(*command).to_string(),
            })
            .collect::<Vec<_>>()
    };
    let contract = LiveQemuReplayContract {
        producer: recipe.producer.to_string(),
        terminal_condition: recipe.terminal_condition.label().to_string(),
        terminal_status: report.status.label().to_string(),
        terminal_outcome: terminal_outcome_label(report.outcome).to_string(),
        terminal_configuration: format_content_hash_ref(terminal.id()),
        final_frontier_ticks: report.final_frontier_ticks,
        final_quanta: report.final_quanta,
        budget_timed_out: report.budget_timed_out,
        max_virtual_time_ticks: recipe.max_virtual_time_ticks,
        max_quanta: recipe.max_quanta,
        run_ceiling_icount: Some(PRODUCTION_CLI_RUN_CEILING_ICOUNT),
        lifecycle_quantum_budget: Some(PRODUCTION_CLI_QUANTUM_BUDGET),
        coverage: recipe.coverage,
        fingerprint_scope,
        branch: recipe.branch,
        network_choice_indices,
        startup_controls: encode_plan_controls(recipe.startup_commands),
        initial_controls: encode_plan_controls(recipe.initial_control_commands),
        controls,
    };
    let fingerprint_stream = verify_fingerprint_stream_bytes(&fingerprint_samples);
    Ok(LiveQemuArtifactEvidence {
        contract,
        event_stream: canonical_verify_log_stream_bytes(&[], &report.streamed_event_frames),
        fingerprint_stream,
        fingerprint_samples,
        resolved_effect_trace: report.resolved_effect_trace.clone(),
        campaign_replay_closure,
    })
}

fn select_live_qemu_artifact_fingerprints(
    nodes: &[crucible::WorldNode],
    mut samples: Vec<VerifyFingerprintSample>,
    scope: LiveQemuFingerprintScope,
) -> Result<Vec<VerifyFingerprintSample>, CliError> {
    if scope == LiveQemuFingerprintScope::FullExecution {
        return Ok(samples);
    }
    let node_count = nodes.len();
    if samples.len() < node_count {
        return Err(artifact_error(format!(
            "terminal fingerprint capture produced {} samples for {node_count} VM nodes",
            samples.len()
        )));
    }
    let mut terminal = samples.split_off(samples.len() - node_count);
    let expected_nodes = nodes
        .iter()
        .map(|node| node.id.name.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let actual_nodes = terminal
        .iter()
        .map(|sample| sample.node.clone())
        .collect::<std::collections::BTreeSet<_>>();
    if actual_nodes != expected_nodes {
        return Err(artifact_error(format!(
            "terminal fingerprint capture nodes {actual_nodes:?} did not match scenario VM nodes {expected_nodes:?}"
        )));
    }
    for (index, sample) in terminal.iter_mut().enumerate() {
        sample.index = index as u64;
    }
    Ok(terminal)
}

/// Encodes the required live-QEMU evidence components for a v3 artifact.
pub(crate) fn live_qemu_artifact_payloads(
    evidence: &LiveQemuArtifactEvidence,
) -> Vec<ReproductionArtifactComponentPayload> {
    let mut payloads = vec![
        ReproductionArtifactComponentPayload {
            kind: String::from("live_qemu_replay_contract"),
            name: String::from("live-qemu-replay-contract.txt"),
            media_type: String::from(LIVE_QEMU_REPLAY_CONTRACT_MEDIA_TYPE),
            bytes: evidence.contract.encode(),
        },
        ReproductionArtifactComponentPayload {
            kind: String::from("live_qemu_event_stream"),
            name: String::from("live-qemu-event-stream.bin"),
            media_type: String::from(LIVE_QEMU_EVENT_STREAM_MEDIA_TYPE),
            bytes: evidence.event_stream.clone(),
        },
        ReproductionArtifactComponentPayload {
            kind: String::from("live_qemu_fingerprint_stream"),
            name: String::from("live-qemu-fingerprint-stream.bin"),
            media_type: String::from(LIVE_QEMU_FINGERPRINT_STREAM_MEDIA_TYPE),
            bytes: evidence.fingerprint_stream.clone(),
        },
    ];
    if let Some(trace) = &evidence.resolved_effect_trace {
        payloads.push(ReproductionArtifactComponentPayload {
            kind: String::from("live_qemu_resolved_effect_trace"),
            name: String::from("resolved-effect-trace.cbor"),
            media_type: String::from(LIVE_QEMU_RESOLVED_EFFECT_TRACE_MEDIA_TYPE),
            bytes: trace.clone(),
        });
    }
    if let Some(closure) = &evidence.campaign_replay_closure {
        payloads.push(ReproductionArtifactComponentPayload {
            kind: String::from("campaign_replay_closure"),
            name: String::from("campaign-replay-closure.bin"),
            media_type: String::from(CAMPAIGN_REPLAY_CLOSURE_MEDIA_TYPE),
            bytes: closure.clone(),
        });
    }
    payloads
}

#[derive(serde::Serialize)]
struct SignalMutationProvenance<'a> {
    schema: &'static str,
    plan: String,
    cases: Vec<SignalMutationCaseProvenance<'a>>,
}

#[derive(serde::Serialize)]
struct SignalMutationCaseProvenance<'a> {
    original_program: String,
    binding: &'a str,
    provenance: String,
    mutation: &'a crucible::MaterializedSearchMutation,
    artifacts: Vec<String>,
}

/// Captures every reachable signal object and optional mutation recipe.
pub(crate) fn signal_artifact_payloads(
    plan: &crucible::FaultSignalPlan,
    store: &dyn crucible::DagStore,
    mutation: Option<&crucible::MaterializedSearchPlan>,
) -> Result<Vec<ReproductionArtifactComponentPayload>, CliError> {
    let objects = crucible_api::collect_signal_artifact_objects(plan, store)
        .map_err(|error| artifact_error(format!("collect signal artifact closure: {error}")))?;
    let mut payloads = Vec::new();
    if !objects.is_empty() || !plan.programs().is_empty() {
        payloads.push(ReproductionArtifactComponentPayload {
            kind: String::from("signal_artifact_bundle"),
            name: String::from("signal-artifacts.bundle"),
            media_type: String::from(SIGNAL_ARTIFACT_BUNDLE_MEDIA_TYPE),
            bytes: encode_signal_artifact_bundle(&objects)?,
        });
    }
    if let Some(mutation) = mutation {
        let provenance = SignalMutationProvenance {
            schema: "crucible.signal-mutation-provenance.v1",
            plan: format_content_hash_ref(mutation.provenance),
            cases: mutation
                .cases
                .iter()
                .map(|case| SignalMutationCaseProvenance {
                    original_program: format_content_hash_ref(case.original_program),
                    binding: case.binding_id.as_str(),
                    provenance: format_content_hash_ref(case.provenance),
                    mutation: &case.mutation,
                    artifacts: case
                        .artifacts
                        .iter()
                        .map(|artifact| format_content_hash_ref(*artifact))
                        .collect(),
                })
                .collect(),
        };
        payloads.push(ReproductionArtifactComponentPayload {
            kind: String::from("signal_mutation_provenance"),
            name: String::from("signal-mutation-provenance.json"),
            media_type: String::from(SIGNAL_MUTATION_PROVENANCE_MEDIA_TYPE),
            bytes: serde_json::to_vec_pretty(&provenance).map_err(|error| {
                artifact_error(format!("encode signal mutation provenance: {error}"))
            })?,
        });
    }
    Ok(payloads)
}

fn encode_signal_artifact_bundle(
    objects: &BTreeMap<crucible::ContentHash, Vec<u8>>,
) -> Result<Vec<u8>, CliError> {
    let count = u64::try_from(objects.len())
        .map_err(|_| artifact_error("signal artifact object count cannot be represented"))?;
    let mut bytes = Vec::from(&b"CSAB\0\0\0\x01"[..]);
    bytes.extend_from_slice(&count.to_le_bytes());
    for (identity, object) in objects {
        let length = u64::try_from(object.len())
            .map_err(|_| artifact_error("signal artifact object size cannot be represented"))?;
        bytes.extend_from_slice(&identity.bytes);
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(object);
    }
    Ok(bytes)
}

/// Restores and authenticates an embedded signal-object closure.
pub(crate) fn decode_signal_artifact_bundle(
    bytes: &[u8],
) -> Result<std::sync::Arc<crucible::MemoryDagStore>, CliError> {
    const HEADER_BYTES: usize = 16;
    if bytes.len() < HEADER_BYTES || bytes.get(..8) != Some(&b"CSAB\0\0\0\x01"[..]) {
        return Err(artifact_error(
            "signal artifact bundle has an invalid header",
        ));
    }
    let count = u64::from_le_bytes(
        bytes[8..16]
            .try_into()
            .map_err(|_| artifact_error("signal artifact bundle count is truncated"))?,
    );
    let count = usize::try_from(count)
        .map_err(|_| artifact_error("signal artifact bundle count cannot be represented"))?;
    let store = std::sync::Arc::new(crucible::MemoryDagStore::new());
    let mut cursor = HEADER_BYTES;
    for _ in 0..count {
        let identity_end = cursor
            .checked_add(32)
            .ok_or_else(|| artifact_error("signal artifact bundle offset overflow"))?;
        let length_end = identity_end
            .checked_add(8)
            .ok_or_else(|| artifact_error("signal artifact bundle offset overflow"))?;
        if length_end > bytes.len() {
            return Err(artifact_error("signal artifact bundle record is truncated"));
        }
        let identity = crucible::ContentHash {
            bytes: bytes[cursor..identity_end]
                .try_into()
                .map_err(|_| artifact_error("signal artifact identity is truncated"))?,
        };
        let length = u64::from_le_bytes(
            bytes[identity_end..length_end]
                .try_into()
                .map_err(|_| artifact_error("signal artifact length is truncated"))?,
        );
        let length = usize::try_from(length)
            .map_err(|_| artifact_error("signal artifact length cannot be represented"))?;
        let object_end = length_end
            .checked_add(length)
            .ok_or_else(|| artifact_error("signal artifact bundle offset overflow"))?;
        let object = bytes
            .get(length_end..object_end)
            .ok_or_else(|| artifact_error("signal artifact object is truncated"))?;
        if crucible::ContentHash::from_bytes(object) != identity {
            return Err(artifact_error(
                "signal artifact object failed authentication",
            ));
        }
        let stored = store.put(object).map_err(CliError::Store)?;
        if stored != identity {
            return Err(artifact_error("restored signal artifact identity changed"));
        }
        cursor = object_end;
    }
    if cursor != bytes.len() {
        return Err(artifact_error("signal artifact bundle has trailing bytes"));
    }
    Ok(store)
}

/// Returns the typed schedule indices that must be forced during live replay.
pub(crate) fn replay_choice_indices(schedule: &crucible::Schedule) -> Vec<u64> {
    let decisions = schedule.decisions();
    let mut network = Vec::new();
    for (index, decision) in decisions.iter().enumerate() {
        if matches!(
            decision,
            crucible::Decision::Override(override_decision)
                if override_decision.point.key.starts_with("live-world-network/")
        ) {
            network.push(index as u64);
        }
    }
    network
}

pub(crate) fn model_reproduction_artifact_payloads(
    artifact: &crucible::ReproductionArtifact,
    replay_state: crucible::ContentHash,
) -> Vec<ReproductionArtifactComponentPayload> {
    vec![
        ReproductionArtifactComponentPayload {
            kind: String::from("model_reproduction"),
            name: String::from("reproduction.crucible-model"),
            media_type: String::from(MODEL_REPRODUCTION_ARTIFACT_MEDIA_TYPE),
            bytes: artifact.to_compact_binary(),
        },
        ReproductionArtifactComponentPayload {
            kind: String::from("model_replay_state"),
            name: String::from("replay-state.txt"),
            media_type: String::from(MODEL_REPLAY_STATE_MEDIA_TYPE),
            bytes: format_content_hash_ref(replay_state).into_bytes(),
        },
    ]
}

pub(crate) fn verify_reproduction_artifact_bytes(
    seed: u64,
    backend: Option<&ResolvedLocalBackend>,
    scenario: &crucible::ScenarioDef,
    canonical_log: &[CanonicalLogEntry],
    fingerprint_samples: &[VerifyFingerprintSample],
) -> Result<Vec<u8>, CliError> {
    verify_reproduction_artifact_bytes_with_components(
        seed,
        backend,
        scenario,
        canonical_log,
        fingerprint_samples,
        &[],
    )
}

pub(crate) fn verify_reproduction_artifact_bytes_with_components(
    seed: u64,
    backend: Option<&ResolvedLocalBackend>,
    scenario: &crucible::ScenarioDef,
    canonical_log: &[CanonicalLogEntry],
    fingerprint_samples: &[VerifyFingerprintSample],
    extra_payloads: &[ReproductionArtifactComponentPayload],
) -> Result<Vec<u8>, CliError> {
    let scenario_bytes = scenario_identity_bytes(scenario);
    reproduction_artifact_bytes_with_scenario_payload(
        seed,
        backend,
        ReproductionScenarioPayload {
            name: "verify.scn",
            media_type: "application/vnd.crucible.scenario+text",
            bytes: &scenario_bytes,
        },
        canonical_log,
        fingerprint_samples,
        extra_payloads,
    )
}

pub(crate) fn run_failure_reproduction_artifact_bytes(
    seed: u64,
    backend: Option<&ResolvedLocalBackend>,
    producer: &str,
    run_plan: &RunInvocationPlan,
    report: &RunWorkflowReport,
    canonical_log: &[CanonicalLogEntry],
) -> Result<Vec<u8>, CliError> {
    let scenario = run_plan.scenario.scenario_form();
    let terminal_configuration = report.terminal_configuration.as_ref().ok_or_else(|| {
        artifact_error("failed-run artifact capture requires a terminal configuration")
    })?;
    if terminal_configuration.def.id() != scenario.id() {
        return Err(CliError::Identity(format!(
            "failed-run terminal scenario {} did not match captured scenario {}",
            terminal_configuration.def.id().to_hex(),
            scenario.id().to_hex()
        )));
    }
    let model_artifact =
        crucible::ReproductionArtifact::capture(scenario, &terminal_configuration.schedule)
            .map_err(|error| {
                artifact_error(format!(
                    "failed-run model reproduction capture failed: {error}"
                ))
            })?;
    let replay = model_artifact.replay().map_err(|error| {
        artifact_error(format!(
            "failed-run model reproduction replay failed: {error}"
        ))
    })?;
    let mut model_payloads = model_reproduction_artifact_payloads(&model_artifact, replay.state);
    let mut fingerprint_samples = run_fingerprint_samples(report);
    if matches!(backend, Some(ResolvedLocalBackend::Qemu { .. })) {
        let live_evidence = live_qemu_artifact_evidence_from_run(
            LiveQemuArtifactRecipe {
                producer,
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
        fingerprint_samples = live_evidence.fingerprint_samples.clone();
        model_payloads.extend(live_qemu_artifact_payloads(&live_evidence));
    }
    reproduction_artifact_bytes_with_scenario_payload(
        seed,
        backend,
        ReproductionScenarioPayload {
            name: "run-scenario.crucible-scenario",
            media_type: "application/vnd.crucible.scenario.compact-binary",
            bytes: &scenario.to_compact_binary(),
        },
        canonical_log,
        &fingerprint_samples,
        &model_payloads,
    )
}

/// Encodes a live QEMU finding with the complete v3 replay evidence bundle.
///
/// # Errors
///
/// Returns [`CliError`] when the live report, scenario identity, model proof, or
/// artifact component encoding is incomplete or inconsistent.
pub(crate) fn live_finding_reproduction_artifact_bytes(
    backend: Option<&ResolvedLocalBackend>,
    finding: &crucible::FindingReproductionArtifact,
    producer: &str,
    run_plan: &RunInvocationPlan,
    report: &RunWorkflowReport,
    branch: LiveQemuReplayBranch,
) -> Result<Vec<u8>, CliError> {
    let scenario = run_plan.scenario.scenario_form();
    if scenario.id() != finding.artifact.scenario_def().id() {
        return Err(CliError::Identity(format!(
            "{producer} finding scenario {} did not match live run scenario {}",
            finding.artifact.scenario_def().id().to_hex(),
            scenario.id().to_hex()
        )));
    }
    let canonical_log = canonical_run_log_entries(run_plan, report);
    let live = live_qemu_artifact_evidence_from_run(
        LiveQemuArtifactRecipe {
            producer,
            terminal_condition: run_plan.terminal_condition,
            max_virtual_time_ticks: run_plan.max_virtual_time_ticks,
            max_quanta: run_plan.max_quanta,
            coverage: true,
            execution_mode: run_plan.execution_mode,
            startup_commands: &run_plan.startup_commands,
            initial_control_commands: &run_plan.initial_control_commands,
            branch,
        },
        scenario,
        report,
    )?;
    let mut payloads =
        model_reproduction_artifact_payloads(&finding.artifact, finding.replay.state);
    payloads.extend(live_qemu_artifact_payloads(&live));
    let scenario_bytes = scenario.to_compact_binary();
    reproduction_artifact_bytes_with_scenario_payload(
        seed_to_u64(finding.artifact.seed()),
        backend,
        ReproductionScenarioPayload {
            name: "finding-scenario.crucible-scenario",
            media_type: "application/vnd.crucible.scenario.compact-binary",
            bytes: &scenario_bytes,
        },
        &canonical_log,
        &live.fingerprint_samples,
        &payloads,
    )
}

#[cfg(test)]
#[path = "artifact_capture_test.rs"]
mod tests;
