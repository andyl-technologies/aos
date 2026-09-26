//! Production QEMU replay and terminal-evidence validation.

use super::embedded::{
    replay_embedded_model_artifact, replay_to_savepoint, resolved_component_payload,
};
use super::proof::replay_bisect_artifacts;
use super::*;

pub(crate) fn replay_reproduction_artifact(
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
                "live-QEMU replay requires an embedded pure model reproduction proof",
            ));
        }
        Some(replay_live_qemu_evidence(
            cli,
            &artifact,
            args.bounded_scheduler_preemption,
        )?)
    } else {
        if args.bounded_scheduler_preemption {
            return Err(backend_error(
                "replay --bounded-scheduler-preemption requires the local QEMU backend",
            ));
        }
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
            .map(|other| {
                replay_bisect_artifacts(
                    cli,
                    other,
                    &artifact,
                    &bytes,
                    args.bounded_scheduler_preemption,
                )
            })
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

pub(super) fn replay_uses_live_qemu(cli: &Cli) -> Result<bool, CliError> {
    let plan = plan_backend_selection(cli)?;
    Ok(matches!(
        plan.as_ref()
            .and_then(|plan| plan.resolved_backend.as_ref()),
        Some(ResolvedLocalBackend::Qemu { .. })
    ))
}

pub(super) fn replay_live_qemu_evidence(
    cli: &Cli,
    artifact: &CliReproductionArtifact,
    bounded_scheduler_preemption: bool,
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
    if artifact.scenario.media_type != "application/vnd.crucible.scenario.compact-binary" {
        return Err(artifact_error(
            "live-QEMU replay requires a compact binary scenario component",
        ));
    }
    let scenario = crucible::ScenarioDefForm::from_compact_binary(resolved_component_payload(
        artifact,
        &artifact.scenario,
    )?)
    .map_err(|error| artifact_error(format!("decode live-QEMU replay scenario: {error}")))?;
    let lifecycle_artifacts = replay_lifecycle_artifacts(
        artifact,
        scenario
            .plan()
            .fault_signals()
            .resource_limits()
            .fat_checkpoint_bytes,
    )?;
    let campaign_replay_closure_bytes = optional_single_component_payload(
        artifact,
        CAMPAIGN_REPLAY_CLOSURE_MEDIA_TYPE,
        "campaign replay closure",
    )?;
    let contract = LiveQemuReplayContract::decode(contract_bytes)?;
    let recorded_event_count = live_qemu_event_frame_count(expected_events)?;
    if recorded_event_count != contract.final_event_log_len {
        return Err(artifact_error(format!(
            "live-QEMU event stream contains {recorded_event_count} frames but the final snapshot records {}",
            contract.final_event_log_len
        )));
    }
    let campaign_replay_closure = match (
        contract.producer.as_str(),
        campaign_replay_closure_bytes,
    ) {
        ("campaign-run" | "campaign-search", Some(bytes)) => Some(
            crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignReplayClosure::from_canonical_bytes(bytes)
                .map_err(|error| artifact_error(format!("decode campaign replay closure: {error}")))?,
        ),
        ("campaign-run" | "campaign-search", None) => {
            return Err(artifact_error(
                "campaign-owned replay requires exactly one campaign replay closure component",
            ));
        }
        (_, Some(_)) => {
            return Err(artifact_error(
                "a session-owned replay artifact cannot carry a campaign replay closure component",
            ));
        }
        (_, None) => None,
    };
    let top_level_fingerprints =
        verify_fingerprint_stream_bytes(&artifact_fingerprint_samples(artifact));
    if top_level_fingerprints != expected_fingerprints {
        return Err(artifact_error(
            "live-QEMU fingerprint component does not match top-level artifact samples",
        ));
    }
    let resolved_effect_trace = resolved_effect_trace_bytes
        .map(|bytes| {
            crucible::ResolvedEffectTrace::from_canonical_bytes(
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
    if let Some(closure) = &campaign_replay_closure {
        closure
            .validate_for_schedule(&scenario, model.schedule())
            .map_err(|error| {
                artifact_error(format!("validate campaign replay closure: {error}"))
            })?;
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
            "live-QEMU reproduction artifacts replay only through the packaged QEMU backend",
        ));
    }
    let terminal_node_count = scenario.world().vm_nodes().len();
    let scenario_nodes = scenario
        .world()
        .vm_nodes()
        .iter()
        .map(|node| node.id.name.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let preemption_evidence = bounded_scheduler_preemption
        .then(crucible_api::BoundedSchedulerPreemptionEvidence::default);
    let (_run_plan, report) = run_live_qemu_artifact_replay(
        backend,
        cli.campaign_deployment.as_deref(),
        scenario,
        model.schedule(),
        &contract,
        LiveQemuReplayResources {
            campaign_closure: campaign_replay_closure,
            effect_trace: resolved_effect_trace,
            lifecycle_artifacts,
            bounded_scheduler_preemption: preemption_evidence.clone(),
        },
    )?;
    let host_scheduler_preemption = preemption_evidence
        .as_ref()
        .map(|evidence| {
            required_scheduler_preemption_snapshot(evidence, "live QEMU artifact replay", 1)
        })
        .transpose()?;
    if report.execution_owner != contract.execution_owner {
        return Err(CliError::ReplayCheck(format!(
            "live QEMU producer `{}` was replayed by the wrong execution owner",
            contract.producer
        )));
    }
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
    if report.reproduction_commands != contract.reproduction_commands {
        return Err(CliError::ReplayCheck(format!(
            "live QEMU reproduction records diverged: expected {} records, replayed {}",
            contract.reproduction_commands.len(),
            report.reproduction_commands.len(),
        )));
    }
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
    Ok(ReplayLiveQemuProof {
        execution_owner: contract.execution_owner,
        producer: contract.producer,
        terminal_status: contract.terminal_status,
        terminal_outcome: contract.terminal_outcome,
        terminal_configuration: contract.terminal_configuration,
        event_stream_digest: content_address_bytes(expected_events),
        fingerprint_stream_digest: content_address_bytes(expected_fingerprints),
        controls: contract.controls.len(),
        host_scheduler_preemption,
    })
}

fn live_qemu_event_frame_count(bytes: &[u8]) -> Result<u64, CliError> {
    const PREFIX: &str = concat!(
        "crucible.verify.canonical-log-stream.v1\n",
        "\ncrucible.verify.api-event-frames.v1\n",
    );
    let text = std::str::from_utf8(bytes)
        .map_err(|error| artifact_error(format!("live-QEMU event stream is not UTF-8: {error}")))?;
    let frames = text.strip_prefix(PREFIX).ok_or_else(|| {
        artifact_error("live-QEMU event stream has an invalid canonical stream header")
    })?;
    let count = frames
        .lines()
        .filter(|line| *line == "crucible.rpc/event-frame")
        .count();
    u64::try_from(count)
        .map_err(|_| artifact_error("live-QEMU event frame count cannot be represented"))
}

fn replay_lifecycle_artifacts(
    artifact: &CliReproductionArtifact,
    maximum_payload_bytes: u64,
) -> Result<Option<std::sync::Arc<crucible::MemoryDagStore>>, CliError> {
    optional_single_component_payload(
        artifact,
        LIFECYCLE_ARTIFACT_BUNDLE_MEDIA_TYPE,
        "lifecycle artifact bundle",
    )?
    .map(|bytes| decode_lifecycle_artifact_bundle(bytes, maximum_payload_bytes))
    .transpose()
}

pub(super) fn required_single_component_payload<'a>(
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
            "replay requires exactly one {label} component, found {}",
            components.len()
        )));
    }
    resolved_component_payload(artifact, components[0])
}

pub(super) fn optional_single_component_payload<'a>(
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
            "replay accepts at most one {label} component, found {}",
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
