//! Embedded-model replay and savepoint projection.

use super::live::{optional_single_component_payload, required_single_component_payload};
use super::proof::{materialize_replay_to_savepoint, prove_replay_schedule_prefix};
use super::*;

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

pub(super) fn resolved_component_payload<'a>(
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
    let replay_closure_bytes = optional_single_component_payload(
        artifact,
        CAMPAIGN_REPLAY_CLOSURE_MEDIA_TYPE,
        "campaign replay closure",
    )?;
    let replay_closure = authenticated_replay_closure(
        &scenario_form,
        &schedule,
        replay_closure_bytes,
        "replay --to embedded savepoint",
    )?;
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
        replay_closure,
        source_observation_proof: None,
        source_observation_evidence: None,
    }))
}
