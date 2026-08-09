//! Savepoint, resume-anchor, and replay-oracle validation.

use super::*;

pub(in super::super) fn validate_savepoint_checkpoint(
    save_plan: &SaveInvocationPlan,
    configuration: &crucible::Configuration,
    checkpoint: &Checkpoint,
    boundary: crucible::VirtualTime,
) -> Result<SavepointOracleProof, CliError> {
    validate_checkpoint_with_replay_oracle(
        "save",
        save_plan.run_plan.scenario.scenario_def(),
        configuration,
        checkpoint,
        boundary,
    )
}

pub(in super::super) fn validate_resume_terminal_savepoint(
    evidence: &ResumeHandleEvidence,
    final_snapshot: &EngineSnapshot,
) -> Result<SavepointOracleProof, CliError> {
    let checkpoint = final_snapshot.terminal_savepoint.as_ref().ok_or_else(|| {
        backend_error("resume completed without a terminal savepoint for replay-oracle validation")
    })?;
    let mut graph = save_validation_graph(&evidence.scenario)?;
    validate_resume_terminal_source_ancestor(evidence, &final_snapshot.configuration)?;
    if !evidence.configuration.is_genesis() {
        graph
            .cache_snapshot(&evidence.configuration, evidence.checkpoint.clone())
            .map_err(|error| {
                CliError::Identity(format!(
                    "resume source checkpoint cache admission failed: {error}"
                ))
            })?;
    }
    validate_resume_replay_anchor(&graph, evidence, &final_snapshot.configuration)?;
    validate_checkpoint_metadata(
        "resume",
        &final_snapshot.configuration,
        checkpoint,
        final_snapshot.frontier,
    )?;
    let replay = graph
        .replay_checkpoint(&final_snapshot.configuration, checkpoint)
        .map_err(|error| {
            CliError::Identity(format!(
                "resume replay-oracle fat==thin validation failed: {error}"
            ))
        })?;
    if replay.fat_checkpoint != checkpoint.id || replay.thin_checkpoint != checkpoint.id {
        return Err(CliError::Identity(format!(
            "resume replay-oracle mismatch: fat={} thin={} saved={}",
            format_content_hash_ref(replay.fat_checkpoint),
            format_content_hash_ref(replay.thin_checkpoint),
            format_content_hash_ref(checkpoint.id)
        )));
    }
    Ok(SavepointOracleProof {
        configuration: replay.configuration,
        fat_checkpoint: replay.fat_checkpoint,
        thin_checkpoint: replay.thin_checkpoint,
        frontier: checkpoint.virtual_time,
        schedule: final_snapshot.configuration.schedule.clone(),
        store_objects: 0,
    })
}

pub(in super::super) fn validate_resume_terminal_source_ancestor(
    evidence: &ResumeHandleEvidence,
    final_configuration: &crucible::Configuration,
) -> Result<(), CliError> {
    if final_configuration.def.id() != evidence.scenario.id() {
        return Err(CliError::Identity(format!(
            "resume terminal scenario {} did not match source scenario {}",
            final_configuration.def.id().to_hex(),
            evidence.scenario.id().to_hex()
        )));
    }
    if final_configuration.schedule.len() < evidence.schedule.len() {
        return Err(CliError::Identity(format!(
            "resume terminal schedule length {} is shorter than source schedule length {}",
            final_configuration.schedule.len(),
            evidence.schedule.len()
        )));
    }
    let source_prefix = final_configuration
        .schedule
        .prefix(evidence.schedule.len())
        .map_err(|error| {
            CliError::Identity(format!("resume terminal source prefix failed: {error}"))
        })?;
    if source_prefix != evidence.schedule {
        return Err(CliError::Identity(format!(
            "resume terminal schedule is not descended from source checkpoint {}",
            format_content_hash_ref(evidence.checkpoint.id)
        )));
    }
    let source_configuration = crucible::Configuration {
        def: final_configuration.def.clone(),
        schedule: source_prefix,
    };
    if source_configuration.id() != evidence.configuration.id() {
        return Err(CliError::Identity(format!(
            "resume terminal source prefix reconstructed {}, expected {}",
            format_content_hash_ref(source_configuration.id()),
            format_content_hash_ref(evidence.configuration.id())
        )));
    }
    validate_checkpoint_metadata(
        "resume source",
        &evidence.configuration,
        &evidence.checkpoint,
        validate_resume_handle_frontier(
            &evidence.schedule,
            evidence.checkpoint.virtual_time.ticks,
        )?,
    )
}

pub(in super::super) fn validate_resume_replay_anchor(
    graph: &ValidationDag,
    evidence: &ResumeHandleEvidence,
    final_configuration: &crucible::Configuration,
) -> Result<(), CliError> {
    if evidence.configuration.is_genesis()
        || final_configuration.id() == evidence.configuration.id()
    {
        return Ok(());
    }
    let ancestor = graph
        .nearest_cached_ancestor(final_configuration)
        .map_err(|error| {
            CliError::Identity(format!("resume replay anchor lookup failed: {error}"))
        })?
        .ok_or_else(|| {
            CliError::Identity(format!(
                "resume replay did not find cached source checkpoint {} as an ancestor",
                format_content_hash_ref(evidence.checkpoint.id)
            ))
        })?;
    if ancestor.id() != evidence.configuration.id() {
        return Err(CliError::Identity(format!(
            "resume replay anchor {} did not match source checkpoint {}",
            format_content_hash_ref(ancestor.id()),
            format_content_hash_ref(evidence.checkpoint.id)
        )));
    }
    Ok(())
}

pub(in super::super) fn validate_checkpoint_with_replay_oracle(
    operation: &'static str,
    scenario: &crucible::ScenarioDef,
    configuration: &crucible::Configuration,
    checkpoint: &Checkpoint,
    boundary: crucible::VirtualTime,
) -> Result<SavepointOracleProof, CliError> {
    validate_checkpoint_with_replay_oracle_anchored(
        operation,
        scenario,
        [],
        configuration,
        checkpoint,
        boundary,
    )
}

pub(in super::super) fn validate_checkpoint_with_replay_oracle_anchored<'a>(
    operation: &'static str,
    scenario: &crucible::ScenarioDef,
    anchors: impl IntoIterator<Item = (&'a crucible::Configuration, &'a Checkpoint)>,
    configuration: &crucible::Configuration,
    checkpoint: &Checkpoint,
    boundary: crucible::VirtualTime,
) -> Result<SavepointOracleProof, CliError> {
    let mut graph = save_validation_graph(scenario)?;
    for (anchor_configuration, anchor_checkpoint) in anchors {
        if !anchor_configuration.is_genesis() {
            graph
                .cache_snapshot(anchor_configuration, anchor_checkpoint.clone())
                .map_err(|error| {
                    CliError::Identity(format!(
                        "{operation} source checkpoint cache admission failed: {error}"
                    ))
                })?;
        }
    }
    validate_checkpoint_metadata(operation, configuration, checkpoint, boundary)?;
    if !configuration.is_genesis() {
        graph
            .cache_snapshot(configuration, checkpoint.clone())
            .map_err(|error| {
                CliError::Identity(format!(
                    "{operation} checkpoint cache admission failed: {error}"
                ))
            })?;
    }
    let replay = graph
        .replay_checkpoint(configuration, checkpoint)
        .map_err(|error| {
            CliError::Identity(format!(
                "{operation} replay-oracle fat==thin validation failed: {error}"
            ))
        })?;
    if replay.fat_checkpoint != checkpoint.id || replay.thin_checkpoint != checkpoint.id {
        return Err(CliError::Identity(format!(
            "{operation} replay-oracle mismatch: fat={} thin={} saved={}",
            format_content_hash_ref(replay.fat_checkpoint),
            format_content_hash_ref(replay.thin_checkpoint),
            format_content_hash_ref(checkpoint.id)
        )));
    }
    let store = MemoryDagStore::new();
    graph
        .persist_checkpoint_closure(&store, configuration)
        .map_err(save_temporal_graph_error)?;
    let store_objects = store.object_count().map_err(CliError::Store)?;
    Ok(SavepointOracleProof {
        configuration: replay.configuration,
        fat_checkpoint: replay.fat_checkpoint,
        thin_checkpoint: replay.thin_checkpoint,
        frontier: checkpoint.virtual_time,
        schedule: configuration.schedule.clone(),
        store_objects,
    })
}

pub(in super::super) fn validate_checkpoint_metadata(
    operation: &'static str,
    configuration: &crucible::Configuration,
    checkpoint: &Checkpoint,
    boundary: crucible::VirtualTime,
) -> Result<(), CliError> {
    if checkpoint.configuration != configuration.id() {
        return Err(CliError::Identity(format!(
            "{operation} checkpoint {} named configuration {}, expected {}",
            format_content_hash_ref(checkpoint.id),
            format_content_hash_ref(checkpoint.configuration),
            format_content_hash_ref(configuration.id())
        )));
    }
    if checkpoint.kind != CheckpointKind::Fat {
        return Err(CliError::Identity(format!(
            "{operation} checkpoint {} was not materialized as fat",
            format_content_hash_ref(checkpoint.id)
        )));
    }
    if checkpoint.virtual_time != boundary {
        return Err(CliError::Identity(format!(
            "{operation} checkpoint {} virtual time {} did not match boundary {}",
            format_content_hash_ref(checkpoint.id),
            checkpoint.virtual_time.ticks,
            boundary.ticks
        )));
    }
    Ok(())
}

pub(in super::super) fn save_validation_graph(
    scenario: &crucible::ScenarioDef,
) -> Result<ValidationDag, CliError> {
    validation_dag_with_baked_genesis(scenario)
        .map_err(|error| CliError::Identity(format!("save validation graph setup failed: {error}")))
}

pub(in super::super) fn save_temporal_graph_error(error: ValidationDagStoreError) -> CliError {
    match error {
        ValidationDagStoreError::Engine { operation, source } => CliError::Identity(format!(
            "save temporal graph {operation} failed replay-oracle validation: {source}"
        )),
        ValidationDagStoreError::Store { source, .. } => CliError::Store(source),
    }
}

pub(in super::super) fn save_control_client_error(
    error: crucible_api::ControlClientError,
) -> CliError {
    save_backend_error(format!("control API error: {error}"))
}

pub(in super::super) fn save_backend_error(reason: impl Into<String>) -> CliError {
    CliError::Identity(reason.into())
}

pub(in super::super) fn run_save_policy_label(policy: RunSavePolicy) -> &'static str {
    match policy {
        RunSavePolicy::OnFail => "fail",
        RunSavePolicy::Always => "always",
        RunSavePolicy::Never => "never",
    }
}

pub(in super::super) fn run_terminal_savepoint_for_policy(
    run_plan: &RunInvocationPlan,
    report: &RunWorkflowReport,
) -> Result<Option<crucible::ContentHash>, CliError> {
    let should_save = match run_plan.save_policy {
        RunSavePolicy::Always => true,
        RunSavePolicy::OnFail => report.status.is_non_passing(),
        RunSavePolicy::Never => false,
    };
    if !should_save {
        return Ok(None);
    }
    report.terminal_savepoint.map(Some).ok_or_else(|| {
        backend_error(format!(
            "run save policy `{}` required an outcome savepoint, but the session did not materialize one",
            run_save_policy_label(run_plan.save_policy)
        ))
    })
}
