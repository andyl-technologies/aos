//! Schedule-prefix proofs, materialization, and divergence reports.

use super::embedded::replay_embedded_model_artifact;
use super::live::{replay_live_qemu_evidence, replay_uses_live_qemu};
use super::*;

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

pub(crate) fn replay_to_savepoint_status_line(target: &ReplayToSavepointReport) -> String {
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
    let evidence = crucible::TemporalGraphReplayEvidence {
        configuration: configuration.clone(),
        replay,
    };
    let report = graph
        .validate_unified_operation(&crucible::UnifiedGraphOperationEvidence::Replay(Box::new(
            evidence,
        )))
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
    bounded_scheduler_preemption: bool,
) -> Result<ReplayBisectionReport, CliError> {
    let other_bytes = fs::read(other_path)?;
    let other_artifact = validate_replayable_reproduction_artifact(cli, &other_bytes)?;
    if replay_uses_live_qemu(cli)? {
        replay_embedded_model_artifact(&other_artifact)?.ok_or_else(|| {
            artifact_error("replay --bisect requires a model proof in the other artifact")
        })?;
        replay_live_qemu_evidence(cli, &other_artifact, bounded_scheduler_preemption)?;
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

pub(crate) fn replay_bisect_error(
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

pub(crate) fn replay_check_mismatch_error(
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
