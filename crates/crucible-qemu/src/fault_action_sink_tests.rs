//! Exact QEMU adapter-coordinate tests.

// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for localization.
#![allow(clippy::expect_used)]

use super::*;

#[test]
fn virtual_time_action_uses_current_qemu_coordinate_without_changing_identity() {
    assert_eq!(qemu_execution_coordinate(None, 73), Ok(73));
    assert_eq!(qemu_execution_coordinate(Some(73), 73), Ok(73));
    assert_eq!(
        qemu_execution_coordinate(Some(72), 73),
        Err(FaultRuntimeError::AdapterActionMismatch)
    );
}

#[test]
fn typed_node_application_evidence_excludes_replay_authorization() {
    let baseline = NodeFaultEvidenceV1 {
        command_kind: FaultCommandKind::NodeLifecycle,
        operation: crucible_shmem::NodeFaultOperationV1::Apply,
        target_kind: crucible_shmem::NodeFaultTargetKindV1::Node,
        model_phase: 1,
        generation: 2,
        prior_generation: 1,
        action_hash: [1; 32],
        target_hash: [2; 32],
        schema_hash: [3; 32],
        request_sha256: [4; 32],
        before_sha256: [5; 32],
        after_sha256: [6; 32],
    };
    let mut replay = baseline.clone();
    replay.action_hash = [7; 32];
    replay.request_sha256 = [8; 32];
    assert_eq!(
        typed_node_application_evidence_hash(&baseline, 73),
        typed_node_application_evidence_hash(&replay, 73)
    );

    replay.after_sha256 = [9; 32];
    assert_ne!(
        typed_node_application_evidence_hash(&baseline, 73),
        typed_node_application_evidence_hash(&replay, 73)
    );
    assert_ne!(
        typed_node_application_evidence_hash(&baseline, 73),
        typed_node_application_evidence_hash(&baseline, 74)
    );

    let mut legacy_material = [0_u8; 152];
    legacy_material[0..2].copy_from_slice(&(baseline.command_kind as u16).to_le_bytes());
    legacy_material[2..4].copy_from_slice(&(baseline.operation as u16).to_le_bytes());
    legacy_material[4..6].copy_from_slice(&(baseline.target_kind as u16).to_le_bytes());
    legacy_material[6..8].copy_from_slice(&baseline.model_phase.to_le_bytes());
    legacy_material[8..16].copy_from_slice(&baseline.generation.to_le_bytes());
    legacy_material[16..24].copy_from_slice(&baseline.prior_generation.to_le_bytes());
    legacy_material[24..56].copy_from_slice(&baseline.target_hash);
    legacy_material[56..88].copy_from_slice(&baseline.schema_hash);
    legacy_material[88..120].copy_from_slice(&baseline.before_sha256);
    legacy_material[120..152].copy_from_slice(&baseline.after_sha256);
    let legacy = ContentHash::from_canonical_hex_bytes(
        "crucible.qemu-node-application-evidence.v1",
        &legacy_material,
    );
    assert_ne!(typed_node_application_evidence_hash(&baseline, 73), legacy);
}

#[test]
fn memory_application_evidence_excludes_replay_authorization() {
    fn payload(precondition: u8, action: u8, evidence: [u8; 3]) -> Vec<u8> {
        let mut payload = vec![
            0;
            MEMORY_MUTATION_BATCH_EVIDENCE_BODY_OFFSET
                + MEMORY_MUTATION_BATCH_EVIDENCE_RECORD_BODY_OFFSET
                + evidence.len()
        ];
        payload[MEMORY_MUTATION_BATCH_EVIDENCE_PRECONDITION_OFFSET
            ..MEMORY_MUTATION_BATCH_EVIDENCE_PRECONDITION_OFFSET + 32]
            .fill(precondition);
        let action_start = MEMORY_MUTATION_BATCH_EVIDENCE_BODY_OFFSET
            + MEMORY_MUTATION_BATCH_EVIDENCE_RECORD_ACTION_HASH_OFFSET;
        payload[action_start..action_start + 32].fill(action);
        let length_start = MEMORY_MUTATION_BATCH_EVIDENCE_BODY_OFFSET
            + MEMORY_MUTATION_BATCH_EVIDENCE_RECORD_LENGTH_OFFSET;
        payload[length_start..length_start + 4]
            .copy_from_slice(&(evidence.len() as u32).to_le_bytes());
        let evidence_start = MEMORY_MUTATION_BATCH_EVIDENCE_BODY_OFFSET
            + MEMORY_MUTATION_BATCH_EVIDENCE_RECORD_BODY_OFFSET;
        payload[evidence_start..].copy_from_slice(&evidence);
        payload
    }

    let mut baseline = payload(1, 2, [3, 4, 5]);
    let mut replay = payload(6, 7, [3, 4, 5]);
    assert_eq!(
        memory_application_evidence_hash(&mut baseline, 1),
        memory_application_evidence_hash(&mut replay, 1)
    );

    let mut changed = payload(1, 2, [3, 4, 8]);
    assert_ne!(
        memory_application_evidence_hash(&mut baseline, 1),
        memory_application_evidence_hash(&mut changed, 1)
    );
}

#[test]
fn staged_qemu_results_and_evidence_use_reserved_storage() {
    fn result(action: ContentHash) -> PreparedActionResult {
        PreparedActionResult {
            action,
            precondition: None,
            observation: FaultObservation {
                semantic_version: FAULT_RUNTIME_STATE_VERSION,
                kind: FaultObservationKind::EffectCommitted,
                coordinate: crucible::model::FaultCoordinate {
                    virtual_nanos: 17,
                    retired_instructions: None,
                },
                binding: None,
                target: None,
                opportunity: None,
                evidence: ContentHash::from_bytes(b"prediction"),
            },
        }
    }

    let first = ContentHash::from_bytes(b"first-action");
    let second = ContentHash::from_bytes(b"second-action");
    let first_precondition = ContentHash::from_bytes(b"first-before");
    let second_precondition = ContentHash::from_bytes(b"second-before");
    let first_evidence = ContentHash::from_bytes(b"first-evidence");
    let second_evidence = ContentHash::from_bytes(b"second-evidence");
    let mut results = Vec::with_capacity(2);
    results.push(result(first));
    results.push(result(second));
    let results_capacity = results.capacity();

    finalize_staged_result(
        &mut results,
        second,
        second_precondition,
        29,
        second_evidence,
    )
    .expect("finalize second staged result");
    finalize_staged_result(&mut results, first, first_precondition, 23, first_evidence)
        .expect("finalize first staged result");

    assert_eq!(results.capacity(), results_capacity);
    assert_eq!(results[0].action, first);
    assert_eq!(results[0].precondition, Some(first_precondition));
    assert_eq!(
        results[0].observation.coordinate.retired_instructions,
        Some(23)
    );
    assert_eq!(results[0].observation.evidence, first_evidence);
    assert_eq!(results[1].action, second);
    assert_eq!(results[1].precondition, Some(second_precondition));
    assert_eq!(
        results[1].observation.coordinate.retired_instructions,
        Some(29)
    );
    assert_eq!(results[1].observation.evidence, second_evidence);

    let committed_evidence = CommittedQemuActionEvidence {
        command_sequence: 3,
        command_kind: FaultCommandKind::NodeLifecycle as u16,
        before_hash: [4; 32],
        after_hash: [5; 32],
    };
    let mut committed = Vec::with_capacity(2);
    let committed_capacity = committed.capacity();
    retain_committed_evidence(&mut committed, first, committed_evidence)
        .expect("retain first committed evidence");
    retain_committed_evidence(&mut committed, second, committed_evidence)
        .expect("retain second committed evidence");
    assert_eq!(committed.capacity(), committed_capacity);
    assert_eq!(
        committed
            .iter()
            .map(|(action, _)| *action)
            .collect::<Vec<_>>(),
        vec![first, second]
    );
    assert_eq!(
        retain_committed_evidence(&mut committed, first, committed_evidence),
        Err(FaultActionCommitError::Fatal(
            FaultRuntimeError::IncompleteAdapterState
        ))
    );
}

#[test]
fn streaming_result_evidence_hash_preserves_the_canonical_identity() {
    let payload = b"typed-result-evidence";
    let header = crucible_shmem::FaultResultHeaderV1 {
        abi_major: FAULT_COMMAND_ABI_MAJOR,
        abi_minor: FAULT_COMMAND_ABI_MINOR,
        command_kind: FaultCommandKind::NodeLifecycle as u16,
        status: FaultResultStatus::Applied,
        semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
        command_sequence: 7,
        observed_icount: 11,
        applied_icount: 11,
        capability_version: 1,
        phase: FaultBoundaryPhase::NodeBoundary,
        before_hash: [1; 32],
        after_hash: [2; 32],
        evidence_hash: [3; 32],
        result_payload_hash: *blake3::hash(payload).as_bytes(),
        result_offset: 0,
        result_length: u32::try_from(payload.len())
            .unwrap_or_else(|error| panic!("test payload length: {error}")),
    };
    let mut prior_material = header.encode().to_vec();
    prior_material.extend_from_slice(payload);
    assert_eq!(
        result_evidence_hash(&header, payload),
        ContentHash::from_bytes(&prior_material)
    );
}
