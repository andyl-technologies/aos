//! Exact QEMU adapter-coordinate tests.

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
        typed_node_application_evidence_hash(&baseline),
        typed_node_application_evidence_hash(&replay)
    );

    replay.after_sha256 = [9; 32];
    assert_ne!(
        typed_node_application_evidence_hash(&baseline),
        typed_node_application_evidence_hash(&replay)
    );
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
