//! Canonical QEMU application evidence and transaction observations.

use super::*;

pub(super) fn memory_evidence_matches(
    evidence: &MemoryMutationEvidenceV1,
    payload: &MemoryMutationPayloadV1,
    coordinate: u64,
    target_node_hash: [u8; 32],
) -> bool {
    evidence.address_space == payload.address_space
        && evidence.transform == payload.transform
        && evidence.vcpu_index == payload.vcpu_index
        && evidence.address == payload.address
        && usize::try_from(evidence.length) == Ok(payload.mask.len())
        && evidence.observed_icount == coordinate
        && evidence.target_node_hash == target_node_hash
}

/// Hashes committed memory state without locked-replay authorization fields.
pub(super) fn memory_application_evidence_hash(
    payload: &mut [u8],
    action_count: usize,
) -> Result<ContentHash, FaultActionCommitError> {
    let precondition_end = MEMORY_MUTATION_BATCH_EVIDENCE_PRECONDITION_OFFSET
        .checked_add(32)
        .ok_or(FaultActionCommitError::Fatal(
            FaultRuntimeError::IncompleteAdapterState,
        ))?;
    let precondition = payload
        .get_mut(MEMORY_MUTATION_BATCH_EVIDENCE_PRECONDITION_OFFSET..precondition_end)
        .ok_or(FaultActionCommitError::Fatal(
            FaultRuntimeError::IncompleteAdapterState,
        ))?;
    precondition.fill(0);

    let mut offset = MEMORY_MUTATION_BATCH_EVIDENCE_BODY_OFFSET;
    for _ in 0..action_count {
        let action_hash_start = offset
            .checked_add(MEMORY_MUTATION_BATCH_EVIDENCE_RECORD_ACTION_HASH_OFFSET)
            .ok_or(FaultActionCommitError::Fatal(
                FaultRuntimeError::IncompleteAdapterState,
            ))?;
        let action_hash_end =
            action_hash_start
                .checked_add(32)
                .ok_or(FaultActionCommitError::Fatal(
                    FaultRuntimeError::IncompleteAdapterState,
                ))?;
        payload
            .get_mut(action_hash_start..action_hash_end)
            .ok_or(FaultActionCommitError::Fatal(
                FaultRuntimeError::IncompleteAdapterState,
            ))?
            .fill(0);

        let length_start = offset
            .checked_add(MEMORY_MUTATION_BATCH_EVIDENCE_RECORD_LENGTH_OFFSET)
            .ok_or(FaultActionCommitError::Fatal(
                FaultRuntimeError::IncompleteAdapterState,
            ))?;
        let length_end = length_start
            .checked_add(4)
            .ok_or(FaultActionCommitError::Fatal(
                FaultRuntimeError::IncompleteAdapterState,
            ))?;
        let evidence_length = u32::from_le_bytes(
            payload
                .get(length_start..length_end)
                .ok_or(FaultActionCommitError::Fatal(
                    FaultRuntimeError::IncompleteAdapterState,
                ))?
                .try_into()
                .map_err(|_source| {
                    FaultActionCommitError::Fatal(FaultRuntimeError::IncompleteAdapterState)
                })?,
        ) as usize;
        offset = offset
            .checked_add(MEMORY_MUTATION_BATCH_EVIDENCE_RECORD_BODY_OFFSET)
            .and_then(|value| value.checked_add(evidence_length))
            .ok_or(FaultActionCommitError::Fatal(
                FaultRuntimeError::IncompleteAdapterState,
            ))?;
    }
    if offset != payload.len() {
        return Err(FaultActionCommitError::Fatal(
            FaultRuntimeError::IncompleteAdapterState,
        ));
    }
    Ok(ContentHash::from_canonical_hex_bytes(
        "crucible.qemu-memory-application-evidence.v1",
        payload,
    ))
}

/// Hashes QEMU application state without command-authorization identities.
pub(super) fn typed_node_application_evidence_hash(
    evidence: &NodeFaultEvidenceV1,
    observed_icount: u64,
) -> ContentHash {
    let mut material = [0_u8; 160];
    material[0..2].copy_from_slice(&(evidence.command_kind as u16).to_le_bytes());
    material[2..4].copy_from_slice(&(evidence.operation as u16).to_le_bytes());
    material[4..6].copy_from_slice(&(evidence.target_kind as u16).to_le_bytes());
    material[6..8].copy_from_slice(&evidence.model_phase.to_le_bytes());
    material[8..16].copy_from_slice(&evidence.generation.to_le_bytes());
    material[16..24].copy_from_slice(&evidence.prior_generation.to_le_bytes());
    material[24..56].copy_from_slice(&evidence.target_hash);
    material[56..88].copy_from_slice(&evidence.schema_hash);
    material[88..120].copy_from_slice(&evidence.before_sha256);
    material[120..152].copy_from_slice(&evidence.after_sha256);
    material[152..160].copy_from_slice(&observed_icount.to_le_bytes());
    ContentHash::from_canonical_hex_bytes("crucible.qemu-node-application-evidence.v2", &material)
}

pub(super) fn result_evidence_hash(
    header: &crucible_shmem::FaultResultHeaderV1,
    payload: &[u8],
) -> ContentHash {
    let mut material = header.encode().to_vec();
    material.extend_from_slice(payload);
    ContentHash::from_bytes(&material)
}

pub(super) fn verify_qemu_evidence_hash(
    header: &crucible_shmem::FaultResultHeaderV1,
    payload: &[u8],
) -> Result<(), FaultActionCommitError> {
    let observed: [u8; 32] = Sha256::digest(payload).into();
    if observed != header.evidence_hash {
        return Err(FaultActionCommitError::Fatal(
            FaultRuntimeError::IncompleteAdapterState,
        ));
    }
    Ok(())
}

pub(super) fn transaction_observation(
    action: &ResolvedBindingAction,
    evidence: ContentHash,
) -> FaultObservation {
    let kind = match action.kind {
        BindingActionKind::UpsertPersistent => FaultObservationKind::BindingActivation,
        BindingActionKind::RemovePersistent => FaultObservationKind::BindingDeactivation,
        BindingActionKind::Apply => FaultObservationKind::EffectCommitted,
    };
    FaultObservation {
        semantic_version: FAULT_RUNTIME_STATE_VERSION,
        kind,
        coordinate: action.coordinate,
        binding: Some(action.binding.clone()),
        target: Some(action.target.clone()),
        opportunity: action.opportunity,
        evidence,
    }
}

pub(super) fn transaction_observation_at(
    action: &ResolvedBindingAction,
    retired_instructions: u64,
    evidence: ContentHash,
) -> FaultObservation {
    let mut observation = transaction_observation(action, evidence);
    observation.coordinate.retired_instructions = Some(retired_instructions);
    observation
}
