//! Allocation-aware validation of QEMU node-action results.

use super::*;

pub(super) fn reserve_fault_result_storage(
    resource_limits: FaultResourceLimits,
    requested: usize,
) -> Result<Vec<u8>, FaultActionCommitError> {
    let requested = u64::try_from(requested).map_err(|_source| {
        FaultActionCommitError::Fatal(FaultRuntimeError::AdapterActionMismatch)
    })?;
    resource_limits
        .reserve("effect_payload_bytes", 0, requested)
        .map_err(|source| {
            FaultActionCommitError::Fatal(FaultRuntimeError::ResourceLimit(source))
        })?;
    let capacity = usize::try_from(requested).map_err(|_source| {
        FaultActionCommitError::Fatal(FaultRuntimeError::AdapterActionMismatch)
    })?;
    let mut storage = Vec::new();
    storage.try_reserve_exact(capacity).map_err(|_| {
        FaultActionCommitError::Fatal(FaultRuntimeError::ResourceLimit(
            FaultResourceLimitError::Exceeded {
                field: "effect_payload_bytes",
                current: 0,
                requested,
                configured: resource_limits.effect_payload_bytes,
                hard: FaultResourceLimits::compiled_maximum().effect_payload_bytes,
            },
        ))
    })?;
    Ok(storage)
}

pub(super) fn map_preparation_result_error(source: crate::QemuNodeError) -> FaultActionCommitError {
    match source {
        crate::QemuNodeError::FaultResultStorage {
            requested,
            configured,
        } => FaultActionCommitError::Fatal(FaultRuntimeError::ResourceLimit(
            FaultResourceLimitError::Exceeded {
                field: "effect_payload_bytes",
                current: 0,
                requested,
                configured,
                hard: FaultResourceLimits::compiled_maximum().effect_payload_bytes,
            },
        )),
        _ => FaultActionCommitError::Fatal(FaultRuntimeError::AdapterTransactionRollback),
    }
}

pub(super) fn stage_apply_commands(
    nodes: &mut QemuNodeSet,
    memory: &mut [AuthorizedQemuNodeBatch],
    typed: &mut [AuthorizedTypedNodeAction],
) -> Result<(), FaultActionCommitError> {
    for authorized in memory {
        let sequence = nodes
            .reserve_fault_command_sequence(&authorized.prepared.node)
            .map_err(|_source| {
                FaultActionCommitError::Fatal(FaultRuntimeError::SequenceOverflow(
                    "qemu_fault_command",
                ))
            })?;
        let header = memory_command_header(
            authorized
                .prepared
                .actions
                .first()
                .ok_or(FaultActionCommitError::Fatal(
                    FaultRuntimeError::IncompleteAdapterState,
                ))?,
            &authorized.prepared.node,
            authorized.prepared.coordinate,
            sequence,
            FAULT_COMMAND_FLAG_NONE,
            authorized.preparation.precondition_sha256,
            &authorized.mutation_payload,
        )?;
        authorized.mutation_sequence = Some(sequence);
        authorized.mutation_header = Some(header);
    }
    for authorized in typed {
        let sequence = nodes
            .reserve_fault_command_sequence(&authorized.prepared.node)
            .map_err(|_source| {
                FaultActionCommitError::Fatal(FaultRuntimeError::SequenceOverflow(
                    "qemu_fault_command",
                ))
            })?;
        let header = typed_command_header(
            &authorized.prepared,
            authorized.prepared.coordinate,
            sequence,
            FAULT_COMMAND_FLAG_NONE,
            authorized.preparation.before_sha256,
        )?;
        authorized.apply_sequence = Some(sequence);
        authorized.apply_header = Some(header);
    }
    Ok(())
}

pub(crate) fn validate_typed_node_result(
    request_payload: &[u8],
    result: DequeuedFaultResult,
    expected_status: FaultResultStatus,
) -> Result<NodeFaultEvidenceV1, FaultActionCommitError> {
    let request = NodeFaultPayloadV1::decode(request_payload).map_err(|_source| {
        FaultActionCommitError::Fatal(FaultRuntimeError::IncompleteAdapterState)
    })?;
    validate_typed_node_result_decoded(&request, request_payload, result, expected_status)
        .map(|(evidence, _result_buffer)| evidence)
}

pub(super) fn validate_typed_node_result_decoded(
    request: &NodeFaultPayloadV1,
    request_payload: &[u8],
    result: DequeuedFaultResult,
    expected_status: FaultResultStatus,
) -> Result<(NodeFaultEvidenceV1, Vec<u8>), FaultActionCommitError> {
    let DequeuedFaultResult::Valid {
        header,
        payload: evidence_bytes,
    } = result
    else {
        return Err(FaultActionCommitError::Fatal(
            FaultRuntimeError::IncompleteAdapterState,
        ));
    };
    verify_qemu_evidence_hash(&header, &evidence_bytes)?;
    if header.status != expected_status {
        return Err(FaultActionCommitError::Fatal(
            FaultRuntimeError::AdapterActionMismatch,
        ));
    }
    let evidence = NodeFaultEvidenceV1::decode(&evidence_bytes).map_err(|_source| {
        FaultActionCommitError::Fatal(FaultRuntimeError::IncompleteAdapterState)
    })?;
    let request_sha256: [u8; 32] = Sha256::digest(request_payload).into();
    if evidence.command_kind != request.command_kind
        || evidence.operation != request.operation
        || evidence.target_kind != request.target_kind
        || evidence.model_phase != request.model_phase
        || evidence.generation != request.generation
        || evidence.action_hash != request.action_hash
        || evidence.target_hash != request.target_hash
        || evidence.schema_hash != request.schema_hash
        || evidence.request_sha256 != request_sha256
        || header.before_hash != evidence.before_sha256
        || header.after_hash != evidence.after_sha256
    {
        return Err(FaultActionCommitError::Fatal(
            FaultRuntimeError::IncompleteAdapterState,
        ));
    }
    Ok((evidence, evidence_bytes))
}
