//! Production signal-driven node actions backed by live patched QEMU.
//!
//! Preparation performs only closed-schema and admitted-capability validation.
//! Commit publishes exact-boundary commands and derives durable observations
//! from authenticated QEMU results. Any ambiguous visibility is fatal; it is
//! never converted into an unchanged adapter rejection.

use crate::{QemuNodeSet, qemu_fault_target_hash};
use crucible::model::{
    BindingActionKind, ContentHash, EffectSpecification, FAULT_RUNTIME_STATE_VERSION,
    FaultActionCommitError, FaultActionSink, FaultObservation, FaultObservationKind, FaultPhase,
    FaultResourceLimitError, FaultResourceLimits, FaultRuntimeError, MemoryAddressSpace,
    MemoryMutationAtomicity as ModelMemoryMutationAtomicity, MemoryMutationKind,
    NodeEffectSpecification, NodeId, PreparedActionBatch, PreparedActionResult,
    RejectedActionBatch, ResolvedBindingAction, ResolvedFaultTarget,
};
use crucible_shmem::{
    DequeuedFaultResult, FAULT_COMMAND_ABI_MAJOR, FAULT_COMMAND_ABI_MINOR, FAULT_COMMAND_FLAG_NONE,
    FAULT_COMMAND_FLAG_PREPARE_ONLY, FAULT_COMMAND_SEMANTIC_VERSION, FaultBoundaryPhase,
    FaultCommandHeaderV1, FaultCommandKind, FaultResultStatus,
    MEMORY_MUTATION_BATCH_EVIDENCE_BODY_OFFSET, MEMORY_MUTATION_BATCH_EVIDENCE_PRECONDITION_OFFSET,
    MEMORY_MUTATION_BATCH_EVIDENCE_RECORD_ACTION_HASH_OFFSET,
    MEMORY_MUTATION_BATCH_EVIDENCE_RECORD_BODY_OFFSET,
    MEMORY_MUTATION_BATCH_EVIDENCE_RECORD_LENGTH_OFFSET, MEMORY_MUTATION_NO_VCPU,
    MemoryMutationAddressSpace, MemoryMutationAtomicity, MemoryMutationBatchActionV1,
    MemoryMutationBatchEvidenceV1, MemoryMutationBatchV1, MemoryMutationEvidenceV1,
    MemoryMutationPayloadV1, MemoryMutationTransformKind, NODE_FAULT_EVIDENCE_V1_BYTES,
    NodeFaultEvidenceV1, NodeFaultPayloadV1,
};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

#[path = "fault_action_sink/event_staging.rs"]
mod event_staging;
#[path = "fault_action_sink/evidence.rs"]
mod evidence;
#[path = "fault_action_sink/memory_payload.rs"]
mod memory_payload;
#[path = "fault_action_sink/node_payload.rs"]
mod node_payload;
pub(crate) use node_payload::rule_backed_state_machine;
#[path = "fault_action_sink/result_validation.rs"]
mod result_validation;
#[path = "fault_action_sink/transaction.rs"]
mod transaction;
use evidence::*;
use memory_payload::{memory_batch, memory_batch_evidence_matches, prepare_memory_action_payload};
use result_validation::{
    map_preparation_result_error, reserve_fault_result_storage, stage_apply_commands,
    validate_typed_node_result_decoded,
};
pub(crate) use result_validation::{
    typed_preparation_rejection_evidence, validate_typed_node_result,
};

#[derive(Clone)]
struct PreparedMemoryAction {
    action: ResolvedBindingAction,
    action_id: ContentHash,
    node: NodeId,
    coordinate: u64,
    payload: MemoryMutationPayloadV1,
}

#[derive(Clone)]
struct PreparedQemuBatch {
    transaction: ContentHash,
    results: Vec<PreparedActionResult>,
    nodes: Vec<PreparedQemuNodeBatch>,
    typed_actions: Vec<PreparedTypedNodeAction>,
}

#[derive(Clone)]
struct PreparedQemuNodeBatch {
    node: NodeId,
    coordinate: u64,
    actions: Vec<PreparedMemoryAction>,
}

#[derive(Clone)]
struct PreparedTypedNodeAction {
    action: ResolvedBindingAction,
    action_id: ContentHash,
    node: NodeId,
    coordinate: u64,
    command_kind: FaultCommandKind,
    payload: Vec<u8>,
}

struct AuthorizedQemuNodeBatch {
    prepared: PreparedQemuNodeBatch,
    preparation: MemoryMutationBatchEvidenceV1,
    preparation_evidence_sha256: [u8; 32],
    preparation_evidence_len: usize,
    result_buffer: Vec<u8>,
    mutation_payload: Vec<u8>,
    mutation_sequence: Option<u64>,
    mutation_header: Option<FaultCommandHeaderV1>,
}

struct AuthorizedTypedNodeAction {
    prepared: PreparedTypedNodeAction,
    preparation: NodeFaultEvidenceV1,
    request: NodeFaultPayloadV1,
    result_buffer: Vec<u8>,
    apply_sequence: Option<u64>,
    apply_header: Option<FaultCommandHeaderV1>,
}

/// Authenticated APPLY-result identity retained for occurrence correlation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct CommittedQemuActionEvidence {
    /// Exact QEMU command sequence that installed or applied the action.
    pub(crate) command_sequence: u64,
    /// Numeric [`FaultCommandKind`] carried by the result header.
    pub(crate) command_kind: u16,
    /// QEMU-authenticated state digest before the APPLY mutation.
    pub(crate) before_hash: [u8; 32],
    /// QEMU-authenticated state digest after the APPLY mutation.
    pub(crate) after_hash: [u8; 32],
}

/// A production node-adapter sink that mutates live patched-QEMU backends.
pub struct QemuFaultActionSink<'a> {
    nodes: &'a mut QemuNodeSet,
    prepared: Option<PreparedQemuBatch>,
    committed: Vec<(ContentHash, CommittedQemuActionEvidence)>,
    resource_limits: FaultResourceLimits,
    maximum_event_records: usize,
}

impl<'a> QemuFaultActionSink<'a> {
    /// Binds a transaction sink to the live node set for one scheduler boundary.
    #[must_use]
    pub const fn new(nodes: &'a mut QemuNodeSet, resource_limits: FaultResourceLimits) -> Self {
        Self::new_with_event_limit(
            nodes,
            resource_limits,
            resource_limits.event_records as usize,
        )
    }

    pub(crate) const fn new_with_event_limit(
        nodes: &'a mut QemuNodeSet,
        resource_limits: FaultResourceLimits,
        maximum_event_records: usize,
    ) -> Self {
        Self {
            nodes,
            prepared: None,
            committed: Vec::new(),
            resource_limits,
            maximum_event_records,
        }
    }

    /// Removes APPLY-result identities committed through this transaction sink.
    pub(crate) fn take_committed_evidence(
        &mut self,
    ) -> Vec<(ContentHash, CommittedQemuActionEvidence)> {
        std::mem::take(&mut self.committed)
    }

    fn reject(
        action: Option<&ResolvedBindingAction>,
        error: FaultRuntimeError,
        evidence: ContentHash,
    ) -> Box<RejectedActionBatch> {
        Box::new(RejectedActionBatch {
            error,
            observations: action
                .map(|action| FaultObservation {
                    semantic_version: FAULT_RUNTIME_STATE_VERSION,
                    kind: FaultObservationKind::EffectRejected,
                    coordinate: action.coordinate,
                    binding: Some(action.binding.clone()),
                    target: Some(action.target.clone()),
                    opportunity: action.opportunity,
                    evidence,
                })
                .into_iter()
                .collect(),
            rejected_action: action.map(ResolvedBindingAction::id),
        })
    }

    fn prepare_memory_action(
        &mut self,
        action: &ResolvedBindingAction,
    ) -> Result<PreparedMemoryAction, FaultRuntimeError> {
        let prepared = prepare_memory_action_payload(action, self.resource_limits)?;
        let encoded = prepared
            .payload
            .encode_preparation()
            .map_err(|_source| FaultRuntimeError::AdapterActionMismatch)?;
        let admitted = self
            .nodes
            .fault_capabilities(&prepared.node)
            .map_err(|_source| FaultRuntimeError::AdapterActionMismatch)?
            .iter()
            .any(|row| {
                row.command_kind == FaultCommandKind::MemoryMutation
                    && row.semantic_version == FAULT_COMMAND_SEMANTIC_VERSION
                    && row.supports_phase(FaultBoundaryPhase::NodeBoundary)
                    && usize::try_from(row.maximum_payload_bytes)
                        .is_ok_and(|maximum| encoded.len() <= maximum)
            });
        if !admitted {
            return Err(FaultRuntimeError::AdapterActionMismatch);
        }
        let current = self
            .nodes
            .fault_command_coordinate(&prepared.node)
            .map_err(|_source| FaultRuntimeError::AdapterActionMismatch)?
            .retired;
        let coordinate =
            qemu_execution_coordinate(action.coordinate.retired_instructions, current)?;
        Ok(PreparedMemoryAction {
            action: prepared.action,
            action_id: action.id(),
            node: prepared.node,
            coordinate,
            payload: prepared.payload,
        })
    }

    fn prepare_typed_action(
        &mut self,
        action: &ResolvedBindingAction,
    ) -> Result<PreparedTypedNodeAction, FaultRuntimeError> {
        let provisional = node_payload::encode_node_action(action, [1; 32])
            .map_err(|_source| FaultRuntimeError::AdapterActionMismatch)?;
        let node = NodeId {
            name: provisional.node,
        };
        let (capability_hash, maximum_payload_bytes) = {
            let capability = self
                .nodes
                .fault_capabilities(&node)
                .map_err(|_source| FaultRuntimeError::AdapterActionMismatch)?
                .iter()
                .find(|row| {
                    row.command_kind == provisional.command_kind
                        && row.semantic_version == FAULT_COMMAND_SEMANTIC_VERSION
                        && row.supports_phase(FaultBoundaryPhase::NodeBoundary)
                })
                .ok_or(FaultRuntimeError::AdapterActionMismatch)?;
            (capability.capability_hash, capability.maximum_payload_bytes)
        };
        let encoded = node_payload::encode_node_action(action, capability_hash)
            .map_err(|_source| FaultRuntimeError::AdapterActionMismatch)?;
        let payload = encoded
            .payload
            .encode()
            .map_err(|_source| FaultRuntimeError::AdapterActionMismatch)?;
        if !usize::try_from(maximum_payload_bytes).is_ok_and(|maximum| payload.len() <= maximum) {
            return Err(FaultRuntimeError::AdapterActionMismatch);
        }
        let current = self
            .nodes
            .fault_command_coordinate(&node)
            .map_err(|_source| FaultRuntimeError::AdapterActionMismatch)?
            .retired;
        let coordinate =
            qemu_execution_coordinate(action.coordinate.retired_instructions, current)?;
        Ok(PreparedTypedNodeAction {
            action: action.clone(),
            action_id: action.id(),
            node,
            coordinate,
            command_kind: encoded.command_kind,
            payload,
        })
    }
}

fn qemu_execution_coordinate(
    recorded: Option<u64>,
    current: u64,
) -> Result<u64, FaultRuntimeError> {
    match recorded {
        Some(recorded) if recorded != current => Err(FaultRuntimeError::AdapterActionMismatch),
        Some(recorded) => Ok(recorded),
        None => Ok(current),
    }
}

// crucible-lint: allow rust-allow -- the command header authenticates each independent memory action field.
#[allow(clippy::too_many_arguments)]
fn memory_command_header(
    prepared: &PreparedMemoryAction,
    node: &NodeId,
    coordinate: u64,
    sequence: u64,
    flags: u16,
    expected_precondition_hash: [u8; 32],
    payload: &[u8],
) -> Result<FaultCommandHeaderV1, FaultActionCommitError> {
    let action = &prepared.action;
    Ok(FaultCommandHeaderV1 {
        abi_major: FAULT_COMMAND_ABI_MAJOR,
        abi_minor: FAULT_COMMAND_ABI_MINOR,
        command_kind: FaultCommandKind::MemoryMutation,
        command_flags: flags,
        phase: FaultBoundaryPhase::NodeBoundary,
        semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
        command_sequence: sequence,
        target_node_hash: qemu_fault_target_hash(&node.name),
        target_icount: coordinate,
        authorization_ceiling_icount: coordinate,
        binding_hash: ContentHash::from_canonical_material(
            "crucible.fault-binding.v1",
            action.binding.as_str(),
        )
        .bytes,
        opportunity_hash: action.opportunity.map_or([0; 32], |hash| hash.bytes),
        expected_precondition_hash,
        payload_hash: *blake3::hash(payload).as_bytes(),
        payload_offset: 0,
        payload_length: u32::try_from(payload.len()).map_err(|_source| {
            FaultActionCommitError::Fatal(FaultRuntimeError::AdapterActionMismatch)
        })?,
    })
}

#[cfg(test)]
#[path = "fault_action_sink_tests.rs"]
mod tests;
