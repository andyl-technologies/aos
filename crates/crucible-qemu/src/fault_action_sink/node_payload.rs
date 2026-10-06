//! Translation from resolved signal actions to the public QEMU node payload.

use crucible::model::{
    AcceleratorTransition, BindingActionCause, BindingActionKind, ClockMonotonicityPolicy,
    ClockMutation, ClockOverdueTimerPolicy, ContentHash, CpuServiceDiscipline, EffectKind,
    EffectSpecification, FaultObjectId, FaultPhase, InstructionMutation, InterruptMutation,
    MappedEffectParameter, MemoryAccessMutation, MemoryAddressSpace, MemoryEccKind,
    MemoryRegionKind, NodeEffectSpecification, NodeHangScope, NodeLifecycleTransition,
    NodeStatePolicy, OpportunityPayload, RegisterMutation, ResolvedBindingAction,
    ResolvedFaultTarget, ResolvedMappingOutput, SignalValue, VcpuState,
};
use crucible_shmem::{
    FaultCommandKind, NODE_FAULT_POLICY_JSON_MAGIC_V1, NodeFaultFieldV1, NodeFaultOperationV1,
    NodeFaultPayloadError, NodeFaultPayloadV1, NodeFaultTargetKindV1, fault_object_id_hash_v1,
    node_fault_field,
};
use sha2::{Digest, Sha256};

/// Fully encoded non-memory-impulse action and its owning QEMU node.
pub(super) struct EncodedNodeAction {
    pub(super) node: String,
    pub(super) command_kind: FaultCommandKind,
    pub(super) payload: NodeFaultPayloadV1,
}

pub(super) fn encode_node_action(
    action: &ResolvedBindingAction,
    schema_hash: [u8; 32],
) -> Result<EncodedNodeAction, NodeFaultPayloadError> {
    let command_kind =
        command_kind(action.effect.specification()).ok_or(NodeFaultPayloadError::CommandKind(0))?;
    if !effect_matches_target(action.effect.specification(), &action.target) {
        return Err(NodeFaultPayloadError::TargetValue);
    }
    let (node, target_kind, mut target_fields) = target_fields(&action.target)?;
    let operation = match action.kind {
        BindingActionKind::UpsertPersistent => NodeFaultOperationV1::Upsert,
        BindingActionKind::RemovePersistent => NodeFaultOperationV1::Remove,
        BindingActionKind::Apply if rule_backed_state_machine(command_kind) => {
            NodeFaultOperationV1::Upsert
        }
        BindingActionKind::Apply => NodeFaultOperationV1::Apply,
    };
    let mut fields = payload_fields(
        operation,
        action.effect.specification(),
        &action.cause,
        &mut target_fields,
    )?;
    materialize_memory_latency(action, operation, &mut fields)?;
    let payload = NodeFaultPayloadV1 {
        command_kind,
        operation,
        target_kind,
        model_phase: phase_tag(action.phase),
        generation: action.transition_sequence,
        action_hash: action.id().bytes,
        target_hash: ContentHash::from_canonical_material(
            "crucible.resolved-fault-target.v1",
            &action.target.canonical_material(),
        )
        .bytes,
        schema_hash,
        fields,
    };
    payload.encode()?;
    Ok(EncodedNodeAction {
        node,
        command_kind,
        payload,
    })
}

/// Applies an authored nanosecond mapping to the native picosecond contract.
///
/// The mapped output is part of the resolved action's authenticated identity.
/// Encoding the template alone would record a changing latency while executing
/// a constant native rule. Removal carries no parameters and preserves its
/// existing wire contract.
fn materialize_memory_latency(
    action: &ResolvedBindingAction,
    operation: NodeFaultOperationV1,
    fields: &mut [NodeFaultFieldV1],
) -> Result<(), NodeFaultPayloadError> {
    if action.effect.kind() != EffectKind::MemoryService
        || operation == NodeFaultOperationV1::Remove
    {
        return Ok(());
    }
    let picoseconds = materialized_memory_service_latency(action)?;
    let field_error = || NodeFaultPayloadError::FieldValue {
        tag: node_fault_field::P1,
    };
    let field = fields
        .iter_mut()
        .find(|field| field.tag == node_fault_field::P1)
        .ok_or_else(field_error)?;
    *field = NodeFaultFieldV1::u64(node_fault_field::P1, picoseconds);
    Ok(())
}

/// Resolves the same configured latency for command encoding and event admission.
pub(crate) fn materialized_memory_service_latency(
    action: &ResolvedBindingAction,
) -> Result<u64, NodeFaultPayloadError> {
    let field_error = || NodeFaultPayloadError::FieldValue {
        tag: node_fault_field::P1,
    };
    let EffectSpecification::Node(NodeEffectSpecification::MemoryService {
        latency_picoseconds,
        bandwidth_bytes_per_second,
        operations_per_second,
        ..
    }) = action.effect.specification()
    else {
        return Err(field_error());
    };
    let picoseconds = match action.mapping_output.as_ref() {
        ResolvedMappingOutput::Parameter {
            parameter: MappedEffectParameter::DurationNanos,
            value,
        } => {
            let SignalValue::DurationNanos(nanoseconds) = value else {
                return Err(field_error());
            };
            nanoseconds
                .checked_mul(crucible::SIM_TICKS_PER_NS)
                .filter(|ticks| *ticks <= i64::MAX as u64)
                .ok_or_else(field_error)?
        }
        _ => *latency_picoseconds,
    };
    if picoseconds == 0 && bandwidth_bytes_per_second.is_none() && operations_per_second.is_none() {
        return Err(field_error());
    }
    Ok(picoseconds)
}

/// Identifies state-machine commands represented by one replaceable QEMU rule.
///
/// The signal runtime records each state transition as an `Apply` action. QEMU
/// implements these commands as durable keyed rules whose replacement performs
/// the transition, so their wire operation is `Upsert`; the committed host
/// observation remains the original one-shot state-machine action.
pub(crate) const fn rule_backed_state_machine(command_kind: FaultCommandKind) -> bool {
    matches!(
        command_kind,
        FaultCommandKind::CpuService
            | FaultCommandKind::CpuVcpuState
            | FaultCommandKind::InterruptStorm
            | FaultCommandKind::MemoryRegionState
            | FaultCommandKind::MemoryService
            | FaultCommandKind::ClockSourceState
            | FaultCommandKind::AcceleratorLifecycle
            | FaultCommandKind::AcceleratorService
    )
}

#[path = "node_payload/effect_fields.rs"]
mod effect_fields;
#[path = "node_payload/encoding.rs"]
mod encoding;
#[path = "node_payload/payload.rs"]
mod payload;

use effect_fields::*;
use encoding::*;
use payload::*;

#[cfg(test)]
#[path = "node_payload_test.rs"]
mod tests;
