//! Owned host-model adapters and authenticated native node preparation.
//!
//! Models retain their existing continuation codecs. Qualified host profiles
//! execute authentic staged requests and pending events within exact grants,
//! preserving original input, publication and native receipt custody. The
//! controlled reference child provides a distinct coarse quantized profile.
//! Native gem5 preparation retains real resources beneath a qualification gate.

pub mod arm_root;
pub mod cnp;
mod condition_debug_model;
pub use condition_debug_model::{
    ConditionDebugDefinition, ConditionDebugModel, ConditionHitCandidate,
};
mod faulted_link;
pub mod gem5;
mod host;
mod host_ingress;
pub use host_ingress::{
    RecordedIngressDefinition, RecordedLogicalInput, RecordedLogicalInputSource,
    validate_recorded_input_source,
};
mod inventory;
mod packet_receiver;
mod preparation_state;
mod rate_alarm_clock;
pub use host::rate_alarm_evidence::{
    RATE_ALARM_PRODUCER_SPECIFICATION, host_rate_alarm_producer_schema,
};
mod reference_device;
pub use rate_alarm_clock::{
    RateAlarmClock, RateAlarmClockDefinition, RateAlarmClockEvent, RateAlarmClockRequest,
    host_rate_alarm_clock_schema,
};
mod scripted_source;
mod seeded_link;
pub use faulted_link::controlled::{
    AuthoredFaultTransition, ControlledFaultLink, ControlledFaultProgram, FaultCoefficients,
};
pub use faulted_link::{FaultDecision, FaultProbability, FaultedInput, FaultedLinkDefinition};
pub use packet_receiver::PacketReceiver;
pub use seeded_link::SeededLinkDefinition;
pub mod transcript;

pub use scripted_source::{
    MAXIMUM_SCRIPTED_REQUESTS, ScriptedRequest, ScriptedRequestKind, ScriptedSource,
};

pub use host::{
    HOST_EXACT_PROFILE, HOST_FAULT_INJECTION_PROFILE, HOST_PHYSICAL_PAUSE_PROFILE,
    HOST_PRESERVATION_PROFILE, HOST_PUBLIC_CLOCK_CONTINUATION_PROFILE,
    HOST_PUBLIC_CLOCK_CONTINUATION_SPECIFICATION, HOST_PUBLIC_CLOCK_EPOCH_CONTINUATION_PROFILE,
    HOST_PUBLIC_CLOCK_PREPARATION_SPECIFICATION, HOST_PUBLIC_OWNED_MODEL_PREPARATION_SPECIFICATION,
    HostContinuationInventory, HostModel, HostModelNode, HostModelQualification,
    HostModelResources, host_clock_initial_bytes, host_public_clock_continuation_schema,
    host_public_clock_epoch_continuation_schema, host_public_clock_preparation_schema,
    reopen_condition_model, validate_host_continuation, validate_public_clock_continuation,
};
pub use inventory::{
    CurrentPort, CurrentPortKind, CurrentWorldInventory, CurrentWorldParticipant,
    WorldInventoryError,
};

pub use reference_device::{
    REFERENCE_DEVICE_QUANTIZED_PROFILE, ReferenceDeviceNode, ReferenceDeviceQualification,
    reference_device_initial_bytes,
};

/// Owns selected assertion model state without issuing native qualification.
pub mod semantic_model;
pub use semantic_model::{
    HostSemanticDefinition, HostSemanticInput, HostSemanticInputKind, HostSemanticModel,
};

// Checks the selected dependency grammar and actual byte closure only; current
// native/source binding remains the responsibility of the owning runtime.
pub(crate) fn verify_condition_dependency_closure(
    roots: Vec<crucible_node_contract::ContentRef>,
    objects: &[&crate::node_scheduling::InputPayload],
    maximum_objects: usize,
    maximum_bytes: usize,
) -> Result<(), crate::node_contract::OperationFailure> {
    let mut store = condition_debug_model::dag::EvidenceDag::new(maximum_objects, maximum_bytes);
    for object in objects {
        store.insert(
            object.reference.clone(),
            &object.bytes,
            condition_debug_model::ConditionDebugModel::original_dependencies(&object.bytes)?,
        )?;
    }
    store.encode(roots)?;
    Ok(())
}

// Runtime edition six uses the same complete byte-bearing DAG grammar. These
// crate-local adapters provide data encoding only; installed native verification
// remains mandatory before any fresh control or execution authority is minted.
pub(crate) fn encode_condition_dependency_dag(
    roots: Vec<crucible_node_contract::ContentRef>,
    objects: &[&crate::node_scheduling::InputPayload],
    maximum_objects: usize,
    maximum_bytes: usize,
) -> Result<Vec<u8>, crate::node_contract::OperationFailure> {
    let mut store = condition_debug_model::dag::EvidenceDag::new(maximum_objects, maximum_bytes);
    for object in objects {
        store.insert(
            object.reference.clone(),
            &object.bytes,
            condition_debug_model::ConditionDebugModel::original_dependencies(&object.bytes)?,
        )?;
    }
    store.encode(roots)
}

pub(crate) fn decode_condition_dependency_dag(
    bytes: &[u8],
    maximum_objects: usize,
    maximum_bytes: usize,
) -> Result<
    (
        Vec<crate::node_scheduling::InputPayload>,
        Vec<crucible_node_contract::ContentRef>,
    ),
    crate::node_contract::OperationFailure,
> {
    let (store, roots) =
        condition_debug_model::dag::EvidenceDag::decode(bytes, maximum_objects, maximum_bytes)?;
    let objects = store
        .objects()
        .map(|object| crate::node_scheduling::InputPayload {
            reference: object.reference.clone(),
            bytes: object.bytes.as_slice().to_vec(),
        })
        .collect();
    Ok((objects, roots))
}

/// Decodes dependency references from the selected original condition codecs.
///
/// The result describes byte dependencies only. It authenticates no producer,
/// native owner, current stopped cut, durable publication or restore operation.
///
/// # Errors
/// Refuses malformed selected records or a body beyond the 16 MiB native limit.
pub fn condition_evidence_dependencies(
    bytes: &[u8],
) -> Result<Vec<crucible_node_contract::ContentRef>, crate::node_contract::OperationFailure> {
    if bytes.len() > 16 << 20 {
        return Err(crate::node_contract::OperationFailure {
            effects: crate::node_contract::EffectKnowledge::None,
            reason: "condition original dependency body exceeds native ceiling".into(),
        });
    }
    condition_debug_model::ConditionDebugModel::original_dependencies(bytes)
}

/// Borrows the fixed specification for the distinct complete rational-clock envelope.
pub fn rate_alarm_clock_specification() -> &'static str {
    rate_alarm_clock::RATE_ALARM_CLOCK_SPECIFICATION
}
