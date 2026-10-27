//! Binds explicit stage18 selection to exact baseline request and terminal DATA.

use super::*;
use crate::bodies::{
    OperationState, RequestBody, ResponseShape, decode_request, decode_response_shape,
};
use crate::envelope::{Envelope, MessageKind};
use crate::reference_packet::service::complete_restore::activation::PacketRestorationActivationTarget;
use crucible_node_format::ContractError;

/// Hashes a stage18 assigned request after removing only its own stage17 proof.
///
/// The full stage binding is mandatory and every other extension is refused.
/// Actual selected full18 definitions, current SDK ownership, genuine once
/// admission and physical effects remain the live issuers' separate duties.
/// All serialization and owning output requires independent construction credit.
///
/// # Errors
/// Refuses another method/kind, foreign routing, missing stage binding, any
/// unrelated extension, invalid baseline body or bounded canonical failure.
pub fn native_import18_stage_assigned_request_digest(
    original: &Envelope,
    phase: PacketNativeImport17Stage,
    maximum_frame_bytes: usize,
) -> Result<[u8; 32], ProviderError> {
    original.validate()?;
    if original.message != MessageKind::Request
        || original.method != phase.method_data()
        || original.request_id.0.is_none()
        || original.node_id.0.is_none()
        || original.execution_owner_id.0.is_none()
        || original.capture_owner_id.0.is_some()
        || original.operation_id.0.is_some()
        || !original
            .extensions
            .contains_key(NATIVE_IMPORT17_STAGE_EXTENSION)
        || original
            .extensions
            .keys()
            .any(|key| key != NATIVE_IMPORT17_STAGE_EXTENSION && key != phase.proof_extension())
    {
        return Err(invalid());
    }
    decode_request(original.method, &original.body)?;
    assigned(original, phase.proof_extension(), maximum_frame_bytes)
}

/// Hashes a completed same-stage terminal after removing only its own receipt.
///
/// Actual retained literal publication and physical truth remain independent.
///
/// # Errors
/// Refuses changed correlation, missing request proof, foreign extensions,
/// accepted/error/noncompleted status or bounded canonical failure.
pub fn native_import18_stage_assigned_response_digest(
    original: &Envelope,
    response: &Envelope,
    phase: PacketNativeImport17Stage,
    maximum_frame_bytes: usize,
) -> Result<[u8; 32], ProviderError> {
    native_import18_stage_assigned_request_digest(original, phase, maximum_frame_bytes)?;
    if !original.extensions.contains_key(phase.proof_extension()) {
        return Err(invalid());
    }
    response.validate()?;
    original.matches_response(response)?;
    if response
        .extensions
        .keys()
        .any(|key| key != phase.receipt_extension())
    {
        return Err(invalid());
    }
    match decode_response_shape(&response.body)? {
        ResponseShape::Completed {
            operation_state: OperationState::Completed,
            extensions,
            ..
        } if extensions.is_empty() => {}
        _ => return Err(invalid()),
    }
    assigned(response, phase.receipt_extension(), maximum_frame_bytes)
}

pub(super) fn authenticate_target_data(
    original: &Envelope,
    target: &PacketRestorationActivationTarget,
    phase: PacketNativeImport17Stage,
) -> Result<(), ProviderError> {
    if original.session_id.0.as_ref() != Some(&target.session)
        || original.incarnation_id.0.as_ref() != Some(&target.incarnation)
        || original.node_id.0.as_ref() != Some(&target.node)
        || original.execution_owner_id.0.as_ref() != Some(&target.owner)
    {
        return Err(invalid());
    }
    let matches = match (phase, decode_request(original.method, &original.body)?) {
        (PacketNativeImport17Stage::Arm, RequestBody::Activate(body)) => {
            body.admission_id == target.admission
                && body.activation_id == target.activation
                && body.world_generation == target.generation
                && body.prepared_token == target.prepared_token
                && body.world_binding_hash == target.world
                && body.gate_id == target.gate
                && body.extensions.is_empty()
        }
        (PacketNativeImport17Stage::World, RequestBody::WorldActivate(body)) => {
            body.transaction_id == target.transaction
                && body.activation_id == target.activation
                && body.world_generation == target.generation
                && body.prepared_token == target.prepared_token
                && body.world_binding_hash == target.world
                && body.gate_id == target.gate
                && body.extensions.is_empty()
        }
        (PacketNativeImport17Stage::FirstObserve, RequestBody::Observe(body)) => {
            body.binding_hash == target.binding_hash
                && body.owner_generation == target.owner_generation
                && body.after_observation_sequence.get() == 0
                && body.maximum_items.get() == 1
                && body.extensions.is_empty()
        }
        _ => false,
    };
    if !matches {
        return Err(invalid());
    }
    Ok(())
}

fn assigned(
    original: &Envelope,
    excluded: &str,
    maximum: usize,
) -> Result<[u8; 32], ProviderError> {
    crate::connection::serialized_credit(original, maximum)?;
    let mut value = serde_json::to_value(original).map_err(ContractError::from)?;
    value
        .get_mut("extensions")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(invalid)?
        .remove(excluded);
    Ok(*blake3::hash(&bounded(&value, maximum)?).as_bytes())
}
