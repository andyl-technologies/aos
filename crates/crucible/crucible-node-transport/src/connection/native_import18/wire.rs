//! Validates closed Native18 transport vocabulary without issuing native rights.

use super::*;
use crate::bodies::{BeginArguments, OperationState, ResponseShape};

/// Checks the new family's exact transport shapes before old-family dispatch.
///
/// # Errors
/// Refuses a selected malformed/foreign frame, changed full roster or receipt.
pub(in crate::connection) fn verify_selected_wire_data(
    selection: &PacketControlSelection,
    authority: &ConnectionAuthority,
    envelope: &Envelope,
    body: &ReceivedBody,
) -> Result<bool, ProviderError> {
    let phase = [
        PacketNativeImport18Phase::Prepare,
        PacketNativeImport18Phase::Commit,
    ]
    .into_iter()
    .find(|phase| {
        envelope.extensions.contains_key(phase.proof_extension())
            || envelope.extensions.contains_key(phase.receipt_extension())
    });
    let Some(phase) = phase else {
        if envelope.extensions.contains_key(NATIVE_IMPORT18_EXTENSION) {
            return Err(invalid());
        }
        return Ok(false);
    };
    authenticate_selection_data(selection, authority)?;
    match (envelope.message, body) {
        (MessageKind::Request, ReceivedBody::Request(request))
            if matches!(request.as_ref(), RequestBody::Begin(begin)
                if matches!(begin.decoded_arguments()?, BeginArguments::PrepareRestore(_))) =>
        {
            authenticate_request_data(selection, authority, envelope, phase, true)?;
        }
        (MessageKind::Response, ReceivedBody::Response(response)) => {
            if envelope.extensions.len() != 1
                || !matches!(
                    &response.shape,
                    ResponseShape::Completed {
                        operation_state: OperationState::Completed,
                        ..
                    }
                )
                || !matches!(
                    response.result,
                    Some(crate::bodies::MethodResult::PrepareRestore(_))
                )
            {
                return Err(invalid());
            }
            let value = envelope
                .extensions
                .get(phase.receipt_extension())
                .ok_or_else(invalid)?;
            match phase {
                PacketNativeImport18Phase::Prepare => {
                    PacketNativeImport17PrepareReceipt::deserialize(value)
                        .map_err(crucible_node_format::ContractError::from)?
                        .validate_data()?;
                }
                PacketNativeImport18Phase::Commit => {
                    PacketNativeImport17CommitReceipt::deserialize(value)
                        .map_err(crucible_node_format::ContractError::from)?
                        .validate_data()?;
                }
            }
        }
        _ => return Err(invalid()),
    }
    authority.ensure_live()?;
    Ok(true)
}

/// Checks one unsigned or sealed new-family request without creating a token.
///
/// # Errors
/// Refuses a changed header, unknown key, phase or typed payload/proof grammar.
pub(super) fn authenticate_request_data(
    selection: &PacketControlSelection,
    authority: &ConnectionAuthority,
    original: &Envelope,
    phase: PacketNativeImport18Phase,
    sealed: bool,
) -> Result<(), ProviderError> {
    let [binding] = selection.realization.bindings.as_slice() else {
        return Err(invalid());
    };
    let [owner] = selection.realization.owners.as_slice() else {
        return Err(invalid());
    };
    original.validate()?;
    if original.message != MessageKind::Request
        || original.method != Method::Begin
        || original.node_id.0.as_ref() != Some(&binding.compatibility.node_id)
        || original.execution_owner_id.0.as_ref() != Some(&owner.id)
        || original.session_id.0.as_ref() != Some(authority.session_id())
        || original.incarnation_id.0.as_ref() != Some(authority.incarnation_id())
        || original.capture_owner_id.0.is_some()
        || original.operation_id.0.is_some()
        || original.extensions.len() != if sealed { 3 } else { 2 }
        || original.extensions.keys().any(|key| {
            key != phase.request_extension()
                && key != NATIVE_IMPORT18_EXTENSION
                && (key != phase.proof_extension() || !sealed)
        })
    {
        return Err(invalid());
    }
    let RequestBody::Begin(begin) = bodies::decode_request(original.method, &original.body)? else {
        return Err(invalid());
    };
    if !matches!(
        begin.decoded_arguments()?,
        BeginArguments::PrepareRestore(_)
    ) || !begin.extensions.is_empty()
    {
        return Err(invalid());
    }
    let binding = PacketNativeImport18Binding::deserialize(
        original
            .extensions
            .get(NATIVE_IMPORT18_EXTENSION)
            .ok_or_else(invalid)?,
    )
    .map_err(crucible_node_format::ContractError::from)?;
    let value = original
        .extensions
        .get(phase.request_extension())
        .ok_or_else(invalid)?;
    match phase {
        PacketNativeImport18Phase::Prepare => {
            let request = PacketCompleteRestorePrepareRequest::deserialize(value)
                .map_err(crucible_node_format::ContractError::from)?;
            let expected = expected_backend_schema_data(selection, &binding)?;
            binding.authenticate_prepare_data(&request, expected)?;
        }
        PacketNativeImport18Phase::Commit => {
            let request = PacketCompleteRestoreCommitRequest::deserialize(value)
                .map_err(crucible_node_format::ContractError::from)?;
            request.validate_data()?;
            let expected = expected_backend_schema_data(selection, &binding)?;
            binding.authenticate_prepare_data(&request.prepare, expected)?;
        }
    }
    if sealed {
        PacketNativeImport17Proof::deserialize(
            original
                .extensions
                .get(phase.proof_extension())
                .ok_or_else(invalid)?,
        )
        .map_err(crucible_node_format::ContractError::from)?
        .validate_data(phase.payload_phase_data())?;
    }
    Ok(())
}

/// Borrows the complete declared archived-format definition from actual selection.
///
/// This is transport compatibility DATA. The Source/cold issuer still binds its
/// independently authenticated archive definition and fresh target compatibility.
fn expected_backend_schema_data<'a>(
    selection: &'a PacketControlSelection,
    binding: &PacketNativeImport18Binding,
) -> Result<&'a SchemaRef, ProviderError> {
    let (id, version) = binding.native_family.snapshot_schema_data();
    let mut formats = selection
        .provider
        .implementation
        .formats
        .iter()
        .filter(|format| format.id.as_str() == id && format.version == version);
    let expected = formats.next().ok_or_else(invalid)?;
    if formats.next().is_some() {
        return Err(invalid());
    }
    Ok(expected)
}
