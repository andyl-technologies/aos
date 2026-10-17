//! Compares every original restoration target against immutable launch custody.
//!
//! Completed Prepare reuses the coordinator validation performed at the SAME
//! verified birth. Commit's existing route retains its independent full decoder.

use super::*;
use crate::reference_packet::coordinator::PacketNative5CoordinatorInstallation;

pub(in super::super) fn authenticate_target(
    launch: &PacketNative5SourceLaunch,
    request: &PacketCompleteRestorePrepareRequest,
    original: &Envelope,
    authority: &ConnectionAuthority,
) -> Result<(), ProviderError> {
    let coordinator = PacketNative5CoordinatorInstallation::decode(
        launch.initial_coordinator.bytes.as_slice(),
        &launch.selection,
    )?;
    authenticate_target_fields(launch, request, original, authority, &coordinator)
}

pub(super) fn authenticate_verified_prepare_target(
    boot: &NativeAckBoot,
    launch: &PacketNative5SourceLaunch,
    request: &PacketCompleteRestorePrepareRequest,
    original: &Envelope,
    authority: &ConnectionAuthority,
) -> Result<(), ProviderError> {
    boot.ensure_origin()?;
    if !boot.ready
        || !boot.verified
        || boot.original.is_none()
        || boot.context.is_none()
        || boot.proof.is_none()
    {
        return Err(refused());
    }
    // The caller just decoded this SAME immutable boot launch. Its initial
    // coordinator bytes were fully validated by launch.validate in verify_admit.
    // Preserve bounded duplicate/unknown refusal and typed decoding; do not
    // regenerate participant schemas and identities from the unchanged bank.
    let coordinator = decode_immutable_coordinator(launch.initial_coordinator.bytes.as_slice())?;
    authenticate_target_fields(launch, request, original, authority, &coordinator)
}

fn decode_immutable_coordinator(
    bytes: &[u8],
) -> Result<PacketNative5CoordinatorInstallation, ProviderError> {
    let value = canonical::parse_json(
        bytes,
        crate::reference_packet::coordinator::PACKET_NATIVE5_COORDINATOR_INSTALLATION_BYTES,
    )?;
    PacketNative5CoordinatorInstallation::deserialize(value)
        .map_err(ContractError::from)
        .map_err(Into::into)
}

fn authenticate_target_fields(
    launch: &PacketNative5SourceLaunch,
    request: &PacketCompleteRestorePrepareRequest,
    original: &Envelope,
    authority: &ConnectionAuthority,
    coordinator: &PacketNative5CoordinatorInstallation,
) -> Result<(), ProviderError> {
    let binding = launch
        .selection
        .realization
        .bindings
        .first()
        .ok_or_else(refused)?;
    let owner = launch
        .selection
        .realization
        .owner_bindings
        .first()
        .ok_or_else(refused)?;
    let RequestBody::Begin(begin) = decode_request(original.method, &original.body)? else {
        return Err(refused());
    };
    let BeginArguments::PrepareRestore(arguments) = begin.decoded_arguments()? else {
        return Err(refused());
    };
    let activation = &coordinator.template["activation"];
    let target = &request.restoration;
    if launch.complete_restore_selection
        != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        || original.session_id.0.as_ref() != Some(authority.session_id())
        || original.incarnation_id.0.as_ref() != Some(authority.incarnation_id())
        || original.node_id.0.as_ref() != Some(&binding.compatibility.node_id)
        || original.capture_owner_id.0.as_ref() != Some(&owner.owner.id)
        || original.execution_owner_id.0.is_some()
        || original.operation_id.0.is_none()
        || target.target_world != launch.selection.world
        || target.target_owner != owner.owner.id
        || target.target_owner_binding != owner.identity()?
        || target.target_owner_generation != binding.authority.owner_generation
        || serde_json::to_value(&target.target_activation).map_err(ContractError::from)?
            != activation["activation_id"]
        || serde_json::to_value(target.target_generation).map_err(ContractError::from)?
            != activation["generation"]
        || begin.binding_hash != target.target_owner_binding
        || begin.activation_id.0.as_ref() != Some(&target.target_activation)
        || begin.world_generation != target.target_generation
        || begin.owner_generation != target.target_owner_generation
        || !begin.extensions.is_empty()
        || arguments.transaction_id != request.transaction_id
        || arguments.capture_manifest != target.capture_manifest
        || arguments.expected_world_binding_hash != target.target_world
        || arguments.expected_owner_binding_hash != target.target_owner_binding
        || arguments.destination_owner_ids.len() != 1
        || arguments.destination_owner_ids.first() != Some(&target.target_owner)
    {
        return Err(refused());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn reused_decoder_matches_actual_fully_validated_original_coordinator_data() -> TestResult {
        let (_handshake, _authority, selection, original) =
            crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
        let validated =
            PacketNative5CoordinatorInstallation::decode(original.bytes.as_slice(), &selection)?;
        let reused = decode_immutable_coordinator(original.bytes.as_slice())?;
        assert_eq!(reused, validated);
        Ok(())
    }

    #[test]
    fn reused_decoder_keeps_duplicate_unknown_and_extent_refusals() -> TestResult {
        let (_handshake, _authority, selection, original) =
            crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
        let validated =
            PacketNative5CoordinatorInstallation::decode(original.bytes.as_slice(), &selection)?;
        let mut value = serde_json::to_value(validated)?;
        value
            .as_object_mut()
            .ok_or("coordinator fixture object")?
            .insert("unrecognized".to_owned(), serde_json::Value::Null);
        assert!(decode_immutable_coordinator(&canonical::canonical_json(&value)?).is_err());
        assert!(decode_immutable_coordinator(br#"{"schema":"one","schema":"two"}"#).is_err());
        assert!(decode_immutable_coordinator(&vec![b' '; 384 * 1024 + 1]).is_err());
        Ok(())
    }
}
