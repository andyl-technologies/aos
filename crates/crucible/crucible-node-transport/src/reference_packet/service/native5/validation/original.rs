//! Preserves the exact pre-extraction launch validator as a test-only oracle.
//!
//! Only the receiver and module-relative type paths change. This never issues
//! authority; ordinary fixtures exercise the original full serializer and every
//! original branch rather than treating the new adapter as its own reference.

use super::*;
use crate::reference_packet::Native5Policy;
use crucible_source_birth_data::profile::reference_packet::service::native5_policy::Native5CompleteRestorePolicyInput;

pub(super) fn validate(launch: &PacketNative5SourceLaunch) -> Result<(), ProviderError> {
    crate::connection::serialized_credit(launch, 1024 * 1024)?;
    launch.storage.validate(&launch.limits)?;
    launch.capture_profile.validate()?;
    let owned = matches!(
        launch.capture_profile,
        PacketNative5CaptureProfile::OwnedProtocol11 { .. }
    );
    if owned != launch.protocol_metadata_limits.is_some() {
        return Err(ProviderError::Correlation(
            "native protocol metadata profile differs",
        ));
    }
    if let Some(metadata) = launch.protocol_metadata_limits {
        metadata.validate_data()?;
    }
    if launch.capture_allocation_selection.is_some()
        && (!owned
            || launch.protocol_metadata_limits.is_none()
            || launch.native_codec_metadata_extent
                != Some(crate::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB)
            || launch.ack_emitter_selection
                != Some(service::PacketNative5AckEmitterSelection::CanonicalSdkBlob5))
    {
        return Err(ProviderError::Correlation(
            "native Capture allocation birth tuple",
        ));
    }
    if launch.fresh_restore_allocation_selection.is_some()
            && (!owned
                || launch.protocol_metadata_limits.is_none()
                || launch.native_codec_metadata_extent != Some(crate::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB)
                || launch.ack_emitter_selection != Some(service::PacketNative5AckEmitterSelection::CanonicalSdkBlob5)
                || launch.complete_restore_selection != Some(service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
                || launch.restore_input_emitter_selection != Some(service::complete_restore::PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12))
        {
            return Err(ProviderError::Correlation("native fresh report birth tuple"));
        }
    launch.controller_executable.validate()?;
    launch.selection.provider.validate()?;
    launch.selection.realization.validate()?;
    launch.selection.realize.validate()?;
    let schema = crate::reference_packet::continuation_contracts::complete_packet_ingress_schema()?;
    if launch.schema_version != 5
        || launch.admission_token.as_slice().len() != 32
        || launch.controller_pid.get() == 0
        || launch.controller_pid.get() > i32::MAX as u64
        || launch.controller_uid.get() > u32::MAX as u64
        || !launch
            .selection
            .provider
            .implementation
            .formats
            .contains(&schema)
        || launch.limits.requests.get() < 32
        || launch.limits.requests.get() > 256
        || launch.limits.nesting.get() != 64
        || launch.limits.journal_entries.get() > 4096
    {
        return Err(ProviderError::Correlation(
            "native5 complete private launch",
        ));
    }
    launch
        .initial_coordinator
        .reference
        .verify(launch.initial_coordinator.bytes.as_slice())?;
    if launch.initial_coordinator.reference.media_type != "application/json" {
        return Err(ProviderError::Correlation("native5 coordinator media"));
    }
    crate::reference_packet::coordinator::PacketNative5CoordinatorInstallation::decode(
        launch.initial_coordinator.bytes.as_slice(),
        &launch.selection,
    )?;
    let configuration = match &launch.program {
        PacketConnectedSourceProgram::Producer { program }
            if program.schema == "source-owned.packet-program.v1" && program.events.len() == 2 =>
        {
            serde_json::to_value(program)
        }
        PacketConnectedSourceProgram::Reactive { program }
            if program.schema == "source-owned.packet-connected-program/4"
                && !program.connections.is_empty()
                && program.connections.len() <= 4 =>
        {
            serde_json::to_value(program)
        }
        _ => {
            return Err(ProviderError::Correlation(
                "native5 model configuration edition",
            ));
        }
    }
    .map_err(ContractError::from)?;
    launch
        .selection
        .realize
        .configuration
        .verify(&canonical::canonical_json(&configuration)?)?;
    if launch.restore_input_emitter_selection.is_some() && launch.complete_restore_selection != Some(service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12) {
            return Err(ProviderError::Correlation("native restore input selection lacks transfer12"));
        }
    if let Some(restoration) = launch.complete_restore_selection {
        Native5Policy::from_original_launch_with_complete_restore(
            Native5CompleteRestorePolicyInput {
                selection: launch.selection.clone(),
                coordinator: launch.initial_coordinator.clone(),
                profile: launch.capture_profile.clone(),
                confirmation: launch
                    .confirmation_selection
                    .ok_or(ProviderError::Correlation(
                        "restoring native confirmation absent",
                    ))?,
                emitter: launch
                    .ack_emitter_selection
                    .ok_or(ProviderError::Correlation("restoring native ACK absent"))?,
                extent: launch
                    .native_codec_metadata_extent
                    .ok_or(ProviderError::Correlation(
                        "restoring native codec extent absent",
                    ))?,
                metadata: launch
                    .protocol_metadata_limits
                    .ok_or(ProviderError::Correlation(
                        "restoring native metadata absent",
                    ))?,
                restoration,
            },
        )?
        .with_restore_input_emitter_selection(launch.restore_input_emitter_selection)?
        .with_capture_allocation_selection(launch.capture_allocation_selection)?
        .with_fresh_restore_allocation_selection(launch.fresh_restore_allocation_selection)?;
    } else if let Some(metadata) = launch.protocol_metadata_limits {
        Native5Policy::from_original_launch_with_protocol_metadata(
            launch.selection.clone(),
            launch.initial_coordinator.clone(),
            launch.capture_profile.clone(),
            launch
                .confirmation_selection
                .ok_or(ProviderError::Correlation(
                    "owned native confirmation absent",
                ))?,
            launch
                .ack_emitter_selection
                .ok_or(ProviderError::Correlation("owned native ACK absent"))?,
            launch
                .native_codec_metadata_extent
                .ok_or(ProviderError::Correlation(
                    "owned native codec extent absent",
                ))?,
            metadata,
        )?
        .with_capture_allocation_selection(launch.capture_allocation_selection)?
        .with_fresh_restore_allocation_selection(launch.fresh_restore_allocation_selection)?;
    } else if let Some(emitter) = launch.ack_emitter_selection {
        let confirmation = launch
            .confirmation_selection
            .ok_or(ProviderError::Correlation(
                "canonical ACK emitter requires selected confirmation",
            ))?;
        if let Some(extent) = launch.native_codec_metadata_extent {
            Native5Policy::from_original_launch_with_ack_emitter_metadata_extent(
                launch.selection.clone(),
                launch.initial_coordinator.clone(),
                launch.capture_profile.clone(),
                confirmation,
                emitter,
                extent,
            )?;
        } else {
            Native5Policy::from_original_launch_with_ack_emitter(
                launch.selection.clone(),
                launch.initial_coordinator.clone(),
                launch.capture_profile.clone(),
                confirmation,
                emitter,
            )?;
        }
    } else if launch.native_codec_metadata_extent.is_some() {
        return Err(ProviderError::Correlation(
            "native codec extent requires canonical ACK selection",
        ));
    } else if let Some(confirmation) = launch.confirmation_selection {
        // Additional source grammar is authenticated before any service
        // allocation or listener effect; selecting it grants no mechanism.
        Native5Policy::from_original_launch_with_confirmation(
            launch.selection.clone(),
            launch.initial_coordinator.clone(),
            launch.capture_profile.clone(),
            confirmation,
        )?;
    } else {
        Native5Policy::from_original_launch(
            launch.selection.clone(),
            launch.initial_coordinator.clone(),
        )?;
    }
    Ok(())
}
