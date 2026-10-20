//! Adds the full fresh query family before original binding hashes are derived.

use super::*;
use crate::reference_packet::service::{
    PacketNative5ConfirmationSelection,
    ack_emitter::PacketNative5AckEmitterSelection,
    capture_allocation::PacketNative5CaptureAllocationSelection,
    complete_restore::{
        PacketNative5CompleteRestoreSelection, PacketNative5RestoreInputEmitterSelection,
    },
    fresh_restore_allocation::{
        PACKET_FRESH_RESTORE_ALLOCATION_FEATURE, PacketNative5FreshRestoreAllocationSelection,
        PacketNativeFreshRestoreAllocationSchema, fresh_restore_allocation_contract,
        fresh_restore_allocation_schema,
    },
};
use crucible_node_format::{ProviderManifest, Validate};

/// Adds all five fresh allocation definitions before provider and binding hashes.
///
/// None delegates exactly to the original capture-allocation declaration. Some
/// records the corrected full query/report/proof/body-receipt/PrepareBinding
/// grammar and feature. This fixes declaration data without constructing a
/// report, startup grant, query ticket or complete preparation permission.
///
/// # Errors
/// Refuses incompatible restoration/input/ACK selections, changed full schema
/// definitions, invalid provider data or fixed-contract serialization failure.
pub fn complete_packet_fresh_restore_allocation_declaration(
    provider: &ProviderManifest,
    confirmation: Option<&PacketNative5ConfirmationSelection>,
    ack: Option<&PacketNative5AckEmitterSelection>,
    restoration: Option<&PacketNative5CompleteRestoreSelection>,
    input: Option<&PacketNative5RestoreInputEmitterSelection>,
    capture: Option<&PacketNative5CaptureAllocationSelection>,
    fresh: Option<&PacketNative5FreshRestoreAllocationSelection>,
) -> Result<PacketNative5CompleteRestoreDeclaration, ProviderError> {
    let mut declaration = complete_packet_capture_allocation_declaration(
        provider,
        confirmation,
        ack,
        restoration,
        input,
        capture,
    )?;
    if fresh.is_none() {
        return Ok(declaration);
    }
    if restoration != Some(&PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        || input != Some(&PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12)
        || confirmation != Some(&PacketNative5ConfirmationSelection::AfterProtocolPoll5)
        || ack != Some(&PacketNative5AckEmitterSelection::CanonicalSdkBlob5)
    {
        return Err(ProviderError::Correlation(
            "fresh allocation requires original complete transfer12",
        ));
    }
    let body = fresh_restore_allocation_contract()?;
    for member in [
        PacketNativeFreshRestoreAllocationSchema::Query,
        PacketNativeFreshRestoreAllocationSchema::Report,
        PacketNativeFreshRestoreAllocationSchema::Proof,
        PacketNativeFreshRestoreAllocationSchema::Receipt,
        PacketNativeFreshRestoreAllocationSchema::PrepareBinding,
    ] {
        let schema = fresh_restore_allocation_schema(member)?;
        let formats = &mut declaration.peer.provider.implementation.formats;
        if let Some(original) = formats.iter().find(|format| format.id == schema.id) {
            if original != &schema {
                return Err(ProviderError::Correlation(
                    "fresh allocation full schema differs",
                ));
            }
        } else {
            formats.push(schema.clone());
        }
        declaration.restoration.push((schema, body.clone()));
    }
    let features = &mut declaration.peer.provider.extensions_supported;
    if !features
        .iter()
        .any(|feature| feature.as_str() == PACKET_FRESH_RESTORE_ALLOCATION_FEATURE)
    {
        features.push(Id::new(PACKET_FRESH_RESTORE_ALLOCATION_FEATURE)?);
    }
    declaration
        .peer
        .provider
        .implementation
        .formats
        .sort_by(|left, right| left.id.cmp(&right.id));
    features.sort();
    declaration.peer.provider.validate()?;
    Ok(declaration)
}
