//! Adds fixed restore definitions before provider, binding and template hashes.

use crate::{
    ProviderError,
    reference_packet::service::{
        PacketNative5ConfirmationSelection,
        ack_emitter::PacketNative5AckEmitterSelection,
        complete_restore::{
            PacketNative5CompleteRestoreSelection, complete_restore_selected_contracts,
            complete_restore_selected_features,
        },
    },
};
use crucible_node_format::{ProviderManifest, SchemaRef, Validate};

/// Retains a prehash complete provider declaration and its fixed restore bodies.
pub struct PacketNative5CompleteRestoreDeclaration {
    /// Retains the exact confirmation and ACK declaration used by all tuples.
    pub peer: super::PacketNative5AckEmitterDeclaration,
    /// Retains the exact selected restore bodies, empty for the original None route.
    pub restoration: Vec<(SchemaRef, Vec<u8>)>,
}

/// Builds all selected restoration grammar before deriving any binding hashes.
///
/// None delegates unchanged to the existing selected ACK declaration. The caller
/// constructs every provider/binding/template tuple from this single result.
/// It must not patch an already captured coordinator.
///
/// # Errors
/// Refuses restore without confirmation/ACK, conflicting full schemas, invalid
/// provider data or failure to encode a fixed complete contract body.
pub fn complete_packet_restore_declaration(
    provider: &ProviderManifest,
    confirmation: Option<&PacketNative5ConfirmationSelection>,
    ack: Option<&PacketNative5AckEmitterSelection>,
    restoration: Option<&PacketNative5CompleteRestoreSelection>,
) -> Result<PacketNative5CompleteRestoreDeclaration, ProviderError> {
    let mut peer = super::complete_packet_ack_emitter_declaration(provider, confirmation, ack)?;
    let mut definitions = Vec::new();
    if let Some(selection) = restoration {
        if ack != Some(&PacketNative5AckEmitterSelection::CanonicalSdkBlob5)
            || confirmation != Some(&PacketNative5ConfirmationSelection::AfterProtocolPoll5)
        {
            return Err(ProviderError::Correlation(
                "complete restore declaration requires ACK peer",
            ));
        }
        for (schema, body) in complete_restore_selected_contracts(*selection)? {
            if let Some(existing) = peer
                .provider
                .implementation
                .formats
                .iter()
                .find(|format| format.id == schema.id)
            {
                if existing != &schema {
                    return Err(ProviderError::Correlation(
                        "complete restore declaration schema differs",
                    ));
                }
            } else {
                peer.provider.implementation.formats.push(schema.clone());
            }
            if !peer.provider.extensions_supported.contains(&schema.id) {
                peer.provider.extensions_supported.push(schema.id.clone());
            }
            definitions.push((schema, body));
        }
        for feature in complete_restore_selected_features(*selection) {
            if !peer
                .provider
                .extensions_supported
                .iter()
                .any(|name| name.as_str() == feature)
            {
                peer.provider
                    .extensions_supported
                    .push(crucible_node_format::Id::new(feature)?);
            }
        }
        peer.provider
            .implementation
            .formats
            .sort_by(|a, b| a.id.cmp(&b.id));
        peer.provider.extensions_supported.sort();
        peer.provider.validate()?;
    }
    Ok(PacketNative5CompleteRestoreDeclaration {
        peer,
        restoration: definitions,
    })
}

/// Builds the distinct canonical restore-input declaration before tuple hashes.
///
/// None delegates exactly to the existing complete restoration declaration.
/// Some adds the fixed writer definition and feature only under selected12; it
/// is not an envelope extension and does not issue a live writer or upload lease.
///
/// # Errors
/// Refuses the writer without selected12, conflicting full schema references or
/// unsupported fixed provider declaration data.
pub fn complete_packet_restore_input_emitter_declaration(
    provider: &ProviderManifest,
    confirmation: Option<&PacketNative5ConfirmationSelection>,
    ack: Option<&PacketNative5AckEmitterSelection>,
    restoration: Option<&PacketNative5CompleteRestoreSelection>,
    input_emitter: Option<&crate::reference_packet::service::complete_restore::PacketNative5RestoreInputEmitterSelection>,
) -> Result<PacketNative5CompleteRestoreDeclaration, ProviderError> {
    let mut declaration =
        complete_packet_restore_declaration(provider, confirmation, ack, restoration)?;
    if input_emitter.is_none() {
        return Ok(declaration);
    }
    use crate::reference_packet::service::complete_restore::{
        PACKET_CANONICAL_RESTORE_INPUTS_FEATURE, PacketNative5RestoreInputEmitterSelection,
        canonical_restore_inputs_contract, canonical_restore_inputs_schema,
    };
    if restoration != Some(&PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        || input_emitter
            != Some(&PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12)
    {
        return Err(ProviderError::Correlation(
            "canonical restore input writer requires selected12",
        ));
    }
    let schema = canonical_restore_inputs_schema()?;
    let formats = &mut declaration.peer.provider.implementation.formats;
    if let Some(existing) = formats.iter().find(|format| format.id == schema.id) {
        if existing != &schema {
            return Err(ProviderError::Correlation(
                "canonical restore input writer schema differs",
            ));
        }
    } else {
        formats.push(schema.clone());
    }
    let features = &mut declaration.peer.provider.extensions_supported;
    if !features
        .iter()
        .any(|feature| feature.as_str() == PACKET_CANONICAL_RESTORE_INPUTS_FEATURE)
    {
        features.push(crucible_node_format::Id::new(
            PACKET_CANONICAL_RESTORE_INPUTS_FEATURE,
        )?);
    }
    formats.sort_by(|a, b| a.id.cmp(&b.id));
    features.sort();
    declaration
        .restoration
        .push((schema, canonical_restore_inputs_contract()?));
    declaration.peer.provider.validate()?;
    Ok(declaration)
}

/// Adds the original Observe report family before provider and binding hashes.
///
/// None delegates exactly to the previous restoration-input declaration. Some
/// records both complete schema definitions and the content feature. The caller
/// must also select the owning profile, native metadata banks and native codec
/// before Source birth; this declaration creates no live observer or admission.
///
/// # Errors
/// Refuses missing confirmation/ACK, conflicting full schemas or invalid fixed
/// provider declaration data.
pub fn complete_packet_capture_allocation_declaration(
    provider: &ProviderManifest,
    confirmation: Option<&PacketNative5ConfirmationSelection>,
    ack: Option<&PacketNative5AckEmitterSelection>,
    restoration: Option<&PacketNative5CompleteRestoreSelection>,
    input_emitter: Option<&crate::reference_packet::service::complete_restore::PacketNative5RestoreInputEmitterSelection>,
    capture_allocation: Option<&crate::reference_packet::service::capture_allocation::PacketNative5CaptureAllocationSelection>,
) -> Result<PacketNative5CompleteRestoreDeclaration, ProviderError> {
    let mut declaration = complete_packet_restore_input_emitter_declaration(
        provider,
        confirmation,
        ack,
        restoration,
        input_emitter,
    )?;
    if capture_allocation.is_none() {
        return Ok(declaration);
    }
    if confirmation != Some(&PacketNative5ConfirmationSelection::AfterProtocolPoll5)
        || ack != Some(&PacketNative5AckEmitterSelection::CanonicalSdkBlob5)
    {
        return Err(ProviderError::Correlation(
            "capture allocation requires original ACK peer",
        ));
    }
    use crate::reference_packet::service::capture_allocation::{
        PACKET_NATIVE_CAPTURE_ALLOCATION_FEATURE, capture_allocation_contract,
        capture_allocation_record_schema, capture_allocation_schema,
    };
    let body = capture_allocation_contract()?;
    for schema in [
        capture_allocation_schema()?,
        capture_allocation_record_schema()?,
    ] {
        let formats = &mut declaration.peer.provider.implementation.formats;
        if let Some(existing) = formats.iter().find(|format| format.id == schema.id) {
            if existing != &schema {
                return Err(ProviderError::Correlation(
                    "capture allocation full schema differs",
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
        .any(|feature| feature.as_str() == PACKET_NATIVE_CAPTURE_ALLOCATION_FEATURE)
    {
        features.push(crucible_node_format::Id::new(
            PACKET_NATIVE_CAPTURE_ALLOCATION_FEATURE,
        )?);
    }
    declaration
        .peer
        .provider
        .implementation
        .formats
        .sort_by(|a, b| a.id.cmp(&b.id));
    features.sort();
    declaration.peer.provider.validate()?;
    Ok(declaration)
}
