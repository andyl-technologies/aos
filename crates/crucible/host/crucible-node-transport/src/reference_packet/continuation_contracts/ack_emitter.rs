//! Builds complete peer declarations before any binding or template hashes.
//!
//! This module adds fixed grammar data. It constructs no source permit, host
//! writer lease, native admission marker, factory or restoration authority.

use crate::ProviderError;
use crate::reference_packet::service::{
    PacketNative5ConfirmationSelection,
    ack_emitter::{
        PACKET_CANONICAL_ACK_ADMISSION_FEATURE, PACKET_NATIVE_CANONICAL_ACK_FEATURE,
        PacketNative5AckEmitterSelection, native_canonical_ack_admission_contract,
        native_canonical_ack_admission_schema, native_canonical_blob_ack_contract,
        native_canonical_blob_ack_schema,
    },
};
use crucible_node_format::{ContentRef, Id, ProviderManifest, SchemaRef, Validate};

/// Retains one full selected provider and its independently available contract bodies.
pub struct PacketNative5AckEmitterDeclaration {
    /// Supplies the provider from which every binding and owner tuple is built.
    pub provider: ProviderManifest,
    /// Supplies the selected confirmation contract, absent for the old route.
    pub confirmation: Option<(SchemaRef, ContentRef, Vec<u8>)>,
    /// Supplies the selected canonical ACK contract, absent for generic peers.
    pub ack_emitter: Option<(SchemaRef, ContentRef, Vec<u8>)>,
    /// Supplies the independently registered assigned-Admit proof contract.
    pub admission: Option<(SchemaRef, ContentRef, Vec<u8>)>,
}

/// Builds confirmation and ACK grammar declarations before deriving binding hashes.
///
/// None selections preserve the complete original provider. The caller uses
/// this one result to construct all provider, binding, owner and template tuples;
/// this helper never modifies an already captured coordinator.
///
/// # Errors
/// Refuses invalid provider data, an ACK selection without confirmation, a
/// conflicting existing ACK schema or fixed contract encoding failure.
pub fn complete_packet_ack_emitter_declaration(
    provider: &ProviderManifest,
    confirmation: Option<&PacketNative5ConfirmationSelection>,
    ack_emitter: Option<&PacketNative5AckEmitterSelection>,
) -> Result<PacketNative5AckEmitterDeclaration, ProviderError> {
    if ack_emitter.is_some()
        && confirmation != Some(&PacketNative5ConfirmationSelection::AfterProtocolPoll5)
    {
        return Err(ProviderError::Correlation(
            "canonical ACK declaration requires confirmation",
        ));
    }
    let selected = super::complete_packet_confirmation_declaration(provider, confirmation)?;
    let mut provider = selected.provider;
    let Some(PacketNative5AckEmitterSelection::CanonicalSdkBlob5) = ack_emitter else {
        return Ok(PacketNative5AckEmitterDeclaration {
            provider,
            confirmation: selected.confirmation,
            ack_emitter: None,
            admission: None,
        });
    };

    let schema = native_canonical_blob_ack_schema()?;
    let admission_schema = native_canonical_ack_admission_schema()?;
    for selected_schema in [&schema, &admission_schema] {
        if let Some(existing) = provider
            .implementation
            .formats
            .iter()
            .find(|format| format.id == selected_schema.id)
        {
            if existing != selected_schema {
                return Err(ProviderError::Correlation(
                    "canonical ACK declaration schema differs",
                ));
            }
        } else {
            provider
                .implementation
                .formats
                .push(selected_schema.clone());
        }
    }
    provider
        .implementation
        .formats
        .sort_by(|left, right| left.id.cmp(&right.id));

    for selected_feature in [
        PACKET_NATIVE_CANONICAL_ACK_FEATURE,
        PACKET_CANONICAL_ACK_ADMISSION_FEATURE,
    ] {
        let feature = Id::new(selected_feature)?;
        if !provider.extensions_supported.contains(&feature) {
            provider.extensions_supported.push(feature);
        }
    }
    provider.extensions_supported.sort();
    provider.validate()?;

    let bytes = native_canonical_blob_ack_contract()?;
    schema.definition.verify(&bytes)?;
    let admission_bytes = native_canonical_ack_admission_contract()?;
    admission_schema.definition.verify(&admission_bytes)?;
    Ok(PacketNative5AckEmitterDeclaration {
        provider,
        confirmation: selected.confirmation,
        ack_emitter: Some((schema.clone(), schema.definition, bytes)),
        admission: Some((
            admission_schema.clone(),
            admission_schema.definition,
            admission_bytes,
        )),
    })
}
