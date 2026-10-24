//! Builds confirmation declarations before native binding and template construction.
//!
//! The returned manifest and content are declaration data. They install no codec,
//! capture mechanism, factory, source association or restoration permission.

use crate::profile::ProviderError;
use crate::profile::reference_packet::service::confirmation::{
    PACKET_NATIVE_AFTER_CONFIRMATION_FEATURE, PacketNative5ConfirmationSelection,
    native_after_confirmation_contract, native_after_confirmation_schema,
};
use crucible_node_format::{ContentRef, Id, ProviderManifest, SchemaRef, Validate};

/// Retains one selected native provider declaration and its added contract content.
pub struct PacketNative5ConfirmationDeclaration {
    /// Supplies the manifest from which every binding and template tuple is built.
    pub provider: ProviderManifest,
    /// Supplies the exact schema and content only for the selected confirmation.
    pub confirmation: Option<(SchemaRef, ContentRef, Vec<u8>)>,
}

/// Builds the selected declaration before deriving any binding or template hashes.
///
/// None preserves all declared manifest fields. The explicit selected route adds
/// the exact compiled confirmation schema and feature. Callers build the complete
/// provider, binding, owner and initializer tuples from this one result; this
/// helper never patches an already captured coordinator.
///
/// # Errors
/// Refuses invalid or non-complete provider declarations, a conflicting existing
/// confirmation format, or a fixed identifier/schema encoding failure.
pub fn complete_packet_confirmation_declaration(
    provider: &ProviderManifest,
    selection: Option<&PacketNative5ConfirmationSelection>,
) -> Result<PacketNative5ConfirmationDeclaration, ProviderError> {
    provider.validate()?;
    if provider.implementation.implementation_id.as_str() != super::PACKET_NATIVE5_IMPLEMENTATION
        || !provider
            .supported_profiles
            .iter()
            .any(|profile| profile.profile_id.as_str() == super::PACKET_COMPLETE_LINEAGE_PROFILE)
    {
        return Err(ProviderError::Correlation(
            "confirmation declaration requires complete native5",
        ));
    }
    let mut selected = provider.clone();
    let Some(PacketNative5ConfirmationSelection::AfterProtocolPoll5) = selection else {
        return Ok(PacketNative5ConfirmationDeclaration {
            provider: selected,
            confirmation: None,
        });
    };

    let schema = native_after_confirmation_schema()?;
    if let Some(existing) = selected
        .implementation
        .formats
        .iter()
        .find(|format| format.id == schema.id)
    {
        if existing != &schema {
            return Err(ProviderError::Correlation(
                "confirmation declaration schema differs",
            ));
        }
    } else {
        selected.implementation.formats.push(schema.clone());
        selected
            .implementation
            .formats
            .sort_by(|left, right| left.id.cmp(&right.id));
    }
    let feature = Id::new(PACKET_NATIVE_AFTER_CONFIRMATION_FEATURE)?;
    if !selected.extensions_supported.contains(&feature) {
        selected.extensions_supported.push(feature);
        selected.extensions_supported.sort();
    }
    selected.validate()?;

    let bytes = native_after_confirmation_contract()?;
    schema.definition.verify(&bytes)?;
    Ok(PacketNative5ConfirmationDeclaration {
        provider: selected,
        confirmation: Some((schema.clone(), schema.definition, bytes)),
    })
}
