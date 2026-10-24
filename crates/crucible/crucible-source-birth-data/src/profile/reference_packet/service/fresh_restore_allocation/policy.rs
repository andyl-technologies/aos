//! Validates complete immutable fresh allocation definitions without negotiation.

use super::*;
use crate::profile::ProviderError;
use crate::profile::reference_packet::control::PacketControlSelection;
use crucible_node_format::ContentRef;

/// Returns the original five immutable fresh allocation schema definitions.
///
/// # Errors
/// Reports fixed contract encoding or identifier failure.
pub fn selected_schemas() -> Result<[crucible_node_format::SchemaRef; 5], ProviderError> {
    use PacketNativeFreshRestoreAllocationSchema as S;
    Ok([
        fresh_restore_allocation_schema(S::Query)?,
        fresh_restore_allocation_schema(S::Report)?,
        fresh_restore_allocation_schema(S::Proof)?,
        fresh_restore_allocation_schema(S::Receipt)?,
        fresh_restore_allocation_schema(S::PrepareBinding)?,
    ])
}

/// Validates the original immutable fresh allocation schema selection as DATA.
///
/// # Errors
/// Refuses a missing, changed or unsupported complete contract selection.
pub fn validate_selection_content(
    selection: &PacketControlSelection,
    definitions: &[ContentRef; 5],
) -> Result<(), ProviderError> {
    let schemas = selected_schemas()?;
    if schemas.iter().zip(definitions).any(|(schema, actual)| {
        &schema.definition != actual
            || !selection.provider.implementation.formats.contains(schema)
            || selection.realization.bindings.iter().any(|binding| {
                !binding
                    .compatibility
                    .implementation
                    .formats
                    .contains(schema)
            })
    }) || !selection
        .provider
        .extensions_supported
        .iter()
        .any(|feature| feature.as_str() == PACKET_FRESH_RESTORE_ALLOCATION_FEATURE)
    {
        return Err(refused());
    }
    Ok(())
}

/// Returns the original family correlation error without protocol effects.
pub fn refused() -> ProviderError {
    ProviderError::Correlation("selected fresh restoration allocation grammar differs")
}
