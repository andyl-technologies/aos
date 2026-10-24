//! Projects immutable Hello roster geometry without authority.

use super::*;
use crate::profile::serialization_storage::OriginalSerializationStorageProjection as Projection;

/// Adds the exact fixed feature roster to the shared geometry visitor.
///
/// # Errors
/// Preserves checked projection overflow or maximum refusal.
pub fn project_features_data(
    out: &mut Projection,
    declaration: &PacketNativeImport18HelloDeclarationData,
) -> Result<(), ProviderError> {
    out.add_array_extent(declaration.feature_count)?;
    for feature in declaration.features.iter().flatten() {
        out.add_string(feature)?;
    }
    Ok(())
}

/// Adds the exact fixed envelope-key roster to the shared geometry visitor.
///
/// # Errors
/// Preserves checked projection overflow or maximum refusal.
pub fn project_keys_data(
    out: &mut Projection,
    declaration: &PacketNativeImport18HelloDeclarationData,
) -> Result<(), ProviderError> {
    out.add_array_extent(declaration.key_count)?;
    for (key, _) in declaration.keys.iter().flatten() {
        out.add_string(key)?;
    }
    Ok(())
}
