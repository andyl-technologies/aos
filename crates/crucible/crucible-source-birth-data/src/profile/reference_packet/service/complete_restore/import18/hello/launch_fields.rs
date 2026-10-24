//! Derives the same closed Hello declaration from borrowed nonsecret fields.
//!
//! This adapter carries no launch token, effects path, process capability or
//! Source permission. The ordinary full-launch entry uses this same schedule.

use super::*;

// The new full-launch wrapper constructs and returns one fixed Fields view,
// keeps it through the shared call, then returns the existing declaration type.
// Both view and introduced call headers are separate from all old roster work.
pub(super) const REAL_INPUT_HEADERS: usize =
    size_of::<PacketNative5LaunchValidationFields<'static>>()
        + size_of::<PacketNative5LaunchValidationFields<'static>>()
        + size_of::<PacketNative5LaunchValidationFields<'static>>()
        + size_of::<&'static PacketNative5SourceLaunch>()
        + size_of::<&'static PacketNative5LaunchValidationFields<'static>>()
        + size_of::<Result<PacketNativeImport18HelloDeclarationData, ProviderError>>();

/// Derives the original Hello roster from inert borrowed launch fields.
///
/// This pure check neither authenticates the supplied fields nor creates Hello,
/// registration or native authority. The parent independently binds the worker
/// inputs and any returned banks to its original operation.
///
/// # Errors
/// Preserves the original required tuple, sole-binding and fixed-roster refusals.
pub fn native_import18_hello_declaration_from_fields_data(
    fields: &PacketNative5LaunchValidationFields<'_>,
) -> Result<PacketNativeImport18HelloDeclarationData, ProviderError> {
    if fields.schema_version != 5
        || fields.ack_emitter_selection.is_none()
        || fields.confirmation_selection.is_none()
        || fields.protocol_metadata_limits.is_none()
        || fields.selection.realization.bindings.len() != 1
    {
        return Err(refused());
    }
    declaration_for_selections_data(
        fields.complete_restore_selection,
        fields.capture_allocation_selection.is_some(),
        fields.fresh_restore_allocation_selection.is_some(),
    )
}
