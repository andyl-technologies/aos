//! Checks the full independent observation contract on the same immutable route.

use super::*;
use crate::{handshake::ConnectionAuthority, reference_packet::control::PacketControlSelection};
use crucible_node_format::SchemaRef;

/// Checks both immutable full rosters and actual negotiated observation support.
///
/// # Errors
/// Refuses missing activation/upload prerequisites, absent or duplicate full
/// observation definitions, empty binding rosters or missing feature/key support.
/// Matching DATA does not authenticate publication or grant observation effects.
pub fn authenticate_restoration_observe_selection_data(
    selection: &PacketControlSelection,
    authority: &ConnectionAuthority,
) -> Result<(), ProviderError> {
    super::super::activation::authenticate_restoration_activation_selection_data(
        selection, authority,
    )?;
    formats(&selection.provider.implementation.formats)?;
    if selection.realization.bindings.is_empty() {
        return Err(invalid());
    }
    for binding in &selection.realization.bindings {
        formats(&binding.compatibility.implementation.formats)?;
    }
    let mut advertised = false;
    for feature in &selection.provider.extensions_supported {
        if feature.as_str() == PACKET_RESTORATION_OBSERVE_FEATURE {
            advertised = true;
        }
    }
    let mut negotiated = false;
    for feature in authority.selected_features() {
        if feature.as_str() == PACKET_RESTORATION_OBSERVE_FEATURE {
            negotiated = true;
        }
    }
    if !advertised
        || !negotiated
        || !authority
            .envelope_extensions()
            .contains(PACKET_RESTORATION_OBSERVE_FEATURE)
    {
        return Err(invalid());
    }
    authority.ensure_live()
}

fn formats(formats: &[SchemaRef]) -> Result<(), ProviderError> {
    let mut matched = None;
    for schema in formats {
        if schema.id.as_str() == PACKET_RESTORATION_OBSERVE_FEATURE
            && matched.replace(schema).is_some()
        {
            return Err(invalid());
        }
    }
    authenticate_restoration_observe_schema_data(matched.ok_or_else(invalid)?)
}

pub(super) fn counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<&PacketControlSelection>()
        + size_of::<&ConnectionAuthority>()
        + size_of::<&[SchemaRef]>()
        + size_of::<std::slice::Iter<'static, SchemaRef>>()
        + size_of::<Option<&SchemaRef>>()
        + size_of::<Result<&SchemaRef, ProviderError>>()
        + size_of::<std::slice::Iter<'static, crucible_node_format::NodeBinding>>()
        + size_of::<std::slice::Iter<'static, crucible_node_format::Id>>()
        + 2 * size_of::<bool>()
        + size_of::<&crucible_node_format::NodeBinding>()
        + size_of::<&crucible_node_format::Id>()
        + size_of::<&SchemaRef>()
        + size_of::<&str>()
}
