//! Authenticates full suffix selection independently of live action authority.

use super::*;
use crate::{handshake::ConnectionAuthority, reference_packet::control::PacketControlSelection};
use crucible_node_format::SchemaRef;

/// Checks the full format rosters and actual independently negotiated feature.
///
/// This feature adds an upfront private allocation family. It is deliberately
/// not a request extension and cannot relax the baseline Input4 verifier.
///
/// # Errors
/// Refuses missing earlier restoration/Observe prerequisites, missing/duplicate
/// full suffix definitions, absent bindings or unavailable actual negotiation.
pub fn authenticate_restoration_suffix_selection_data(
    selection: &PacketControlSelection,
    authority: &ConnectionAuthority,
) -> Result<(), ProviderError> {
    crate::reference_packet::service::complete_restore::restoration_observe::authenticate_restoration_observe_selection_data(selection, authority)?;
    formats(&selection.provider.implementation.formats)?;
    if selection.realization.bindings.is_empty() {
        return Err(invalid());
    }
    for binding in &selection.realization.bindings {
        formats(&binding.compatibility.implementation.formats)?;
    }
    if !selection
        .provider
        .extensions_supported
        .iter()
        .any(|feature| feature.as_str() == PACKET_RESTORATION_SUFFIX_FEATURE)
        || !authority
            .selected_features()
            .iter()
            .any(|feature| feature.as_str() == PACKET_RESTORATION_SUFFIX_FEATURE)
    {
        return Err(invalid());
    }
    authority.ensure_live()
}

fn formats(rows: &[SchemaRef]) -> Result<(), ProviderError> {
    let mut found = None;
    for row in rows {
        if row.id.as_str() == PACKET_RESTORATION_SUFFIX_FEATURE && found.replace(row).is_some() {
            return Err(invalid());
        }
    }
    authenticate_restoration_suffix_schema_data(found.ok_or_else(invalid)?)
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
        + size_of::<std::slice::Iter<'static, crucible_node_format::Id>>() * 2
        + size_of::<&crucible_node_format::NodeBinding>()
        + size_of::<&crucible_node_format::Id>()
        + size_of::<&SchemaRef>()
        + size_of::<&str>()
        + restoration_suffix_schema_counter_scratch_data()
        + crate::reference_packet::service::complete_restore::restoration_observe::restoration_observe_protocol_counter_scratch_data()
}
