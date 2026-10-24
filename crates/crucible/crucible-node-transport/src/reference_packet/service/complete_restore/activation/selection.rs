//! Checks full immutable activation rosters before lending target routing data.

use super::*;
use crate::{handshake::ConnectionAuthority, reference_packet::control::PacketControlSelection};

/// Checks both complete immutable format rosters and the negotiated activation key.
///
/// This borrows existing schemas and uses only fixed hash/comparison views. It
/// never constructs a schema DTO or authenticates a Source MAC or phase claim.
///
/// # Errors
/// Refuses a missing, duplicated or altered full definition, an empty binding
/// roster, a missing provider feature or unnegotiated feature/extension key.
pub fn authenticate_restoration_activation_selection_data(
    selection: &PacketControlSelection,
    authority: &ConnectionAuthority,
) -> Result<(), ProviderError> {
    for (feature, authenticate) in SCHEMAS {
        authenticate_formats(
            &selection.provider.implementation.formats,
            feature,
            authenticate,
        )?;
        if selection.realization.bindings.is_empty() {
            return Err(invalid());
        }
        for binding in &selection.realization.bindings {
            authenticate_formats(
                &binding.compatibility.implementation.formats,
                feature,
                authenticate,
            )?;
        }
        if !selection
            .provider
            .extensions_supported
            .iter()
            .any(|one| one.as_str() == feature)
            || !authority
                .selected_features()
                .iter()
                .any(|one| one.as_str() == feature)
            || !authority.envelope_extensions().contains(feature)
        {
            return Err(invalid());
        }
    }
    authority.ensure_live()
}

type SchemaAuthenticator = fn(&crucible_node_format::SchemaRef) -> Result<(), ProviderError>;
type FeatureAuthenticator = (&'static str, SchemaAuthenticator);
const SCHEMAS: [FeatureAuthenticator; 2] = [
    (
        PACKET_RESTORATION_ACTIVATION_FEATURE,
        authenticate_restoration_activation_schema_data,
    ),
    (
        upload::PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE,
        upload::authenticate_restoration_activation_upload_schema_data,
    ),
];

fn authenticate_formats(
    formats: &[crucible_node_format::SchemaRef],
    feature: &str,
    authenticate: SchemaAuthenticator,
) -> Result<(), ProviderError> {
    let mut matched = None;
    for schema in formats {
        if schema.id.as_str() == feature && matched.replace(schema).is_some() {
            return Err(invalid());
        }
    }
    let schema = matched.ok_or_else(invalid)?;
    authenticate(schema)
}

pub(super) fn counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<[FeatureAuthenticator; 2]>()
        + size_of::<std::array::IntoIter<FeatureAuthenticator, 2>>()
        + size_of::<FeatureAuthenticator>()
        + size_of::<&[crucible_node_format::SchemaRef]>()
        + size_of::<std::slice::Iter<'static, crucible_node_format::SchemaRef>>()
        + size_of::<Option<&crucible_node_format::SchemaRef>>()
        + size_of::<Result<&crucible_node_format::SchemaRef, ProviderError>>()
        + size_of::<std::slice::Iter<'static, crucible_node_format::NodeBinding>>()
        + size_of::<std::slice::Iter<'static, Id>>()
        + size_of::<&str>()
        + size_of::<SchemaAuthenticator>()
        + size_of::<Result<(), ProviderError>>()
}
