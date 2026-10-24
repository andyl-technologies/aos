//! Selects historical archive grammar independently of future Capture selection.
//!
//! A signed InitialInvocation15 key remains native schema14. The new Settled17
//! branch is distinct; neither branch rewrites a key or revives archived rights.

use super::*;
use crate::node_contract::NativeStateKey;
use crucible_node_transport::reference_packet::service::native_snapshot::{
    authenticate_native_owned14_snapshot_schema_data,
    authenticate_native_restored_settled17_snapshot_schema_data,
};

/// Identifies a supported signed historical native family as inert DATA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompleteHistoricalArchiveFamily {
    /// Selects the unchanged genuine invocation15 archive (native schema14).
    InitialInvocation15,
    /// Selects the distinct current-state and immutable-DAG settled17 reader.
    Settled17,
}

impl PacketCompleteSemanticSource {
    /// Classifies the actual archived key beneath one explicitly selected17 Source.
    ///
    /// Both code and fresh target Sources retain that same future selection.
    /// Only the signed historical key chooses its decoder. This method validates
    /// immutable correspondence DATA; it does not validate archive provenance,
    /// construct a cold owner, issue a ticket or authorize native installation.
    ///
    /// # Errors
    /// Refuses another creator/selection, missing or duplicated preservation
    /// facet, altered full schema or unequal implementation/provider/binding rows.
    pub fn supported_complete_historical_archive_family_data(
        &self,
        key: &NativeStateKey,
    ) -> Result<CompleteHistoricalArchiveFamily, OperationFailure> {
        self.ensure_origin()?;
        self.original_restored_settled_capture_schema_data()?;
        let installed = self.installation();
        let mut preservation = None;
        for facet in &installed.profile.operation_facets {
            if facet.id.as_str() == "source-owned.packet-complete-original-lineage/5" {
                if facet.version != 5 || preservation.replace(&facet.id).is_some() {
                    return Err(refused(
                        "historical preservation facet differs or is duplicate",
                    ));
                }
            }
        }
        let preservation =
            preservation.ok_or_else(|| refused("historical preservation facet absent"))?;
        classify(
            key,
            &installed.provider.implementation.implementation_id,
            &installed
                .binding
                .compatibility
                .implementation
                .implementation_id,
            preservation,
            &installed.provider.implementation.formats,
            &installed.binding.compatibility.implementation.formats,
        )
    }

    /// Names fixed full-schema and historical-family comparison views.
    pub fn supported_complete_historical_archive_family_counter_scratch_data() -> usize {
        size_of::<CompleteHistoricalArchiveFamily>()
            + size_of::<Result<CompleteHistoricalArchiveFamily, OperationFailure>>()
            + size_of::<&NativeStateKey>() + size_of::<&Self>()
            + 2 * size_of::<&Id>() + 2 * size_of::<&[SchemaRef]>()
            + 3 * size_of::<std::slice::Iter<'static, SchemaRef>>()
            + size_of::<std::slice::Iter<'static, crucible_node_format::FacetSelection>>()
            + 2 * size_of::<&crucible_node_format::FacetSelection>()
            + size_of::<Option<&crucible_node_format::FacetSelection>>()
            + size_of::<Result<&crucible_node_format::FacetSelection, OperationFailure>>()
            + 3 * size_of::<&SchemaRef>()
            + size_of::<Result<(), OperationFailure>>()
            + size_of::<Result<(), crucible_node_transport::ProviderError>>()
            + size_of::<usize>() + size_of::<Option<usize>>()
            + Self::original_restored_settled_capture_schema_counter_scratch_data()
            + crucible_node_transport::reference_packet::service::native_snapshot::native_owned14_snapshot_schema_counter_scratch_data()
            + crucible_node_transport::reference_packet::service::native_snapshot::native_restored_settled17_snapshot_schema_counter_scratch_data()
    }
}

fn classify(
    key: &NativeStateKey,
    provider_implementation: &Id,
    binding_implementation: &Id,
    preservation: &Id,
    provider_formats: &[SchemaRef],
    binding_formats: &[SchemaRef],
) -> Result<CompleteHistoricalArchiveFamily, OperationFailure> {
    if &key.implementation != provider_implementation
        || &key.implementation != binding_implementation
        || &key.profile != preservation
    {
        return Err(refused("historical implementation identity differs"));
    }
    let family = match (key.schema.id.as_str(), key.schema.version) {
        ("source-owned.packet-native-continuation/14", 14) => {
            authenticate_native_owned14_snapshot_schema_data(&key.schema).map_err(unknown)?;
            CompleteHistoricalArchiveFamily::InitialInvocation15
        }
        ("source-owned.packet-native-continuation/17", 17) => {
            authenticate_native_restored_settled17_snapshot_schema_data(&key.schema)
                .map_err(unknown)?;
            CompleteHistoricalArchiveFamily::Settled17
        }
        _ => return Err(refused("unsupported signed historical native family")),
    };
    for formats in [provider_formats, binding_formats] {
        let mut found = false;
        for schema in formats {
            if schema.id == key.schema.id {
                if found || schema != &key.schema {
                    return Err(refused("historical native schema differs or is duplicate"));
                }
                found = true;
            }
        }
        if !found {
            return Err(refused("historical native schema absent from full roster"));
        }
    }
    Ok(family)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_transport::reference_packet::service::native_snapshot::{
        native_owned14_snapshot_schema, native_restored_settled17_snapshot_schema,
    };

    #[test]
    fn actual_signed_schema_selects_its_own_reader_without_rekeying() {
        let implementation = Id::new("test/historical-family-implementation").unwrap();
        let schemas = [
            native_owned14_snapshot_schema().unwrap(),
            native_restored_settled17_snapshot_schema().unwrap(),
        ];
        for (index, expected) in [
            CompleteHistoricalArchiveFamily::InitialInvocation15,
            CompleteHistoricalArchiveFamily::Settled17,
        ]
        .into_iter()
        .enumerate()
        {
            let key = NativeStateKey {
                implementation: implementation.clone(),
                profile: Id::new("source-owned.packet-complete-original-lineage/5").unwrap(),
                schema: schemas[index].clone(),
            };
            let before = key.clone();
            let preservation = &before.profile;
            assert_eq!(
                classify(
                    &key,
                    &implementation,
                    &implementation,
                    preservation,
                    &schemas,
                    &schemas
                )
                .unwrap(),
                expected
            );
            assert_eq!(key, before);
            assert!(
                classify(
                    &key,
                    &implementation,
                    &implementation,
                    &Id::new("foreign/profile").unwrap(),
                    &schemas,
                    &schemas
                )
                .is_err()
            );
            assert!(
                classify(
                    &key,
                    &implementation,
                    &Id::new("foreign/implementation").unwrap(),
                    preservation,
                    &schemas,
                    &schemas
                )
                .is_err()
            );
            assert!(
                classify(
                    &key,
                    &implementation,
                    &implementation,
                    preservation,
                    &schemas,
                    &[]
                )
                .is_err()
            );
            assert!(
                classify(
                    &key,
                    &implementation,
                    &implementation,
                    preservation,
                    &[key.schema.clone(), key.schema.clone()],
                    &schemas
                )
                .is_err()
            );
        }
    }
}

#[path = "settled/cold.rs"]
mod cold;
pub(crate) use cold::{
    OriginalCompleteHistoricalColdGroup, OriginalRestoredSettledColdGroup,
    OriginalRestoredSettledColdOwnerMetadata, OriginalRestoredSettledColdOwnerView,
};
