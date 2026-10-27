//! Preserves the actual installation capacity census for Source runtime funding.
//!
//! The protocol payload, enclosing coordinator Box, Core facet Vec and independent
//! saved activation are all observed from the same original Source. This is one
//! Source component; it does not assert a complete Source/Node history or native
//! traversal-work budget. Common capacity rows omit scalar visit counts.

use super::*;
use crate::node_contract::{
    RuntimeError,
    restored_owner_history::{OriginalOwnerCapacityMetadataData, merge_capacity_metadata_data},
};
use crucible_node_transport::retained_metadata::{
    RetainedProtocolMetadataFacts,
    records::{MetadataCapacityRecord, MetadataRecordKind, PacketRuntimeMetadataRecordBank},
};
use std::mem::align_of;

impl PacketCompleteSemanticSource {
    /// Observes actual installation capacities and optionally appends their rows.
    ///
    /// The caller admits the bank and
    /// [`Self::original_complete_installation_capacity_counter_scratch_data`]
    /// before this DATA query. Numeric DATA issues no Source action.
    /// Existing rows survive; failure preserves the initialized component prefix.
    /// Core scalar visits are not represented by this capacity roster, so its
    /// `observed_nodes` must not be used as a whole-Source work restriction.
    ///
    /// # Errors
    /// Refuses foreign Source creation, unsupported original world, invalid or
    /// overflowing geometry, busy/unready backing or exhausted selected rows.
    pub fn original_complete_installation_capacity_data(
        &self,
        bank: Option<&mut PacketRuntimeMetadataRecordBank>,
    ) -> Result<RetainedProtocolMetadataFacts, RuntimeError> {
        self.original_complete_installation_capacity_with_error::<RuntimeError>(bank)
    }

    /// Shares the actual installation walk with both retained-storage error paths.
    ///
    /// # Errors
    /// Refuses foreign creation, an unsupported world, invalid geometry or
    /// unavailable physical rows while preserving earlier initialized records.
    pub(in crate::node_adapters::cnp::semantic) fn original_complete_installation_capacity_with_error<
        E: StorageError,
    >(
        &self,
        mut bank: Option<&mut PacketRuntimeMetadataRecordBank>,
    ) -> Result<RetainedProtocolMetadataFacts, E> {
        let (view, facets, activation) = self.borrowed_installation_capacity_parts::<E>()?;
        // Validate the closed Core facet roster before changing any bank prefix.
        for facet in facets {
            match facet {
                FacetKind::ExactExecution
                | FacetKind::QuantizedExecution
                | FacetKind::PhysicalPause
                | FacetKind::Preservation
                | FacetKind::Replay
                | FacetKind::FaultInjection
                | FacetKind::Coverage
                | FacetKind::Introspection
                | FacetKind::Debugging
                | FacetKind::TerminalAssertions => {}
            }
        }
        let mut facts = match bank.as_deref_mut() {
            Some(bank) => view
                .record_retained_metadata_data(bank)
                .map_err(|error| match error {
                    crucible_node_transport::ProviderError::ResourceExhausted(_) => {
                        E::limit("complete installation capacity rows exhausted")
                    }
                    error => E::unknown(error),
                }),
            None => view.observe_retained_metadata().map_err(E::unknown),
        }?;
        let maximum_rows = bank.as_ref().map_or(usize::MAX, |bank| bank.maximum_rows());
        let mut common = OriginalOwnerCapacityMetadataData::new(maximum_rows, bank);
        common
            .record(MetadataCapacityRecord {
                kind: MetadataRecordKind::Vector,
                extent: facets.capacity(),
                element_bytes: size_of::<FacetKind>(),
                alignment: align_of::<FacetKind>(),
            })
            .map_err(E::runtime)?;
        // complete_retained_parts accepts only the actual Complete world arm,
        // whose coordinator is independently boxed; its payload was walked above.
        common
            .record(MetadataCapacityRecord {
                kind: MetadataRecordKind::Boxed,
                extent: size_of::<PacketNative5CoordinatorInstallation>(),
                element_bytes: 1,
                alignment: align_of::<PacketNative5CoordinatorInstallation>(),
            })
            .map_err(E::runtime)?;
        common.observe(activation).map_err(E::runtime)?;
        merge_capacity_metadata_data(&mut facts, &common.finish()).map_err(E::runtime)?;
        self.storage_origin_with_error::<E>()?;
        Ok(facts)
    }

    fn borrowed_installation_capacity_parts<E: StorageError>(
        &self,
    ) -> Result<
        (
            RetainedCompleteSourceMetadata<'_>,
            &Vec<FacetKind>,
            &SavedRuntimeActivation,
        ),
        E,
    > {
        self.storage_origin_with_error::<E>()?;
        let (definition, coordinator, activation) = match &self.original {
            CompletePacketOriginal::Producer(source) => {
                let (definition, coordinator, activation) =
                    source.complete_retained_declaration_parts_with_error::<E>()?;
                (
                    RetainedCompleteSourceDefinition::Program(definition),
                    coordinator,
                    activation,
                )
            }
            CompletePacketOriginal::Reactive(source) => {
                let (definition, coordinator, activation) =
                    source.complete_retained_declaration_parts_with_error::<E>()?;
                (
                    RetainedCompleteSourceDefinition::Connected(definition),
                    coordinator,
                    activation,
                )
            }
        };
        let installation = self.installation();
        let view = RetainedCompleteSourceMetadata {
            provider: &installation.provider,
            manifest: &installation.profile,
            descriptor: &installation.descriptor,
            binding: &installation.binding,
            capabilities: &installation.capabilities,
            facet: &installation.exact_facet,
            guarantees: &installation.guarantees,
            owner: &installation.owner,
            realize: &installation.realize,
            admission: &installation.admission,
            transaction: &installation.transaction,
            gate: &installation.gate,
            admission_receipt: &installation.admission_receipt,
            world: &installation.world_binding_hash,
            receipt_schema: &installation.receipt_schema,
            operating_contract: &installation.binding.compatibility.operating_contract,
            coordinator,
            definition,
        };

        Ok((view, &installation.facets, activation))
    }

    /// Names actual protocol and common-capacity census controls before walking.
    pub fn original_complete_installation_capacity_counter_scratch_data() -> usize {
        use crucible_node_transport::reference_packet::{
            PacketProgramDefinition, connected::PacketConnectedDefinition,
        };

        RetainedCompleteSourceMetadata::recording_counter_scratch_data()
            + OriginalOwnerCapacityMetadataData::counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&CompletePacketOriginal>()
            + size_of::<&CnpSemanticInstallation>()
            + size_of::<RetainedCompleteSourceDefinition<'static>>()
            + size_of::<(
                RetainedCompleteSourceMetadata<'static>,
                &Vec<FacetKind>,
                &SavedRuntimeActivation,
            )>()
            + size_of::<
                Result<
                    (
                        RetainedCompleteSourceMetadata<'static>,
                        &Vec<FacetKind>,
                        &SavedRuntimeActivation,
                    ),
                    RuntimeError,
                >,
            >()
            + size_of::<
                Result<
                    (
                        &PacketProgramDefinition,
                        &PacketNative5CoordinatorInstallation,
                        &SavedRuntimeActivation,
                    ),
                    RuntimeError,
                >,
            >()
            + size_of::<
                Result<
                    (
                        &PacketConnectedDefinition,
                        &PacketNative5CoordinatorInstallation,
                        &SavedRuntimeActivation,
                    ),
                    RuntimeError,
                >,
            >()
            + size_of::<&SavedRuntimeActivation>()
            + size_of::<&Vec<FacetKind>>()
            + size_of::<std::slice::Iter<'static, FacetKind>>()
            + size_of::<std::slice::Iter<'static, OwnerIdentity>>()
            + size_of::<&OwnerIdentity>()
            + size_of::<&Id>()
            + size_of::<&HashRef>()
            + size_of::<&String>()
            + size_of::<&Vec<OwnerIdentity>>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<Option<&mut PacketRuntimeMetadataRecordBank>>()
            + size_of::<Result<RetainedProtocolMetadataFacts, RuntimeError>>()
            + size_of::<MetadataCapacityRecord>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<usize>()
    }
}

#[cfg(test)]
#[path = "metadata/tests.rs"]
mod tests;
