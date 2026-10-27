//! Preserves Source allocation headers, own path and retained mechanism views.
//!
//! The real Rc payload and independent producer/reactive Box are separate rows.
//! Other nested owners belong to the remaining Source component walks. The
//! receiver group and opaque native runtime remain external obligations.

use super::*;
use crate::node_contract::{
    RuntimeError, restored_owner_history::OriginalOwnerCapacityMetadataData,
};
use crucible_node_transport::retained_metadata::{
    RetainedProtocolMetadataFacts,
    records::{MetadataCapacityRecord, MetadataRecordKind, PacketRuntimeMetadataRecordBank},
};
use std::mem::align_of_val;

impl PacketCompleteSemanticSource {
    /// Observes its Rc, independent Box, own path and known mechanism capacities.
    ///
    /// The caller admits the bank and
    /// [`Self::original_complete_holder_capacity_counter_scratch_data`] first.
    /// Rows append without clearing earlier components; refusal retains their
    /// initialized prefix and backing. Aliases receive no shared-view discount.
    /// Other nested owners and opaque native backing remain separate. These
    /// facts do not authorize native actions or complete a Source footprint.
    ///
    /// # Errors
    /// Refuses a foreign creator, invalid or overflowing geometry, unready bank
    /// or an exhausted selected row restriction.
    pub fn original_complete_holder_capacity_data(
        self: &Rc<Self>,
        bank: Option<&mut PacketRuntimeMetadataRecordBank>,
    ) -> Result<RetainedProtocolMetadataFacts, RuntimeError> {
        self.original_complete_holder_capacity_with_error::<RuntimeError>(bank)
    }

    /// Shares the actual holder walk with the diagnostic and typed error paths.
    ///
    /// # Errors
    /// Refuses foreign creation, invalid geometry or unavailable bank capacity.
    pub(super) fn original_complete_holder_capacity_with_error<E: StorageError>(
        self: &Rc<Self>,
        bank: Option<&mut PacketRuntimeMetadataRecordBank>,
    ) -> Result<RetainedProtocolMetadataFacts, E> {
        self.storage_origin_with_error::<E>()?;
        let maximum_rows = bank.as_ref().map_or(usize::MAX, |bank| bank.maximum_rows());
        let mut census = OriginalOwnerCapacityMetadataData::new(maximum_rows, bank);

        // This is the actual enclosing Rc payload, not a proxy for any of its
        // independently allocated dynamic fields or tree element layouts.
        census
            .record(MetadataCapacityRecord {
                kind: MetadataRecordKind::Shared,
                extent: size_of::<Self>(),
                element_bytes: 1,
                alignment: align_of::<Self>(),
            })
            .map_err(E::runtime)?;
        let (bytes, alignment) = match &self.original {
            CompletePacketOriginal::Producer(source) => {
                (size_of_val(source.as_ref()), align_of_val(source.as_ref()))
            }
            CompletePacketOriginal::Reactive(source) => {
                (size_of_val(source.as_ref()), align_of_val(source.as_ref()))
            }
        };
        census
            .record(MetadataCapacityRecord {
                kind: MetadataRecordKind::Boxed,
                extent: bytes,
                element_bytes: 1,
                alignment,
            })
            .map_err(E::runtime)?;
        if let Some(receiver) = &self.effect_receiver {
            census
                .record(receiver.retained_path_capacity_record_data())
                .map_err(E::runtime)?;
        }

        self.record_mechanism_capacity_data(&mut census)
            .map_err(E::runtime)?;
        self.storage_origin_with_error::<E>()?;
        Ok(census.finish())
    }

    fn record_mechanism_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        if let Some(mechanism) = &self.native_import18_derivation_mechanism {
            census.observe_shared_allocation_data(mechanism)?;
            census.observe_component_capacity_data(|remaining, bank| {
                mechanism.known_capacity_data(remaining, bank)
            })?;
        }
        Ok(())
    }

    /// Prices the same mechanism population beneath a separately counted Source.
    pub(super) fn original_complete_mechanism_storage_with_error<E: StorageError>(
        &self,
        maximum: usize,
    ) -> Result<usize, E> {
        self.storage_origin_with_error::<E>()?;
        let mut census = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);
        self.record_mechanism_capacity_data(&mut census)
            .map_err(E::runtime)?;
        self.storage_origin_with_error::<E>()?;
        Self::complete_retained_metadata_storage_with_error::<E>(&census.finish(), maximum)
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn original_complete_mechanism_capacity_counter_scratch_data()
    -> usize {
        use crate::node_adapters::cnp::source_birth_derivation::installation::VerifiedSourceBirthMechanism;

        OriginalOwnerCapacityMetadataData::counter_scratch_data()
            + VerifiedSourceBirthMechanism::known_capacity_counter_scratch_data()
            + size_of::<&Self>() * 2
            + size_of::<Option<&Rc<VerifiedSourceBirthMechanism>>>()
            + size_of::<&Rc<VerifiedSourceBirthMechanism>>() * 2
            + size_of::<Option<&mut PacketRuntimeMetadataRecordBank>>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<usize>()
    }

    /// Names actual holder-census controls for the typed precredit walk.
    pub fn original_complete_holder_capacity_counter_scratch_data() -> usize {
        OriginalOwnerCapacityMetadataData::counter_scratch_data()
            + Self::original_complete_mechanism_capacity_counter_scratch_data()
            + size_of::<&Rc<Self>>()
            + size_of::<&Self>()
            + size_of::<&CompletePacketOriginal>()
            + size_of::<&Box<PacketSemanticSource>>()
            + size_of::<&Box<PacketConnectedSemanticSource>>()
            + size_of::<&effects::OriginalCompleteEffectReceiver>()
            + size_of::<Option<&mut PacketRuntimeMetadataRecordBank>>()
            + size_of::<MetadataCapacityRecord>()
            + size_of::<(usize, usize)>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<Result<RetainedProtocolMetadataFacts, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<usize>()
    }
}

#[cfg(test)]
#[path = "metadata/tests.rs"]
mod tests;
