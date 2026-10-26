//! Preserves actual Source allocation headers and its own Unix path capacity.
//!
//! The real Rc payload and independent producer/reactive Box are separate rows.
//! Their nested dynamic owners belong to the other Source component walks. The
//! receiver group's shared allocation and kernel resources remain external rows.

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
    /// Observes its actual Rc, independent Box and own path as capacity DATA.
    ///
    /// The caller admits the bank and
    /// [`Self::original_complete_holder_capacity_counter_scratch_data`] first.
    /// Rows append without clearing earlier components; refusal retains their
    /// initialized prefix and backing. Aliases receive no shared-view discount.
    /// This does not traverse nested dynamic owners or authorize native actions.
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

        self.storage_origin_with_error::<E>()?;
        Ok(census.finish())
    }

    /// Names actual holder-census controls for the typed precredit walk.
    pub fn original_complete_holder_capacity_counter_scratch_data() -> usize {
        OriginalOwnerCapacityMetadataData::counter_scratch_data()
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
