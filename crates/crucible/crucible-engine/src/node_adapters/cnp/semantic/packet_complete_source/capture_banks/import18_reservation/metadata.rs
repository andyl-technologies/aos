//! Preserves the original reservation Box and all retained partial-bank backing.
//!
//! A spent or failed construction row remains inline in its actual Box. Its
//! source pointer is non-owning correlation data and never enters capacity rows.
//! The bank roster counts every present owner without asserting publication or
//! completed construction. Published Source banks are visited independently.

use super::*;
use crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData;
use crucible_node_transport::retained_metadata::{
    RetainedProtocolMetadataFacts,
    records::{MetadataCapacityRecord, MetadataRecordKind},
};
use std::mem::align_of;

impl Import18CaptureBankReservation {
    /// Records the retained Box and its defining fields without renewing its row.
    ///
    /// # Errors
    /// Refuses invalid layout, selected-row exhaustion, unavailable physical
    /// backing or the defining SDK bank walk's origin and observation failures.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn record_boxed_capacity_data(
        self: &Box<Self>,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            row,
            started,
            complete,
            failed,
            published,
            banks,
        } = self.as_ref();
        census.record(MetadataCapacityRecord {
            kind: MetadataRecordKind::Boxed,
            extent: size_of::<Self>(),
            element_bytes: 1,
            alignment: align_of::<Self>(),
        })?;
        // Copy rows cannot silently acquire owned backing. The raw source
        // binding identifies no additional allocation owned by this reservation.
        census.observe_inline_data(row);
        census.observe_inline_data(started);
        census.observe_inline_data(complete);
        census.observe_inline_data(failed);
        census.observe_inline_data(published);

        if let Some(banks) = banks {
            banks.record_capacity_data(census)?;
        }
        Ok(())
    }
}

/// Names both the original borrowed holder and the closed reservation roster.
pub(in crate::node_adapters::cnp::semantic::packet_complete_source::capture_banks) fn capacity_counter_scratch_data()
-> usize {
    size_of::<&Import18CaptureBankReservation>()
        + size_of::<&Box<Import18CaptureBankReservation>>()
        + size_of::<Option<&Box<Import18CaptureBankReservation>>>()
        + size_of::<Ref<'static, Option<Box<Import18CaptureBankReservation>>>>()
        + size_of::<Result<Ref<'static, Option<Box<Import18CaptureBankReservation>>>, BorrowError>>(
        )
        + size_of::<Result<Ref<'static, Option<Box<Import18CaptureBankReservation>>>, RuntimeError>>(
        )
        + field_view_bytes(|owner: &'static Import18CaptureBankReservation| {
            let Import18CaptureBankReservation {
                row,
                started,
                complete,
                failed,
                published,
                banks,
            } = owner;
            (row, started, complete, failed, published, banks)
        })
        + size_of::<&PacketCompleteCaptureBanks>()
        + size_of::<Option<&PacketCompleteCaptureBanks>>()
        + size_of::<MetadataCapacityRecord>()
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<RetainedProtocolMetadataFacts>()
}

fn field_view_bytes<T>(_: impl FnOnce(&'static Import18CaptureBankReservation) -> T) -> usize {
    size_of::<T>()
}

#[cfg(test)]
#[path = "metadata/tests.rs"]
mod tests;
