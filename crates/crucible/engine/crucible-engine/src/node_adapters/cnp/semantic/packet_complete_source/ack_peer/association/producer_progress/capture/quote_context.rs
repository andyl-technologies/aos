//! Borrows admitted counting banks and genuine immutable archive operands.
//!
//! These loans supply DATA to a private extent sink. They cannot construct a
//! Capture claim, a preencoder cut or any completed historical Source record.

use super::{
    ancestry::OriginalRestoredCaptureAncestry17Data, logical::OriginalSourceRestoredSettled17Read,
};
use crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityAliases;
use crucible_node_transport::{
    protocol_snapshot::restored_journal17::PacketRestoredSettledAncestry17,
    retained_metadata::{aliases::MetadataAliasBank, records::MetadataRecordBank},
};
use std::cell::RefCell;

/// Borrows actual archive evidence and separately admitted counting workspaces.
///
/// The Window supplies the signed ancestry from its actual archive/ticket and
/// the prior opaque Source from its original cold owner. The request separately
/// carries its genuine Runtime issuer's coordinator encoding bound. Pointer
/// or integer DATA alone never establishes those owning-caller conjunctions.
pub(crate) struct OriginalSourceRestoredCaptureQuoteInputs<'a> {
    pub(crate) ancestry: &'a OriginalRestoredCaptureAncestry17Data<'a>,
    pub(crate) inherited: Option<&'a OriginalSourceRestoredSettled17Read>,
    pub(crate) aliases: &'a RefCell<OriginalRestoredOwnerCapacityAliases>,
    pub(crate) records: &'a RefCell<MetadataRecordBank>,
    pub(crate) provider_aliases: &'a RefCell<MetadataAliasBank>,
}

/// Borrows independently admitted encoding work and the actual cold Source.
///
/// Ancestry is intentionally absent: the effect obtains and retains its real
/// owned DTO under its own immutable Controller loan before SDK mutation.
pub(crate) struct OriginalSourceRestoredCaptureEncodingInputs<'a> {
    pub(crate) inherited: Option<&'a OriginalSourceRestoredSettled17Read>,
    pub(crate) aliases: &'a RefCell<OriginalRestoredOwnerCapacityAliases>,
    pub(crate) records: &'a RefCell<MetadataRecordBank>,
    pub(crate) provider_aliases: &'a RefCell<MetadataAliasBank>,
}

/// Reports actual metadata-bank demand before reservation or encoding.
///
/// These counts are constructor DATA. The whole Window independently funds the
/// backing and retains actual constructor results, including refusal partials.
#[derive(Clone, Copy)]
pub(crate) struct OriginalSourceRestoredCaptureCountingBanksData {
    pub(crate) common_rows: usize,
    pub(crate) common_shared: usize,
    pub(crate) provider_records: usize,
    pub(crate) provider_shared: usize,
    pub(crate) retained: usize,
}

impl crate::node_adapters::cnp::PacketCompleteSemanticSource {
    /// Quotes the defining banks for the actual Node plus outer Source header.
    ///
    /// # Errors
    /// Refuses unsupported actual metadata, finite row limits or checked overflow.
    pub(crate) fn original_restored_capture_counting_banks_data(
        &self,
        node: &crate::node_adapters::cnp::semantic::node::OriginalRestoredSettledNodeHistoryView<
            '_,
        >,
        maximum: usize,
    ) -> Result<OriginalSourceRestoredCaptureCountingBanksData, crate::node_contract::RuntimeError>
    {
        use crate::node_contract::RuntimeError;
        use crucible_node_transport::retained_metadata::records::MetadataCapacityRecord;
        use std::mem::size_of;
        let node = node.metadata_demand_data()?;
        let header = self.settled17_header_metadata_demand_data()?;
        let common_rows = node
            .common_rows_data()
            .checked_add(header.0)
            .ok_or(RuntimeError::ResourceLimit)?;
        // Defining reserve constructors require a positive bank, even for an
        // empty stream. Price that one actual minimum slot independently.
        let common_shared = node
            .common_shared_occurrences_data()
            .checked_add(header.1)
            .ok_or(RuntimeError::ResourceLimit)?
            .max(1);
        let provider_records = node.provider_metadata_records_data().max(1);
        let provider_shared = node.provider_shared_occurrences_data().max(1);
        let retained = super::construction_quote::sum(
            &[
                OriginalRestoredOwnerCapacityAliases::requested_bytes(common_shared)?,
                provider_records
                    .checked_mul(size_of::<MetadataCapacityRecord>())
                    .ok_or(RuntimeError::ResourceLimit)?,
                MetadataAliasBank::reservation_requested_bytes(provider_shared)
                    .map_err(|_| RuntimeError::ResourceLimit)?,
                size_of::<RefCell<OriginalRestoredOwnerCapacityAliases>>(),
                size_of::<RefCell<MetadataRecordBank>>(),
                size_of::<RefCell<MetadataAliasBank>>(),
            ],
            maximum,
        )?;
        if common_rows > 131072 || provider_records > 131072 {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(OriginalSourceRestoredCaptureCountingBanksData {
            common_rows,
            common_shared,
            provider_records,
            provider_shared,
            retained,
        })
    }
}

impl crate::node_adapters::cnp::PacketCompleteSemanticSource {
    pub(super) fn authenticate_capture17_counting_banks_data(
        &self,
        node: &crate::node_adapters::cnp::semantic::node::OriginalRestoredSettledNodeHistoryView<
            '_,
        >,
        aliases: &RefCell<OriginalRestoredOwnerCapacityAliases>,
        records: &RefCell<MetadataRecordBank>,
        provider_aliases: &RefCell<MetadataAliasBank>,
        maximum: usize,
    ) -> Result<(), crate::node_contract::RuntimeError> {
        use crate::node_contract::RuntimeError;
        use std::mem::size_of;
        let expected = self.original_restored_capture_counting_banks_data(node, maximum)?;
        let actual = super::construction_quote::sum(
            &[
                aliases
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?
                    .allocated_bytes()?,
                records
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?
                    .allocated_bytes(),
                provider_aliases
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?
                    .allocated_bytes(),
                size_of::<RefCell<OriginalRestoredOwnerCapacityAliases>>(),
                size_of::<RefCell<MetadataRecordBank>>(),
                size_of::<RefCell<MetadataAliasBank>>(),
            ],
            maximum,
        )?;
        if actual > expected.retained {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(())
    }
}
