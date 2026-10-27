//! Reserves distinct source-owned phase12 banks before private key and Child.
//!
//! These encoded comparison banks are not the SDK's assigned request/literal
//! slots, and do not authorize an upload. Both complete phases remain allocated
//! independently; reusing one would erase the authenticated prepare history.

use super::*;

use crate::node_adapters::cnp::semantic::packet_complete_source::storage_error::StorageError;
use crucible_node_transport::reference_packet::service::complete_restore::transfer::{
    MAXIMUM_COMPLETE_RESTORE_TRANSFER_CONTEXT_BYTES, MAXIMUM_COMPLETE_RESTORE_TRANSFER_PROOF_BYTES,
    MAXIMUM_COMPLETE_RESTORE_TRANSFER_RECEIPT_BYTES,
    MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES,
};

#[path = "restore_transfer_banks/capacities.rs"]
mod capacities;

pub(super) struct OriginalRestoreTransferBanks {
    pub(super) prepare: [Vec<u8>; 5],
    pub(super) commit: [Vec<u8>; 5],
    pub(super) signer: Option<super::restoration_transfer::OriginalSourceRestoreTransferAttempt>,
    pub(super) mapping_attempted: bool,
    pub(super) mapping_complete: bool,
}

fn limits(frame_bytes: usize) -> [usize; 5] {
    [
        MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES,
        MAXIMUM_COMPLETE_RESTORE_TRANSFER_CONTEXT_BYTES,
        MAXIMUM_COMPLETE_RESTORE_TRANSFER_PROOF_BYTES,
        frame_bytes,
        MAXIMUM_COMPLETE_RESTORE_TRANSFER_RECEIPT_BYTES,
    ]
}

impl OriginalRestoreTransferBanks {
    pub(super) fn allocated_bytes(&self) -> Result<usize, OperationFailure> {
        self.allocated_bytes_with_error::<OperationFailure>()
    }

    pub(in crate::node_adapters::cnp::semantic) fn allocated_bytes_with_error<E: StorageError>(
        &self,
    ) -> Result<usize, E> {
        self.prepare
            .iter()
            .chain(&self.commit)
            .try_fold(0usize, |sum, bank| {
                sum.checked_add(bank.capacity())
                    .ok_or_else(|| E::limit("selected12 actual phase capacity overflow"))
            })
    }
}

impl OriginalAckPeerAssociation {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn minimum_restore_transfer_phase_bank_bytes(
        frame_bytes: usize,
    ) -> Result<usize, OperationFailure> {
        if frame_bytes == 0 || frame_bytes > 65_536 {
            return Err(refused("selected12 phase frame selection unsupported"));
        }
        limits(frame_bytes)
            .into_iter()
            .try_fold(0usize, |sum, bytes| {
                sum.checked_add(bytes)
                    .ok_or_else(|| refused("selected12 phase bank minimum overflow"))
            })?
            .checked_mul(2)
            .ok_or_else(|| refused("selected12 two phase banks overflow"))
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn reserve_restore_transfer_phase_banks(
        &mut self,
        frame_bytes: usize,
    ) -> Result<(), OperationFailure> {
        Self::minimum_restore_transfer_phase_bank_bytes(frame_bytes)?;
        if self.attempted || self.restore_transfer_banks.is_some() || self.restore.is_none() {
            return Err(refused(
                "selected12 phase banks are used, repeated or lack base banks",
            ));
        }
        self.restore_transfer_banks = Some(OriginalRestoreTransferBanks {
            prepare: std::array::from_fn(|_| Vec::new()),
            commit: std::array::from_fn(|_| Vec::new()),
            signer: None,
            mapping_attempted: false,
            mapping_complete: false,
        });
        let banks = self
            .restore_transfer_banks
            .as_mut()
            .ok_or_else(|| refused("selected12 phase banks absent"))?;
        for (bank, maximum) in banks
            .prepare
            .iter_mut()
            .zip(limits(frame_bytes))
            .chain(banks.commit.iter_mut().zip(limits(frame_bytes)))
        {
            bank.try_reserve_exact(maximum)
                .map_err(|_| refused("selected12 phase bank allocation refused"))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_phase_reservation_keeps_base_banks_and_refuses_replacement() {
        let mut slot = None;
        OriginalAckPeerAssociation::reserve_into(8192, &mut slot).unwrap();
        let association = slot.as_mut().unwrap();
        association.reserve_complete_restore_banks(8192).unwrap();
        let before = association.allocated_bank_bytes().unwrap();
        let minimum =
            OriginalAckPeerAssociation::minimum_restore_transfer_phase_bank_bytes(8192).unwrap();

        association
            .reserve_restore_transfer_phase_banks(8192)
            .unwrap();
        let total = association.allocated_bank_bytes().unwrap();
        assert!(total >= before + minimum);
        assert!(
            association
                .reserve_restore_transfer_phase_banks(8192)
                .is_err()
        );
        assert_eq!(association.allocated_bank_bytes().unwrap(), total);
    }
}

impl OriginalRestoreTransferBanks {
    pub(in crate::node_adapters::cnp::semantic) fn authenticate_reserved_prebirth_data_with_error<
        E: crate::node_adapters::cnp::semantic::packet_complete_source::storage_error::StorageError,
    >(
        &self,
    ) -> Result<(), E> {
        let Self {
            prepare,
            commit,
            signer,
            mapping_attempted,
            mapping_complete,
        } = self;
        if signer.is_some()
            || *mapping_attempted
            || *mapping_complete
            || prepare.iter().chain(commit).any(|bank| !bank.is_empty())
        {
            return Err(E::refused(
                "reserved prebirth transfer banks are already used",
            ));
        }
        Ok(())
    }
}

/// Lends both actual phase-bank arrays and their retained signer partials.
pub(crate) struct SourceRestoreTransferBanksHistoryData<'a> {
    original: &'a OriginalRestoreTransferBanks,
}

impl OriginalRestoreTransferBanks {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn historical_data(
        &self,
    ) -> SourceRestoreTransferBanksHistoryData<'_> {
        SourceRestoreTransferBanksHistoryData { original: self }
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn historical_counter_scratch_data()
    -> usize {
        std::mem::size_of::<SourceRestoreTransferBanksHistoryData<'static>>()
            + std::mem::size_of::<&OriginalRestoreTransferBanks>()
            + std::mem::size_of::<&[Vec<u8>; 5]>()
            + crate::node_contract::restored_owner_history::original_restored_owner_capacity_counter_scratch_data()
            + super::restoration_transfer::OriginalSourceRestoreTransferAttempt::historical_counter_scratch_data()
    }
}

impl serde::Serialize for SourceRestoreTransferBanksHistoryData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use crate::node_contract::restored_owner_history::OriginalRestoredOwnerCapacityRows;
        use serde::ser::SerializeStruct;
        let OriginalRestoreTransferBanks {
            prepare,
            commit,
            signer,
            mapping_attempted,
            mapping_complete,
        } = self.original;
        let mut value = serializer.serialize_struct("SourceRestoreTransferBanksHistory", 7)?;
        value.serialize_field("prepare", prepare)?;
        value.serialize_field(
            "prepare_capacities",
            &OriginalRestoredOwnerCapacityRows(prepare.as_slice()),
        )?;
        value.serialize_field("commit", commit)?;
        value.serialize_field(
            "commit_capacities",
            &OriginalRestoredOwnerCapacityRows(commit.as_slice()),
        )?;
        value.serialize_field(
            "signer",
            &signer.as_ref().map(|signer| signer.historical_data()),
        )?;
        value.serialize_field("mapping_attempted", mapping_attempted)?;
        value.serialize_field("mapping_complete", mapping_complete)?;
        value.end()
    }
}
