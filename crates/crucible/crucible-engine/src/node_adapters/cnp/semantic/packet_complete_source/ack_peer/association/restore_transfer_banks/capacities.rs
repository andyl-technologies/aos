//! Counts distinct prepare/commit banks alongside the original retained signer.

use super::*;
use crate::node_contract::{
    RuntimeError, restored_owner_history::OriginalOwnerCapacityMetadataData,
};
use std::mem::size_of;

impl OriginalRestoreTransferBanks {
    /// Records both actual phase-bank arrays and every retained signer partial.
    ///
    /// # Errors
    /// Refuses row/depth exhaustion, unavailable backing or checked layout overflow.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn record_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            prepare,
            commit,
            signer,
            mapping_attempted,
            mapping_complete,
        } = self;

        census.observe_inline_data(mapping_attempted)?;
        census.observe_inline_data(mapping_complete)?;

        for bank in prepare.iter().chain(commit) {
            census.observe(bank)?;
        }

        if let Some(signer) = signer {
            signer.record_capacity_data(census)?;
        }
        Ok(())
    }

    /// Names actual bank, signer and fixed-state census controls.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn capacity_counter_scratch_data()
    -> usize {
        size_of::<&Self>()
            + size_of::<(&[Vec<u8>; 5], &[Vec<u8>; 5],
                &Option<super::super::restoration_transfer::OriginalSourceRestoreTransferAttempt>, &bool, &bool)>()
            + size_of::<std::iter::Chain<std::slice::Iter<'_, Vec<u8>>, std::slice::Iter<'_, Vec<u8>>>>()
            + size_of::<Option<&super::super::restoration_transfer::OriginalSourceRestoreTransferAttempt>>()
            + size_of::<&mut OriginalOwnerCapacityMetadataData<'_>>()
            + size_of::<Result<(), RuntimeError>>()
            + super::super::restoration_transfer::OriginalSourceRestoreTransferAttempt::capacity_counter_scratch_data()
    }
}
