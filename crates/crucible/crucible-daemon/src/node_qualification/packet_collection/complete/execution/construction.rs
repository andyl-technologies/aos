//! Quotes the new scene Rc without recounting the caller's real retained inputs.

use super::*;
use crate::node_qualification::packet_collection::complete::{
    retained::shared_requested_storage, witness::PacketCompleteConstructionStorageData,
};
use crucible_engine::node_contract::RuntimeError;
use std::mem::{align_of, size_of};

impl PacketCompleteExecutionScene {
    /// Quotes only this new Rc; source/plan/Oracle owners remain caller-funded.
    ///
    /// # Errors
    /// Refuses checked layout overflow or the supplied requested-byte ceiling.
    pub(crate) fn original_construction_storage_data(
        maximum: usize,
    ) -> Result<PacketCompleteConstructionStorageData, RuntimeError> {
        let retained = shared_requested_storage(size_of::<Self>(), align_of::<Self>())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        PacketCompleteConstructionStorageData::new(
            retained,
            0,
            Self::original_construction_counter_scratch_data()?,
            maximum,
        )
    }

    /// Quotes the fixed explicit scene construction view without running it.
    ///
    /// # Errors
    /// Refuses checked layout arithmetic overflow; called validation work is
    /// independently admitted by the retaining caller before installation.
    pub(crate) fn original_construction_counter_scratch_data() -> Result<usize, RuntimeError> {
        size_of::<Self>()
            .checked_add(size_of::<Rc<Self>>())
            .and_then(|n| n.checked_add(size_of::<PacketCompleteConstructionStorageData>()))
            .ok_or(RuntimeError::ResourceLimit)
    }
}
