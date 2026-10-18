//! Counts independent construction work for one exact restored input phase.
//!
//! These fixed rows record identity and resource correspondence. They supply no
//! native permission or Window claim. Actual Runtime batch custody, SourceRead,
//! signed Source proof and whole-Window admission remain separate obligations.

use crate::node_adapters::cnp::PacketCompleteSemanticSource;
use crate::node_contract::{OriginalRuntimeInputPhase, RuntimeError};
use crucible_node_provider::{
    client::CnpController,
    reference_packet::service::native_startup::PacketNativeStartupAllocationRow,
};
use std::thread::ThreadId;

/// Contains separately quoted construction DATA for one exact Input17 phase.
///
/// A matching row grants no effect. The complete Window, SourceRead, actual
/// Runtime dispatch, Source MAC and native graph plan remain independent owners.
#[derive(Clone, Copy)]
pub struct OriginalRestoredInput17ConstructionData {
    /// Identifies the process that produced this construction row.
    pub(crate) process: u32,
    /// Identifies the producing thread independently of the process.
    pub(crate) thread: ThreadId,
    /// Compares the actual retained Source allocation without dereferencing it.
    pub(crate) source: *const PacketCompleteSemanticSource,
    /// Compares the actual SDK Controller allocation.
    pub(crate) controller: *const CnpController,
    /// Compares the retained native read owner inside the real claim.
    pub(crate) read_owner: *const (),
    /// Selects the independently quoted Stage or Commit work.
    pub(crate) phase: OriginalRuntimeInputPhase,
    /// Commits the complete immutable Runtime batch.
    pub(crate) batch_digest: [u8; 32],
    /// Selects the original retained Source history slot.
    pub(crate) source_slot: usize,
    /// Retains the independently produced native construction row.
    pub(crate) native: PacketNativeStartupAllocationRow,
    /// Counts future Source and SDK retained backing.
    pub(crate) retained: usize,
    /// Bounds simultaneous Source and SDK construction backing.
    pub(crate) transient: usize,
    /// Counts the defining Source and SDK observer layouts.
    pub(crate) scratch: usize,
    /// Retains independent Runtime retained, transient and scratch work.
    pub(crate) runtime_work: (usize, usize, usize),
    /// Preserves the owning Window construction ceiling.
    pub(crate) maximum: usize,
}

impl OriginalRestoredInput17ConstructionData {
    /// Returns the independently summed simultaneous future demand.
    ///
    /// # Errors
    /// Refuses checked overflow or a demand above the unchanged owning ceiling.
    pub fn requested_bytes_data(&self) -> Result<usize, RuntimeError> {
        let terms = [
            self.retained,
            self.transient,
            self.scratch,
            self.runtime_work.0,
            self.runtime_work.1,
            self.runtime_work.2,
            usize::try_from(self.native.retained_requested_bytes.get())
                .map_err(|_| RuntimeError::ResourceLimit)?,
            usize::try_from(self.native.maximum_simultaneous_transient_bytes.get())
                .map_err(|_| RuntimeError::ResourceLimit)?,
            usize::try_from(self.native.declared_counter_scratch_bytes.get())
                .map_err(|_| RuntimeError::ResourceLimit)?,
        ];
        terms.into_iter().try_fold(0usize, |total, bytes| {
            total
                .checked_add(bytes)
                .filter(|total| *total <= self.maximum)
                .ok_or(RuntimeError::ResourceLimit)
        })
    }

    /// Checks producing identity, actual owner pointers and quoted bounds.
    ///
    /// # Errors
    /// Refuses a foreign owner, invalid native row or exhausted construction ceiling.
    pub(crate) fn authenticate_owner_data(
        &self,
        source: &PacketCompleteSemanticSource,
        controller: *const CnpController,
    ) -> Result<(), RuntimeError> {
        if self.process != std::process::id()
            || self.thread != std::thread::current().id()
            || !std::ptr::eq(self.source, source)
            || self.controller != controller
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.native
            .requested_peak_data()
            .map_err(|_| RuntimeError::ResourceLimit)?;
        self.requested_bytes_data()?;
        Ok(())
    }
}
