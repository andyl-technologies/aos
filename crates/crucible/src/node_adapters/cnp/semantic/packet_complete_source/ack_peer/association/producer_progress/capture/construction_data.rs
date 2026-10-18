//! Defines an independently funded Source/SDK/decoder row for real Capture17.
//!
//! The row records original identities and complete construction geometry. It
//! grants no Capture, current read, native credit or historical completion.

use crate::{
    node_adapters::cnp::PacketCompleteSemanticSource,
    node_admission::OriginalRestoredCaptureRequestData, node_contract::RuntimeError,
};
use crucible_node_contract::{Position, U64};
use crucible_node_provider::{
    client::{CnpController, OriginalRestoredSettledCaptureConstructionData},
    reference_packet::service::{
        PacketNative5SourceLaunch,
        native_startup::{
            PacketRestoredSettledNativeCarrierData,
            PacketRestoredSettledNativeOutputValidationStorageData,
        },
    },
};

/// Retains complete geometry bound to the actual originating Capture members.
///
/// This copyable DATA has no public constructor or authority conversion. The
/// original Window still admits its full axes and issues the real once claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginalSourceRestoredCaptureConstructionData {
    pub(super) process: u32,
    pub(super) thread: std::thread::ThreadId,
    pub(super) source: *const PacketCompleteSemanticSource,
    pub(super) controller: *const CnpController,
    pub(super) read_owner: *const (),
    pub(super) launch: *const PacketNative5SourceLaunch,
    pub(super) launch_digest: [u8; 32],
    pub(super) capture_id: [u8; 32],
    pub(super) cut: Position,
    pub(super) ordinal: U64,
    pub(super) runtime: usize,
    pub(super) prefix: usize,
    pub(super) checkpoint: usize,
    pub(super) semantic: usize,
    pub(super) frozen: usize,
    pub(super) sdk: OriginalRestoredSettledCaptureConstructionData,
    pub(super) native: PacketRestoredSettledNativeCarrierData,
    pub(super) validation: PacketRestoredSettledNativeOutputValidationStorageData,
    pub(super) retained: usize,
    pub(super) transient: usize,
    pub(super) scratch: usize,
    pub(super) maximum: usize,
}

impl OriginalSourceRestoredCaptureConstructionData {
    /// Returns all independent retained construction owners.
    pub const fn retained_requested_bytes_data(&self) -> usize {
        self.retained
    }

    /// Returns independently admitted simultaneous temporary construction work.
    pub const fn maximum_simultaneous_transient_bytes_data(&self) -> usize {
        self.transient
    }

    /// Returns the defining fixed traversal and construction frames.
    pub const fn counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }

    /// Returns the complete simultaneous R + T + S obligation.
    ///
    /// # Errors
    /// Refuses overflow or demand exceeding the original construction ceiling.
    pub fn requested_bytes_data(&self) -> Result<usize, RuntimeError> {
        super::construction_quote::sum(&[self.retained, self.transient, self.scratch], self.maximum)
    }

    pub(crate) fn authenticate_owner_data(
        &self,
        source: &PacketCompleteSemanticSource,
        controller: *const CnpController,
        read_owner: *const (),
        request: &OriginalRestoredCaptureRequestData<'_>,
    ) -> Result<(), RuntimeError> {
        source.storage_origin_with_error::<RuntimeError>()?;
        if self.process != std::process::id()
            || self.thread != std::thread::current().id()
            || !std::ptr::eq(self.source, source)
            || self.controller != controller
            || self.read_owner != read_owner
            || self.capture_id != *blake3::hash(request.capture_id.as_str().as_bytes()).as_bytes()
            || self.cut != request.cut
            || self.ordinal != request.ordinal
            || self.runtime != request.maximum_runtime_record_encoded_bytes
            || self.checkpoint != request.maximum_coordinator_checkpoint_encoded_bytes
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.requested_bytes_data()?;
        Ok(())
    }

    pub(crate) fn authenticate_same_construction_data(
        &self,
        other: &Self,
    ) -> Result<(), RuntimeError> {
        if self != other {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.requested_bytes_data()?;
        Ok(())
    }
}
