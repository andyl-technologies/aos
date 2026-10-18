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
            PacketRestoredSettledNativeUploadFutureStorageData,
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
    pub(super) finalization: super::finalization::FinalizationStorage,
    pub(super) materialization: super::materialization_storage::CaptureMaterializationStorage,
    pub(super) sdk: OriginalRestoredSettledCaptureConstructionData,
    pub(super) native: PacketRestoredSettledNativeCarrierData,
    pub(super) native_upload: PacketRestoredSettledNativeUploadFutureStorageData,
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

    /// Checks every output role against the actual remaining native capture limits.
    ///
    /// The owning Node invokes this before SDK effects and repeats it during
    /// materialization. It grants no Capture action and raises no original cap.
    ///
    /// # Errors
    /// Refuses a record, aggregate-byte or object ceiling below any required role.
    pub fn authenticate_capture_output_limits_data(
        &self,
        limits: crate::node_contract::NativeCaptureLimits,
    ) -> Result<(), RuntimeError> {
        self.materialization.authenticate_limits_data(limits)
    }

    /// Returns the separate born-row and returned-row geometry for this Source.
    ///
    /// The native owning preflight and archive factory must independently admit
    /// these axes before any row is retained or cloned. This is DATA only.
    pub fn capture_dependency_storage_data(
        &self,
    ) -> crate::node_adapters::cnp::PacketCompleteCaptureDependencyStorageData {
        self.materialization.born.dependency_storage_data()
    }

    /// Returns original closure geometry before SDK effects without another walk.
    ///
    /// Tuple order is objects, complete body bytes, fullref clone backing, edge
    /// occurrences, adjacency Vec-plus-ref backing, largest body, maximum
    /// returned-row copy, and maximum row-plus-hash window. These facts were
    /// derived from the actual original archive/ticket during funded quotation.
    /// Destination map/owner headers and the native action remain independent.
    pub const fn capture_imported_closure_storage_data(
        &self,
    ) -> (usize, usize, usize, usize, usize, usize, usize, usize) {
        self.materialization.born.imported_closure_storage_data()
    }

    /// Checks this stored row's actual Source and request provenance only.
    ///
    /// This metadata guard authenticates no controller, read, native permission,
    /// allocation or quota. Full owning callers retain those independent loans.
    ///
    /// # Errors
    /// Refuses foreign actor/Source custody, another actual Capture request,
    /// changed cut/ordinal or different defining Runtime/checkpoint maxima.
    pub(crate) fn authenticate_source_data(
        &self,
        source: &PacketCompleteSemanticSource,
        request: &OriginalRestoredCaptureRequestData<'_>,
    ) -> Result<(), RuntimeError> {
        source.storage_origin_with_error::<RuntimeError>()?;
        if self.process != std::process::id()
            || self.thread != std::thread::current().id()
            || !std::ptr::eq(self.source, source)
            || self.capture_id != *blake3::hash(request.capture_id.as_str().as_bytes()).as_bytes()
            || self.cut != request.cut
            || self.ordinal != request.ordinal
            || self.runtime != request.maximum_runtime_record_encoded_bytes
            || self.checkpoint != request.maximum_coordinator_checkpoint_encoded_bytes
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    /// Names this narrow metadata guard's fixed actual request/hash controls.
    pub(crate) fn authenticate_source_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<&Self>()
            + size_of::<&PacketCompleteSemanticSource>()
            + size_of::<&OriginalRestoredCaptureRequestData<'static>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<std::thread::Thread>()
            + size_of::<std::thread::ThreadId>()
            + size_of::<u32>()
            + size_of::<blake3::Hash>()
            + size_of::<blake3::Hasher>()
            + size_of::<[u8; 32]>()
            + size_of::<&[u8; 32]>()
    }

    pub(crate) fn authenticate_owner_data(
        &self,
        source: &PacketCompleteSemanticSource,
        controller: *const CnpController,
        read_owner: *const (),
        request: &OriginalRestoredCaptureRequestData<'_>,
    ) -> Result<(), RuntimeError> {
        source.storage_origin_with_error::<RuntimeError>()?;
        // Check the real controller/read identities before performing the
        // request digest; foreign owners do not gain a new metadata pass.
        if self.controller != controller || self.read_owner != read_owner {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.authenticate_source_data(source, request)?;
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
