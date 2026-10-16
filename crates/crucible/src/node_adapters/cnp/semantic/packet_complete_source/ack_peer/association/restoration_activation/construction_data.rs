//! Binds an independent fixed Source activation quote to its original owners.
//!
//! This opaque row owns only fixed scalars, raw identity pointers and the fixed
//! Provider DATA row. It retains no allocation, Rc, Weak, key, Window or claim.
//! Core counts its inline NodeRow slot and admits the separately quoted future
//! banks, normalized originals, proof decoders and read-fence work before Prepare.

use super::*;

/// Retains independently quoted Source signing and activation-evidence demand.
///
/// No public constructor or conversion exists. This DATA cannot authorize a
/// phase, allocate the future banks, sign a replacement original or issue Ready.
/// The same genuine Window must admit it and supply its once-spent claim.
#[derive(Clone, Copy)]
pub struct OriginalSourceRestorationActivationConstructionData {
    pub(super) process: u32,
    pub(super) thread: std::thread::ThreadId,
    pub(super) source: *const PacketCompleteSemanticSource,
    pub(super) controller: *const CnpController,
    pub(super) provider: OriginalInstalledRestorationActivationConstructionData,
    pub(super) retained: usize,
    pub(super) transient: usize,
    pub(super) scratch: usize,
    pub(super) requested: usize,
    pub(super) maximum: usize,
    pub(super) frame: usize,
    pub(super) manifest: usize,
}

// These are the actual references bound by each exhaustive comparison view,
// not a substitute payload size or a claim about a compiler stack frame.
type BorrowedConstructionFields<'a> = (
    &'a u32,
    &'a std::thread::ThreadId,
    &'a *const PacketCompleteSemanticSource,
    &'a *const CnpController,
    &'a OriginalInstalledRestorationActivationConstructionData,
    &'a usize,
    &'a usize,
    &'a usize,
    &'a usize,
    &'a usize,
    &'a usize,
    &'a usize,
);

pub(super) fn counter_scratch_data() -> usize {
    2 * size_of::<BorrowedConstructionFields<'static>>()
        + 2 * size_of::<&OriginalSourceRestorationActivationConstructionData>()
        + size_of::<Result<(), crucible_node_provider::ProviderError>>()
        + size_of::<Result<(), RuntimeError>>()
}

impl OriginalSourceRestorationActivationConstructionData {
    pub(crate) fn retained_requested_bytes_data(&self) -> usize {
        self.retained
    }

    pub(crate) fn maximum_simultaneous_transient_bytes_data(&self) -> usize {
        self.transient
    }

    pub(crate) fn requested_peak_bytes_data(&self) -> usize {
        self.requested
    }

    pub(crate) fn counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }

    pub(super) fn maximum_frame_bytes_data(&self) -> usize {
        self.frame
    }

    pub(super) fn maximum_activation_manifest_encoded_bytes_data(&self) -> usize {
        self.manifest
    }

    // Core lends this fixed DATA by value so its Window loan ends before the
    // mutable Controller loan. Compare the complete defining fields, not the
    // address of that temporary copy; the genuine owned claim remains required.
    pub(super) fn authenticate_same_construction_data(
        &self,
        other: &Self,
    ) -> Result<(), RuntimeError> {
        let Self {
            process,
            thread,
            source,
            controller,
            provider,
            retained,
            transient,
            scratch,
            requested,
            maximum,
            frame,
            manifest,
        } = self;
        let Self {
            process: other_process,
            thread: other_thread,
            source: other_source,
            controller: other_controller,
            provider: other_provider,
            retained: other_retained,
            transient: other_transient,
            scratch: other_scratch,
            requested: other_requested,
            maximum: other_maximum,
            frame: other_frame,
            manifest: other_manifest,
        } = other;
        if process != other_process
            || thread != other_thread
            || source != other_source
            || controller != other_controller
            || retained != other_retained
            || transient != other_transient
            || scratch != other_scratch
            || requested != other_requested
            || maximum != other_maximum
            || frame != other_frame
            || manifest != other_manifest
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        provider
            .authenticate_same_construction_data(other_provider)
            .map_err(|_| RuntimeError::ForeignAuthority)
    }

    pub(super) fn authenticate_original(
        &self,
        source: &PacketCompleteSemanticSource,
        controller: &CnpController,
    ) -> Result<(), RuntimeError> {
        source.storage_origin_with_error::<RuntimeError>()?;
        if !source.is_original_restoration_activation_declaration_data()? {
            return Err(RuntimeError::UnsupportedFacet);
        }
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        if !std::ptr::eq(self.source, source)
            || !std::ptr::eq(self.controller, controller)
            || self.frame
                != usize::try_from(controller.authority().limits().frame_bytes.get())
                    .map_err(|_| RuntimeError::ResourceLimit)?
            || self.requested != sum([self.retained, self.transient, self.scratch], self.maximum)?
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(super) fn authenticate_request_data(
        &self,
        request: &PacketRestorationActivationRequest,
    ) -> Result<(), RuntimeError> {
        request
            .validate_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if request.native_allocation != self.provider.native_allocation_data(request.phase) {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}
