//! Binds the fixed observation quote to the same actual Source and Controller.
//!
//! This row owns no allocation, key, claim, Window, World or Rc. Core may copy
//! it out of its Window loan; equality compares complete defining fields rather
//! than the address of that temporary header.

use super::super::restoration_activation::OriginalSourceRestorationActivationConstructionData;
use super::*;

/// Retains separately pre-admitted observation signing and scheduling demand.
///
/// This fixed DATA has no public constructor or authority conversion. A genuine
/// once Core claim, current Source read and actual SDK/native proof remain
/// necessary independently of this row.
#[derive(Clone, Copy)]
pub struct OriginalSourceRestorationObservationConstructionData {
    pub(super) process: u32,
    pub(super) thread: std::thread::ThreadId,
    pub(super) source: *const PacketCompleteSemanticSource,
    pub(super) controller: *const CnpController,
    pub(super) provider: OriginalInstalledRestorationObservationConstructionData,
    pub(super) activation: OriginalSourceRestorationActivationConstructionData,
    pub(super) request_id: [u8; 32],
    pub(super) retained: usize,
    pub(super) transient: usize,
    pub(super) scratch: usize,
    pub(super) requested: usize,
    pub(super) maximum: usize,
    pub(super) frame: usize,
    pub(super) scheduling: usize,
    pub(super) node_scheduling_copies: usize,
}

impl OriginalSourceRestorationObservationConstructionData {
    pub(crate) fn retained_requested_bytes_data(&self) -> usize {
        self.retained
    }

    pub(crate) fn maximum_simultaneous_transient_bytes_data(&self) -> usize {
        self.transient
    }

    pub(crate) fn counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }

    pub(crate) fn requested_peak_bytes_data(&self) -> usize {
        self.requested
    }

    /// Returns the independently quoted backing of one real scheduling copy.
    ///
    /// The Source and node each retain a separate owner. Their enclosing
    /// collectors add this term independently before issuing the phase.
    pub(crate) fn scheduling_observation_requested_bytes_data(&self) -> usize {
        self.scheduling
    }

    pub(crate) fn node_scheduling_copy_requested_bytes_data(&self) -> usize {
        self.node_scheduling_copies
    }

    pub(super) fn authenticate_same_construction_data(
        &self,
        other: &Self,
    ) -> Result<(), RuntimeError> {
        // Exhaustive patterns make adding a defining field a compile-time
        // obligation. Direct comparisons avoid retaining field-reference tuples.
        let Self {
            process: _,
            thread: _,
            source: _,
            controller: _,
            provider: _,
            activation: _,
            request_id: _,
            retained: _,
            transient: _,
            scratch: _,
            requested: _,
            maximum: _,
            frame: _,
            scheduling: _,
            node_scheduling_copies: _,
        } = *self;
        if self.process != other.process
            || self.thread != other.thread
            || self.source != other.source
            || self.controller != other.controller
            || self.request_id != other.request_id
            || self.retained != other.retained
            || self.transient != other.transient
            || self.scratch != other.scratch
            || self.requested != other.requested
            || self.maximum != other.maximum
            || self.frame != other.frame
            || self.scheduling != other.scheduling
            || self.node_scheduling_copies != other.node_scheduling_copies
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.provider
            .authenticate_same_construction_data(&other.provider)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        self.activation
            .authenticate_same_construction_data(&other.activation)
    }

    pub(super) fn authenticate_original(
        &self,
        source: &PacketCompleteSemanticSource,
        controller: &CnpController,
    ) -> Result<(), RuntimeError> {
        source.storage_origin_with_error::<RuntimeError>()?;
        if self.process != std::process::id()
            || self.thread != std::thread::current().id()
            || !std::ptr::eq(self.source, source)
            || !std::ptr::eq(self.controller, controller)
            || self.frame
                != usize::try_from(controller.authority().limits().frame_bytes.get())
                    .map_err(|_| RuntimeError::ResourceLimit)?
            || self.requested != sum([self.retained, self.transient, self.scratch], self.maximum)?
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.activation.authenticate_original(source, controller)
    }

    pub(super) fn authenticate_request_data(
        &self,
        request: &PacketRestorationObservationRequest,
        id: &Id,
    ) -> Result<(), RuntimeError> {
        request
            .validate_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if self.request_id != *blake3::hash(id.as_str().as_bytes()).as_bytes()
            || request.native_allocation != self.provider.native_allocation_data()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}

pub(super) const fn counter_scratch_data() -> usize {
    size_of::<OriginalSourceRestorationObservationConstructionData>()
        + 2 * size_of::<&OriginalSourceRestorationObservationConstructionData>()
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<Result<(), crucible_node_provider::ProviderError>>()
        + size_of::<Result<usize, RuntimeError>>()
        + size_of::<[usize; 3]>()
        + size_of::<std::array::IntoIter<usize, 3>>()
        + size_of::<blake3::Hash>()
        + size_of::<[u8; 32]>()
}
