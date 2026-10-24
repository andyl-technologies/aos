//! Borrows the original permissions for one Control dispatch.
//!
//! The view retains the same independent optional permits and exclusive Observe
//! preparation. It creates no native right and supplies no replay or retry path.

use super::OriginalObserveAllocationPreparation;
use crate::reference_packet::service::ack_emitter::{
    OriginalCanonicalAckControlAdmit, OriginalRestorationActivationPermit,
    OriginalRestorationObservationPermit, OriginalRestoredProducerRead,
    OriginalRestoredSuffixObserveRead,
};
use std::mem::size_of;

/// Groups actual borrowed permissions without constructing or cloning a permit.
pub(super) struct OriginalControlPermissionsData<'loan, 'admit, 'observe, 'suffix, 'producer> {
    /// Borrows the original once-only canonical Admit handoff, when present.
    pub(super) canonical_ack_admit: Option<&'loan OriginalCanonicalAckControlAdmit<'admit>>,
    /// Exclusively borrows the original Observe transformation and preparation.
    pub(super) selected_observe: Option<&'loan mut OriginalObserveAllocationPreparation<'observe>>,
    /// Borrows the original physical-restoration activation permit.
    pub(super) restoration_activation: Option<&'loan OriginalRestorationActivationPermit>,
    /// Borrows the original first-restoration observation permit.
    pub(super) restoration_observation: Option<&'loan OriginalRestorationObservationPermit>,
    /// Borrows the separately spent recurring-Observe scope.
    pub(super) suffix_observation: Option<&'loan OriginalRestoredSuffixObserveRead<'suffix>>,
    /// Borrows the separately spent current Producer scope.
    pub(super) producer_action: Option<&'loan OriginalRestoredProducerRead<'producer>>,
}

/// Counts both permission headers at the independently funded dispatch boundary.
pub(crate) const fn original_control_permissions_counter_scratch_data() -> usize {
    2 * size_of::<OriginalControlPermissionsData<'static, 'static, 'static, 'static, 'static>>()
        + size_of::<usize>()
}
