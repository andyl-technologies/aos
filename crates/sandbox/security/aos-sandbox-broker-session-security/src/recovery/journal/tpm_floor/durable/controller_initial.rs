//! Acquires only the actual Controller Storage sidecar under its genuine B.
//!
//! This remains a staged attachment operation. Completing sidecar custody never
//! makes the physical TPM/backend ready, resets failure, or finishes the outer
//! floor. The same admitted main and original loan remain continuously held.

use super::{BrokerAttachmentAttemptV1, BrokerAttachmentFailureV1, BrokerAttachmentPhaseV1,
    FloorErrorV1, store::ControllerSidecarOpenOriginalV1};

impl BrokerAttachmentAttemptV1 {
    /// Captures the existing sibling after its distinct fixed and prefix debits.
    ///
    /// # Errors
    /// Retains actual finance, native, typed-shape and independent endpoint
    /// outcomes. It never enters a physical/helper operation or marks Ready.
    pub(super) fn capture_controller_sidecar_once_v1(
        &mut self,
        owner: &mut crate::recovery::journal::ProtectedBrokerSessionJournalV1,
        receiving: &mut aos_sandbox_controller_domain::ControllerInitialBrokerSessionReceivingLoanV1<'_>,
    ) -> Result<(), FloorErrorV1> {
        if self.phase != BrokerAttachmentPhaseV1::Checking
            || self.first_failure.is_some() || self.opening.is_some()
            || self.controller_fixed.is_some() || self.controller_opening.is_some()
            || self.store.is_some()
        {
            return Err(FloorErrorV1::Unavailable);
        }
        let Some(main) = owner.journal.as_ref() else {
            return Err(FloorErrorV1::Unavailable);
        };
        // Fixed DATA construction allocates nothing. The whole once debit is
        // parked on this actual attachment BEFORE Box/facade construction.
        let fixed = ControllerSidecarOpenOriginalV1::fixed_shape_v1()
            .ok_or(FloorErrorV1::Encoding)?;
        self.controller_fixed = Some(receiving.require_storage_floor_fixed_preparation_once_v1(
            main, &fixed,
        ));
        if !matches!(self.controller_fixed, Some(Ok(()))) {
            self.record(BrokerAttachmentFailureV1::ControllerSidecar);
            return Err(FloorErrorV1::Unavailable);
        }
        self.controller_opening = Some(Box::new(ControllerSidecarOpenOriginalV1::new()));
        let original = self.controller_opening.as_mut().ok_or(FloorErrorV1::Unavailable)?;
        let result = original.capture_once(owner, receiving);
        if result.is_err() {
            self.record(BrokerAttachmentFailureV1::ControllerSidecar);
            return result;
        }
        let result = original.finish_into(owner, receiving, &mut self.store);
        if result.is_err() {
            self.record(BrokerAttachmentFailureV1::ControllerSidecar);
        }
        result
    }

    pub(super) fn controller_sidecar_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if !matches!(self.first_failure, Some(BrokerAttachmentFailureV1::ControllerSidecar)) {
            return None;
        }
        self.controller_fixed.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.controller_opening.as_ref()?.failure())
    }
}
