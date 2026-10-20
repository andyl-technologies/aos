//! Captures only Storage's actual fixed floor through the retained original F.
//!
//! This is the real admission caller of the sole captured-writer and typed
//! floor suppliers. The physical helper remains a separately paid prerequisite;
//! a positive capture never produces Required readiness or permission to act.

use super::*;

impl BrokerAttachmentAttemptV1 {
    pub(super) fn capture_storage_sidecar_once_v2(
        &mut self,
        owner: &mut crate::recovery::journal::ProtectedBrokerSessionJournalV1,
        receiving: &mut aos_sandbox::StoragePrepareReceivingLoanV1<'_>,
    ) -> Result<(), FloorErrorV1> {
        if self.phase != BrokerAttachmentPhaseV1::Checking || self.first_failure.is_some()
            || self.storage_opening.is_some() || self.controller_opening.is_some()
            || self.opening.is_some() || self.store.is_some()
        { return Err(FloorErrorV1::Unavailable); }
        let main = owner.journal.as_ref().ok_or(FloorErrorV1::Unavailable)?;
        let fixed = store::StorageSidecarOpenOriginalV2::fixed_demand();
        let payment = match fixed.as_ref() {
            Ok(bound) => receiving.reserve_floor_capture_v2(main, *bound),
            Err(_) => Err(aos_sandbox::StorageReceivingClosedV1),
        };
        // A refused fixed stage retains its complete arithmetic/payment result
        // before returning. No allocation or native acquisition follows it.
        if fixed.is_err() || payment.is_err() {
            self.storage_fixed = Some((fixed, payment));
            self.record(BrokerAttachmentFailureV1::StorageSidecar);
            return Err(FloorErrorV1::Unavailable);
        }
        self.storage_opening = Some(Box::new(store::StorageSidecarOpenOriginalV2::new(fixed, payment)));
        let original = self.storage_opening.as_mut().ok_or(FloorErrorV1::Unavailable)?;
        let result = original.capture_once(owner, receiving)
            .and_then(|()| original.finish_into(owner, &mut self.store));
        if result.is_err() { self.record(BrokerAttachmentFailureV1::StorageSidecar); }
        result
    }

    pub(in crate::recovery::journal::tpm_floor) fn storage_sidecar_failure_v2(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if !matches!(self.first_failure, Some(BrokerAttachmentFailureV1::StorageSidecar)) {
            return self.store.as_ref()?.storage_read_failure_v2();
        }
        self.storage_fixed.as_ref().and_then(|(fixed, paid)| {
            fixed.as_ref().err().map(|cause| cause as &(dyn std::error::Error + 'static))
                .or_else(|| paid.as_ref().err().map(|cause| cause as _))
        }).or_else(|| self.storage_opening.as_ref()?.failure())
    }
}
