//! Retains the real target publisher in the same registered fresh capsule.

use super::*;
use crate::node_qualification::packet_collection::complete::restored_publication::PacketRestoredProducerPublicationInputs;

impl PacketCompleteReportStartupHolder {
    /// Retains target result storage before the complete restoration window.
    ///
    /// The full incoming bank moves into the same actual fresh capsule before
    /// quoting or allocating future slots. Repeated or late calls leave the
    /// caller's bank untouched. No Directory or native effect occurs here.
    ///
    /// # Errors
    /// Refuses a foreign or nonfresh holder, absent suffix selection, occupied
    /// publisher, late window/transaction, missing inputs or a busy owner loan.
    pub fn retain_original_restored_producer_publication_into(
        original: &Rc<RefCell<Self>>,
        incoming: &mut Option<PacketRestoredProducerPublicationInputs>,
    ) -> Result<(), RuntimeError> {
        let held = original.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        held.authenticate_native_origin_data()?;
        if held.restoration_attempted.get()
            || held.restoration_window.get().is_some()
            || held.original_scene_retired.get()
            || !held.restored_suffix_startup_selected_data()?
            || held.restored_result_publication.get().is_some()
            || incoming.is_none()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let StartupHolderPurpose::FreshRestoration(capsule) = &held.purpose else {
            return Err(RuntimeError::ForeignAuthority);
        };
        let maximum = held.restoration_policy_data()?.maximum_requested_bytes;
        let mut capsule = capsule
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let pointer = capsule.retain_original_restored_results_into(
            original,
            Rc::clone(&held.plan),
            incoming,
            maximum,
        )?;
        held.restored_result_publication
            .set(pointer)
            .map_err(|_| RuntimeError::DuplicateOperation)
    }
}

impl PacketCompleteReportStartupHolder {
    pub(super) fn original_restored_result_counter_scratch_data(
        &self,
    ) -> Result<usize, RuntimeError> {
        if self.restored_result_publication.get().is_none() {
            return Ok(0);
        }
        let StartupHolderPurpose::FreshRestoration(capsule) = &self.purpose else {
            return Ok(0);
        };
        capsule
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .original_restored_result_counter_scratch_data()
    }
}

impl PacketCompleteReportStartupHolder {
    pub(super) fn authenticate_original_restored_result_candidate_data(
        &self,
        scope: &OriginalRestorationConstructionScope<'_>,
    ) -> Result<(), RuntimeError> {
        if self.restored_result_publication.get().is_none() {
            return if scope
                .original_restored_producer_publication_candidate_data()
                .is_none()
            {
                Ok(())
            } else {
                Err(RuntimeError::ForeignAuthority)
            };
        }
        let StartupHolderPurpose::FreshRestoration(capsule) = &self.purpose else {
            return Err(RuntimeError::ForeignAuthority);
        };
        let observed = capsule
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .original_restored_result_candidate_data(scope.plan(), scope.inputs(), Some(scope))?;
        match (
            scope.original_restored_producer_publication_candidate_data(),
            observed,
        ) {
            (None, Some((pointer, _)))
                if scope.phase()
                    == crucible_engine::node_admission::OriginalRestorationConstructionPhase::ColdOwners
                    && self.restored_result_publication.get() == Some(&pointer) =>
            {
                Ok(())
            }
            (Some((expected, row)), Some((pointer, actual)))
                if expected == pointer
                    && row == &actual
                    && self.restored_result_publication.get() == Some(&pointer) =>
            {
                Ok(())
            }
            _ => Err(RuntimeError::ForeignAuthority),
        }
    }
}
