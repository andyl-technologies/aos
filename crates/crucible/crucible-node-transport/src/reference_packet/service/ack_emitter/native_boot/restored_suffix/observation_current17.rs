//! Borrows the actual first-observation link without regenerating signed DTOs.

use super::*;

impl NativeRestoredSuffixStartupOwner {
    /// Borrows the genuine first link while every old progress bank is unused.
    ///
    /// # Errors
    /// Refuses foreign/failed/unsealed owners, another first attempt, old
    /// startup16 provenance or any initialized recurring/Producer history.
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn original_observation17_seed_record_data(
        &self,
        first: &Rc<RefCell<NativeRestorationObservationAttempt>>,
    ) -> Result<usize, ProviderError> {
        self.ensure_current()?;
        if !self.preamble.is_settled17_data()
            || self.sealed.is_none()
            || !self.observe_attempts.is_empty()
            || !self.producer_attempts.is_empty()
            || !self.observation.ptr_eq(&Rc::downgrade(first))
        {
            return Err(refused());
        }
        // Any initialized old16 progress blocks the seed, including failures.
        // Its current proof must eventually be joined through its own owner.
        self.post_record.ok_or_else(refused)
    }
}
