//! Selects a prior completed observation from the actual nonrenewing native bank.

use super::*;

type Prior = (usize, Rc<RefCell<NativeRestoredSettledActionAttempt>>);

impl NativeRestoredSettledCaptureOwner {
    /// Selects only prior privately published observations from the same bank.
    ///
    /// # Errors
    /// Refuses another receiving occurrence, failed/unsealed custody,
    /// unsupported prior families or nonmonotonic publication records.
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn original_observation17_prior_data(
        &self,
        boot: &Rc<RefCell<NativeAckBoot>>,
        receiving_index: usize,
        receiving: &Rc<RefCell<NativeRestoredSettledActionAttempt>>,
        first_record: usize,
    ) -> Result<Option<Prior>, ProviderError> {
        self.authenticate_retained_attempt_data(boot, receiving_index, receiving)?;
        if self.sealed.is_none() || receiving_index.checked_add(1) != Some(self.attempts.len()) {
            return Err(refused());
        }
        let mut previous_record = first_record;
        let mut selected = None;
        for (index, attempt) in self.attempts[..receiving_index].iter().enumerate() {
            let actual = attempt.try_borrow().map_err(|_| refused())?;
            actual.with_published_observation_checkpoint17_data(|_, _, record| {
                if record <= previous_record {
                    return Err(refused());
                }
                previous_record = record;
                Ok(())
            })?;
            selected = Some((index, Rc::clone(attempt)));
        }
        // Capture/uploads and Input/Run/Poll/Retire deliberately refuse here:
        // no absence or metadata-only result is an administrative bridge.
        Ok(selected)
    }
}
