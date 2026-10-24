//! Retains Capture failure custody across archive refusal and unwinding.

use super::*;

/// Poisons the original admitted attempt unless every archive tail completes.
///
/// This guard lends no owner permission. Claims remain separately bound to the
/// actual ticket, current native read and independently admitted Source rows.
pub(crate) struct OriginalRestoredCaptureAttemptGuard<'a> {
    window: &'a CompleteOriginalRestorationWindow,
    slot: usize,
    completed: bool,
}

impl OriginalRestoredCaptureAttemptGuard<'_> {
    /// Disarms only after genuine archive completion and its whole observation.
    ///
    /// # Errors
    /// Refuses a pending observation, foreign slot or any incomplete owner tail.
    pub(crate) fn complete_data(mut self) -> Result<(), RuntimeError> {
        self.window.origin()?;
        self.window.whole_observation.authenticate_dispatch_data()?;
        let ledger = self
            .window
            .restored_captures
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let attempt = ledger.active(self.slot)?;
        if attempt.stage.get() != Stage::Verified
            || attempt.writer_join.get() != checkpoint::WriterJoinStage::Verified
            || attempt.members.iter().any(|member| member.get() != 2)
            || self.window.restored_capture_in_flight.get()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.completed = true;
        Ok(())
    }
}

impl Drop for OriginalRestoredCaptureAttemptGuard<'_> {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        if let Ok(ledger) = self.window.restored_captures.try_borrow()
            && let Ok(attempt) = ledger.active(self.slot)
        {
            attempt.stage.set(Stage::Failed);
        }
        self.window.restored_capture_in_flight.set(true);
        self.window.whole_observation.require_observation();
    }
}

impl CompleteOriginalRestorationWindow {
    /// Retains failure custody immediately after the real admitted append.
    ///
    /// # Errors
    /// Refuses a foreign slot, absent admission or a previously submitted owner.
    pub(crate) fn retain_restored_capture_attempt_guard_data(
        &self,
        slot: usize,
    ) -> Result<OriginalRestoredCaptureAttemptGuard<'_>, RuntimeError> {
        self.origin()?;
        let ledger = self
            .restored_captures
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let attempt = ledger.active(slot)?;
        if attempt.stage.get() != Stage::Admitted
            || attempt.members.iter().any(|member| member.get() != 0)
            || !self.restored_capture_in_flight.get()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(OriginalRestoredCaptureAttemptGuard {
            window: self,
            slot,
            completed: false,
        })
    }
}
