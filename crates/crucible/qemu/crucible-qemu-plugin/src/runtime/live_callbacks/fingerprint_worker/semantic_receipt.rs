//! Correlates actual worker/material closure with the retained sample action.
//!
//! These local counters are checked, nonrenewing receipt identities in the paid
//! worker control. They issue no operation or progress. A receipt is deposited
//! only after the real owning job has returned all physical leaves.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::runtime::live_callbacks) struct CaptureReceipt {
    pub(in crate::runtime::live_callbacks) epoch: u64,
    pub(in crate::runtime::live_callbacks) capture: u32,
    pub(in crate::runtime::live_callbacks) sample_completed: bool,
    pub(in crate::runtime::live_callbacks) first: i32,
}

#[derive(Clone, Copy)]
pub(in crate::runtime::live_callbacks) struct CaptureReceiptSnapshot {
    pub(in crate::runtime::live_callbacks) sequence: u64,
    pub(in crate::runtime::live_callbacks) returned: [Option<CaptureReceipt>; 2],
    pub(in crate::runtime::live_callbacks) quiet: bool,
    pub(in crate::runtime::live_callbacks) closed: bool,
}

#[derive(Default)]
pub(super) struct ReceiptJournal {
    sequence: u64,
    returned: [Option<CaptureReceipt>; 2],
}

impl ReceiptJournal {
    pub(super) fn reserve(&mut self) -> Result<u64, i32> {
        let next = self.sequence.checked_add(1).ok_or(-libc::EOVERFLOW)?;
        self.sequence = next;
        Ok(next)
    }

    pub(super) fn record(&mut self, index: usize, receipt: CaptureReceipt) -> Result<(), i32> {
        let field = self.returned.get_mut(index).ok_or(-libc::EPROTO)?;
        if *field == Some(receipt) {
            return Ok(());
        }
        if receipt.epoch == 0
            || receipt.epoch > self.sequence
            || field.is_some_and(|previous| previous.epoch >= receipt.epoch)
        {
            return Err(-libc::ESTALE);
        }
        *field = Some(receipt);
        Ok(())
    }

    fn snapshot(&self, quiet: bool, closed: bool) -> CaptureReceiptSnapshot {
        CaptureReceiptSnapshot {
            sequence: self.sequence,
            returned: self.returned,
            quiet,
            closed,
        }
    }
}

impl LiveFingerprintDigestWorker {
    /// Observes genuine retained worker custody without creating an operation.
    ///
    /// # Errors
    /// Refuses a foreign actor, absent Source lifetime scope, contention or
    /// poisoned journals. Busy physical leaves are reported as retained debt.
    #[cfg(not(test))]
    pub(in crate::runtime::live_callbacks) fn semantic_receipt_snapshot(
        &self,
    ) -> Result<CaptureReceiptSnapshot, i32> {
        if !self.creator_process_is_current() {
            return Err(-libc::EPERM);
        }
        // Closing selects an attempt, never permission. The actual terminal
        // scope independently requires Source's completed close and genuine
        // Main cleanup entry. A refusal cannot fall back to ordinary admission.
        let terminal = self.native.observe().map_err(|_| -libc::ESTALE)?.closing == 1;
        self.native
            .with_control(terminal, |control| {
                let mut quiet = true;
                for index in 0..2 {
                    let job = control.jobs[index]
                        .try_lock()
                        .map_err(|_| super::native::status_error(-libc::EBUSY))?;
                    quiet &= job
                        .as_ref()
                        .is_none_or(|job| job.physical_leaves_returned());
                }
                let attempt = control
                    .capture_attempt
                    .try_lock()
                    .map_err(|_| super::native::status_error(-libc::EBUSY))?;
                quiet &= !attempt.has_material_debt();
                quiet &= self.native.workspace_quiet().is_ok();
                let state = control
                    .state
                    .try_lock()
                    .map_err(|_| super::native::status_error(-libc::EBUSY))?;
                Ok(state.receipts.snapshot(quiet, terminal || state.closed))
            })
            .map_err(|_| -libc::ESTALE)
    }

    #[cfg(test)]
    pub(in crate::runtime::live_callbacks) fn semantic_receipt_snapshot(
        &self,
    ) -> Result<CaptureReceiptSnapshot, i32> {
        if !self.creator_process_is_current() {
            return Err(-libc::EPERM);
        }
        let control = self.control.as_ref().ok_or(-libc::ENOENT)?;
        let job = control.in_flight.try_lock().map_err(|_| -libc::EBUSY)?;
        let state = control.state.try_lock().map_err(|_| -libc::EBUSY)?;
        Ok(state
            .receipts
            .snapshot(job.is_none() && state.pending.is_none(), state.closed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhausted_receipt_epoch_retains_the_actual_unsubmitted_capture() {
        let control = FingerprintWorkerControl::new(None);
        control.lock().receipts.sequence = u64::MAX;
        let mut captured = Some(CapturedFingerprintSample::test_empty());

        assert_eq!(control.enqueue(&mut captured, 1), Err(()));

        assert!(captured.is_some());
        let state = control.lock();
        assert!(state.pending.is_none());
        assert_eq!(state.receipts.sequence, u64::MAX);
        assert_eq!(state.receipts.returned, [None; 2]);
    }
}
