//! Shares the actual four-Root-post and same-peer crossing with cleanup reads.
//!
//! Only the private paid acquisition owner supplies its completed native model
//! loan. This branch appends nothing and cannot certify a floor transition.

use super::*;
use crate::policy_compiler::execution_no_apply_root::acquisition::CompletedAcquisitionModelsLoanV2;
use crate::policy_compiler::provisioning_current::RootContinuationClockGateV1;

impl Crossing {
    pub(in crate::policy_compiler::execution_no_apply_root) fn complete_acquisition_read_once_v2(
        &mut self,
        flight: &RootPolicyAcceptedFlightV1<'_, '_>,
        original: &RetainedUnixStream,
        writers: &RootCreateStorageCurrentWritersV1,
        models: &CompletedAcquisitionModelsLoanV2<'_>,
        clock: &mut RootContinuationClockGateV1,
    ) -> Result<(), JournalError> {
        if self.completion.is_some() {
            self.reentry.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        // The same engine's four independently owed destinations were armed
        // before any slow acquisition read. Finish drains them on every path.
        self.finish_after_once(writers);
        self.peer_result =
            Some(flight.observe_execution_no_apply_floor_peer_once_v2(original, &mut self.peer));
        self.peer_settlement = Some(self.peer.settle_after_root_post_once_v1());
        self.clock = Some(
            clock
                .check_next_once_v1()
                .and_then(|sample| models.require_current_at_v2(sample)),
        );
        self.external_trust = matches!(self.clock, Some(Err(_)))
            && clock.failure().is_some()
            && matches!(self.peer_result, Some(Ok(())))
            && matches!(self.peer_settlement, Some(Ok(())))
            && self
                .before
                .iter()
                .chain(self.after.iter())
                .all(|value| matches!(value, Some(Ok(()))));
        self.completion = Some((|| {
            for post in &self.before {
                positive(post)?;
            }
            for post in &self.after {
                positive(post)?;
            }
            positive(&self.peer_result)?;
            positive(&self.peer_settlement)?;
            positive(&self.clock)?;
            Ok(())
        })());
        self.require_complete()
    }
}
