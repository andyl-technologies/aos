//! Borrows the actual committed Prepare outcome for the closed native C9 recipe.
//!
//! Packet bytes stay in the original Session commit. The native owner checks
//! the complete C8 prefix/readback and always closes entered refusal posts.

use super::*;
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;

impl OriginalStorageCreatePreparationFlightV1 {
    pub(crate) fn committed_prepare_outcome_v1(&self)
        -> Result<&AuthenticatedBrokerMethodOutcomeV1, OutputPreparationClosedV1> {
        if !self.complete || self.use_first.is_some() || self.shared.inner.closed {
            return Err(OutputPreparationClosedV1);
        }
        let Some(crate::ProtectedBrokerOutcomeCommitResultV1::Committed(terminal)) = self.shared.inner.committed.as_ref() else {
            return Err(OutputPreparationClosedV1);
        };
        terminal.storage_prepare_client_originals_v1().map(|(outcome, _)| outcome)
            .map_err(|_| OutputPreparationClosedV1)
    }

    pub(crate) fn record_outcome_once(&mut self, session: &mut DormantAuthenticatedBrokerSessionV1,
        ready: &mut aos_sandbox_controller_domain::OriginalCreateStorageReadyV1<'_, '_>,
    ) -> bool {
        if self.recorded_outcome.is_some() || self.use_first.is_some() || !self.complete || self.shared.inner.closed {
            return self.close_use(UsePreparationFailureV1::Closed);
        }
        let journal = match session.owner.retained_storage_client_journal_v1() {
            Ok(journal) => Some(journal),
            Err(cause) => {
                self.shared.inner.protected_failure.get_or_insert(cause);
                None
            }
        };
        let missing_journal = journal.is_none();
        let produced = match self.committed_prepare_outcome_v1() {
            Ok(outcome) => ready.produce_original_storage_outcome_once(journal, &session.socket, &session.transcript, outcome),
            Err(_) => return self.close_use(UsePreparationFailureV1::Closed),
        };
        self.recorded_outcome = Some(produced);
        if missing_journal { self.use_first.get_or_insert(UsePreparationFailureV1::OutcomeShared); }
        if !matches!(self.recorded_outcome, Some(Ok(()))) {
            return self.close_use(UsePreparationFailureV1::OutcomeNative);
        }
        true
    }
}
