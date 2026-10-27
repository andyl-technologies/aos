//! Retains the existing upper receiving envelope for unrelated live callers.

use super::super::ResourceReservationErrorV1;
use super::RootReceivingOriginalV1;
use crate::journal::JournalError;
use aos_sandbox_model::ResourceVector;

#[derive(Debug, thiserror::Error)]
pub(super) enum RootJournalDemandErrorV1 {
    #[error("Root original receiving provision is insufficient")]
    Provision(#[from] ResourceReservationErrorV1),
    #[error("Root held prefix representation cannot be priced")]
    Native(#[from] JournalError),
}

impl RootReceivingOriginalV1 {
    // All callers join cumulative stages, permanent flight capacity and native
    // debt in require_complete_liability. Return the actual original envelope;
    // subtracting debt here would charge that same liability twice.
    pub(super) fn receiving_envelope(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        self.original
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .and_then(|original| original.policy.bootstrap_provisions().root_receiving)
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)
    }
}
