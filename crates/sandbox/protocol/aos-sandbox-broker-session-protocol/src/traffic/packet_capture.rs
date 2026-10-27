//! Reached canonical packet and signature/sequence admission destinations.
//!
//! Successful contents are pure traffic DATA. They establish no persisted CAS,
//! current peer, method-body validation, protected funding or effect authority.

use super::*;
use crate::projection::CanonicalBrokerResponseDecodeCaptureV1;

/// Retains one bounded packet decode and pure outcome admission, including Err.
#[derive(Default)]
pub struct BrokerOutcomePacketAdmissionCaptureV1 {
    pub(super) attempted: bool,
    pub(super) closed: Option<BrokerSessionSequenceError>,
    pub(super) canonical: CanonicalBrokerResponseDecodeCaptureV1,
    pub(super) admitted: BrokerOutcomeAdmissionCaptureV1,
    pub(super) result: Option<Result<BrokerOutcomeAdmissionV1, BrokerSessionSequenceError>>,
}

impl BrokerOutcomePacketAdmissionCaptureV1 {
    /// Constructs empty comparison DATA destinations without authentication.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Borrows the original sequence/decode classification without moving owners.
    #[must_use]
    pub fn failure(&self) -> Option<&BrokerSessionSequenceError> {
        self.result.as_ref().and_then(|result| result.as_ref().err()).or(self.closed.as_ref())
    }

    /// Borrows the earliest concrete decode, verification or admission cause.
    #[must_use]
    pub fn cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.canonical.failure().map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.admitted.cause())
            .or_else(|| self.failure().map(|cause| cause as &(dyn std::error::Error + 'static)))
    }

    /// Borrows completed traffic DATA without advancing the caller's state.
    #[must_use]
    pub fn admission(&self) -> Option<&BrokerOutcomeAdmissionV1> {
        if self.closed.is_some() { return None; }
        self.result.as_ref().and_then(|result| result.as_ref().ok())
    }

    /// Moves the complete admission once while keeping partial failures held.
    ///
    /// # Errors
    /// Refuses failed, incomplete, repeated or already consumed destinations.
    pub fn take_admission_once(&mut self) -> Result<BrokerOutcomeAdmissionV1, BrokerSessionSequenceError> {
        if let Some(error) = self.failure() { return Err(error.clone()); }
        self.result.take().ok_or(BrokerSessionSequenceError::Continuity)?
    }

    /// Counts actual fixed result/control destinations, excluding dynamic models.
    #[must_use]
    pub fn receiving_metadata_cells_v1() -> Option<usize> {
        CanonicalBrokerResponseDecodeCaptureV1::receiving_metadata_cells_v1()?
            .checked_add(BrokerOutcomeAdmissionCaptureV1::receiving_metadata_cells_v1()?)?
            .checked_add(3)
    }
}
