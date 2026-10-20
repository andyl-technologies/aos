//! Retains provisional historical checkpoint construction and verification.
//!
//! Ordinary construction shares this engine and disposes verification at its
//! existing boundary. Selected construction keeps reached checkpoint bytes,
//! nested verification and comparison results in the prearmed destination.

use super::*;

type Cause = dyn std::error::Error + Send + Sync + 'static;

/// Owns one provisional checkpoint and its original verification outcomes.
///
/// This inert owner exposes historical DATA only. It constructs no current
/// Session, protected writer, resource allowance or verification authority.
#[doc(hidden)]
pub struct HistoricalSessionCheckpointConstructionCaptureV1 {
    checkpoint: Option<HistoricalSessionCheckpointV1>,
    verification: Option<HistoricalSessionCheckpointVerifyCaptureV1>,
    comparison: Option<Result<(), HistoricalCheckpointErrorV1>>,
    completion: Option<Result<(), HistoricalCheckpointErrorV1>>,
    closed: Option<HistoricalCheckpointErrorV1>,
    retained: bool,
    entered: bool,
}

impl Default for HistoricalSessionCheckpointConstructionCaptureV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl HistoricalSessionCheckpointConstructionCaptureV1 {
    /// Prearms empty owning slots without allocation or observation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            checkpoint: None,
            verification: None,
            comparison: None,
            completion: None,
            closed: None,
            retained: true,
            entered: false,
        }
    }

    pub(super) fn ordinary() -> Self {
        Self { retained: false, ..Self::new() }
    }

    /// Borrows the earliest nested refusal before its coarse comparison marker.
    #[must_use]
    pub fn failure(&self) -> Option<&Cause> {
        self.verification.as_ref().and_then(|capture| capture.failure())
            .or_else(|| self.comparison.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &Cause))
            .or_else(|| self.completion.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &Cause))
            .or_else(|| self.closed.as_ref().map(|cause| cause as &Cause))
    }

    /// Borrows the reached checkpoint even when later verification refused it.
    #[must_use]
    pub fn provisional_checkpoint(&self) -> Option<&HistoricalSessionCheckpointV1> {
        self.checkpoint.as_ref()
    }

    /// Moves the actual checkpoint only after verification and exact comparison.
    ///
    /// # Errors
    /// Rejects incomplete, failed, repeated or already-taken construction.
    pub fn take_checkpoint_once(&mut self)
        -> Result<HistoricalSessionCheckpointV1, HistoricalCheckpointErrorV1>
    {
        if self.failure().is_none() && matches!(self.completion, Some(Ok(()))) {
            if let Some(checkpoint) = self.checkpoint.take() {
                return Ok(checkpoint);
            }
        }
        self.closed.get_or_insert(HistoricalCheckpointErrorV1::Invalid);
        Err(HistoricalCheckpointErrorV1::Invalid)
    }

    /// Reports an actual constructor/move representation outside a resident slot.
    #[must_use]
    pub const fn construction_bytes_v1() -> usize {
        std::mem::size_of::<Self>()
    }

    /// Bounds checkpoint byte copies and reached nonprojection verify backing.
    ///
    /// The surrounding HELLO supplier separately prices the two matching
    /// canonical Hello projections and their cleared models. This helper uses
    /// their actual admitted encoded widths, never a generic request maximum.
    #[must_use]
    pub fn receiving_nonprojection_heap_bytes_v1(encoded_hello_bytes: usize) -> Option<usize> {
        HistoricalSessionCheckpointVerifyCaptureV1::receiving_nonprojection_heap_bytes_v1(encoded_hello_bytes)?
            .checked_add(encoded_hello_bytes)
    }

    /// Counts its seven fields and the actual nested verification destinations.
    #[must_use]
    pub fn receiving_metadata_cells_v1() -> Option<usize> {
        HistoricalSessionCheckpointVerifyCaptureV1::receiving_metadata_cells_v1()?.checked_add(7)
    }

    /// Bounds reached negotiated tables from the same admitted Hello widths.
    #[must_use]
    pub fn receiving_table_metadata_cells_v1(encoded_hello_bytes: usize) -> Option<usize> {
        HistoricalSessionCheckpointVerifyCaptureV1::receiving_table_metadata_cells_v1(encoded_hello_bytes)
    }

    pub(super) fn capture_once(
        &mut self,
        context: ProtectedBrokerSessionVerificationContextV1,
        client_hello: &[u8],
        broker_hello: &[u8],
        peer: PeerCredentials,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), HistoricalCheckpointErrorV1> {
        if self.entered {
            self.closed.get_or_insert(HistoricalCheckpointErrorV1::Invalid);
            return Err(HistoricalCheckpointErrorV1::Invalid);
        }
        self.entered = true;
        // This is the sole original constructor. The complete actual input
        // owner is resident before either fallible verification adapter runs.
        self.checkpoint = Some(HistoricalSessionCheckpointV1 {
            context,
            client_hello: client_hello.to_vec(),
            broker_hello: broker_hello.to_vec(),
            peer,
        });
        self.completion = Some(self.verify_and_compare(transcript));
        self.completion.as_ref().ok_or(HistoricalCheckpointErrorV1::Invalid)?
            .as_ref().map(|_| ()).map_err(|cause| *cause)
    }

    fn verify_and_compare(&mut self, expected: &VerifiedBrokerSessionTranscriptV1)
        -> Result<(), HistoricalCheckpointErrorV1>
    {
        let checkpoint = self.checkpoint.as_ref().ok_or(HistoricalCheckpointErrorV1::Invalid)?;
        if self.retained {
            self.verification = Some(HistoricalSessionCheckpointVerifyCaptureV1::new());
            let capture = self.verification.as_mut().ok_or(HistoricalCheckpointErrorV1::Invalid)?;
            checkpoint.verify_retaining(capture)?;
            self.comparison = Some(match capture.transcript() {
                Some(actual) if actual == expected => Ok(()),
                _ => Err(HistoricalCheckpointErrorV1::Invalid),
            });
        } else {
            // Ordinary verification retains its consuming projection and exact
            // nested disposal boundary before the transcript comparison.
            let actual = checkpoint.verify()?;
            self.comparison = Some(if actual == *expected {
                Ok(())
            } else {
                Err(HistoricalCheckpointErrorV1::Invalid)
            });
        }
        self.comparison.as_ref().ok_or(HistoricalCheckpointErrorV1::Invalid)?
            .as_ref().map(|_| ()).map_err(|cause| *cause)
    }

    pub(super) fn into_ordinary_result(mut self)
        -> Result<HistoricalSessionCheckpointV1, HistoricalCheckpointErrorV1>
    {
        if self.failure().is_some() {
            return Err(HistoricalCheckpointErrorV1::Invalid);
        }
        self.take_checkpoint_once()
    }
}
