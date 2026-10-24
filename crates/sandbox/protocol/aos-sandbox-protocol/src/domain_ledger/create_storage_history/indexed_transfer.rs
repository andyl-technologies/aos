//! Owns passive indexed transfer format selection and canonical commitments.
//!
//! Native receipt, financial stages and same-original posts remain on their
//! actual owners. This module only chooses an existing format and validates DATA.

use super::{HistoryErrorV1, ready::ready_commitment_v1,
    continuation::SignedPreparationBundleDataV1, transport::FrameKindV1};

/// Selects only an existing indexed wire format and its passive commitment.
///
/// This DATA cannot create a paid receiver, semantic role or native completion.
#[derive(Clone, Copy)]
pub enum IndexedTransferPurposeDataV1 {
    /// Uses the inert Ready commitment and ReadyChunk frame.
    Ready,
    /// Uses the canonical signed-preparation bundle and its declared maxima.
    Signed {
        /// Bounds plan, signature and request-body byte extents in order.
        maxima: [usize; 3],
    },
    /// Uses the canonical outcome bundle and its declared maxima.
    Outcome {
        /// Bounds signed outcome and terminal archive byte extents in order.
        maxima: [usize; 2],
    },
}

impl IndexedTransferPurposeDataV1 {
    /// Returns the existing chunk frame kind for this passive format.
    #[must_use]
    pub fn chunk_kind(self) -> FrameKindV1 {
        match self { Self::Ready => FrameKindV1::ReadyChunk, Self::Signed { .. } => FrameKindV1::SignedChunk, Self::Outcome { .. } => FrameKindV1::OutcomeChunk }
    }

    /// Computes the same canonical commitment after bounded bundle decoding.
    ///
    /// # Errors
    /// Refuses malformed Signed/Outcome extents or a bundle beyond its maxima.
    pub fn commitment(self, bytes: &[u8]) -> Result<[u8; 32], HistoryErrorV1> {
        match self {
            Self::Ready => Ok(ready_commitment_v1(bytes)),
            Self::Signed { maxima } => SignedPreparationBundleDataV1::decode(bytes, maxima)?.commitment(),
            Self::Outcome { maxima } => crate::domain_ledger::create_storage_history::outcome::
                OutcomeBundleDataV1::decode(bytes, maxima)?.commitment(),
        }
    }
}
