//! Retains a signed historical coordinator checkpoint without issuing progress.
//!
//! The variant identifies the actual authenticated archive path. Neither a
//! future17 declaration nor decoded numeric counters chooses an import family.
//! The fresh Runtime must separately preadmit its full bank before inheriting
//! this exact policy/counter state beneath its new World and archive ticket.

use super::*;
use crate::node_contract::NodeRuntime;
use crucible_node_provider::reference_packet::service::complete_restore::settled_recapture::CoordinatorCommitmentCheckpoint17;

pub(super) enum CompleteCoordinatorArchiveRecord {
    /// Reserved for the real signed Initial15 sidecar validator's output.
    /// Legacy Initial15 loaders without that validator leave the cache absent.
    InitialInvocation15 {
        reference: ContentRef,
        checkpoint: CoordinatorCommitmentCheckpoint17,
    },
    /// Comes only from the completed strict17 archive validation attempt.
    Settled17 {
        reference: ContentRef,
        checkpoint: CoordinatorCommitmentCheckpoint17,
    },
}

impl CompleteCoordinatorArchiveRecord {
    fn parts(&self) -> (&ContentRef, &CoordinatorCommitmentCheckpoint17) {
        match self {
            Self::InitialInvocation15 {
                reference,
                checkpoint,
            }
            | Self::Settled17 {
                reference,
                checkpoint,
            } => (reference, checkpoint),
        }
    }

    /// Counts real owned backing only; the enclosing Source pays the inline enum.
    pub(super) fn retained_backing_requested_bytes_data(&self) -> Result<usize, RuntimeError> {
        let (reference, checkpoint) = self.parts();
        NodeRuntime::capture_reference_storage(reference)?
            .checked_add(
                checkpoint
                    .retained_backing_requested_bytes_data()
                    .map_err(|_| RuntimeError::ResourceLimit)?,
            )
            .ok_or(RuntimeError::ResourceLimit)
    }
}

impl CompleteOriginalRestorationSource {
    /// Lends the checkpoint authenticated by this exact retained signed archive.
    ///
    /// No parsed DTO, matching schema, new target allocation or caller ordinal
    /// creates this cache. The independent fresh issuer must retain the original
    /// parent reference and every first/next operational and semantic counter;
    /// it cannot reset usage when allocating a new process-local Vec.
    ///
    /// # Errors
    /// Refuses foreign Source custody or an import lacking an authenticated
    /// sidecar/current17 checkpoint. Legacy Initial15 has no implicit default.
    pub(crate) fn historical_coordinator_checkpoint17_data(
        &self,
    ) -> Result<(&ContentRef, &CoordinatorCommitmentCheckpoint17), RuntimeError> {
        self.inner.authenticate_birth()?;
        self.inner
            .coordinator_checkpoint
            .as_ref()
            .map(CompleteCoordinatorArchiveRecord::parts)
            .ok_or(RuntimeError::UnsupportedFacet)
    }

    /// Names the distinct cache and direct borrowed-result layouts.
    pub(crate) fn historical_coordinator_checkpoint17_counter_scratch_data() -> usize {
        use std::mem::size_of;
        CoordinatorCommitmentCheckpoint17::counter_scratch_data()
            + size_of::<CompleteCoordinatorArchiveRecord>()
            + size_of::<Option<CompleteCoordinatorArchiveRecord>>()
            + size_of::<&Self>()
            + size_of::<&CompleteCoordinatorArchiveRecord>()
            + size_of::<Option<&CompleteCoordinatorArchiveRecord>>()
            + size_of::<(&ContentRef, &CoordinatorCommitmentCheckpoint17)>()
            + size_of::<Result<(&ContentRef, &CoordinatorCommitmentCheckpoint17), RuntimeError>>()
            + size_of::<Result<usize, crucible_node_provider::ProviderError>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Option<usize>>()
    }
}
