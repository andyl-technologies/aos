//! Carries privately checked native publication across the storage boundary.
//!
//! The backend consumes fixed neutral records while repository verification
//! lives in the descendant producer module. Only that producer can initialize
//! the private capability fields, after checking actual held observations and
//! current authority. Decoded format records have no constructor into this type.

#[path = "guard/selected.rs"]
pub(crate) mod native_guard;

use crate::bucket::publication::SelectedObservation;
use crate::store::StoreFailure;
use terrane_core::gc::publication::{LogicalChange, PublicationProof, PublicationState};

/// Retains genuine request checks for the final selected-slot dispatch.
#[cfg(feature = "send")]
type FinalCheck<'operation> = dyn Fn() -> Result<(), StoreFailure> + Send + Sync + 'operation;

/// Retains genuine request checks without imposing native runtime bounds.
#[cfg(not(feature = "send"))]
type FinalCheck<'operation> = dyn Fn() -> Result<(), StoreFailure> + 'operation;

/// Binds one checked transition to its actual retained backend observations.
///
/// The two lifetimes keep both the observation borrow and its underlying held
/// namespace alive through publication and portable-pointer acknowledgment.
/// No field, builder or deserializer permits ordinary callers to mint it.
pub(crate) struct CheckedMutation<'operation, 'held> {
    observed: &'operation SelectedObservation<'held>,
    sources: Vec<&'operation SelectedObservation<'held>>,
    next: PublicationState,
    changes: Vec<LogicalChange>,
    evidence: CheckedEvidence,
    final_check: Box<FinalCheck<'operation>>,
}

/// Distinguishes genuine Guard installation from checked candidate admission.
enum CheckedEvidence {
    Guard { snapshot: Vec<u8> },
    Candidate { snapshot: Vec<u8>, lineage: Vec<u8> },
}

impl<'operation, 'held> CheckedMutation<'operation, 'held> {
    /// Rechecks genuine operation authority immediately before slot dispatch.
    ///
    /// The backend invokes this after every asynchronous staging operation and
    /// before dispatching its final create-once primitive. The producer retains
    /// actual authenticated requests, trusted selected configuration and clock;
    /// backend and protected-control exclusions remain held through acknowledgment.
    /// This synchronous check performs no I/O or recursive lock acquisition.
    ///
    /// # Errors
    /// Rejects expired or retired capability keys, expired tokens, request
    /// caveat failures, or an elapsed operation deadline at the actual clock.
    pub(crate) fn recheck_before_slot(&self) -> Result<(), StoreFailure> {
        (self.final_check)()
    }

    /// Borrows the exact destination observation checked by the producer.
    pub(crate) fn observed(&self) -> &'operation SelectedObservation<'held> {
        self.observed
    }

    /// Borrows every actual source observation retained by the producer.
    pub(crate) fn sources(&self) -> &[&'operation SelectedObservation<'held>] {
        &self.sources
    }

    /// Borrows the fixed whole successor, including Guard and lineage selectors.
    pub(crate) fn next(&self) -> &PublicationState {
        &self.next
    }

    /// Borrows the exact whole-value logical mutations checked by the producer.
    pub(crate) fn changes(&self) -> &[LogicalChange] {
        &self.changes
    }

    /// Borrows the complete independently checked canonical Guard bytes.
    pub(crate) fn guard_snapshot(&self) -> &[u8] {
        match &self.evidence {
            CheckedEvidence::Guard { snapshot } | CheckedEvidence::Candidate { snapshot, .. } => {
                snapshot
            }
        }
    }

    /// Borrows checked candidate lineage, absent for a Guard-only transition.
    pub(crate) fn lineage(&self) -> Option<&[u8]> {
        match &self.evidence {
            CheckedEvidence::Guard { .. } => None,
            CheckedEvidence::Candidate { lineage, .. } => Some(lineage),
        }
    }

    /// Returns the exact proof selector derived from the fixed checked bytes.
    pub(crate) fn proof(&self) -> PublicationProof {
        match &self.evidence {
            CheckedEvidence::Guard { snapshot } => {
                PublicationProof::Guard(*blake3::hash(snapshot).as_bytes())
            }
            CheckedEvidence::Candidate { lineage, .. } => {
                PublicationProof::Candidate(*blake3::hash(lineage).as_bytes())
            }
        }
    }
}
