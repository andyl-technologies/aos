//! Process-local host ownership of paired control request preparation.
//!
//! The native stopped-output writer shares the public claim word, but owns a
//! different value. Its contention is availability only; no observed scalar
//! supplies this lease or authenticates a native callback or execution phase.

use super::runtime::ControlBoundaryPublicationClaim;
use super::*;

/// A host publication lease minted by one successful shared claim CAS.
///
/// The lease excludes other host and native publishers while paired fields are
/// read and prepared. It supplies neither native phase nor execution authority
/// and is never placed in shared memory. Ordinary readers still refuse a held
/// claim. Dropping an uncommitted lease releases only its own host claim.
pub struct HostControlBoundaryPublication<'a> {
    slot: &'a NodeSlot,
    claim: ControlBoundaryPublicationClaim<'a>,
}

impl NodeSlot {
    /// Attempts to own one host control publication before paired preparation.
    ///
    /// Returns `None` only when the native stopped-output publisher owns its
    /// claim. The caller retains its original deadline and all phase owners;
    /// that observation grants no permission to change any field or request.
    ///
    /// # Errors
    ///
    /// Refuses a competing host publisher or an unknown claim value without
    /// changing the word, request, paired fields, or wake counter.
    pub fn try_claim_control_boundary_publication(
        &self,
    ) -> Result<Option<HostControlBoundaryPublication<'_>>, NodeSlotError> {
        match self.control_boundary_publication_claim.compare_exchange(
            0,
            1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => Ok(Some(HostControlBoundaryPublication {
                slot: self,
                claim: ControlBoundaryPublicationClaim(&self.control_boundary_publication_claim),
            })),
            Err(2) => Ok(None),
            Err(_) => Err(NodeSlotError::ControlBoundaryPublicationBusy),
        }
    }
}

impl HostControlBoundaryPublication<'_> {
    /// Attempts one coherent read under this actual host publication lease.
    ///
    /// All node, advance and ACK stability checks remain in force. This local
    /// read accepts only the lease's held claim; global readers require zero.
    #[must_use]
    pub fn try_snapshot(&self) -> Option<NodeSlotSnapshot> {
        self.slot.try_snapshot_with_control_claim(1)
    }

    /// Publishes or rejoins one exact request under the retained lease.
    ///
    /// # Errors
    ///
    /// Returns original frontier, capture, competing publication or wake errors.
    /// Wake failure preserves the request and its retained local pairing.
    ///
    /// # Panics
    ///
    /// Propagates a retained-effect panic after request publication. The claim
    /// is released on unwind; the already-published request remains pending.
    pub fn request_with_effect(
        self,
        fault_command_frontier: u64,
        capture_request: Option<u32>,
        retained: impl FnOnce(u32),
    ) -> Result<u32, NodeSlotError> {
        let slot = self.slot;
        self.request_with_fields_and_wake(
            fault_command_frontier,
            capture_request,
            None::<fn(PreparedControlBoundaryRequest)>,
            retained,
            || slot.wake_after_signal_increment(),
        )
    }

    /// Commits prepared paired fields before one original request Release.
    ///
    /// The lease is released after the retained effect and before waking the
    /// consumer. An existing exact pending request keeps its original fields.
    ///
    /// # Errors
    ///
    /// Returns original frontier, capture, competing publication or wake errors.
    /// Validation failures precede paired-field preparation. A later publication
    /// race keeps the original prepared-field refusal semantics; a wake failure
    /// retains the already-published request and local custody.
    ///
    /// # Panics
    ///
    /// Propagates an effect panic. A fields panic precedes request publication;
    /// a retained-effect panic leaves the published request pending. Unwind
    /// releases only this host claim.
    pub fn request_with_prepared_fields(
        self,
        fault_command_frontier: u64,
        capture_request: Option<u32>,
        fields: impl FnOnce(PreparedControlBoundaryRequest),
        retained: impl FnOnce(u32),
    ) -> Result<u32, NodeSlotError> {
        let slot = self.slot;
        self.request_with_fields_and_wake(
            fault_command_frontier,
            capture_request,
            Some(fields),
            retained,
            || slot.wake_after_signal_increment(),
        )
    }

    pub(super) fn request_with_fields_and_wake(
        self,
        fault_command_frontier: u64,
        capture_request: Option<u32>,
        fields: Option<impl FnOnce(PreparedControlBoundaryRequest)>,
        retained: impl FnOnce(u32),
        wake: impl FnOnce() -> Result<WakeAction, FutexError>,
    ) -> Result<u32, NodeSlotError> {
        self.slot
            .request_control_boundary_claimed_with_fields_and_wake(
                self.claim,
                fault_command_frontier,
                capture_request,
                fields,
                retained,
                wake,
            )
    }
}

#[cfg(feature = "test-support")]
#[path = "control_publication_model.rs"]
mod model;
#[cfg(feature = "test-support")]
pub use model::{ModeledControlBoundaryPublication, ModeledNodeStatePublication};

#[cfg(test)]
#[path = "control_publication_tests.rs"]
mod tests;
