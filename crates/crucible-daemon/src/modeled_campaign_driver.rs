//! Materialization-independent campaign scheduler and observation semantics.
//!
//! [`ModeledAttemptLifecycle`] exposes admitted scheduler progress without native
//! process custody. Shared stop and selection projections consume canonical
//! scheduler evidence; implementation adapters retain marker proofs, selectable
//! transport, launch, restoration, fork and terminal resource ownership.

use std::collections::BTreeMap;

use crucible::{
    AssertionPhase, FingerprintSample, NodeId, ObservableEventPayload, QuantumOutcome,
    QuantumRequest, QuantumTerminalVerdict, SchedulerError, SchedulerEventLogEntry,
    SchedulerEventLogPayload, SchedulerQuiescence, VirtualTime,
};
use crucible_campaign::{
    AssertionViolationWitness, BoundedStopProof, CampaignCodecError, CampaignHash, ChoiceDiscovery,
    ChoiceOpportunityId, ConfigurationId, ObservationCondition, ObservationEventLogProof,
    ObservationQuantumBoundary, ObservationStopProof, ObservationStopSatisfaction,
    PolicyTimeoutKind, StopCondition,
};
use thiserror::Error;

use crate::{CrucibleMeasurementError, CrucibleObservationBoundaryEvidence};

pub(crate) mod selection_projection;
pub(crate) mod stop_boundary;

/// Rejects an inconsistent semantic boundary without assigning native custody.
#[derive(Debug, Error)]
pub(crate) enum ModeledCampaignError {
    /// Canonical campaign values or their bindings failed validation.
    #[error("campaign canonical construction failed: {0}")]
    Campaign(#[from] CampaignCodecError),
    /// Retained observation evidence did not describe the completed quantum.
    #[error("campaign observation evidence failed: {0}")]
    Measurements(#[source] CrucibleMeasurementError),
    /// Retained event or proof construction exceeded its admitted bound.
    #[error("campaign projection exceeded `{limit}`")]
    LimitExceeded { limit: &'static str },
    /// An observation claimed completion without advancing the quantum coordinate.
    #[error("scheduler quantum coordinate did not advance from {before} (reported {after})")]
    QuantumCounterDidNotAdvance { before: u64, after: u64 },
    /// The event-prefix offset disagreed with the observed stop boundary.
    #[error("observation stop proof disagrees with the completed quantum")]
    ObservationStopProof,
    /// A bounded stop could not be validated against its retained coordinates.
    #[error("bounded stop proof disagrees with the completed quantum")]
    BoundedStopProof,
    /// A resulting schedule discarded or changed an authenticated start decision.
    #[error("child schedule does not extend the authenticated start")]
    StartSchedulePrefixMismatch,
}

/// Exposes scheduler semantics for an already materialized campaign attempt.
///
/// Implementations provide admitted progress, frontier control, choice settlement,
/// quiescence and observation. This interface grants no launch, restore, fork,
/// checkpoint publication, process termination or resource-release authority.
/// Native marker and selectable custody remain in implementation adapters.
/// Operations occur at scheduler boundaries, never per guest instruction.
pub trait ModeledAttemptLifecycle {
    /// Installs the exact nonterminal scheduler frontier for this attempt.
    ///
    /// Passing `None` clears the prior attempt's frontier.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the lifecycle cannot install the
    /// frontier without crossing its current scheduler boundary.
    fn set_attempt_stop_frontier(
        &mut self,
        frontier: Option<VirtualTime>,
    ) -> Result<(), SchedulerError>;

    /// Enables a preselection pause for a choice-search attempt.
    fn set_live_network_choice_pause(&mut self, _enabled: bool) {}

    /// Uses concurrent RUNs only within a caller-proven choice-free boot epoch.
    fn set_choice_free_parallel_boot(&mut self, _enabled: bool) {}

    /// Returns the unresolved World-network choice at this boundary.
    fn live_network_preselection(&self) -> Option<crucible::LiveNetworkPreselection> {
        None
    }

    /// Settles a reserved choice through its default before a higher-priority stop.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when there is no valid reservation.
    fn settle_live_network_preselection(&mut self) -> Result<QuantumOutcome, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("modeled lifecycle has no live-network preselection"),
        })
    }

    /// Hands an exact unresolved choice to a NextChoice observation.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the reservation does not match.
    fn handoff_live_network_preselection(
        &mut self,
        _expected: &crucible::LiveNetworkPreselection,
    ) -> Result<(), SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("modeled lifecycle has no live-network preselection"),
        })
    }

    /// Advances exactly one scheduler quantum.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the guarded scheduler cannot complete
    /// the requested quantum.
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError>;

    /// Returns the absolute scheduler-quantum coordinate at the current boundary.
    #[must_use]
    fn completed_quanta(&self) -> u64;

    /// Observes the current modeled terminal verdict, if any.
    fn terminal_verdict_for_stop(&mut self) -> Option<QuantumTerminalVerdict>;

    /// Returns whether every live node is at an exact checkpoint boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when quiescence cannot be authenticated.
    fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError>;

    /// Reports whether adapter-owned network queues are empty at activation.
    ///
    /// # Errors
    ///
    /// Returns an error when their state cannot be authenticated.
    fn campaign_network_queues_empty(&self) -> Result<bool, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("campaign network queue proof is unavailable"),
        })
    }

    /// Returns the number of guest frames not yet globally committed.
    #[must_use]
    fn pending_network_output_count(&self) -> usize;

    /// Samples one node's concrete execution fingerprint for diagnostics.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the stopped node's live state cannot be
    /// read consistently.
    fn sample_fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, SchedulerError>;
}

pub(crate) fn savepoint_event_prefix_digest(entries: &[SchedulerEventLogEntry]) -> [u8; 32] {
    savepoint_event_prefix_digest_iter(entries.len(), entries.iter())
}

pub(crate) fn savepoint_event_prefix_digest_iter<'a>(
    count: usize,
    entries: impl Iterator<Item = &'a SchedulerEventLogEntry>,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crucible.savepoint-replay-event-prefix.v1\0");
    hasher.update(&(count as u64).to_be_bytes());
    for entry in entries {
        hasher.update(&entry.sequence().to_be_bytes());
        hasher.update(&entry.content_hash().bytes);
    }
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests;
