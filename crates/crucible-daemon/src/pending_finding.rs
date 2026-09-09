//! Durable finding-candidate ownership between executor completion and incorporation.
//!
//! An executor retains a [`PendingFindingCandidate`] in its assignment ledger
//! after every object in the candidate bundle is durable. The coordinator can
//! obtain an [`AuthenticatedFindingCandidateIncorporation`] only after the
//! campaign repository has incorporated and authenticated that exact bundle.
//! Matching the proof yields an [`AcknowledgedFindingCandidate`], which
//! authorizes the ledger owner to remove the bundle from its operational GC
//! roots.
//!
//! These types do not mutate campaign state. They keep the executor's retention
//! decision separate from the coordinator-owned repository transaction.

use crucible_campaign::{
    AuthenticatedFindingCandidateIncorporation, CampaignName, CampaignRepository,
    CampaignRepositoryError, CampaignSnapshotId, ExecutionId, FindingCandidateBundleId, FindingId,
    FindingPublicationResult, ObservationId,
};

use crate::{
    AssignmentRetentionAdmin, AttemptExecutionKey, AttemptRuntimeState, AttemptStateCas,
    CompletedFindingCandidate,
};

/// One candidate bundle that remains an executor-owned operational GC root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingFindingCandidate {
    bundle: FindingCandidateBundleId,
}

impl PendingFindingCandidate {
    /// Begins durable retention for one fully published candidate bundle.
    #[must_use]
    pub const fn new(bundle: FindingCandidateBundleId) -> Self {
        Self { bundle }
    }

    /// Returns the bundle reported with completed execution status.
    #[must_use]
    pub const fn bundle(self) -> FindingCandidateBundleId {
        self.bundle
    }

    /// Returns the immutable root that assignment-ledger GC must retain.
    #[must_use]
    pub const fn retention_root(self) -> FindingCandidateBundleId {
        self.bundle
    }

    /// Matches repository-authenticated incorporation before root release.
    ///
    /// The resulting token authorizes only the caller's later compare-and-swap
    /// from the matching pending ledger state; it does not remove the root
    /// itself.
    ///
    /// # Errors
    ///
    /// Returns [`PendingFindingAcknowledgementError::BundleMismatch`] when the
    /// authenticated proof belongs to another candidate. The pending value
    /// remains usable so the caller can retry with the correct proof.
    pub fn acknowledge(
        &self,
        incorporation: AuthenticatedFindingCandidateIncorporation,
    ) -> Result<AcknowledgedFindingCandidate, PendingFindingAcknowledgementError> {
        if incorporation.bundle() != self.bundle {
            return Err(PendingFindingAcknowledgementError::BundleMismatch {
                pending: self.bundle,
                received: incorporation.bundle(),
            });
        }

        Ok(AcknowledgedFindingCandidate {
            bundle: incorporation.bundle(),
            snapshot: incorporation.snapshot(),
            finding: incorporation.finding(),
        })
    }
}

/// Exact incorporated result that authorizes a pending-root release CAS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcknowledgedFindingCandidate {
    bundle: FindingCandidateBundleId,
    snapshot: CampaignSnapshotId,
    finding: FindingId,
}

impl AcknowledgedFindingCandidate {
    /// Returns the exact bundle whose operational root may be released.
    #[must_use]
    pub const fn bundle(self) -> FindingCandidateBundleId {
        self.bundle
    }

    /// Returns the durable snapshot that supersedes the operational root.
    #[must_use]
    pub const fn snapshot(self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns the finding that retains the candidate in the snapshot closure.
    #[must_use]
    pub const fn finding(self) -> FindingId {
        self.finding
    }
}

/// Stable failure while matching a pending finding to coordinator evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PendingFindingAcknowledgementError {
    /// The acknowledgement names a different immutable candidate bundle.
    #[error("finding-candidate acknowledgement does not match the pending bundle")]
    BundleMismatch {
        /// Candidate bundle retained by the assignment ledger.
        pending: FindingCandidateBundleId,
        /// Candidate bundle named by the coordinator receipt.
        received: FindingCandidateBundleId,
    },
}

/// Result of one idempotent candidate incorporation and retention handoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FindingCandidateHandoffResult {
    publication: FindingPublicationResult,
    acknowledgement: FindingCandidateRetentionOutcome,
}

impl FindingCandidateHandoffResult {
    /// Returns the repository transaction that incorporated the candidate.
    #[must_use]
    pub const fn publication(self) -> FindingPublicationResult {
        self.publication
    }

    /// Returns whether the exact executor root was released or already absent.
    #[must_use]
    pub const fn acknowledgement(self) -> FindingCandidateRetentionOutcome {
        self.acknowledgement
    }
}

/// Durable disposition of one exact pending-candidate root release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingCandidateRetentionOutcome {
    /// The authenticated current campaign head now supersedes the ledger root.
    Released(AcknowledgedFindingCandidate),
    /// A prior exact retry had already released the root.
    AlreadyReleased(AcknowledgedFindingCandidate),
    /// The named execution completion is no longer the current ledger state.
    NotCurrent,
}

/// Incorporates a candidate and releases its matching executor retention root.
///
/// Repository incorporation commits first. The release phase then acquires one
/// assignment-retention fence, reloads the exact completed state, and
/// reauthenticates the named campaign's current head while that fence remains
/// held. The fence exposes the release compare-and-swap directly, so this path
/// never recursively acquires ledger ownership.
///
/// Repeating the operation recognizes both repository replay and an already
/// released exact ledger state. A `NotCurrent` acknowledgement leaves the
/// incorporated finding durable and asks the caller to reconcile the executor
/// identity before another release attempt.
///
/// # Errors
///
/// Returns a repository error when incorporation or current-head
/// reauthentication fails, a ledger error when the fenced state cannot be read
/// or updated durably, or a typed mismatch when authenticated evidence names a
/// different bundle.
// crucible-lint: allow rust-allow -- incorporation keeps repository, ledger, and evidence authorities explicit.
#[allow(clippy::too_many_arguments)]
pub fn incorporate_and_acknowledge_finding_candidate<A>(
    repository: &CampaignRepository,
    ledger: &mut A,
    campaign: &CampaignName,
    expected_snapshot: CampaignSnapshotId,
    key: AttemptExecutionKey,
    execution: ExecutionId,
    observation: ObservationId,
    candidate: FindingCandidateBundleId,
) -> Result<FindingCandidateHandoffResult, FindingCandidateHandoffError<A::Error>>
where
    A: AssignmentRetentionAdmin,
{
    let publication = repository
        .incorporate_finding_candidate_bundle(campaign.as_str(), expected_snapshot, candidate)
        .map_err(FindingCandidateHandoffError::Repository)?;
    let acknowledgement = acknowledge_incorporated_finding_candidate(
        repository,
        ledger,
        campaign,
        key,
        execution,
        observation,
        publication.finding,
        candidate,
    )?;

    Ok(FindingCandidateHandoffResult {
        publication,
        acknowledgement,
    })
}

/// Reauthenticates one incorporated candidate and releases its exact root.
///
/// # Errors
///
/// Returns a repository error when the exact finding is not retained by the
/// named current head, a ledger error when fenced state access fails, or a
/// typed mismatch when the repository proof names another bundle.
// crucible-lint: allow rust-allow -- acknowledgement keeps repository, ledger, and proof bindings explicit.
#[allow(clippy::too_many_arguments)]
pub fn acknowledge_incorporated_finding_candidate<A>(
    repository: &CampaignRepository,
    ledger: &mut A,
    campaign: &CampaignName,
    key: AttemptExecutionKey,
    execution: ExecutionId,
    observation: ObservationId,
    finding: FindingId,
    candidate: FindingCandidateBundleId,
) -> Result<FindingCandidateRetentionOutcome, FindingCandidateHandoffError<A::Error>>
where
    A: AssignmentRetentionAdmin,
{
    let _gc_exclusion = repository
        .acquire_gc_exclusion_guard()
        .map_err(FindingCandidateHandoffError::Repository)?;
    let mut fence = ledger
        .acquire_retention_fence()
        .map_err(FindingCandidateHandoffError::Ledger)?;
    let current = fence
        .load_attempt(key)
        .map_err(FindingCandidateHandoffError::Ledger)?;
    let Some(
        completed @ AttemptRuntimeState::Completed {
            execution_basis,
            origin,
            daemon_epoch,
            execution: current_execution,
            observation: current_observation,
            finding_candidate,
        },
    ) = current
    else {
        return Ok(FindingCandidateRetentionOutcome::NotCurrent);
    };
    if current_execution != execution || current_observation != observation {
        return Ok(FindingCandidateRetentionOutcome::NotCurrent);
    }
    if finding_candidate.candidate() != Some(candidate) {
        return Ok(FindingCandidateRetentionOutcome::NotCurrent);
    }

    let incorporation = repository
        .authenticate_current_finding_candidate_incorporation(campaign, finding, candidate)
        .map_err(FindingCandidateHandoffError::Repository)?;
    let acknowledgement = PendingFindingCandidate::new(candidate)
        .acknowledge(incorporation)
        .map_err(FindingCandidateHandoffError::Acknowledgement)?;
    if finding_candidate.is_acknowledged() {
        return Ok(FindingCandidateRetentionOutcome::AlreadyReleased(
            acknowledgement,
        ));
    }

    let released = AttemptRuntimeState::Completed {
        execution_basis,
        origin,
        daemon_epoch,
        execution,
        observation,
        finding_candidate: CompletedFindingCandidate::Acknowledged(candidate),
    };
    match fence
        .compare_exchange_attempt(key, Some(completed), Some(released))
        .map_err(FindingCandidateHandoffError::Ledger)?
    {
        AttemptStateCas::Advanced => {
            Ok(FindingCandidateRetentionOutcome::Released(acknowledgement))
        }
        AttemptStateCas::Conflict { .. } => Ok(FindingCandidateRetentionOutcome::NotCurrent),
    }
}

/// Failure to complete a repository-to-executor candidate handoff.
#[derive(Debug, thiserror::Error)]
pub enum FindingCandidateHandoffError<E> {
    /// Repository incorporation or exact current-head authentication failed.
    #[error("finding-candidate repository handoff failed")]
    Repository(#[source] CampaignRepositoryError),
    /// The assignment-retention fence could not read or update durable state.
    #[error("finding-candidate ledger handoff failed")]
    Ledger(#[source] E),
    /// Authenticated evidence named a different bundle than the pending root.
    #[error(transparent)]
    Acknowledgement(#[from] PendingFindingAcknowledgementError),
}
