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
    FindingPublicationResult, ObservationDisposition, ObservationId,
};

use crate::{
    AssignmentLedger, AssignmentRetentionAdmin, AttemptExecutionKey, AttemptRuntimeState,
    AttemptStateCas, CompletedFindingCandidate,
};

/// Maximum pending candidates reconciled for one campaign in a restart pass.
pub const MAX_PENDING_FINDING_HANDOFFS_PER_PASS: usize = 4_096;

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

/// Bounded result of rebuilding campaign finding ownership from the ledger.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FindingCandidateRestartSummary {
    pending: usize,
    remaining: usize,
    released: usize,
    replayed_publications: usize,
    not_current: usize,
}

impl FindingCandidateRestartSummary {
    /// Returns pending roots discovered for the campaign lineage.
    #[must_use]
    pub const fn pending(self) -> usize {
        self.pending
    }

    /// Returns matching roots deferred to a later bounded pass.
    #[must_use]
    pub const fn remaining(self) -> usize {
        self.remaining
    }

    /// Returns roots released after authenticated incorporation.
    #[must_use]
    pub const fn released(self) -> usize {
        self.released
    }

    /// Returns incorporations that were already present in campaign history.
    #[must_use]
    pub const fn replayed_publications(self) -> usize {
        self.replayed_publications
    }

    /// Returns roots whose exact completion changed before release.
    #[must_use]
    pub const fn not_current(self) -> usize {
        self.not_current
    }
}

#[derive(Clone, Copy)]
struct PendingFindingRestartWork {
    key: AttemptExecutionKey,
    execution: ExecutionId,
    observation: ObservationId,
    candidate: FindingCandidateBundleId,
}

#[derive(Default)]
struct PendingFindingRestartInventory {
    work: Vec<PendingFindingRestartWork>,
    pending: usize,
    overflow: bool,
}

impl PendingFindingRestartInventory {
    fn retain(&mut self, item: PendingFindingRestartWork) {
        let Some(pending) = self.pending.checked_add(1) else {
            self.overflow = true;
            return;
        };
        self.pending = pending;
        if self.work.len() < MAX_PENDING_FINDING_HANDOFFS_PER_PASS {
            self.work.push(item);
        }
    }

    fn finish(
        self,
    ) -> Result<
        (
            Vec<PendingFindingRestartWork>,
            FindingCandidateRestartSummary,
        ),
        FindingCandidateRestartInventoryError,
    > {
        if self.overflow {
            return Err(FindingCandidateRestartInventoryError);
        }
        let summary = FindingCandidateRestartSummary {
            pending: self.pending,
            remaining: self.pending - self.work.len(),
            ..FindingCandidateRestartSummary::default()
        };
        Ok((self.work, summary))
    }
}

#[derive(Debug)]
struct FindingCandidateRestartInventoryError;

/// Rebuilds and completes pending finding handoffs after coordinator restart.
///
/// The scan accepts only completed pending roots in the named campaign's exact
/// lineage and retains at most 4,096 work items. Additional matches are counted
/// without allocation and reported through [`FindingCandidateRestartSummary::remaining`]
/// so the caller can immediately run another pass. Each item reloads the
/// current campaign head before incorporation because a preceding finding may
/// have advanced it. Repository replay detection and the fenced ledger CAS make
/// the operation safe to repeat after a crash between either durable transition.
///
/// # Errors
///
/// Returns [`FindingCandidateRestartError::Repository`] when the campaign head
/// cannot be authenticated, [`FindingCandidateRestartError::Ledger`] when the
/// durable inventory cannot be completed,
/// [`FindingCandidateRestartError::InventoryOverflow`] when the number of
/// matching roots cannot be represented, or
/// [`FindingCandidateRestartError::Handoff`] when an exact incorporation and
/// acknowledgement cannot be completed.
pub fn reconcile_pending_finding_candidates<A>(
    repository: &CampaignRepository,
    ledger: &mut A,
    campaign: &CampaignName,
) -> Result<
    FindingCandidateRestartSummary,
    FindingCandidateRestartError<<A as AssignmentLedger>::Error>,
>
where
    A: AssignmentLedger + AssignmentRetentionAdmin<Error = <A as AssignmentLedger>::Error>,
{
    let lineage = repository
        .head(campaign.as_str())
        .map_err(FindingCandidateRestartError::Repository)?
        .snapshot()
        .lineage();
    let mut inventory = PendingFindingRestartInventory::default();
    ledger
        .visit_attempt_states(&mut |key, state| {
            let AttemptRuntimeState::Completed {
                execution,
                observation,
                finding_candidate: CompletedFindingCandidate::Pending(candidate),
                ..
            } = state
            else {
                return;
            };
            if key.lineage() != lineage {
                return;
            }

            inventory.retain(PendingFindingRestartWork {
                key,
                execution,
                observation,
                candidate,
            });
        })
        .map_err(FindingCandidateRestartError::Ledger)?;
    let (work, mut summary) =
        inventory
            .finish()
            .map_err(|FindingCandidateRestartInventoryError| {
                FindingCandidateRestartError::InventoryOverflow
            })?;
    for pending in work {
        let bundle = repository
            .load_finding_candidate_bundle(pending.candidate)
            .map_err(FindingCandidateRestartError::Repository)?;
        let observation = repository
            .load_observation(pending.observation)
            .map_err(FindingCandidateRestartError::Repository)?;
        if bundle.observation() != pending.observation
            || observation.attempt() != pending.key.attempt()
        {
            return Err(FindingCandidateRestartError::CompletionMismatch);
        }

        let expected = repository
            .head(campaign.as_str())
            .map_err(FindingCandidateRestartError::Repository)?
            .snapshot_id();
        let observation_publication = repository
            .publish_observation(campaign.as_str(), expected, &observation)
            .map_err(FindingCandidateRestartError::Repository)?;
        if !matches!(
            observation_publication.disposition,
            ObservationDisposition::Canonical
        ) {
            return Err(FindingCandidateRestartError::NonCanonicalObservation {
                observation: pending.observation,
            });
        }

        let expected = repository
            .head(campaign.as_str())
            .map_err(FindingCandidateRestartError::Repository)?
            .snapshot_id();
        let handoff = incorporate_and_acknowledge_finding_candidate(
            repository,
            ledger,
            campaign,
            expected,
            pending.key,
            pending.execution,
            pending.observation,
            pending.candidate,
        )
        .map_err(FindingCandidateRestartError::Handoff)?;
        if handoff.publication().replayed {
            summary.replayed_publications += 1;
        }
        match handoff.acknowledgement() {
            FindingCandidateRetentionOutcome::Released(_)
            | FindingCandidateRetentionOutcome::AlreadyReleased(_) => summary.released += 1,
            FindingCandidateRetentionOutcome::NotCurrent => summary.not_current += 1,
        }
    }

    Ok(summary)
}

/// Failure while rebuilding pending campaign finding ownership after restart.
#[derive(Debug, thiserror::Error)]
pub enum FindingCandidateRestartError<E> {
    /// The named campaign head or successor could not be authenticated.
    #[error("finding-candidate restart reconciliation failed in the campaign repository")]
    Repository(#[source] CampaignRepositoryError),
    /// The durable assignment inventory could not be read completely.
    #[error("finding-candidate restart reconciliation failed in the assignment ledger")]
    Ledger(#[source] E),
    /// The matching durable inventory count cannot be represented by `usize`.
    #[error("finding-candidate restart reconciliation inventory count overflowed")]
    InventoryOverflow,
    /// The pending candidate, observation, and attempt do not form one completion.
    #[error("pending finding candidate does not match its completed observation and attempt")]
    CompletionMismatch,
    /// Another observation already won canonical completion for this attempt.
    #[error("pending finding observation `{observation}` is not the canonical completion")]
    NonCanonicalObservation {
        /// Exact pending observation that lost deterministic canonicalization.
        observation: ObservationId,
    },
    /// One exact repository-to-ledger handoff failed.
    #[error("finding-candidate restart handoff failed")]
    Handoff(#[source] FindingCandidateHandoffError<E>),
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

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- exact fixture failures should stop these bound tests.
#[allow(clippy::expect_used)]
mod tests {
    use crucible_campaign::{AttemptId, CampaignLineageId};
    use crucible_cas::content_store::{ContentId, ObjectKind};

    use super::*;

    fn restart_work() -> PendingFindingRestartWork {
        let typed_id = |tag: &str, byte: u8| {
            format!("{tag}@campaign-fact.1.{}", format!("{byte:02x}").repeat(32))
        };
        let lineage = CampaignLineageId::parse(&typed_id("crucible.campaign.lineage", 0x71))
            .expect("lineage");
        let attempt =
            AttemptId::parse(&typed_id("crucible.campaign.attempt", 0x72)).expect("attempt");
        let observation_content = ContentId::for_bytes(
            ObjectKind::Observation,
            1,
            b"bounded pending finding observation",
        );
        let observation = ObservationId::parse(&format!(
            "crucible.campaign.observation@{observation_content}"
        ))
        .expect("observation");
        let candidate_content =
            ContentId::for_bytes(ObjectKind::Finding, 1, b"bounded pending finding candidate");
        let candidate = FindingCandidateBundleId::parse(&format!(
            "crucible.campaign.finding-candidate-bundle@{candidate_content}"
        ))
        .expect("candidate");

        PendingFindingRestartWork {
            key: AttemptExecutionKey::new(lineage, attempt),
            execution: ExecutionId::from_bytes([0x73; 16]).expect("execution"),
            observation,
            candidate,
        }
    }

    #[test]
    fn restart_inventory_retains_one_fixed_batch_and_reports_repeatable_remainder() {
        let mut first = PendingFindingRestartInventory::default();
        for _ in 0..=MAX_PENDING_FINDING_HANDOFFS_PER_PASS {
            first.retain(restart_work());
        }
        let (work, summary) = first.finish().expect("bounded first pass");
        assert_eq!(work.len(), MAX_PENDING_FINDING_HANDOFFS_PER_PASS);
        assert_eq!(summary.pending(), MAX_PENDING_FINDING_HANDOFFS_PER_PASS + 1);
        assert_eq!(summary.remaining(), 1);

        let mut second = PendingFindingRestartInventory::default();
        for _ in 0..summary.remaining() {
            second.retain(restart_work());
        }
        let (work, summary) = second.finish().expect("bounded second pass");
        assert_eq!(work.len(), 1);
        assert_eq!(summary.pending(), 1);
        assert_eq!(summary.remaining(), 0);
    }
}
