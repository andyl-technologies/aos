//! Exact method-family facts retained beside an irreversible semantic witness.

use aos_sandbox_core::{
    model::snapshot::RetentionClaim, AssignmentEpoch, ObjectDigest, ResourceId, Revision,
    SandboxId, SnapshotId,
};
use sha2::{Digest as _, Sha256};

use super::digest::snapshot_release_digest;
use super::evidence::LifecycleSemanticEvidenceV1;
use super::model::intent_semantic_cas_is_valid;
use super::snapshot::LifecycleSnapshotTombstoneDigestV1;

pub use super::semantic_digest::{
    LifecycleCascadePlanDigestV1, LifecycleMethodSemanticCommitDigestV1,
    LifecycleRetentionClaimDigestV1, LifecycleSnapshotManifestDigestV1,
};

use super::{
    DesiredStateCasDigestV1, DesiredStateCasV1, LifecycleCoordinationRecordDigestV1,
    LifecycleDatasetTransactionDigestV1, LifecycleIntentV1, LifecycleModelError,
    LifecycleProtectedCoordinationV1, LifecycleProtectedRetentionLedgerV1,
    LifecycleResourceStateDigestV1, LifecycleResourceV1, LifecycleRetentionCommitFactV1,
    LifecycleRetentionLedgerDigestV1, LifecycleRetentionLedgerReceiptV1,
    LifecycleRetentionLedgerV1, LifecycleSemanticCommitV1, ResourceExpectationV1,
    ResourceExpectedStateV1, MAXIMUM_LIFECYCLE_EXPECTATIONS,
};

/// Identifies one atomic semantic transaction without granting authority.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LifecycleTransactionIdV1(ResourceId);

impl LifecycleTransactionIdV1 {
    /// Constructs a non-sentinel transaction identity.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] for the zero identity.
    pub fn new(value: ResourceId) -> Result<Self, LifecycleModelError> {
        if value.as_bytes() == &[0; 16] {
            Err(LifecycleModelError::InvalidModel)
        } else {
            Ok(Self(value))
        }
    }
    /// Returns the opaque transaction identity.
    #[must_use]
    pub const fn get(self) -> ResourceId {
        self.0
    }
}

/// Retains the exact predecessor and successor state for one committed resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleCommittedResourceV1 {
    resource: LifecycleResourceV1,
    predecessor: ResourceExpectedStateV1,
    successor_revision: Revision,
    successor_state: LifecycleResourceStateDigestV1,
    desired_state_transition: Option<DesiredStateCasDigestV1>,
}

/// Retains one exact read-only expectation consumed by semantic commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleReadCommitFactV1 {
    resource: LifecycleResourceV1,
    expected: ResourceExpectedStateV1,
}

impl LifecycleReadCommitFactV1 {
    /// Constructs one exact read-only semantic dependency.
    #[must_use]
    pub const fn new(resource: LifecycleResourceV1, expected: ResourceExpectedStateV1) -> Self {
        Self { resource, expected }
    }
    /// Returns the typed resource identity.
    #[must_use]
    pub const fn resource(self) -> LifecycleResourceV1 {
        self.resource
    }
    /// Returns the exact admitted state.
    #[must_use]
    pub const fn expected(self) -> ResourceExpectedStateV1 {
        self.expected
    }
}

impl LifecycleCommittedResourceV1 {
    /// Constructs a checked one-revision resource transition.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] for a non-successor revision.
    pub fn new(
        resource: LifecycleResourceV1,
        predecessor: ResourceExpectedStateV1,
        successor_revision: Revision,
        successor_state: LifecycleResourceStateDigestV1,
        desired_state_transition: Option<DesiredStateCasDigestV1>,
    ) -> Result<Self, LifecycleModelError> {
        let valid = match predecessor {
            ResourceExpectedStateV1::Absent => successor_revision.get() == 1,
            ResourceExpectedStateV1::Present { revision, .. } => revision
                .checked_next()
                .is_ok_and(|next| next == successor_revision),
        };
        if !valid || successor_revision.get() == u64::MAX {
            return Err(LifecycleModelError::InvalidModel);
        }
        Ok(Self {
            resource,
            predecessor,
            successor_revision,
            successor_state,
            desired_state_transition,
        })
    }

    /// Returns the typed resource.
    #[must_use]
    pub const fn resource(self) -> LifecycleResourceV1 {
        self.resource
    }
    /// Returns the exact admitted predecessor state.
    #[must_use]
    pub const fn predecessor(self) -> ResourceExpectedStateV1 {
        self.predecessor
    }
    /// Returns the exact committed successor revision.
    #[must_use]
    pub const fn successor_revision(self) -> Revision {
        self.successor_revision
    }
    /// Returns the exact committed successor state.
    #[must_use]
    pub const fn successor_state(self) -> LifecycleResourceStateDigestV1 {
        self.successor_state
    }

    /// Returns the exact desired-state CAS linked to this committed write.
    #[must_use]
    pub const fn desired_state_transition(self) -> Option<DesiredStateCasDigestV1> {
        self.desired_state_transition
    }
}

/// Retains one exact assignment published by semantic commit.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LifecycleAssignmentCommitFactV1 {
    sandbox: SandboxId,
    assignment: ResourceId,
    epoch: AssignmentEpoch,
}

impl LifecycleAssignmentCommitFactV1 {
    /// Constructs an exact non-sentinel assignment fact.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] for sentinel fields.
    pub fn new(
        sandbox: SandboxId,
        assignment: ResourceId,
        epoch: AssignmentEpoch,
    ) -> Result<Self, LifecycleModelError> {
        if sandbox.as_bytes() == &[0; 16]
            || assignment.as_bytes() == &[0; 16]
            || epoch.get() == 0
            || epoch.get() == u64::MAX
        {
            Err(LifecycleModelError::InvalidModel)
        } else {
            Ok(Self {
                sandbox,
                assignment,
                epoch,
            })
        }
    }
    /// Returns the assigned sandbox.
    #[must_use]
    pub const fn sandbox(self) -> SandboxId {
        self.sandbox
    }
    /// Returns the assignment resource identity.
    #[must_use]
    pub const fn assignment(self) -> ResourceId {
        self.assignment
    }
    /// Returns the committed assignment epoch.
    #[must_use]
    pub const fn epoch(self) -> AssignmentEpoch {
        self.epoch
    }
}

/// Retains one exact resource reservation published by semantic commit.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LifecycleReservationCommitFactV1 {
    reservation: ResourceId,
    revision: Revision,
    state: LifecycleResourceStateDigestV1,
}

impl LifecycleReservationCommitFactV1 {
    /// Constructs an exact non-sentinel reservation fact.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] for sentinel fields.
    pub fn new(
        reservation: ResourceId,
        revision: Revision,
        state: LifecycleResourceStateDigestV1,
    ) -> Result<Self, LifecycleModelError> {
        if reservation.as_bytes() == &[0; 16] || revision.get() == 0 || revision.get() == u64::MAX {
            Err(LifecycleModelError::InvalidModel)
        } else {
            Ok(Self {
                reservation,
                revision,
                state,
            })
        }
    }
    /// Returns the reservation identity.
    #[must_use]
    pub const fn reservation(self) -> ResourceId {
        self.reservation
    }
    /// Returns the reservation revision.
    #[must_use]
    pub const fn revision(self) -> Revision {
        self.revision
    }
    /// Returns the reservation state commitment.
    #[must_use]
    pub const fn state(self) -> LifecycleResourceStateDigestV1 {
        self.state
    }
}

/// Retains one durable snapshot-retention acknowledgement.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LifecycleRetentionAcknowledgementV1 {
    claim_index: u32,
    snapshot: SnapshotId,
    resource: LifecycleResourceV1,
    holder: ResourceId,
    claim: LifecycleRetentionClaimDigestV1,
    revision: Revision,
    ledger: LifecycleRetentionLedgerDigestV1,
    claim_receipt: ObjectDigest,
    receipt: LifecycleRetentionLedgerReceiptV1,
}

/// Proves that one snapshot's exact retention-ledger entry set was released.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleSnapshotRetentionReleaseV1 {
    snapshot: SnapshotId,
    holder: ResourceId,
    predecessor_revision: Revision,
    successor_revision: Revision,
    predecessor_ledger: LifecycleRetentionLedgerDigestV1,
    successor_ledger: LifecycleRetentionLedgerDigestV1,
    release: ObjectDigest,
}

impl LifecycleSnapshotRetentionReleaseV1 {
    /// Derives release evidence from exact consecutive complete ledgers.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] unless the successor is
    /// the immediate, digest-linked predecessor with precisely the selected
    /// holder's entries removed and every unrelated entry retained unchanged.
    pub(super) fn from_ledgers(
        snapshot: SnapshotId,
        holder: ResourceId,
        predecessor: &LifecycleRetentionLedgerV1,
        successor: &LifecycleRetentionLedgerV1,
    ) -> Result<Self, LifecycleModelError> {
        let predecessor_fact = LifecycleRetentionCommitFactV1::from_ledger(predecessor);
        let successor_fact = LifecycleRetentionCommitFactV1::from_ledger(successor);
        let mut expected_entries = predecessor.entries().iter().filter(|entry| {
            entry.holder() != holder
                || entry.purpose() != super::LifecycleRetentionPurposeV1::Snapshot
        });
        let removed = predecessor.entries().iter().any(|entry| {
            entry.holder() == holder
                && entry.purpose() == super::LifecycleRetentionPurposeV1::Snapshot
        });
        let successor_is_exact_release = successor.entries().iter().all(|entry| {
            expected_entries
                .next()
                .is_some_and(|expected| expected == entry)
        }) && expected_entries.next().is_none();
        if snapshot.as_bytes() == &[0; 16]
            || holder.as_bytes() == &[0; 16]
            || holder.as_bytes() != snapshot.as_bytes()
            || !removed
            || !successor_is_exact_release
            || !predecessor
                .revision()
                .checked_next()
                .is_ok_and(|revision| revision == successor.revision())
            || successor.predecessor() != Some(predecessor_fact.record().digest())
        {
            return Err(LifecycleModelError::InvalidModel);
        }
        let release = snapshot_release_digest(
            snapshot,
            holder,
            predecessor.revision(),
            successor.revision(),
            predecessor_fact.record(),
            successor_fact.record(),
        );
        Ok(Self {
            snapshot,
            holder,
            predecessor_revision: predecessor.revision(),
            successor_revision: successor.revision(),
            predecessor_ledger: predecessor_fact.record(),
            successor_ledger: successor_fact.record(),
            release,
        })
    }

    /// Derives release evidence from consecutive authoritative ledger handles.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] unless the successor
    /// removes exactly the selected holder's entries and preserves all others.
    pub fn from_protected_ledgers(
        snapshot: SnapshotId,
        holder: ResourceId,
        predecessor: &LifecycleProtectedRetentionLedgerV1,
        successor: &LifecycleProtectedRetentionLedgerV1,
    ) -> Result<Self, LifecycleModelError> {
        Self::from_ledgers(snapshot, holder, predecessor.ledger(), successor.ledger())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_stored(
        snapshot: SnapshotId,
        holder: ResourceId,
        predecessor_revision: Revision,
        successor_revision: Revision,
        predecessor_ledger: LifecycleRetentionLedgerDigestV1,
        successor_ledger: LifecycleRetentionLedgerDigestV1,
        release: ObjectDigest,
    ) -> Result<Self, LifecycleModelError> {
        if snapshot.as_bytes() == &[0; 16]
            || holder.as_bytes() == &[0; 16]
            || holder.as_bytes() != snapshot.as_bytes()
            || release.as_bytes() == &[0; 32]
            || !predecessor_revision
                .checked_next()
                .is_ok_and(|revision| revision == successor_revision)
            || release
                != snapshot_release_digest(
                    snapshot,
                    holder,
                    predecessor_revision,
                    successor_revision,
                    predecessor_ledger,
                    successor_ledger,
                )
        {
            return Err(LifecycleModelError::CorruptEncoding);
        }
        Ok(Self {
            snapshot,
            holder,
            predecessor_revision,
            successor_revision,
            predecessor_ledger,
            successor_ledger,
            release,
        })
    }

    /// Returns the deleted snapshot.
    #[must_use]
    pub const fn snapshot(self) -> SnapshotId {
        self.snapshot
    }
    /// Returns the retention holder released atomically.
    #[must_use]
    pub const fn holder(self) -> ResourceId {
        self.holder
    }
    /// Returns the predecessor ledger revision.
    #[must_use]
    pub const fn predecessor_revision(self) -> Revision {
        self.predecessor_revision
    }
    /// Returns the successor ledger revision.
    #[must_use]
    pub const fn successor_revision(self) -> Revision {
        self.successor_revision
    }
    /// Returns the predecessor ledger commitment.
    #[must_use]
    pub const fn predecessor_ledger(self) -> LifecycleRetentionLedgerDigestV1 {
        self.predecessor_ledger
    }
    /// Returns the successor ledger commitment.
    #[must_use]
    pub const fn successor_ledger(self) -> LifecycleRetentionLedgerDigestV1 {
        self.successor_ledger
    }
    /// Returns the exact release transition commitment.
    #[must_use]
    pub const fn release(self) -> ObjectDigest {
        self.release
    }
}

impl LifecycleRetentionAcknowledgementV1 {
    /// Derives an acknowledgement from one exact complete retention ledger.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] for sentinel fields.
    pub(super) fn from_ledger(
        claim_index: u32,
        snapshot: SnapshotId,
        resource: LifecycleResourceV1,
        holder: ResourceId,
        claim: &RetentionClaim,
        ledger: &LifecycleRetentionLedgerV1,
    ) -> Result<Self, LifecycleModelError> {
        let claim_receipt = retention_claim_receipt(claim);
        let entry_matches = ledger.entries().iter().any(|entry| {
            entry.resource() == resource
                && entry.holder() == holder
                && entry.purpose() == super::LifecycleRetentionPurposeV1::Snapshot
                && entry.receipt() == claim_receipt
        });
        if snapshot.as_bytes() == &[0; 16]
            || holder.as_bytes() == &[0; 16]
            || holder.as_bytes() != snapshot.as_bytes()
            || claim_receipt.as_bytes() == &[0; 32]
            || !entry_matches
        {
            return Err(LifecycleModelError::InvalidModel);
        }
        let receipt = ledger.receipt_for(
            resource,
            holder,
            super::LifecycleRetentionPurposeV1::Snapshot,
        )?;
        let ledger_record = LifecycleRetentionCommitFactV1::from_ledger(ledger).record();
        Ok(Self {
            claim_index,
            snapshot,
            resource,
            holder,
            claim: LifecycleRetentionClaimDigestV1::from_claim(claim),
            revision: ledger.revision(),
            ledger: ledger_record,
            claim_receipt,
            receipt,
        })
    }

    /// Derives an acknowledgement from an authoritative replayed ledger.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] when the exact typed claim
    /// is not covered by the protected ledger's resource, holder, and receipt.
    pub fn from_protected_ledger(
        claim_index: u32,
        snapshot: SnapshotId,
        resource: LifecycleResourceV1,
        holder: ResourceId,
        claim: &RetentionClaim,
        ledger: &LifecycleProtectedRetentionLedgerV1,
    ) -> Result<Self, LifecycleModelError> {
        Self::from_ledger(
            claim_index,
            snapshot,
            resource,
            holder,
            claim,
            ledger.ledger(),
        )
    }

    /// Revalidates this decoded acknowledgement against replayed ledger state.
    #[must_use]
    pub fn is_bound_to(&self, ledger: &LifecycleProtectedRetentionLedgerV1) -> bool {
        self.revision == ledger.ledger().revision()
            && self.ledger == ledger.record()
            && ledger.ledger().entries().iter().any(|entry| {
                entry.resource() == self.resource
                    && entry.holder() == self.holder
                    && entry.purpose() == super::LifecycleRetentionPurposeV1::Snapshot
                    && entry.receipt() == self.claim_receipt
            })
            && ledger
                .ledger()
                .receipt_for(
                    self.resource,
                    self.holder,
                    super::LifecycleRetentionPurposeV1::Snapshot,
                )
                .is_ok_and(|receipt| receipt == self.receipt)
    }

    pub(super) fn from_stored(
        claim_index: u32,
        snapshot: SnapshotId,
        resource: LifecycleResourceV1,
        holder: ResourceId,
        claim: LifecycleRetentionClaimDigestV1,
        revision: Revision,
        ledger: LifecycleRetentionLedgerDigestV1,
        claim_receipt: ObjectDigest,
        receipt: LifecycleRetentionLedgerReceiptV1,
    ) -> Result<Self, LifecycleModelError> {
        if snapshot.as_bytes() == &[0; 16]
            || resource.as_bytes() == &[0; 16]
            || holder.as_bytes() == &[0; 16]
            || holder.as_bytes() != snapshot.as_bytes()
            || revision.get() == 0
            || revision.get() == u64::MAX
            || claim_receipt.as_bytes() == &[0; 32]
        {
            return Err(LifecycleModelError::CorruptEncoding);
        }
        Ok(Self {
            claim_index,
            snapshot,
            resource,
            holder,
            claim,
            revision,
            ledger,
            claim_receipt,
            receipt,
        })
    }
    /// Returns the zero-based canonical snapshot-claim index.
    #[must_use]
    pub const fn claim_index(self) -> u32 {
        self.claim_index
    }
    /// Returns the snapshot whose exact claim set is covered.
    #[must_use]
    pub const fn snapshot(self) -> SnapshotId {
        self.snapshot
    }
    /// Returns the exact ledger resource retained for this claim.
    #[must_use]
    pub const fn resource(self) -> LifecycleResourceV1 {
        self.resource
    }
    /// Returns the holder identity.
    #[must_use]
    pub const fn holder(self) -> ResourceId {
        self.holder
    }
    /// Returns the commitment to the full typed portable retention claim.
    #[must_use]
    pub const fn claim(self) -> LifecycleRetentionClaimDigestV1 {
        self.claim
    }
    /// Returns the acknowledgement revision.
    #[must_use]
    pub const fn revision(self) -> Revision {
        self.revision
    }
    /// Returns the complete retention-ledger revision commitment.
    #[must_use]
    pub const fn ledger(self) -> LifecycleRetentionLedgerDigestV1 {
        self.ledger
    }
    /// Returns the exact receipt embedded in the portable snapshot claim.
    #[must_use]
    pub const fn claim_receipt(self) -> ObjectDigest {
        self.claim_receipt
    }
    /// Returns the exact receipt committed by the corresponding snapshot claim.
    #[must_use]
    pub const fn receipt(self) -> LifecycleRetentionLedgerReceiptV1 {
        self.receipt
    }
}

fn retention_claim_receipt(claim: &RetentionClaim) -> ObjectDigest {
    match claim {
        RetentionClaim::Storage { receipt, .. }
        | RetentionClaim::Content { receipt, .. }
        | RetentionClaim::Nix { receipt, .. }
        | RetentionClaim::Service { receipt, .. }
        | RetentionClaim::Secret { receipt, .. } => receipt.digest(),
    }
}

/// Retains the exact transaction and ordered tombstones for cascade deletion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleCascadeTombstonePlanV1 {
    transaction: LifecycleTransactionIdV1,
    dependency_snapshot: ObjectDigest,
    coordination_record: LifecycleCoordinationRecordDigestV1,
    dataset_transaction: LifecycleDatasetTransactionDigestV1,
    manifest: LifecycleSnapshotManifestDigestV1,
    plan: LifecycleCascadePlanDigestV1,
    dependency_edges: Vec<LifecycleDependencyEdgeV1>,
    postorder: Vec<LifecycleResourceV1>,
}

/// Retains one dependency edge used to derive a cascade-delete postorder.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LifecycleDependencyEdgeV1 {
    dependent: LifecycleResourceV1,
    dependency: LifecycleResourceV1,
}

impl LifecycleDependencyEdgeV1 {
    /// Constructs a non-reflexive typed dependency edge.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] for a self edge.
    pub fn new(
        dependent: LifecycleResourceV1,
        dependency: LifecycleResourceV1,
    ) -> Result<Self, LifecycleModelError> {
        if dependent == dependency {
            Err(LifecycleModelError::InvalidModel)
        } else {
            Ok(Self {
                dependent,
                dependency,
            })
        }
    }

    /// Returns the resource that must be deleted first.
    #[must_use]
    pub const fn dependent(self) -> LifecycleResourceV1 {
        self.dependent
    }

    /// Returns the retained resource on which it depends.
    #[must_use]
    pub const fn dependency(self) -> LifecycleResourceV1 {
        self.dependency
    }
}

impl LifecycleCascadeTombstonePlanV1 {
    /// Constructs a cascade plan from an authoritative closed coordination record.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] unless coordination has a
    /// committed dataset transaction and the graph/postorder exactly covers its
    /// canonical dependency set.
    pub fn from_protected_coordination(
        coordination: &LifecycleProtectedCoordinationV1,
    ) -> Result<Self, LifecycleModelError> {
        let transaction = coordination.transaction();
        let dataset_transaction = transaction
            .dataset_transaction()
            .ok_or(LifecycleModelError::InvalidModel)?;
        let mut dependency_edges = Vec::new();
        dependency_edges
            .try_reserve_exact(transaction.dependency_edges().len())
            .map_err(|_| LifecycleModelError::Allocation)?;
        dependency_edges.extend_from_slice(transaction.dependency_edges());
        let mut postorder = Vec::new();
        postorder
            .try_reserve_exact(transaction.postorder().len())
            .map_err(|_| LifecycleModelError::Allocation)?;
        postorder.extend_from_slice(transaction.postorder());
        Self::new(
            transaction.transaction(),
            transaction.dependency_snapshot(),
            coordination.record(),
            dataset_transaction,
            transaction.manifest(),
            dependency_edges,
            postorder,
        )
    }

    /// Constructs a bounded canonical cascade plan.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] for an empty, excessive,
    /// duplicate, or unordered tombstone set.
    pub(super) fn new(
        transaction: LifecycleTransactionIdV1,
        dependency_snapshot: ObjectDigest,
        coordination_record: LifecycleCoordinationRecordDigestV1,
        dataset_transaction: LifecycleDatasetTransactionDigestV1,
        manifest: LifecycleSnapshotManifestDigestV1,
        dependency_edges: Vec<LifecycleDependencyEdgeV1>,
        postorder: Vec<LifecycleResourceV1>,
    ) -> Result<Self, LifecycleModelError> {
        if postorder.is_empty()
            || dependency_snapshot.as_bytes() == &[0; 32]
            || postorder.len() > MAXIMUM_LIFECYCLE_EXPECTATIONS
            || dependency_edges.len() > MAXIMUM_LIFECYCLE_EXPECTATIONS
            || !dependency_edges.windows(2).all(|pair| pair[0] < pair[1])
            || postorder
                .iter()
                .enumerate()
                .any(|(index, resource)| postorder[..index].contains(resource))
            || !dependency_postorder_is_complete(&dependency_edges, &postorder)
        {
            Err(LifecycleModelError::InvalidModel)
        } else {
            let plan = cascade_plan_digest(
                transaction,
                dependency_snapshot,
                coordination_record,
                dataset_transaction,
                manifest,
                &dependency_edges,
                &postorder,
            );
            Ok(Self {
                transaction,
                dependency_snapshot,
                coordination_record,
                dataset_transaction,
                manifest,
                plan,
                dependency_edges,
                postorder,
            })
        }
    }
    /// Returns the atomic transaction identity.
    #[must_use]
    pub const fn transaction(&self) -> LifecycleTransactionIdV1 {
        self.transaction
    }
    /// Returns the canonical cascade plan commitment.
    #[must_use]
    pub const fn plan(&self) -> LifecycleCascadePlanDigestV1 {
        self.plan
    }
    /// Returns the authoritative closed dependency-snapshot commitment.
    #[must_use]
    pub const fn dependency_snapshot(&self) -> ObjectDigest {
        self.dependency_snapshot
    }
    /// Returns the exact coordination record that froze the dependency set.
    #[must_use]
    pub const fn coordination_record(&self) -> LifecycleCoordinationRecordDigestV1 {
        self.coordination_record
    }
    /// Returns the atomic dataset transaction covering cascade state.
    #[must_use]
    pub const fn dataset_transaction(&self) -> LifecycleDatasetTransactionDigestV1 {
        self.dataset_transaction
    }
    /// Returns the canonical manifest commitment used by the tombstone plan.
    #[must_use]
    pub const fn manifest(&self) -> LifecycleSnapshotManifestDigestV1 {
        self.manifest
    }
    /// Borrows the exact verified dependency edges.
    #[must_use]
    pub fn dependency_edges(&self) -> &[LifecycleDependencyEdgeV1] {
        &self.dependency_edges
    }

    /// Borrows the exact dependent-before-dependency tombstone postorder.
    #[must_use]
    pub fn postorder(&self) -> &[LifecycleResourceV1] {
        &self.postorder
    }

    /// Rebinds decoded cascade facts to authoritative coordination history.
    #[must_use]
    pub fn is_bound_to(&self, coordination: &LifecycleProtectedCoordinationV1) -> bool {
        let transaction = coordination.transaction();
        self.transaction == transaction.transaction()
            && self.dependency_snapshot == transaction.dependency_snapshot()
            && self.coordination_record == coordination.record()
            && transaction
                .dataset_transaction()
                .is_some_and(|digest| self.dataset_transaction == digest)
            && self.manifest == transaction.manifest()
            && self.dependency_edges.as_slice() == transaction.dependency_edges()
            && self.postorder.as_slice() == transaction.postorder()
            && matches!(
                transaction.phase(),
                super::LifecycleCoordinationPhaseV1::DatasetCommitted
                    | super::LifecycleCoordinationPhaseV1::Thawed
            )
    }
}

pub(super) fn dependency_postorder_is_complete(
    edges: &[LifecycleDependencyEdgeV1],
    postorder: &[LifecycleResourceV1],
) -> bool {
    let Some(root) = postorder.last().copied() else {
        return false;
    };
    if edges.iter().any(|edge| {
        let dependent = postorder.iter().position(|item| *item == edge.dependent());
        let dependency = postorder.iter().position(|item| *item == edge.dependency());
        !matches!((dependent, dependency), (Some(left), Some(right)) if left < right)
    }) || postorder.iter().any(|resource| {
        let outgoing = edges
            .iter()
            .filter(|edge| edge.dependent() == *resource)
            .count();
        (*resource == root && outgoing != 0) || (*resource != root && outgoing == 0)
    }) {
        return false;
    }
    postorder.iter().all(|start| {
        let mut current = *start;
        for _ in 0..postorder.len() {
            if current == root {
                return true;
            }
            let Some(next) = edges
                .iter()
                .find(|edge| edge.dependent() == current)
                .map(|edge| edge.dependency())
            else {
                return false;
            };
            current = next;
        }
        false
    })
}

fn cascade_plan_digest(
    transaction: LifecycleTransactionIdV1,
    dependency_snapshot: ObjectDigest,
    coordination_record: LifecycleCoordinationRecordDigestV1,
    dataset_transaction: LifecycleDatasetTransactionDigestV1,
    manifest: LifecycleSnapshotManifestDigestV1,
    edges: &[LifecycleDependencyEdgeV1],
    postorder: &[LifecycleResourceV1],
) -> LifecycleCascadePlanDigestV1 {
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.cascade-plan.v1\0")
        .chain_update(transaction.get().as_bytes())
        .chain_update(dependency_snapshot.as_bytes())
        .chain_update(coordination_record.digest().as_bytes())
        .chain_update(dataset_transaction.digest().as_bytes())
        .chain_update(manifest.digest().as_bytes())
        .chain_update(u64::try_from(edges.len()).unwrap_or(u64::MAX).to_be_bytes());
    for edge in edges {
        hasher = hasher
            .chain_update([edge.dependent().code()])
            .chain_update(edge.dependent().as_bytes())
            .chain_update([edge.dependency().code()])
            .chain_update(edge.dependency().as_bytes());
    }
    hasher = hasher.chain_update(
        u64::try_from(postorder.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for resource in postorder {
        hasher = hasher
            .chain_update([resource.code()])
            .chain_update(resource.as_bytes());
    }
    LifecycleCascadePlanDigestV1(ObjectDigest::from_bytes(hasher.finalize().into()))
}

/// Selects the complete semantic facts required by one method family.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleSemanticCommitFactV1 {
    /// Publishes desired resources, assignments, and reservations atomically.
    DesiredState {
        /// Exact desired-state compare-and-swap.
        cas: DesiredStateCasV1,
        /// Exact canonical read-only set.
        reads: Vec<LifecycleReadCommitFactV1>,
        /// Exact canonical committed resource set.
        resources: Vec<LifecycleCommittedResourceV1>,
        /// Exact canonical assignment set.
        assignments: Vec<LifecycleAssignmentCommitFactV1>,
        /// Exact canonical reservation set.
        reservations: Vec<LifecycleReservationCommitFactV1>,
    },
    /// Publishes a snapshot only after every retention acknowledgement.
    Snapshot {
        /// Exact desired-state compare-and-swap.
        cas: DesiredStateCasV1,
        /// Exact canonical read-only set.
        reads: Vec<LifecycleReadCommitFactV1>,
        /// Snapshot identity.
        snapshot: SnapshotId,
        /// Canonical snapshot manifest commitment.
        manifest: LifecycleSnapshotManifestDigestV1,
        /// Exact canonical committed resource set.
        resources: Vec<LifecycleCommittedResourceV1>,
        /// Exact canonical assignment set.
        assignments: Vec<LifecycleAssignmentCommitFactV1>,
        /// Exact canonical reservation set.
        reservations: Vec<LifecycleReservationCommitFactV1>,
        /// Exact canonical retention acknowledgements.
        retention: Vec<LifecycleRetentionAcknowledgementV1>,
    },
    /// Tombstones one snapshot and atomically releases its retention holds.
    DeleteSnapshot {
        /// Exact desired-state compare-and-swap.
        cas: DesiredStateCasV1,
        /// Exact canonical read-only set.
        reads: Vec<LifecycleReadCommitFactV1>,
        /// Snapshot identity.
        snapshot: SnapshotId,
        /// Exact canonical tombstone document commitment.
        tombstone: LifecycleSnapshotTombstoneDigestV1,
        /// Exact canonical committed resource set.
        resources: Vec<LifecycleCommittedResourceV1>,
        /// Exact ledger transition proving retention release.
        retention_release: LifecycleSnapshotRetentionReleaseV1,
    },
    /// Publishes one atomic cascade tombstone transaction.
    CascadeDelete {
        /// Exact desired-state compare-and-swap.
        cas: DesiredStateCasV1,
        /// Exact canonical read-only set.
        reads: Vec<LifecycleReadCommitFactV1>,
        /// Root sandbox being deleted.
        root: SandboxId,
        /// Exact canonical cascade plan and transaction.
        cascade: LifecycleCascadeTombstonePlanV1,
        /// Exact canonical committed resource set.
        resources: Vec<LifecycleCommittedResourceV1>,
        /// Exact canonical assignment set.
        assignments: Vec<LifecycleAssignmentCommitFactV1>,
        /// Exact canonical reservation set.
        reservations: Vec<LifecycleReservationCommitFactV1>,
    },
}

impl LifecycleSemanticCommitFactV1 {
    /// Constructs snapshot facts from a decoded complete retention proof.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::Allocation`] if the bounded retention
    /// acknowledgement set cannot be reserved.
    pub fn snapshot(
        cas: DesiredStateCasV1,
        snapshot: SnapshotId,
        validated: &super::snapshot::LifecycleValidatedSnapshotV1,
        reads: Vec<LifecycleReadCommitFactV1>,
        resources: Vec<LifecycleCommittedResourceV1>,
        assignments: Vec<LifecycleAssignmentCommitFactV1>,
        reservations: Vec<LifecycleReservationCommitFactV1>,
    ) -> Result<Self, LifecycleModelError> {
        let mut retention = Vec::new();
        retention
            .try_reserve_exact(validated.acknowledgements().len())
            .map_err(|_| LifecycleModelError::Allocation)?;
        retention.extend_from_slice(validated.acknowledgements());
        Ok(Self::Snapshot {
            cas,
            reads,
            snapshot,
            manifest: validated.manifest(),
            resources,
            assignments,
            reservations,
            retention,
        })
    }

    pub(super) fn cas(&self) -> DesiredStateCasV1 {
        match self {
            Self::DesiredState { cas, .. }
            | Self::Snapshot { cas, .. }
            | Self::DeleteSnapshot { cas, .. }
            | Self::CascadeDelete { cas, .. } => *cas,
        }
    }

    pub(super) fn resources(&self) -> &[LifecycleCommittedResourceV1] {
        match self {
            Self::DesiredState { resources, .. }
            | Self::Snapshot { resources, .. }
            | Self::DeleteSnapshot { resources, .. }
            | Self::CascadeDelete { resources, .. } => resources,
        }
    }
}

/// Binds the generic irreversible witness to exact closed method-family facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleMethodSemanticCommitV1 {
    witness: LifecycleSemanticCommitV1,
    facts: LifecycleSemanticCommitFactV1,
    evidence: LifecycleSemanticEvidenceV1,
    digest: LifecycleMethodSemanticCommitDigestV1,
}

/// Marks semantic facts rebound to authoritative auxiliary projections.
///
/// Construction is restricted to lifecycle replay. The value remains a
/// non-authorizing proof object and carries no journal or runtime handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleAuthoritativeSemanticCommitV1(LifecycleMethodSemanticCommitV1);

impl LifecycleAuthoritativeSemanticCommitV1 {
    pub(super) const fn from_replay(commit: LifecycleMethodSemanticCommitV1) -> Self {
        Self(commit)
    }

    /// Borrows the exact method-family semantic commit.
    #[must_use]
    pub const fn commit(&self) -> &LifecycleMethodSemanticCommitV1 {
        &self.0
    }
}

impl LifecycleMethodSemanticCommitV1 {
    /// Constructs and cross-validates exact semantic facts against intent and expectations.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] for a wrong method family,
    /// mismatched CAS, non-canonical set, or incomplete expectation binding.
    pub fn new(
        witness: LifecycleSemanticCommitV1,
        facts: LifecycleSemanticCommitFactV1,
        evidence: LifecycleSemanticEvidenceV1,
        intent: &LifecycleIntentV1,
        expectations: &[ResourceExpectationV1],
    ) -> Result<Self, LifecycleModelError> {
        if facts.cas() != witness.desired_state_cas()
            || !intent_semantic_cas_is_valid(intent, witness)
            || !facts_are_valid(&facts, intent, expectations)
            || !evidence.matches_intent(intent, witness.desired_state_cas())
            || !semantic_evidence_matches_facts(&facts, &evidence)
        {
            return Err(LifecycleModelError::InvalidModel);
        }
        let mut value = Self {
            witness,
            facts,
            evidence,
            digest: LifecycleMethodSemanticCommitDigestV1(ObjectDigest::from_bytes([0; 32])),
        };
        let facts = super::semantic_format::encode_semantic_fact(&value)?;
        value.digest = LifecycleMethodSemanticCommitDigestV1(ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(b"aos.sandbox.lifecycle.method-semantic-commit.v1\0")
                .chain_update(value.witness.witness_digest().digest().as_bytes())
                .chain_update(&facts)
                .finalize()
                .into(),
        ));
        Ok(value)
    }
    /// Returns the irreversible generic witness.
    #[must_use]
    pub const fn witness(&self) -> LifecycleSemanticCommitV1 {
        self.witness
    }
    /// Borrows exact method-family facts.
    #[must_use]
    pub const fn facts(&self) -> &LifecycleSemanticCommitFactV1 {
        &self.facts
    }

    /// Borrows method-specific coordination and runtime evidence.
    #[must_use]
    pub const fn evidence(&self) -> &LifecycleSemanticEvidenceV1 {
        &self.evidence
    }

    /// Commits the witness and its exact canonical method-family fact body.
    #[must_use]
    pub const fn complete_digest(&self) -> LifecycleMethodSemanticCommitDigestV1 {
        self.digest
    }
}

fn semantic_evidence_matches_facts(
    facts: &LifecycleSemanticCommitFactV1,
    evidence: &LifecycleSemanticEvidenceV1,
) -> bool {
    match facts {
        LifecycleSemanticCommitFactV1::Snapshot { retention, .. } => {
            evidence.retention().is_some_and(|ledger| {
                retention.iter().all(|acknowledgement| {
                    acknowledgement.revision() == ledger.revision()
                        && acknowledgement.ledger() == ledger.record()
                })
            })
        }
        LifecycleSemanticCommitFactV1::DeleteSnapshot { .. } => evidence.retention().is_none(),
        _ => evidence.retention().is_none(),
    }
}

fn facts_are_valid(
    facts: &LifecycleSemanticCommitFactV1,
    intent: &LifecycleIntentV1,
    expectations: &[ResourceExpectationV1],
) -> bool {
    match facts {
        LifecycleSemanticCommitFactV1::DesiredState {
            reads,
            resources,
            assignments,
            reservations,
            ..
        } => {
            !matches!(
                intent,
                LifecycleIntentV1::Snapshot { .. }
                    | LifecycleIntentV1::Hibernate { .. }
                    | LifecycleIntentV1::DeleteSandbox { .. }
                    | LifecycleIntentV1::DeleteSnapshot { .. }
            ) && canonical_access_sets_match_expectations(reads, resources, expectations)
                && writes_include_semantic_cas(resources, facts.cas())
                && method_fact_sets_are_complete(intent, assignments, reservations)
                && assignments_are_scoped(assignments, expectations)
        }
        LifecycleSemanticCommitFactV1::Snapshot {
            snapshot,
            reads,
            resources,
            assignments,
            reservations,
            retention,
            ..
        } => {
            matches!(intent, LifecycleIntentV1::Snapshot { snapshot: expected, .. } | LifecycleIntentV1::Hibernate { snapshot: expected, .. } if expected == snapshot)
                && canonical_access_sets_match_expectations(reads, resources, expectations)
                && writes_include_semantic_cas(resources, facts.cas())
                && resources
                    .iter()
                    .any(|resource| resource.resource() == LifecycleResourceV1::Snapshot(*snapshot))
                && canonical_assignment_and_reservation_sets(assignments, reservations)
                && assignments_are_scoped(assignments, expectations)
                && !retention.is_empty()
                && retention.len() <= MAXIMUM_LIFECYCLE_EXPECTATIONS
                && retention
                    .iter()
                    .enumerate()
                    .all(|(index, acknowledgement)| {
                        u32::try_from(index).ok() == Some(acknowledgement.claim_index())
                            && acknowledgement.snapshot() == *snapshot
                    })
        }
        LifecycleSemanticCommitFactV1::DeleteSnapshot {
            reads,
            snapshot,
            tombstone,
            resources,
            retention_release,
            ..
        } => {
            matches!(intent, LifecycleIntentV1::DeleteSnapshot { snapshot: expected, .. } if expected == snapshot)
                && retention_release.snapshot() == *snapshot
                && canonical_access_sets_match_expectations(reads, resources, expectations)
                && writes_include_semantic_cas(resources, facts.cas())
                && resources.len() == 1
                && resources[0].resource() == LifecycleResourceV1::Snapshot(*snapshot)
                && resources[0].successor_state()
                    == snapshot_deletion_state(*tombstone, retention_release)
        }
        LifecycleSemanticCommitFactV1::CascadeDelete {
            root,
            cascade,
            reads,
            resources,
            assignments,
            reservations,
            ..
        } => {
            matches!(intent, LifecycleIntentV1::DeleteSandbox { sandbox, .. } if sandbox == root)
                && canonical_access_sets_match_expectations(reads, resources, expectations)
                && writes_include_semantic_cas(resources, facts.cas())
                && canonical_assignment_and_reservation_sets(assignments, reservations)
                && assignments_are_scoped(assignments, expectations)
                && reads.is_empty()
                && resources.len() == expectations.len()
                && cascade
                    .postorder()
                    .contains(&LifecycleResourceV1::Sandbox(*root))
                && cascade.postorder().last() == Some(&LifecycleResourceV1::Sandbox(*root))
                && expectations.len() == cascade.postorder().len()
                && expectations.iter().all(|expectation| {
                    cascade.postorder().contains(&expectation.resource())
                        && matches!(
                            expectation.expected(),
                            ResourceExpectedStateV1::Present { .. }
                        )
                })
                && resources.iter().all(|write| {
                    write.successor_state()
                        == cascade_tombstone_state(
                            cascade.transaction(),
                            write.resource(),
                            write.predecessor(),
                        )
                })
        }
    }
}

fn snapshot_deletion_state(
    tombstone: LifecycleSnapshotTombstoneDigestV1,
    release: &LifecycleSnapshotRetentionReleaseV1,
) -> LifecycleResourceStateDigestV1 {
    let mut bytes = [0_u8; 64];
    bytes[..32].copy_from_slice(tombstone.digest().as_bytes());
    bytes[32..].copy_from_slice(release.release().as_bytes());
    LifecycleResourceStateDigestV1::commit(&bytes)
}

fn cascade_tombstone_state(
    transaction: LifecycleTransactionIdV1,
    resource: LifecycleResourceV1,
    predecessor: ResourceExpectedStateV1,
) -> LifecycleResourceStateDigestV1 {
    let mut bytes = [0_u8; 74];
    bytes[..16].copy_from_slice(transaction.get().as_bytes());
    bytes[16] = resource.code();
    bytes[17..33].copy_from_slice(resource.as_bytes());
    if let ResourceExpectedStateV1::Present {
        revision,
        state_digest,
    } = predecessor
    {
        bytes[33] = 1;
        bytes[34..42].copy_from_slice(&revision.get().to_be_bytes());
        bytes[42..74].copy_from_slice(state_digest.digest().as_bytes());
    }
    LifecycleResourceStateDigestV1::commit(&bytes)
}

fn assignments_are_scoped(
    assignments: &[LifecycleAssignmentCommitFactV1],
    expectations: &[ResourceExpectationV1],
) -> bool {
    assignments.iter().all(|assignment| {
        expectations.iter().any(|expectation| {
            expectation.resource() == LifecycleResourceV1::Sandbox(assignment.sandbox())
        })
    })
}

fn writes_include_semantic_cas(
    resources: &[LifecycleCommittedResourceV1],
    cas: DesiredStateCasV1,
) -> bool {
    resources
        .iter()
        .filter(|resource| resource.desired_state_transition().is_some())
        .count()
        == 1
        && resources.iter().any(|resource| {
            resource.resource() == cas.resource()
                && resource.desired_state_transition() == Some(cas.digest())
        })
}

fn method_fact_sets_are_complete(
    intent: &LifecycleIntentV1,
    assignments: &[LifecycleAssignmentCommitFactV1],
    reservations: &[LifecycleReservationCommitFactV1],
) -> bool {
    if !canonical_assignment_and_reservation_sets(assignments, reservations) {
        return false;
    }
    let assigned_sandbox = match intent {
        LifecycleIntentV1::Create { sandbox }
        | LifecycleIntentV1::Restore { sandbox, .. }
        | LifecycleIntentV1::Start { sandbox, .. }
        | LifecycleIntentV1::Resume { sandbox, .. } => Some(*sandbox),
        LifecycleIntentV1::Fork { target, .. } => Some(*target),
        _ => None,
    };
    let reservation_required = matches!(
        intent,
        LifecycleIntentV1::Create { .. }
            | LifecycleIntentV1::Fork { .. }
            | LifecycleIntentV1::Restore { .. }
            | LifecycleIntentV1::CreateExecution { .. }
    );
    assigned_sandbox.map_or(assignments.is_empty(), |sandbox| {
        assignments.len() == 1 && assignments[0].sandbox() == sandbox
    }) && reservation_required == !reservations.is_empty()
}

fn canonical_assignment_and_reservation_sets(
    assignments: &[LifecycleAssignmentCommitFactV1],
    reservations: &[LifecycleReservationCommitFactV1],
) -> bool {
    assignments.len() <= MAXIMUM_LIFECYCLE_EXPECTATIONS
        && assignments.windows(2).all(|pair| pair[0] < pair[1])
        && reservations.len() <= MAXIMUM_LIFECYCLE_EXPECTATIONS
        && reservations.windows(2).all(|pair| pair[0] < pair[1])
}

fn canonical_access_sets_match_expectations(
    reads: &[LifecycleReadCommitFactV1],
    resources: &[LifecycleCommittedResourceV1],
    expectations: &[ResourceExpectationV1],
) -> bool {
    let Some(access_count) = reads.len().checked_add(resources.len()) else {
        return false;
    };
    access_count == expectations.len()
        && access_count > 0
        && access_count <= MAXIMUM_LIFECYCLE_EXPECTATIONS
        && reads
            .windows(2)
            .all(|pair| pair[0].resource() < pair[1].resource())
        && resources
            .windows(2)
            .all(|pair| pair[0].resource() < pair[1].resource())
        && reads.iter().all(|read| {
            !resources
                .iter()
                .any(|write| write.resource() == read.resource())
        })
        && expectations.iter().all(|expectation| {
            reads.iter().any(|read| {
                read.resource() == expectation.resource()
                    && read.expected() == expectation.expected()
            }) ^ resources.iter().any(|write| {
                write.resource() == expectation.resource()
                    && write.predecessor() == expectation.expected()
            })
        })
}
