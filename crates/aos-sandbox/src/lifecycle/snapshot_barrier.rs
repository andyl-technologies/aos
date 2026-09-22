//! LIFE-01 dependency-closure freeze and atomic snapshot orchestration.

use aos_sandbox_core::{ObjectDigest, OperationId, SandboxId, SnapshotId};
use sha2::{Digest as _, Sha256};

use super::{
    CurrentLifecycleCoordinationV1, CurrentLifecycleEffectV1, CurrentLifecycleOperationV1,
    CurrentLifecycleRetentionLedgerV1, LifecycleControllerDependencySnapshotV1,
    LifecycleCoordinationPhaseV1, LifecycleCoordinationTransactionV1, LifecycleEffectDomainV1,
    LifecycleEffectObservationV1, LifecycleMethodV1, LifecyclePhase6EffectPlanV1,
    LifecyclePhase6ErrorV1, LifecyclePhaseV1, LifecycleResourceV1, LifecycleStepClassV1,
    LifecycleStepV1, LifecycleStorageInventoryKindV1, lifecycle_phase6_planned_step_v1,
};

/// Identifies one exact owned dataset in a coordinated atomic snapshot.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LifecycleAtomicDatasetSnapshotMemberV1 {
    resource: LifecycleResourceV1,
    storage_handle: ObjectDigest,
    physical_identity: ObjectDigest,
    creating_request: ObjectDigest,
}

impl LifecycleAtomicDatasetSnapshotMemberV1 {
    /// Returns the logical resource whose owned dataset is captured.
    #[must_use]
    pub const fn resource(self) -> LifecycleResourceV1 {
        self.resource
    }

    /// Returns the exact protected Storage handle of the source dataset.
    #[must_use]
    pub const fn storage_handle(self) -> ObjectDigest {
        self.storage_handle
    }

    /// Returns the complete physical-row identity observed before the barrier.
    #[must_use]
    pub const fn physical_identity(self) -> ObjectDigest {
        self.physical_identity
    }

    /// Returns the creating Storage request commitment for the source dataset.
    #[must_use]
    pub const fn creating_request(self) -> ObjectDigest {
        self.creating_request
    }
}

/// Carries the bounded exact member set for one protected atomic Storage effect.
///
/// The only constructor consumes a current lifecycle barrier and an
/// authenticated complete Storage inventory. Downstream Storage code must
/// still reread its protected physical catalog and match every member before
/// crossing the single backend mutation boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleAtomicDatasetSnapshotPlanV1 {
    operation: OperationId,
    snapshot: SnapshotId,
    transaction: super::LifecycleTransactionIdV1,
    effect: super::LifecycleEffectRequestV1,
    inventory_generation: u64,
    inventory_source: ObjectDigest,
    inventory: ObjectDigest,
    closed_resources: Vec<LifecycleResourceV1>,
    members: Vec<LifecycleAtomicDatasetSnapshotMemberV1>,
    commitment: ObjectDigest,
}

impl LifecycleAtomicDatasetSnapshotPlanV1 {
    /// Returns the protected lifecycle operation identity.
    #[must_use]
    pub const fn operation(&self) -> OperationId {
        self.operation
    }

    /// Returns the actual SnapshotId selected by durable lifecycle intent.
    #[must_use]
    pub const fn snapshot(&self) -> SnapshotId {
        self.snapshot
    }

    /// Returns the coordination transaction covering every member.
    #[must_use]
    pub const fn transaction(&self) -> super::LifecycleTransactionIdV1 {
        self.transaction
    }

    /// Returns the protected source generation of the complete Storage set.
    #[must_use]
    pub const fn inventory_generation(&self) -> u64 {
        self.inventory_generation
    }

    /// Returns the protected Storage catalog source commitment.
    #[must_use]
    pub const fn inventory_source(&self) -> ObjectDigest {
        self.inventory_source
    }

    /// Returns the complete authenticated pre-effect Storage inventory.
    #[must_use]
    pub const fn inventory(&self) -> ObjectDigest {
        self.inventory
    }

    /// Borrows the complete closed lifecycle resource set selecting ownership.
    #[must_use]
    pub fn closed_resources(&self) -> &[LifecycleResourceV1] {
        &self.closed_resources
    }

    /// Borrows the exact stable-sorted nonempty dataset member set.
    #[must_use]
    pub fn members(&self) -> &[LifecycleAtomicDatasetSnapshotMemberV1] {
        &self.members
    }

    /// Returns the exact persisted lifecycle effect commitment.
    #[must_use]
    pub const fn effect_commitment(&self) -> ObjectDigest {
        self.effect.payload()
    }

    pub(super) const fn lifecycle_effect(&self) -> super::LifecycleEffectRequestV1 {
        self.effect
    }

    /// Returns the complete plan commitment consumed by Storage custody.
    #[must_use]
    pub const fn commitment(&self) -> ObjectDigest {
        self.commitment
    }
}

/// Selects the next closed LIFE-01 barrier action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LifecycleSnapshotBarrierActionV1 {
    /// Acquires every mutation lock in canonical resource order.
    LockClosure,
    /// Closes admissions and drains active writers/publications.
    QuiesceWriters,
    /// Freezes every runtime that can write the closure.
    FreezeRuntimes,
    /// Commits the complete multi-dataset storage transaction.
    SnapshotDatasets,
    /// Confirms every durable availability acknowledgement.
    CommitRetention,
    /// Thaws exactly the runtimes that entered the barrier running.
    ThawRuntimes,
    /// Executes mandatory thaw compensation after pre-commit failure.
    CompensateThaw,
    /// The snapshot portion is durably complete.
    Complete,
}

/// Retains a fixed-owner LIFE-01 transaction and its exact next action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleSnapshotBarrierV1 {
    sandbox: SandboxId,
    snapshot: SnapshotId,
    operation: aos_sandbox_core::OperationId,
    projection_root: ObjectDigest,
    transaction: LifecycleCoordinationTransactionV1,
    hibernate: bool,
    method_plan: super::LifecycleMethodPlanV1,
    action: LifecycleSnapshotBarrierActionV1,
    compensated: bool,
}

impl LifecycleSnapshotBarrierV1 {
    /// Compiles the six immutable actions for a standalone snapshot barrier.
    ///
    /// Closure locking through retention commit remains reversible and precedes
    /// semantic commit. Thaw is the sole post-commit action. Compensation uses
    /// the same protected owner in reverse direction, except that a completed
    /// freeze is explicitly paired with the thaw action commitment.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless the accepted unbound Snapshot
    /// operation, dependency closure, and protected coordination transaction
    /// agree exactly, or when a canonical step cannot be constructed.
    pub fn planned_snapshot_steps(
        current: &CurrentLifecycleOperationV1<'_>,
        closure: &LifecycleControllerDependencySnapshotV1,
        protected_transaction: &CurrentLifecycleCoordinationV1<'_>,
    ) -> Result<Vec<LifecycleStepV1>, LifecyclePhase6ErrorV1> {
        current.require_method(&[LifecycleMethodV1::Snapshot])?;
        let (sandbox, snapshot, intent_fence) = match current.operation().intent() {
            super::LifecycleIntentV1::Snapshot {
                sandbox,
                snapshot,
                fence,
                ..
            } => (*sandbox, *snapshot, *fence),
            _ => return Err(LifecyclePhase6ErrorV1::InvalidInput),
        };
        let transaction = protected_transaction.coordination().transaction();
        if current.operation().phase() != LifecyclePhaseV1::Accepted
            || !current.operation().plan_is_unbound()
            || protected_transaction.projection_root() != current.projection_root()
            || transaction.sandbox() != sandbox
            || transaction.dependency_snapshot() != closure.digest()
            || transaction.live_fence() != intent_fence
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }

        let actions = [
            LifecycleSnapshotBarrierActionV1::LockClosure,
            LifecycleSnapshotBarrierActionV1::QuiesceWriters,
            LifecycleSnapshotBarrierActionV1::FreezeRuntimes,
            LifecycleSnapshotBarrierActionV1::SnapshotDatasets,
            LifecycleSnapshotBarrierActionV1::CommitRetention,
            LifecycleSnapshotBarrierActionV1::ThawRuntimes,
        ];
        actions
            .into_iter()
            .enumerate()
            .map(|(index, action)| {
                let class = if action == LifecycleSnapshotBarrierActionV1::ThawRuntimes {
                    LifecycleStepClassV1::PostCommitForward
                } else {
                    LifecycleStepClassV1::PreCommitReversible
                };
                let compensation = match action {
                    LifecycleSnapshotBarrierActionV1::FreezeRuntimes => {
                        Some(LifecycleSnapshotBarrierActionV1::CompensateThaw)
                    }
                    LifecycleSnapshotBarrierActionV1::ThawRuntimes => None,
                    _ => Some(action),
                };
                planned_barrier_step(
                    current.operation().operation_id(),
                    u32::try_from(index).map_err(|_| LifecyclePhase6ErrorV1::Capacity)?,
                    class,
                    sandbox,
                    snapshot,
                    transaction,
                    action,
                    compensation,
                )
            })
            .collect()
    }

    /// Starts a barrier from current Snapshot or Hibernate intent.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless the protected operation,
    /// controller dependency closure, and admitted transaction agree exactly.
    pub fn start(
        current: &CurrentLifecycleOperationV1<'_>,
        closure: &LifecycleControllerDependencySnapshotV1,
        protected_transaction: &CurrentLifecycleCoordinationV1<'_>,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        let transaction = protected_transaction.coordination().transaction();
        current.require_method(&[LifecycleMethodV1::Snapshot, LifecycleMethodV1::Hibernate])?;
        let (sandbox, snapshot, intent_fence) = match current.operation().intent() {
            super::LifecycleIntentV1::Snapshot {
                sandbox,
                snapshot,
                fence,
                ..
            }
            | super::LifecycleIntentV1::Hibernate {
                sandbox,
                snapshot,
                fence,
                ..
            } => (*sandbox, *snapshot, *fence),
            _ => return Err(LifecyclePhase6ErrorV1::InvalidInput),
        };
        if protected_transaction.projection_root() != current.projection_root()
            || transaction.sandbox() != sandbox
            || transaction.dependency_snapshot() != closure.digest()
            || transaction.live_fence() != intent_fence
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let hibernate = current.operation().intent().method() == LifecycleMethodV1::Hibernate;
        let method_plan =
            super::LifecycleMethodPlanV1::from_current(current, if hibernate { 11 } else { 6 })?;
        let mut barrier = Self {
            sandbox,
            snapshot,
            operation: current.operation().operation_id(),
            projection_root: current.projection_root(),
            transaction: transaction.clone(),
            hibernate,
            method_plan,
            action: LifecycleSnapshotBarrierActionV1::LockClosure,
            compensated: false,
        };
        barrier.validate_method_plan(current)?;
        barrier.action = barrier.persisted_action(current)?;
        Ok(barrier)
    }

    /// Returns the exact current barrier action.
    #[must_use]
    pub const fn action(&self) -> LifecycleSnapshotBarrierActionV1 {
        self.action
    }

    /// Borrows the complete closed coordination transaction.
    #[must_use]
    pub const fn transaction(&self) -> &LifecycleCoordinationTransactionV1 {
        &self.transaction
    }

    /// Derives the exact multi-dataset Storage transaction from current inventory.
    ///
    /// Every Dataset row correlated to the closed dependency set is included.
    /// Snapshot, clone, hold, and quota bookkeeping rows cannot become mutation
    /// members. The actual SnapshotId comes from durable lifecycle intent, not
    /// from the lifecycle operation or a Storage request identifier.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless dataset snapshotting is the
    /// exact reserved action and the authenticated Storage inventory supplies
    /// a nonempty, bounded, unique set covering the closed owned resources.
    pub fn atomic_dataset_snapshot_plan(
        &self,
        current: &CurrentLifecycleOperationV1<'_>,
        storage: &super::LifecycleAuthenticatedStorageInventoryV1,
    ) -> Result<LifecycleAtomicDatasetSnapshotPlanV1, LifecyclePhase6ErrorV1> {
        if self.action != LifecycleSnapshotBarrierActionV1::SnapshotDatasets
            || current.operation().operation_id() != self.operation
        {
            return Err(LifecyclePhase6ErrorV1::InvalidTransition);
        }
        let snapshot = match current.operation().intent() {
            super::LifecycleIntentV1::Snapshot { snapshot, .. }
            | super::LifecycleIntentV1::Hibernate { snapshot, .. } => *snapshot,
            _ => return Err(LifecyclePhase6ErrorV1::InvalidInput),
        };
        if snapshot != self.snapshot || current.projection_root() != self.projection_root {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        let effect = self.next_effect(current)?.request();
        let mut members = storage
            .entries()
            .iter()
            .copied()
            .filter(|entry| {
                entry.kind() == LifecycleStorageInventoryKindV1::Dataset
                    && !matches!(entry.resource(), LifecycleResourceV1::Other(_))
                    && self.transaction.dependencies().contains(&entry.resource())
            })
            .map(|entry| LifecycleAtomicDatasetSnapshotMemberV1 {
                resource: entry.resource(),
                storage_handle: entry.effect_subject(),
                physical_identity: entry.identity(),
                creating_request: entry.effect_request(),
            })
            .collect::<Vec<_>>();
        members.sort_unstable();
        if members.is_empty()
            || members.len() > super::MAXIMUM_LIFECYCLE_EXPECTATIONS
            || !members.windows(2).all(|pair| pair[0] < pair[1])
            || members.iter().any(|member| {
                member.storage_handle.as_bytes() == &[0; 32]
                    || member.physical_identity.as_bytes() == &[0; 32]
                    || member.creating_request.as_bytes() == &[0; 32]
            })
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        let commitment = atomic_dataset_snapshot_plan_commitment(
            self,
            snapshot,
            effect,
            storage.generation(),
            storage.source(),
            storage.commitment(),
            self.transaction.dependencies(),
            &members,
        );
        Ok(LifecycleAtomicDatasetSnapshotPlanV1 {
            operation: self.operation,
            snapshot,
            transaction: self.transaction.transaction(),
            effect,
            inventory_generation: storage.generation(),
            inventory_source: storage.source(),
            inventory: storage.commitment(),
            closed_resources: self.transaction.dependencies().to_vec(),
            members,
            commitment,
        })
    }

    /// Returns the complete current barrier-state commitment.
    #[must_use]
    pub fn commitment(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(b"aos.sandbox.lifecycle.snapshot-barrier-state.v1\0")
                .chain_update(barrier_payload(self).as_bytes())
                .chain_update([self.transaction.phase() as u8, u8::from(self.compensated)])
                .finalize()
                .into(),
        )
    }

    pub(super) fn plan_identity(&self) -> ObjectDigest {
        let transaction = &self.transaction;
        ObjectDigest::from_bytes(
            Sha256::new()
                .chain_update(b"aos.sandbox.lifecycle.snapshot-barrier-plan.v1\0")
                .chain_update(transaction.transaction().get().as_bytes())
                .chain_update(transaction.dependency_snapshot().as_bytes())
                .chain_update(transaction.manifest().digest().as_bytes())
                .chain_update(transaction.retention_ledger().digest().as_bytes())
                .chain_update(transaction.thaw_compensation().digest().as_bytes())
                .finalize()
                .into(),
        )
    }

    pub(super) fn is_bound_to(&self, sandbox: SandboxId) -> bool {
        self.sandbox == sandbox
    }

    pub(super) fn outer_freeze_requires_thaw(&self) -> bool {
        self.hibernate
            && matches!(
                self.action,
                LifecycleSnapshotBarrierActionV1::LockClosure
                    | LifecycleSnapshotBarrierActionV1::QuiesceWriters
            )
    }

    pub(super) fn completed_by_compensation(&self) -> bool {
        self.action == LifecycleSnapshotBarrierActionV1::Complete
            && (self.compensated
                || self.transaction.phase() == LifecycleCoordinationPhaseV1::Compensated)
    }

    /// Advances a controller-owned barrier edge after protected readback.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1::InvalidTransition`] unless the action
    /// is the exact next lock/quiesce/freeze edge.
    pub fn observe_control_effect(
        mut self,
        current: &CurrentLifecycleOperationV1<'_>,
        observation: LifecycleEffectObservationV1,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        if observation.request() != self.next_effect(current)?.request() {
            return Err(LifecyclePhase6ErrorV1::InvalidTransition);
        }
        self.action = match self.action {
            LifecycleSnapshotBarrierActionV1::LockClosure => {
                LifecycleSnapshotBarrierActionV1::QuiesceWriters
            }
            LifecycleSnapshotBarrierActionV1::QuiesceWriters => {
                LifecycleSnapshotBarrierActionV1::FreezeRuntimes
            }
            _ => return Err(LifecyclePhase6ErrorV1::InvalidTransition),
        };
        Ok(self)
    }

    /// Adopts one exact protected coordination successor.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] for changed closure identity,
    /// non-adjacent phase, or evidence inconsistent with the expected action.
    pub fn observe(
        mut self,
        successor: &CurrentLifecycleCoordinationV1<'_>,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        let successor_transaction = successor.coordination().transaction();
        if successor.projection_root() != self.projection_root
            || !same_transaction(&self.transaction, successor_transaction)
        {
            return Err(LifecyclePhase6ErrorV1::InvalidInput);
        }
        self.action = match (self.action, successor_transaction.phase()) {
            (
                LifecycleSnapshotBarrierActionV1::FreezeRuntimes,
                LifecycleCoordinationPhaseV1::Frozen,
            ) if successor_transaction.manifest() == self.transaction.manifest()
                && successor_transaction.retention_ledger()
                    == self.transaction.retention_ledger() =>
            {
                LifecycleSnapshotBarrierActionV1::SnapshotDatasets
            }
            (
                LifecycleSnapshotBarrierActionV1::SnapshotDatasets,
                LifecycleCoordinationPhaseV1::DatasetCommitted,
            ) if successor_transaction.manifest() == self.transaction.manifest()
                && successor_transaction.retention_ledger()
                    == self.transaction.retention_ledger() =>
            {
                LifecycleSnapshotBarrierActionV1::CommitRetention
            }
            (
                LifecycleSnapshotBarrierActionV1::CommitRetention,
                LifecycleCoordinationPhaseV1::DatasetCommitted,
            ) if successor_transaction.retention_ledger()
                != self.transaction.retention_ledger() =>
            {
                LifecycleSnapshotBarrierActionV1::CommitRetention
            }
            (
                LifecycleSnapshotBarrierActionV1::CommitRetention,
                LifecycleCoordinationPhaseV1::DatasetCommitted,
            ) if successor_transaction.manifest() != self.transaction.manifest()
                && successor_transaction.retention_ledger()
                    == self.transaction.retention_ledger() =>
            {
                LifecycleSnapshotBarrierActionV1::CommitRetention
            }
            (
                LifecycleSnapshotBarrierActionV1::ThawRuntimes,
                LifecycleCoordinationPhaseV1::Thawed,
            ) if successor_transaction.manifest() == self.transaction.manifest()
                && successor_transaction.retention_ledger()
                    == self.transaction.retention_ledger() =>
            {
                LifecycleSnapshotBarrierActionV1::Complete
            }
            (
                LifecycleSnapshotBarrierActionV1::FreezeRuntimes
                | LifecycleSnapshotBarrierActionV1::SnapshotDatasets
                | LifecycleSnapshotBarrierActionV1::CommitRetention
                | LifecycleSnapshotBarrierActionV1::ThawRuntimes
                | LifecycleSnapshotBarrierActionV1::CompensateThaw,
                LifecycleCoordinationPhaseV1::Compensated,
            ) => LifecycleSnapshotBarrierActionV1::Complete,
            (
                LifecycleSnapshotBarrierActionV1::Complete,
                LifecycleCoordinationPhaseV1::Compensated,
            ) if self.hibernate => LifecycleSnapshotBarrierActionV1::Complete,
            _ => return Err(LifecyclePhase6ErrorV1::InvalidTransition),
        };
        self.transaction = successor_transaction.clone();
        self.compensated =
            successor_transaction.phase() == LifecycleCoordinationPhaseV1::Compensated;
        Ok(self)
    }

    /// Adopts the exact protected retention ledger after dataset commit.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] unless the ledger is bound to this
    /// transaction and retention is the exact next barrier action.
    pub fn observe_retention(
        mut self,
        retention: &CurrentLifecycleRetentionLedgerV1<'_>,
    ) -> Result<Self, LifecyclePhase6ErrorV1> {
        let protected_retention = retention.retention();
        if self.action != LifecycleSnapshotBarrierActionV1::CommitRetention
            || retention.projection_root() != self.projection_root
            || self.transaction.phase() != LifecycleCoordinationPhaseV1::DatasetCommitted
            || protected_retention.record() != self.transaction.retention_ledger()
            || self
                .transaction
                .dependencies()
                .iter()
                .filter(|resource| {
                    **resource != LifecycleResourceV1::Sandbox(self.transaction.sandbox())
                })
                .any(|resource| {
                    !protected_retention.ledger().entries().iter().any(|entry| {
                        entry.resource() == *resource
                            && entry.holder()
                                == aos_sandbox_core::ResourceId::from_bytes(
                                    *self.snapshot.as_bytes(),
                                )
                            && entry.purpose() == super::LifecycleRetentionPurposeV1::Snapshot
                    })
                })
        {
            return Err(LifecyclePhase6ErrorV1::InvalidTransition);
        }
        self.action = if self.hibernate {
            LifecycleSnapshotBarrierActionV1::Complete
        } else {
            LifecycleSnapshotBarrierActionV1::ThawRuntimes
        };
        Ok(self)
    }

    /// Selects mandatory thaw compensation after any post-freeze failure.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1::InvalidTransition`] before a freeze
    /// has been requested or after a normal thaw has already become durable.
    pub fn require_compensation(mut self) -> Result<Self, LifecyclePhase6ErrorV1> {
        let post_freeze_action = matches!(
            self.action,
            LifecycleSnapshotBarrierActionV1::FreezeRuntimes
                | LifecycleSnapshotBarrierActionV1::SnapshotDatasets
                | LifecycleSnapshotBarrierActionV1::CommitRetention
                | LifecycleSnapshotBarrierActionV1::ThawRuntimes
        ) || (self.hibernate
            && self.action == LifecycleSnapshotBarrierActionV1::Complete
            && self.transaction.phase() == LifecycleCoordinationPhaseV1::DatasetCommitted);
        if !post_freeze_action
            || matches!(
                self.transaction.phase(),
                LifecycleCoordinationPhaseV1::Thawed | LifecycleCoordinationPhaseV1::Compensated
            )
        {
            return Err(LifecyclePhase6ErrorV1::InvalidTransition);
        }
        self.action = LifecycleSnapshotBarrierActionV1::CompensateThaw;
        Ok(self)
    }

    /// Derives the next inert lower-domain handoff.
    ///
    /// # Errors
    ///
    /// Returns [`LifecyclePhase6ErrorV1`] if a terminal barrier is queried.
    pub fn next_effect<'current>(
        &self,
        current: &CurrentLifecycleOperationV1<'current>,
    ) -> Result<CurrentLifecycleEffectV1<'current>, LifecyclePhase6ErrorV1> {
        if current.operation().operation_id() != self.operation {
            return Err(LifecyclePhase6ErrorV1::StaleAuthority);
        }
        let (domain, ordinal) = match self.action {
            LifecycleSnapshotBarrierActionV1::LockClosure => {
                (LifecycleEffectDomainV1::Controller, 1)
            }
            LifecycleSnapshotBarrierActionV1::QuiesceWriters => {
                (LifecycleEffectDomainV1::Controller, 2)
            }
            LifecycleSnapshotBarrierActionV1::FreezeRuntimes => {
                (LifecycleEffectDomainV1::Runtime, 3)
            }
            LifecycleSnapshotBarrierActionV1::SnapshotDatasets => {
                (LifecycleEffectDomainV1::Storage, 4)
            }
            LifecycleSnapshotBarrierActionV1::CommitRetention => {
                (LifecycleEffectDomainV1::Controller, 5)
            }
            LifecycleSnapshotBarrierActionV1::ThawRuntimes
            | LifecycleSnapshotBarrierActionV1::CompensateThaw => {
                (LifecycleEffectDomainV1::Runtime, 6)
            }
            LifecycleSnapshotBarrierActionV1::Complete => {
                return Err(LifecyclePhase6ErrorV1::InvalidTransition);
            }
        };
        current.recover_reserved_effect(
            domain,
            ordinal,
            *self.sandbox.as_bytes(),
            if self.action == LifecycleSnapshotBarrierActionV1::CommitRetention {
                self.transaction.retention_ledger().digest()
            } else {
                self.transaction.dependency_snapshot()
            },
            barrier_payload(self),
        )
    }

    fn persisted_action(
        &mut self,
        current: &CurrentLifecycleOperationV1<'_>,
    ) -> Result<LifecycleSnapshotBarrierActionV1, LifecyclePhase6ErrorV1> {
        match self.method_plan.cursor_index(current)? {
            Some(index) => {
                let base = if self.hibernate { 3 } else { 0 };
                let cursor = current
                    .persisted_effect_cursor()?
                    .ok_or(LifecyclePhase6ErrorV1::InvalidTransition)?;
                if cursor.direction() == super::LifecycleEffectDirectionV1::Compensation {
                    if self.hibernate && index < base {
                        return Ok(LifecycleSnapshotBarrierActionV1::LockClosure);
                    }
                    let relative = index
                        .checked_sub(base)
                        .filter(|relative| *relative < if self.hibernate { 5 } else { 6 })
                        .ok_or(LifecyclePhase6ErrorV1::InvalidTransition)?;
                    self.action = if relative == 2 {
                        LifecycleSnapshotBarrierActionV1::CompensateThaw
                    } else {
                        [
                            LifecycleSnapshotBarrierActionV1::LockClosure,
                            LifecycleSnapshotBarrierActionV1::QuiesceWriters,
                            LifecycleSnapshotBarrierActionV1::FreezeRuntimes,
                            LifecycleSnapshotBarrierActionV1::SnapshotDatasets,
                            LifecycleSnapshotBarrierActionV1::CommitRetention,
                            LifecycleSnapshotBarrierActionV1::ThawRuntimes,
                        ][relative]
                    };
                    let _current_effect = self.next_effect(current)?;
                    return Ok(self.action);
                }
                if self.hibernate && index < base {
                    return Ok(LifecycleSnapshotBarrierActionV1::LockClosure);
                }
                if self.hibernate
                    && index >= base + 5
                    && self.transaction.phase() == LifecycleCoordinationPhaseV1::DatasetCommitted
                {
                    return Ok(LifecycleSnapshotBarrierActionV1::Complete);
                }
                let relative = index
                    .checked_sub(base)
                    .filter(|relative| *relative < if self.hibernate { 5 } else { 6 })
                    .ok_or(LifecyclePhase6ErrorV1::InvalidTransition)?;
                let actions = [
                    LifecycleSnapshotBarrierActionV1::LockClosure,
                    LifecycleSnapshotBarrierActionV1::QuiesceWriters,
                    LifecycleSnapshotBarrierActionV1::FreezeRuntimes,
                    LifecycleSnapshotBarrierActionV1::SnapshotDatasets,
                    LifecycleSnapshotBarrierActionV1::CommitRetention,
                    LifecycleSnapshotBarrierActionV1::ThawRuntimes,
                ];
                let action = actions[relative];
                self.action = action;
                let _current_effect = self.next_effect(current)?;
                Ok(action)
            }
            None if matches!(
                self.transaction.phase(),
                LifecycleCoordinationPhaseV1::Thawed | LifecycleCoordinationPhaseV1::Compensated
            ) =>
            {
                self.compensated =
                    self.transaction.phase() == LifecycleCoordinationPhaseV1::Compensated;
                Ok(LifecycleSnapshotBarrierActionV1::Complete)
            }
            None if self.hibernate
                && current.operation().steps()[2].state()
                    == super::LifecycleStepStateV1::Compensated
                && current.operation().steps()[2]
                    .compensation_result()
                    .is_some() =>
            {
                self.compensated = true;
                Ok(LifecycleSnapshotBarrierActionV1::Complete)
            }
            None if current.operation().steps()[if self.hibernate { 7 } else { 4 }].state()
                == super::LifecycleStepStateV1::Applied
                && current.operation().steps()[if self.hibernate { 7 } else { 4 }]
                    .result()
                    .is_some()
                && current.operation().steps()[if self.hibernate { 7 } else { 4 }]
                    .inventory()
                    .is_some()
                && self.transaction.phase() == LifecycleCoordinationPhaseV1::DatasetCommitted =>
            {
                Ok(if self.hibernate {
                    LifecycleSnapshotBarrierActionV1::Complete
                } else {
                    LifecycleSnapshotBarrierActionV1::ThawRuntimes
                })
            }
            None => Err(LifecyclePhase6ErrorV1::InvalidTransition),
        }
    }

    fn validate_method_plan(
        &mut self,
        current: &CurrentLifecycleOperationV1<'_>,
    ) -> Result<(), LifecyclePhase6ErrorV1> {
        let base = if self.hibernate { 3 } else { 0 };
        let actions = [
            LifecycleSnapshotBarrierActionV1::LockClosure,
            LifecycleSnapshotBarrierActionV1::QuiesceWriters,
            LifecycleSnapshotBarrierActionV1::FreezeRuntimes,
            LifecycleSnapshotBarrierActionV1::SnapshotDatasets,
            LifecycleSnapshotBarrierActionV1::CommitRetention,
            LifecycleSnapshotBarrierActionV1::ThawRuntimes,
        ];
        let action_count = if self.hibernate { 5 } else { actions.len() };
        for (relative, action) in actions.into_iter().take(action_count).enumerate() {
            self.action = action;
            let expected =
                super::LifecycleStepPlanDigestV1::commit(barrier_payload(self).as_bytes());
            if current.operation().steps()[base + relative].plan() != expected {
                return Err(LifecyclePhase6ErrorV1::InvalidInput);
            }
            if relative < 5 {
                self.action = if relative == 2 {
                    LifecycleSnapshotBarrierActionV1::CompensateThaw
                } else {
                    action
                };
                let compensation =
                    super::LifecycleStepPlanDigestV1::commit(barrier_payload(self).as_bytes());
                if current.operation().steps()[base + relative].compensation_plan()
                    != Some(compensation)
                {
                    return Err(LifecyclePhase6ErrorV1::InvalidInput);
                }
            }
        }
        Ok(())
    }
}

fn same_transaction(
    current: &LifecycleCoordinationTransactionV1,
    successor: &LifecycleCoordinationTransactionV1,
) -> bool {
    current.transaction() == successor.transaction()
        && current.sandbox() == successor.sandbox()
        && current.live_fence() == successor.live_fence()
        && current.dependencies() == successor.dependencies()
        && current.dependency_edges() == successor.dependency_edges()
        && current.postorder() == successor.postorder()
        && current.thaw_compensation() == successor.thaw_compensation()
}

fn atomic_dataset_snapshot_plan_commitment(
    barrier: &LifecycleSnapshotBarrierV1,
    snapshot: SnapshotId,
    effect: super::LifecycleEffectRequestV1,
    inventory_generation: u64,
    inventory_source: ObjectDigest,
    inventory: ObjectDigest,
    closed_resources: &[LifecycleResourceV1],
    members: &[LifecycleAtomicDatasetSnapshotMemberV1],
) -> ObjectDigest {
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.atomic-dataset-snapshot-plan.v1\0")
        .chain_update(barrier.operation.as_bytes())
        .chain_update(snapshot.as_bytes())
        .chain_update(barrier.transaction.transaction().get().as_bytes())
        .chain_update(effect.operation_revision().get().to_be_bytes())
        .chain_update([effect.domain() as u8])
        .chain_update(effect.ordinal().to_be_bytes())
        .chain_update(effect.step().to_be_bytes())
        .chain_update([effect.direction() as u8])
        .chain_update(effect.attempt().to_be_bytes())
        .chain_update(effect.admission().as_bytes())
        .chain_update(effect.logical_request().digest().as_bytes())
        .chain_update(effect.target())
        .chain_update(effect.prerequisite().as_bytes())
        .chain_update(effect.plan().as_bytes())
        .chain_update(effect.payload().as_bytes())
        .chain_update(inventory_generation.to_be_bytes())
        .chain_update(inventory_source.as_bytes())
        .chain_update(inventory.as_bytes())
        .chain_update((closed_resources.len() as u32).to_be_bytes());
    for resource in closed_resources {
        hasher = hasher
            .chain_update([resource.code()])
            .chain_update(resource.as_bytes());
    }
    hasher = hasher.chain_update((members.len() as u32).to_be_bytes());
    for member in members {
        hasher = hasher
            .chain_update([member.resource.code()])
            .chain_update(member.resource.as_bytes())
            .chain_update(member.storage_handle.as_bytes())
            .chain_update(member.physical_identity.as_bytes())
            .chain_update(member.creating_request.as_bytes());
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn barrier_payload(barrier: &LifecycleSnapshotBarrierV1) -> ObjectDigest {
    barrier_payload_parts(&barrier.transaction, barrier.snapshot, barrier.action)
}

fn barrier_payload_parts(
    transaction: &LifecycleCoordinationTransactionV1,
    snapshot: SnapshotId,
    action: LifecycleSnapshotBarrierActionV1,
) -> ObjectDigest {
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.snapshot-barrier-effect.v1\0")
        .chain_update(transaction.transaction().get().as_bytes())
        .chain_update(snapshot.as_bytes())
        .chain_update(transaction.dependency_snapshot().as_bytes())
        .chain_update(transaction.manifest().digest().as_bytes())
        .chain_update([action as u8])
        .chain_update(transaction.retention_ledger().digest().as_bytes())
        .chain_update((transaction.postorder().len() as u32).to_be_bytes());
    for resource in transaction.postorder() {
        hasher = hasher
            .chain_update([resource.code()])
            .chain_update(resource.as_bytes());
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}

#[allow(clippy::too_many_arguments)]
fn planned_barrier_step(
    operation: OperationId,
    index: u32,
    class: LifecycleStepClassV1,
    sandbox: SandboxId,
    snapshot: SnapshotId,
    transaction: &LifecycleCoordinationTransactionV1,
    action: LifecycleSnapshotBarrierActionV1,
    compensation: Option<LifecycleSnapshotBarrierActionV1>,
) -> Result<LifecycleStepV1, LifecyclePhase6ErrorV1> {
    let effect = |action| {
        let (domain, ordinal) = match action {
            LifecycleSnapshotBarrierActionV1::LockClosure => {
                (LifecycleEffectDomainV1::Controller, 1)
            }
            LifecycleSnapshotBarrierActionV1::QuiesceWriters => {
                (LifecycleEffectDomainV1::Controller, 2)
            }
            LifecycleSnapshotBarrierActionV1::FreezeRuntimes => {
                (LifecycleEffectDomainV1::Runtime, 3)
            }
            LifecycleSnapshotBarrierActionV1::SnapshotDatasets => {
                (LifecycleEffectDomainV1::Storage, 4)
            }
            LifecycleSnapshotBarrierActionV1::CommitRetention => {
                (LifecycleEffectDomainV1::Controller, 5)
            }
            LifecycleSnapshotBarrierActionV1::ThawRuntimes
            | LifecycleSnapshotBarrierActionV1::CompensateThaw => {
                (LifecycleEffectDomainV1::Runtime, 6)
            }
            LifecycleSnapshotBarrierActionV1::Complete => {
                return Err(LifecyclePhase6ErrorV1::InvalidInput);
            }
        };
        let prerequisite = if action == LifecycleSnapshotBarrierActionV1::CommitRetention {
            transaction.retention_ledger().digest()
        } else {
            transaction.dependency_snapshot()
        };
        LifecyclePhase6EffectPlanV1::new(
            domain,
            ordinal,
            *sandbox.as_bytes(),
            prerequisite,
            barrier_payload_parts(transaction, snapshot, action),
        )
    };
    let forward = effect(action)?;
    let compensation = compensation.map(effect).transpose()?;

    lifecycle_phase6_planned_step_v1(operation, index, class, forward, compensation)
}
