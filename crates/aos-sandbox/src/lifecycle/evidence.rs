//! Method-specific durable evidence linked into semantic commit.
//!
//! These facts are canonical commitments to separately replayed coordination,
//! retention, suspend, and boot records. They contain no live authority.

use aos_sandbox_core::{ObjectDigest, Revision, SandboxId, SnapshotId};
use sha2::{Digest as _, Sha256};

use super::{
    LifecycleBootInventoryV1, LifecycleCoordinationPhaseV1, LifecycleCoordinationTransactionV1,
    LifecycleDatasetTransactionDigestV1, LifecycleIntentV1, LifecycleModelError,
    LifecycleQuiesceDigestV1, LifecycleRetentionLedgerV1, LifecycleSnapshotManifestDigestV1,
    LifecycleSuspendObservationV1, LifecycleThawCompensationDigestV1, LifecycleTimeV1,
    LifecycleTransactionIdV1, LifecycleWriterFenceDigestV1, LiveRuntimeFenceV1,
};

macro_rules! evidence_digest {
    ($name:ident, $domain:literal, $summary:literal) => {
        #[doc = $summary]
        #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $name(ObjectDigest);

        impl $name {
            fn commit(bytes: &[u8]) -> Self {
                Self(ObjectDigest::from_bytes(
                    Sha256::new()
                        .chain_update($domain)
                        .chain_update(bytes)
                        .finalize()
                        .into(),
                ))
            }

            /// Returns the underlying SHA-256 commitment.
            #[must_use]
            pub const fn digest(self) -> ObjectDigest {
                self.0
            }

            pub(super) fn from_stored(value: ObjectDigest) -> Result<Self, LifecycleModelError> {
                if value.as_bytes() == &[0; 32] {
                    Err(LifecycleModelError::CorruptEncoding)
                } else {
                    Ok(Self(value))
                }
            }
        }
    };
}

evidence_digest!(
    LifecycleCoordinationRecordDigestV1,
    b"aos.sandbox.lifecycle.coordination-record.v1\0",
    "Commits a complete coordination transaction snapshot."
);
evidence_digest!(
    LifecycleRetentionLedgerDigestV1,
    b"aos.sandbox.lifecycle.retention-ledger.v1\0",
    "Commits a complete retention-ledger revision."
);
evidence_digest!(
    LifecycleBootRecordDigestV1,
    b"aos.sandbox.lifecycle.boot-record.v1\0",
    "Commits an exact boot inventory record."
);

/// Carries verifier-owned access to one authoritative coordination record.
///
/// The handle is obtainable only from replayed auxiliary history. It grants no
/// runtime authority; it prevents caller-manufactured digests from satisfying
/// semantic rebinding checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleProtectedCoordinationV1 {
    transaction: LifecycleCoordinationTransactionV1,
    record: LifecycleCoordinationRecordDigestV1,
}

impl LifecycleProtectedCoordinationV1 {
    pub(super) fn from_authoritative(transaction: LifecycleCoordinationTransactionV1) -> Self {
        let record = coordination_digest(&transaction);
        Self {
            transaction,
            record,
        }
    }

    /// Borrows the exact replayed transaction.
    #[must_use]
    pub const fn transaction(&self) -> &LifecycleCoordinationTransactionV1 {
        &self.transaction
    }

    /// Returns its canonical coordination-record commitment.
    #[must_use]
    pub const fn record(&self) -> LifecycleCoordinationRecordDigestV1 {
        self.record
    }
}

/// Carries verifier-owned access to one authoritative retention ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleProtectedRetentionLedgerV1 {
    ledger: LifecycleRetentionLedgerV1,
    record: LifecycleRetentionLedgerDigestV1,
}

impl LifecycleProtectedRetentionLedgerV1 {
    pub(super) fn from_authoritative(ledger: LifecycleRetentionLedgerV1) -> Self {
        let record = retention_digest(&ledger);
        Self { ledger, record }
    }

    /// Borrows the exact replayed complete ledger revision.
    #[must_use]
    pub const fn ledger(&self) -> &LifecycleRetentionLedgerV1 {
        &self.ledger
    }

    /// Returns its complete canonical ledger commitment.
    #[must_use]
    pub const fn record(&self) -> LifecycleRetentionLedgerDigestV1 {
        self.record
    }
}

/// Links semantic commit to a complete dependency coordination record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleCoordinationCommitFactV1 {
    transaction: LifecycleTransactionIdV1,
    sandbox: SandboxId,
    fence: LiveRuntimeFenceV1,
    phase: LifecycleCoordinationPhaseV1,
    quiesce: Option<LifecycleQuiesceDigestV1>,
    writer_fence: Option<LifecycleWriterFenceDigestV1>,
    dataset_transaction: Option<LifecycleDatasetTransactionDigestV1>,
    thaw_compensation: LifecycleThawCompensationDigestV1,
    manifest: Option<LifecycleSnapshotManifestDigestV1>,
    retention_ledger: Option<LifecycleRetentionLedgerDigestV1>,
    record: LifecycleCoordinationRecordDigestV1,
}

impl LifecycleCoordinationCommitFactV1 {
    /// Derives the fact from one fully validated coordination snapshot.
    #[must_use]
    pub fn from_transaction(value: &LifecycleCoordinationTransactionV1) -> Self {
        Self {
            transaction: value.transaction(),
            sandbox: value.sandbox(),
            fence: value.live_fence(),
            phase: value.phase(),
            quiesce: value.quiesce(),
            writer_fence: value.writer_fence(),
            dataset_transaction: value.dataset_transaction(),
            thaw_compensation: value.thaw_compensation(),
            manifest: Some(value.manifest()),
            retention_ledger: Some(value.retention_ledger()),
            record: coordination_digest(value),
        }
    }

    pub(super) const fn from_stored(
        transaction: LifecycleTransactionIdV1,
        sandbox: SandboxId,
        fence: LiveRuntimeFenceV1,
        phase: LifecycleCoordinationPhaseV1,
        quiesce: Option<LifecycleQuiesceDigestV1>,
        writer_fence: Option<LifecycleWriterFenceDigestV1>,
        dataset_transaction: Option<LifecycleDatasetTransactionDigestV1>,
        thaw_compensation: LifecycleThawCompensationDigestV1,
        manifest: Option<LifecycleSnapshotManifestDigestV1>,
        retention_ledger: Option<LifecycleRetentionLedgerDigestV1>,
        record: LifecycleCoordinationRecordDigestV1,
    ) -> Self {
        Self {
            transaction,
            sandbox,
            fence,
            phase,
            quiesce,
            writer_fence,
            dataset_transaction,
            thaw_compensation,
            manifest,
            retention_ledger,
            record,
        }
    }

    /// Returns the transaction identity.
    #[must_use]
    pub const fn transaction(self) -> LifecycleTransactionIdV1 {
        self.transaction
    }
    /// Returns the coordinated sandbox.
    #[must_use]
    pub const fn sandbox(self) -> SandboxId {
        self.sandbox
    }
    /// Returns the exact coordinated runtime fence.
    #[must_use]
    pub const fn fence(self) -> LiveRuntimeFenceV1 {
        self.fence
    }
    /// Returns the durable coordination phase.
    #[must_use]
    pub const fn phase(self) -> LifecycleCoordinationPhaseV1 {
        self.phase
    }
    /// Returns exact guest-quiesce evidence.
    #[must_use]
    pub const fn quiesce(self) -> Option<LifecycleQuiesceDigestV1> {
        self.quiesce
    }
    /// Returns exact closed-writer evidence.
    #[must_use]
    pub const fn writer_fence(self) -> Option<LifecycleWriterFenceDigestV1> {
        self.writer_fence
    }
    /// Returns the atomic dataset-transaction evidence.
    #[must_use]
    pub const fn dataset_transaction(self) -> Option<LifecycleDatasetTransactionDigestV1> {
        self.dataset_transaction
    }
    /// Returns the reverse thaw-compensation plan.
    #[must_use]
    pub const fn thaw_compensation(self) -> LifecycleThawCompensationDigestV1 {
        self.thaw_compensation
    }
    /// Returns the exact protected snapshot-manifest commitment when encoded.
    #[must_use]
    pub const fn manifest(self) -> Option<LifecycleSnapshotManifestDigestV1> {
        self.manifest
    }
    /// Returns the exact protected post-effect retention ledger when encoded.
    #[must_use]
    pub const fn retention_ledger(self) -> Option<LifecycleRetentionLedgerDigestV1> {
        self.retention_ledger
    }
    /// Returns the complete record commitment.
    #[must_use]
    pub const fn record(self) -> LifecycleCoordinationRecordDigestV1 {
        self.record
    }

    /// Revalidates this decoded fact against an authoritative replay handle.
    #[must_use]
    pub fn is_bound_to(self, protected: &LifecycleProtectedCoordinationV1) -> bool {
        let current = Self::from_transaction(protected.transaction());
        self.transaction == current.transaction
            && self.sandbox == current.sandbox
            && self.fence == current.fence
            && self.phase == current.phase
            && self.quiesce == current.quiesce
            && self.writer_fence == current.writer_fence
            && self.dataset_transaction == current.dataset_transaction
            && self.thaw_compensation == current.thaw_compensation
            && self.record == current.record
            && self
                .manifest
                .map_or(true, |manifest| Some(manifest) == current.manifest)
            && self
                .retention_ledger
                .map_or(true, |ledger| Some(ledger) == current.retention_ledger)
    }
}

/// Links semantic commit to a complete retention-ledger revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleRetentionCommitFactV1 {
    revision: Revision,
    record: LifecycleRetentionLedgerDigestV1,
}

impl LifecycleRetentionCommitFactV1 {
    /// Derives the fact from one complete canonical ledger revision.
    #[must_use]
    pub fn from_ledger(value: &LifecycleRetentionLedgerV1) -> Self {
        Self {
            revision: value.revision(),
            record: retention_digest(value),
        }
    }

    pub(super) const fn from_stored(
        revision: Revision,
        record: LifecycleRetentionLedgerDigestV1,
    ) -> Self {
        Self { revision, record }
    }

    /// Revalidates this decoded fact against an authoritative replay handle.
    #[must_use]
    pub fn is_bound_to(self, protected: &LifecycleProtectedRetentionLedgerV1) -> bool {
        self == Self::from_ledger(protected.ledger())
    }

    /// Returns the retained ledger revision.
    #[must_use]
    pub const fn revision(self) -> Revision {
        self.revision
    }
    /// Returns the complete ledger commitment.
    #[must_use]
    pub const fn record(self) -> LifecycleRetentionLedgerDigestV1 {
        self.record
    }
}

/// Names how a new sandbox incarnation entered durable state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleIncarnationOriginV1 {
    /// A new sandbox was created without a snapshot source.
    Created,
    /// A sandbox was forked from this exact snapshot.
    Forked(SnapshotId),
    /// A sandbox was restored from this exact snapshot.
    Restored(SnapshotId),
}

/// Retains the first exact live fence for Create, Fork, or Restore.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleIncarnationCommitFactV1 {
    origin: LifecycleIncarnationOriginV1,
    fence: LiveRuntimeFenceV1,
}

impl LifecycleIncarnationCommitFactV1 {
    /// Constructs one exact non-authorizing incarnation fact.
    #[must_use]
    pub const fn new(origin: LifecycleIncarnationOriginV1, fence: LiveRuntimeFenceV1) -> Self {
        Self { origin, fence }
    }
    /// Returns the incarnation origin.
    #[must_use]
    pub const fn origin(self) -> LifecycleIncarnationOriginV1 {
        self.origin
    }
    /// Returns the complete first live-runtime fence.
    #[must_use]
    pub const fn fence(self) -> LiveRuntimeFenceV1 {
        self.fence
    }
}

/// Links semantic commit to a complete boot inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleBootCommitFactV1 {
    fence: LiveRuntimeFenceV1,
    observed_at: LifecycleTimeV1,
    record: LifecycleBootRecordDigestV1,
}

impl LifecycleBootCommitFactV1 {
    /// Derives the fact from one complete canonical boot inventory.
    #[must_use]
    pub fn from_inventory(value: &LifecycleBootInventoryV1) -> Self {
        Self {
            fence: value.fence(),
            observed_at: value.observed_at(),
            record: boot_digest(value),
        }
    }

    pub(super) const fn from_stored(
        fence: LiveRuntimeFenceV1,
        observed_at: LifecycleTimeV1,
        record: LifecycleBootRecordDigestV1,
    ) -> Self {
        Self {
            fence,
            observed_at,
            record,
        }
    }

    /// Returns the exact observed boot fence.
    #[must_use]
    pub const fn fence(self) -> LiveRuntimeFenceV1 {
        self.fence
    }
    /// Returns the durable observation time.
    #[must_use]
    pub const fn observed_at(self) -> LifecycleTimeV1 {
        self.observed_at
    }
    /// Returns the complete boot-record commitment.
    #[must_use]
    pub const fn record(self) -> LifecycleBootRecordDigestV1 {
        self.record
    }
}

/// Collects the closed evidence surface required by one lifecycle method.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LifecycleSemanticEvidenceV1 {
    coordination: Option<LifecycleCoordinationCommitFactV1>,
    retention: Option<LifecycleRetentionCommitFactV1>,
    suspend: Option<LifecycleSuspendObservationV1>,
    boot: Option<LifecycleBootCommitFactV1>,
    incarnation: Option<LifecycleIncarnationCommitFactV1>,
}

impl LifecycleSemanticEvidenceV1 {
    /// Constructs an exact method evidence set.
    #[must_use]
    pub const fn new(
        coordination: Option<LifecycleCoordinationCommitFactV1>,
        retention: Option<LifecycleRetentionCommitFactV1>,
        suspend: Option<LifecycleSuspendObservationV1>,
        boot: Option<LifecycleBootCommitFactV1>,
        incarnation: Option<LifecycleIncarnationCommitFactV1>,
    ) -> Self {
        Self {
            coordination,
            retention,
            suspend,
            boot,
            incarnation,
        }
    }
    /// Returns coordination evidence.
    #[must_use]
    pub const fn coordination(&self) -> Option<LifecycleCoordinationCommitFactV1> {
        self.coordination
    }
    /// Returns retention-ledger evidence.
    #[must_use]
    pub const fn retention(&self) -> Option<LifecycleRetentionCommitFactV1> {
        self.retention
    }
    /// Returns suspend observation evidence.
    #[must_use]
    pub const fn suspend(&self) -> Option<LifecycleSuspendObservationV1> {
        self.suspend
    }
    /// Returns boot inventory evidence.
    #[must_use]
    pub const fn boot(&self) -> Option<LifecycleBootCommitFactV1> {
        self.boot
    }
    /// Returns initial incarnation evidence.
    #[must_use]
    pub const fn incarnation(&self) -> Option<LifecycleIncarnationCommitFactV1> {
        self.incarnation
    }

    pub(super) fn matches_intent(
        &self,
        intent: &LifecycleIntentV1,
        cas: super::DesiredStateCasV1,
    ) -> bool {
        let incarnation = match intent {
            LifecycleIntentV1::Create { sandbox } => matches!(
                self.incarnation,
                Some(fact) if fact.fence().sandbox() == *sandbox
                    && fact.fence().desired().expected_generation() == cas.successor_generation()
                    && cas.resource() == super::LifecycleResourceV1::Sandbox(*sandbox)
                    && fact.origin() == LifecycleIncarnationOriginV1::Created
            ),
            LifecycleIntentV1::Fork { source, target } => matches!(
                self.incarnation,
                Some(fact) if fact.fence().sandbox() == *target
                    && fact.fence().desired().expected_generation() == cas.successor_generation()
                    && cas.resource() == super::LifecycleResourceV1::Sandbox(*target)
                    && fact.origin() == LifecycleIncarnationOriginV1::Forked(*source)
            ),
            LifecycleIntentV1::Restore { snapshot, sandbox } => matches!(
                self.incarnation,
                Some(fact) if fact.fence().sandbox() == *sandbox
                    && fact.fence().desired().expected_generation() == cas.successor_generation()
                    && cas.resource() == super::LifecycleResourceV1::Sandbox(*sandbox)
                    && fact.origin() == LifecycleIncarnationOriginV1::Restored(*snapshot)
            ),
            _ => self.incarnation.is_none(),
        };
        let coordination = match intent {
            LifecycleIntentV1::Snapshot { sandbox, fence, .. }
            | LifecycleIntentV1::Hibernate { sandbox, fence, .. } => matches!(
                self.coordination,
                Some(fact) if fact.sandbox() == *sandbox
                    && fact.fence() == *fence
                    && matches!(fact.phase(), LifecycleCoordinationPhaseV1::DatasetCommitted | LifecycleCoordinationPhaseV1::Thawed)
            ),
            LifecycleIntentV1::Resume {
                source: super::LifecycleResumeSourceV1::Memory { .. },
                ..
            } => self.coordination.is_none(),
            _ => self.coordination.is_none(),
        };
        let retention = matches!(
            intent,
            LifecycleIntentV1::Snapshot { .. } | LifecycleIntentV1::Hibernate { .. }
        ) == self.retention.is_some();
        // Suspension is observed only after semantic commit. Its exact
        // operation-bound terminal record belongs to auxiliary replay.
        let suspend = self.suspend.is_none();
        // Start and Resume commit desired state before any boot/reconcile
        // observation. Memory resume binds a frozen runtime at plan time;
        // boot inventory belongs to post-commit step history.
        let boot = self.boot.is_none();
        incarnation && coordination && retention && suspend && boot
    }
}

fn coordination_digest(
    value: &LifecycleCoordinationTransactionV1,
) -> LifecycleCoordinationRecordDigestV1 {
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.coordination-record.v1\0")
        .chain_update(value.transaction().get().as_bytes())
        .chain_update(value.sandbox().as_bytes());
    hasher = hash_live_fence(hasher, value.live_fence())
        .chain_update((value.dependencies().len() as u32).to_be_bytes());
    for dependency in value.dependencies() {
        hasher = hasher
            .chain_update([dependency.code()])
            .chain_update(dependency.as_bytes());
    }
    hasher = hasher.chain_update((value.dependency_edges().len() as u32).to_be_bytes());
    for edge in value.dependency_edges() {
        hasher = hasher
            .chain_update([edge.dependent().code()])
            .chain_update(edge.dependent().as_bytes())
            .chain_update([edge.dependency().code()])
            .chain_update(edge.dependency().as_bytes());
    }
    hasher = hasher.chain_update((value.postorder().len() as u32).to_be_bytes());
    for resource in value.postorder() {
        hasher = hasher
            .chain_update([resource.code()])
            .chain_update(resource.as_bytes());
    }
    hasher = hasher
        .chain_update(value.dependency_snapshot().as_bytes())
        .chain_update(value.manifest().digest().as_bytes())
        .chain_update(value.retention_ledger().digest().as_bytes());
    for digest in [
        value.quiesce().map(|value| value.digest()),
        value.writer_fence().map(|value| value.digest()),
        value.dataset_transaction().map(|value| value.digest()),
        Some(value.thaw_compensation().digest()),
    ] {
        hasher = hasher.chain_update(
            digest
                .unwrap_or_else(|| ObjectDigest::from_bytes([0; 32]))
                .as_bytes(),
        );
    }
    hasher = hasher.chain_update([value.phase() as u8]);
    LifecycleCoordinationRecordDigestV1(ObjectDigest::from_bytes(hasher.finalize().into()))
}

fn retention_digest(value: &LifecycleRetentionLedgerV1) -> LifecycleRetentionLedgerDigestV1 {
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.retention-ledger.v1\0")
        .chain_update(value.revision().get().to_be_bytes())
        .chain_update(
            value
                .predecessor()
                .unwrap_or_else(|| ObjectDigest::from_bytes([0; 32]))
                .as_bytes(),
        )
        .chain_update((value.entries().len() as u32).to_be_bytes());
    for entry in value.entries() {
        hasher = hasher
            .chain_update([entry.resource().code()])
            .chain_update(entry.resource().as_bytes())
            .chain_update(entry.holder().as_bytes())
            .chain_update([entry.purpose() as u8])
            .chain_update(entry.receipt().as_bytes());
    }
    LifecycleRetentionLedgerDigestV1(ObjectDigest::from_bytes(hasher.finalize().into()))
}

fn boot_digest(value: &LifecycleBootInventoryV1) -> LifecycleBootRecordDigestV1 {
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.boot-record.v1\0")
        .chain_update(value.operation().as_bytes())
        .chain_update(value.operation_revision().get().to_be_bytes())
        .chain_update(value.operation_record().digest().as_bytes())
        .chain_update(value.step().to_be_bytes())
        .chain_update(value.step_result().digest().as_bytes());
    hasher = hash_live_fence(hasher, value.fence());
    for digest in [
        value.domains().runtime(),
        value.domains().mounts(),
        value.domains().storage(),
        value.domains().network(),
        value.domains().cache(),
        value.domains().transfers(),
    ] {
        hasher = hasher.chain_update(digest.as_bytes());
    }
    hasher = hasher.chain_update((value.resources().len() as u32).to_be_bytes());
    for resource in value.resources() {
        hasher = hasher
            .chain_update([resource.code()])
            .chain_update(resource.as_bytes());
    }
    hasher = hasher
        .chain_update(value.inventory().digest().as_bytes())
        .chain_update(value.observed_at().get().to_be_bytes());
    LifecycleBootRecordDigestV1(ObjectDigest::from_bytes(hasher.finalize().into()))
}

fn hash_live_fence(mut hasher: Sha256, fence: LiveRuntimeFenceV1) -> Sha256 {
    let desired = fence.desired();
    hasher.update([desired.resource().code()]);
    hasher.update(desired.resource().as_bytes());
    hasher.update(desired.resource_revision().get().to_be_bytes());
    hasher.update(desired.resource_state().digest().as_bytes());
    hasher.update(desired.expected_generation().get().to_be_bytes());
    hasher.update(fence.incarnation().as_bytes());
    hasher.update(fence.assignment_epoch().get().to_be_bytes());
    hasher.update(fence.namespace_generation().get().to_be_bytes());
    hasher
}
