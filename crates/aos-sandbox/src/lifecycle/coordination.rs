//! Durable dependency, quiesce, retention, suspension, and boot evidence.
//!
//! These records preserve transaction inputs and observations. They contain no
//! live handle, credential, effect request, or permission to contact a guest.

use aos_sandbox_core::{ObjectDigest, OperationId, ResourceId, Revision, SandboxId};
use sha2::{Digest as _, Sha256};

use super::{
    LifecycleModelError, LifecycleRecordDigestV1, LifecycleResourceV1,
    LifecycleRetentionLedgerDigestV1, LifecycleSnapshotManifestDigestV1,
    LifecycleStepResultDigestV1, LifecycleTimeV1, LifecycleTransactionIdV1, LiveRuntimeFenceV1,
    MAXIMUM_LIFECYCLE_EXPECTATIONS,
};

macro_rules! purpose_digest {
    ($name:ident, $domain:literal, $summary:literal) => {
        #[doc = $summary]
        #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $name(ObjectDigest);

        impl $name {
            /// Commits exact canonical evidence bytes in this value's domain.
            #[must_use]
            pub fn commit(bytes: &[u8]) -> Self {
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

purpose_digest!(
    LifecycleQuiesceDigestV1,
    b"aos.sandbox.lifecycle.quiesce.v1\0",
    "Commits exact guest-quiesce evidence."
);
purpose_digest!(
    LifecycleWriterFenceDigestV1,
    b"aos.sandbox.lifecycle.writer-fence.v1\0",
    "Commits the exact closed writer set and freeze generation."
);
purpose_digest!(
    LifecycleDatasetTransactionDigestV1,
    b"aos.sandbox.lifecycle.dataset-transaction.v1\0",
    "Commits one atomic dataset snapshot transaction."
);
purpose_digest!(
    LifecycleThawCompensationDigestV1,
    b"aos.sandbox.lifecycle.thaw-compensation.v1\0",
    "Commits the reverse thaw plan for a failed pre-commit transaction."
);
purpose_digest!(
    LifecycleSuspendObservationDigestV1,
    b"aos.sandbox.lifecycle.suspend-observation.v1\0",
    "Commits an exact suspended-runtime observation."
);
purpose_digest!(
    LifecycleBootInventoryDigestV1,
    b"aos.sandbox.lifecycle.boot-inventory.v1\0",
    "Commits exact resources observed at guest boot."
);
purpose_digest!(
    LifecycleRetentionLedgerReceiptV1,
    b"aos.sandbox.lifecycle.retention-ledger-receipt.v1\0",
    "Commits one exact entry in a validated retention-ledger revision."
);

/// Commits the six complete LIFE-06 inventory domains observed for one boot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleBootInventoryDomainsV1 {
    runtime: ObjectDigest,
    mounts: ObjectDigest,
    storage: ObjectDigest,
    network: ObjectDigest,
    cache: ObjectDigest,
    transfers: ObjectDigest,
}

impl LifecycleBootInventoryDomainsV1 {
    /// Constructs one closed set of complete domain-inventory commitments.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] if any required domain
    /// lacks a nonzero complete-inventory commitment.
    pub fn new(
        runtime: ObjectDigest,
        mounts: ObjectDigest,
        storage: ObjectDigest,
        network: ObjectDigest,
        cache: ObjectDigest,
        transfers: ObjectDigest,
    ) -> Result<Self, LifecycleModelError> {
        if [runtime, mounts, storage, network, cache, transfers]
            .iter()
            .any(|digest| digest.as_bytes() == &[0; 32])
        {
            return Err(LifecycleModelError::InvalidModel);
        }
        Ok(Self {
            runtime,
            mounts,
            storage,
            network,
            cache,
            transfers,
        })
    }

    /// Returns the complete runtime inventory commitment.
    #[must_use]
    pub const fn runtime(self) -> ObjectDigest {
        self.runtime
    }

    /// Returns the complete mount inventory commitment.
    #[must_use]
    pub const fn mounts(self) -> ObjectDigest {
        self.mounts
    }

    /// Returns the complete storage inventory commitment.
    #[must_use]
    pub const fn storage(self) -> ObjectDigest {
        self.storage
    }

    /// Returns the complete network inventory commitment.
    #[must_use]
    pub const fn network(self) -> ObjectDigest {
        self.network
    }

    /// Returns the complete cache inventory commitment.
    #[must_use]
    pub const fn cache(self) -> ObjectDigest {
        self.cache
    }

    /// Returns the complete transfer inventory commitment.
    #[must_use]
    pub const fn transfers(self) -> ObjectDigest {
        self.transfers
    }

    fn inventory_digest(
        self,
        fence: LiveRuntimeFenceV1,
        resources: &[LifecycleResourceV1],
    ) -> LifecycleBootInventoryDigestV1 {
        let desired = fence.desired();
        let mut hasher = Sha256::new()
            .chain_update(b"aos.sandbox.lifecycle.boot-inventory-set.v1\0")
            .chain_update(fence.sandbox().as_bytes())
            .chain_update([desired.resource().code()])
            .chain_update(desired.resource().as_bytes())
            .chain_update(desired.expected_generation().get().to_be_bytes())
            .chain_update(desired.resource_revision().get().to_be_bytes())
            .chain_update(desired.resource_state().digest().as_bytes())
            .chain_update(fence.incarnation().as_bytes())
            .chain_update(fence.assignment_epoch().get().to_be_bytes())
            .chain_update(fence.namespace_generation().get().to_be_bytes());
        for digest in [
            self.runtime,
            self.mounts,
            self.storage,
            self.network,
            self.cache,
            self.transfers,
        ] {
            hasher = hasher.chain_update(digest.as_bytes());
        }
        hasher = hasher.chain_update((resources.len() as u64).to_be_bytes());
        for resource in resources {
            hasher = hasher
                .chain_update([resource.code()])
                .chain_update(resource.as_bytes());
        }
        LifecycleBootInventoryDigestV1::commit(&hasher.finalize())
    }
}

/// Selects a monotone quiesce and dataset-transaction phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LifecycleCoordinationPhaseV1 {
    /// The exact dependency and runtime fences are durable.
    Admitted = 1,
    /// Guest quiesce and writer freeze are both observed.
    Frozen = 2,
    /// The atomic dataset transaction is durable.
    DatasetCommitted = 3,
    /// Writers were thawed after semantic commit.
    Thawed = 4,
    /// Pre-commit failure completed the exact thaw compensation.
    Compensated = 5,
}

/// Carries one controller-verified closed dependency snapshot.
///
/// The snapshot has no public constructor. The dormant lifecycle journal
/// verifier issues it after binding the complete graph, canonical postorder,
/// manifest, retention ledger, and live sandbox fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleControllerDependencySnapshotV1 {
    sandbox: SandboxId,
    live_fence: LiveRuntimeFenceV1,
    dependencies: Vec<LifecycleResourceV1>,
    dependency_edges: Vec<super::LifecycleDependencyEdgeV1>,
    postorder: Vec<LifecycleResourceV1>,
    manifest: LifecycleSnapshotManifestDigestV1,
    retention_ledger: LifecycleRetentionLedgerDigestV1,
    digest: ObjectDigest,
}

impl LifecycleControllerDependencySnapshotV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verified_controller(
        sandbox: SandboxId,
        live_fence: LiveRuntimeFenceV1,
        dependencies: Vec<LifecycleResourceV1>,
        dependency_edges: Vec<super::LifecycleDependencyEdgeV1>,
        postorder: Vec<LifecycleResourceV1>,
        manifest: LifecycleSnapshotManifestDigestV1,
        retention_ledger: LifecycleRetentionLedgerDigestV1,
    ) -> Result<Self, LifecycleModelError> {
        if sandbox.as_bytes() == &[0; 16]
            || live_fence.sandbox() != sandbox
            || dependencies.is_empty()
            || dependencies.len() > MAXIMUM_LIFECYCLE_EXPECTATIONS
            || !dependencies.windows(2).all(|pair| pair[0] < pair[1])
            || dependency_edges.len() > MAXIMUM_LIFECYCLE_EXPECTATIONS
            || !dependency_edges.windows(2).all(|pair| pair[0] < pair[1])
            || !controller_graph_is_closed(&dependencies, &dependency_edges, &postorder)
        {
            return Err(LifecycleModelError::InvalidModel);
        }
        let digest = controller_dependency_snapshot_digest(
            sandbox,
            live_fence,
            manifest,
            retention_ledger,
            &dependencies,
            &dependency_edges,
            &postorder,
        );
        Ok(Self {
            sandbox,
            live_fence,
            dependencies,
            dependency_edges,
            postorder,
            manifest,
            retention_ledger,
            digest,
        })
    }

    /// Returns the complete authoritative dependency-snapshot commitment.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }
}

/// Retains one exact dependency quiesce and dataset transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleCoordinationTransactionV1 {
    transaction: LifecycleTransactionIdV1,
    sandbox: SandboxId,
    live_fence: LiveRuntimeFenceV1,
    dependencies: Vec<LifecycleResourceV1>,
    dependency_edges: Vec<super::LifecycleDependencyEdgeV1>,
    postorder: Vec<LifecycleResourceV1>,
    dependency_snapshot: ObjectDigest,
    manifest: LifecycleSnapshotManifestDigestV1,
    retention_ledger: LifecycleRetentionLedgerDigestV1,
    quiesce: Option<LifecycleQuiesceDigestV1>,
    writer_fence: Option<LifecycleWriterFenceDigestV1>,
    dataset_transaction: Option<LifecycleDatasetTransactionDigestV1>,
    thaw_compensation: LifecycleThawCompensationDigestV1,
    phase: LifecycleCoordinationPhaseV1,
}

impl LifecycleCoordinationTransactionV1 {
    /// Admits coordination from one verifier-issued controller snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] for an invalid transaction
    /// identity or thaw-compensation commitment.
    pub fn from_controller_snapshot(
        transaction: LifecycleTransactionIdV1,
        snapshot: &LifecycleControllerDependencySnapshotV1,
        thaw_compensation: LifecycleThawCompensationDigestV1,
    ) -> Result<Self, LifecycleModelError> {
        Self::from_stored(
            transaction,
            snapshot.sandbox,
            snapshot.live_fence,
            snapshot.dependencies.clone(),
            snapshot.dependency_edges.clone(),
            snapshot.postorder.clone(),
            snapshot.digest,
            snapshot.manifest,
            snapshot.retention_ledger,
            None,
            None,
            None,
            thaw_compensation,
            LifecycleCoordinationPhaseV1::Admitted,
        )
    }

    /// Constructs a closed, non-authorizing coordination transaction record.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] for inconsistent identity,
    /// collection ordering, or evidence shape for the selected phase.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_stored(
        transaction: LifecycleTransactionIdV1,
        sandbox: SandboxId,
        live_fence: LiveRuntimeFenceV1,
        dependencies: Vec<LifecycleResourceV1>,
        dependency_edges: Vec<super::LifecycleDependencyEdgeV1>,
        postorder: Vec<LifecycleResourceV1>,
        dependency_snapshot: ObjectDigest,
        manifest: LifecycleSnapshotManifestDigestV1,
        retention_ledger: LifecycleRetentionLedgerDigestV1,
        quiesce: Option<LifecycleQuiesceDigestV1>,
        writer_fence: Option<LifecycleWriterFenceDigestV1>,
        dataset_transaction: Option<LifecycleDatasetTransactionDigestV1>,
        thaw_compensation: LifecycleThawCompensationDigestV1,
        phase: LifecycleCoordinationPhaseV1,
    ) -> Result<Self, LifecycleModelError> {
        let frozen = quiesce.is_some() && writer_fence.is_some();
        let evidence_is_valid = match phase {
            LifecycleCoordinationPhaseV1::Admitted => {
                quiesce.is_none() && writer_fence.is_none() && dataset_transaction.is_none()
            }
            LifecycleCoordinationPhaseV1::Frozen => frozen && dataset_transaction.is_none(),
            LifecycleCoordinationPhaseV1::DatasetCommitted
            | LifecycleCoordinationPhaseV1::Thawed => frozen && dataset_transaction.is_some(),
            LifecycleCoordinationPhaseV1::Compensated => frozen,
        };
        if sandbox.as_bytes() == &[0; 16]
            || live_fence.sandbox() != sandbox
            || dependencies.is_empty()
            || dependencies.len() > MAXIMUM_LIFECYCLE_EXPECTATIONS
            || !dependencies.windows(2).all(|pair| pair[0] < pair[1])
            || dependency_edges.len() > MAXIMUM_LIFECYCLE_EXPECTATIONS
            || !dependency_edges.windows(2).all(|pair| pair[0] < pair[1])
            || !controller_graph_is_closed(&dependencies, &dependency_edges, &postorder)
            || dependency_snapshot
                != controller_dependency_snapshot_digest(
                    sandbox,
                    live_fence,
                    manifest,
                    retention_ledger,
                    &dependencies,
                    &dependency_edges,
                    &postorder,
                )
            || !evidence_is_valid
        {
            return Err(LifecycleModelError::InvalidModel);
        }
        Ok(Self {
            transaction,
            sandbox,
            live_fence,
            dependencies,
            dependency_edges,
            postorder,
            dependency_snapshot,
            manifest,
            retention_ledger,
            quiesce,
            writer_fence,
            dataset_transaction,
            thaw_compensation,
            phase,
        })
    }

    /// Returns the transaction identity.
    #[must_use]
    pub const fn transaction(&self) -> LifecycleTransactionIdV1 {
        self.transaction
    }

    /// Returns the coordinated sandbox identity.
    #[must_use]
    pub const fn sandbox(&self) -> SandboxId {
        self.sandbox
    }

    /// Returns the exact live sandbox fence.
    #[must_use]
    pub const fn live_fence(&self) -> LiveRuntimeFenceV1 {
        self.live_fence
    }

    /// Borrows the canonical dependency set.
    #[must_use]
    pub fn dependencies(&self) -> &[LifecycleResourceV1] {
        &self.dependencies
    }

    /// Borrows the complete controller-verified dependency edge set.
    #[must_use]
    pub fn dependency_edges(&self) -> &[super::LifecycleDependencyEdgeV1] {
        &self.dependency_edges
    }

    /// Borrows the exact verified dependent-before-dependency order.
    #[must_use]
    pub fn postorder(&self) -> &[LifecycleResourceV1] {
        &self.postorder
    }

    /// Returns the authoritative closed dependency-snapshot commitment.
    #[must_use]
    pub const fn dependency_snapshot(&self) -> ObjectDigest {
        self.dependency_snapshot
    }

    /// Returns the exact coordinated manifest commitment.
    #[must_use]
    pub const fn manifest(&self) -> LifecycleSnapshotManifestDigestV1 {
        self.manifest
    }

    /// Returns the exact retention-ledger revision commitment.
    #[must_use]
    pub const fn retention_ledger(&self) -> LifecycleRetentionLedgerDigestV1 {
        self.retention_ledger
    }

    /// Returns the guest-quiesce evidence commitment.
    #[must_use]
    pub const fn quiesce(&self) -> Option<LifecycleQuiesceDigestV1> {
        self.quiesce
    }

    /// Returns the exact writer-fence commitment.
    #[must_use]
    pub const fn writer_fence(&self) -> Option<LifecycleWriterFenceDigestV1> {
        self.writer_fence
    }

    /// Returns the atomic dataset-transaction commitment.
    #[must_use]
    pub const fn dataset_transaction(&self) -> Option<LifecycleDatasetTransactionDigestV1> {
        self.dataset_transaction
    }

    /// Returns the exact thaw compensation plan commitment.
    #[must_use]
    pub const fn thaw_compensation(&self) -> LifecycleThawCompensationDigestV1 {
        self.thaw_compensation
    }

    /// Returns the current durable phase.
    #[must_use]
    pub const fn phase(&self) -> LifecycleCoordinationPhaseV1 {
        self.phase
    }

    /// Constructs a monotone evidence refinement without authorizing an effect.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidTransition`] for changed immutable
    /// inputs, removed evidence, or a non-adjacent phase transition.
    pub fn successor(
        &self,
        quiesce: Option<LifecycleQuiesceDigestV1>,
        writer_fence: Option<LifecycleWriterFenceDigestV1>,
        dataset_transaction: Option<LifecycleDatasetTransactionDigestV1>,
        phase: LifecycleCoordinationPhaseV1,
    ) -> Result<Self, LifecycleModelError> {
        let edge = matches!(
            (self.phase, phase),
            (
                LifecycleCoordinationPhaseV1::Admitted,
                LifecycleCoordinationPhaseV1::Frozen
            ) | (
                LifecycleCoordinationPhaseV1::Frozen,
                LifecycleCoordinationPhaseV1::DatasetCommitted
            ) | (
                LifecycleCoordinationPhaseV1::Frozen,
                LifecycleCoordinationPhaseV1::Compensated
            ) | (
                LifecycleCoordinationPhaseV1::DatasetCommitted,
                LifecycleCoordinationPhaseV1::Thawed
            )
        );
        let monotone = self.quiesce.is_none_or(|value| quiesce == Some(value))
            && self
                .writer_fence
                .is_none_or(|value| writer_fence == Some(value))
            && self
                .dataset_transaction
                .is_none_or(|value| dataset_transaction == Some(value));
        if !edge || !monotone {
            return Err(LifecycleModelError::InvalidTransition);
        }
        Self::from_stored(
            self.transaction,
            self.sandbox,
            self.live_fence,
            self.dependencies.clone(),
            self.dependency_edges.clone(),
            self.postorder.clone(),
            self.dependency_snapshot,
            self.manifest,
            self.retention_ledger,
            quiesce,
            writer_fence,
            dataset_transaction,
            self.thaw_compensation,
            phase,
        )
        .map_err(|_| LifecycleModelError::InvalidTransition)
    }
}

/// Selects why a controller retention-ledger entry exists.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum LifecycleRetentionPurposeV1 {
    /// Retains an object for one immutable snapshot manifest.
    Snapshot = 1,
    /// Retains an object while a cascade transaction is incomplete.
    Cascade = 2,
    /// Retains an object while an external transfer is incomplete.
    Transfer = 3,
}

/// Retains one exact purpose-scoped dependency hold in the controller ledger.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LifecycleRetentionLedgerEntryV1 {
    resource: LifecycleResourceV1,
    holder: ResourceId,
    purpose: LifecycleRetentionPurposeV1,
    receipt: ObjectDigest,
}

impl LifecycleRetentionLedgerEntryV1 {
    /// Constructs one non-secret held-dependency acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] for sentinel values.
    pub fn new(
        resource: LifecycleResourceV1,
        holder: ResourceId,
        purpose: LifecycleRetentionPurposeV1,
        receipt: ObjectDigest,
    ) -> Result<Self, LifecycleModelError> {
        if resource.as_bytes() == &[0; 16]
            || holder.as_bytes() == &[0; 16]
            || receipt.as_bytes() == &[0; 32]
        {
            Err(LifecycleModelError::InvalidModel)
        } else {
            Ok(Self {
                resource,
                holder,
                purpose,
                receipt,
            })
        }
    }

    /// Returns the retained typed dependency.
    #[must_use]
    pub const fn resource(self) -> LifecycleResourceV1 {
        self.resource
    }

    /// Returns the non-authorizing holder identity.
    #[must_use]
    pub const fn holder(self) -> ResourceId {
        self.holder
    }

    /// Returns the closed retention purpose for this exact entry.
    #[must_use]
    pub const fn purpose(self) -> LifecycleRetentionPurposeV1 {
        self.purpose
    }

    /// Returns the durable acknowledgement receipt.
    #[must_use]
    pub const fn receipt(self) -> ObjectDigest {
        self.receipt
    }
}

/// Stores one revision of the complete canonical retention ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleRetentionLedgerV1 {
    revision: Revision,
    predecessor: Option<ObjectDigest>,
    entries: Vec<LifecycleRetentionLedgerEntryV1>,
}

impl LifecycleRetentionLedgerV1 {
    /// Constructs one bounded canonical retention-ledger revision.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] for a broken first-record
    /// shape, sentinel revision, excessive entries, or duplicate ordering.
    pub fn new(
        revision: Revision,
        predecessor: Option<ObjectDigest>,
        entries: Vec<LifecycleRetentionLedgerEntryV1>,
    ) -> Result<Self, LifecycleModelError> {
        if revision.get() == 0
            || revision.get() == u64::MAX
            || (revision.get() == 1) != predecessor.is_none()
            || entries.len() > MAXIMUM_LIFECYCLE_EXPECTATIONS
            || !entries.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(LifecycleModelError::InvalidModel);
        }
        Ok(Self {
            revision,
            predecessor,
            entries,
        })
    }

    /// Borrows the complete held-dependency set.
    #[must_use]
    pub fn entries(&self) -> &[LifecycleRetentionLedgerEntryV1] {
        &self.entries
    }

    /// Returns the ledger revision.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// Returns the predecessor record commitment.
    #[must_use]
    pub const fn predecessor(&self) -> Option<ObjectDigest> {
        self.predecessor
    }

    /// Derives an opaque receipt for one exact retained entry in this revision.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] when the exact resource
    /// and holder are absent from this complete ledger revision.
    pub fn receipt_for(
        &self,
        resource: LifecycleResourceV1,
        holder: ResourceId,
        purpose: LifecycleRetentionPurposeV1,
    ) -> Result<LifecycleRetentionLedgerReceiptV1, LifecycleModelError> {
        let entry = self
            .entries
            .iter()
            .find(|entry| {
                entry.resource() == resource
                    && entry.holder() == holder
                    && entry.purpose() == purpose
            })
            .ok_or(LifecycleModelError::InvalidModel)?;
        let mut bytes = [0_u8; 106];
        bytes[0] = resource.code();
        bytes[1..17].copy_from_slice(resource.as_bytes());
        bytes[17..33].copy_from_slice(holder.as_bytes());
        bytes[33] = purpose as u8;
        bytes[34..42].copy_from_slice(&self.revision.get().to_be_bytes());
        bytes[42..74].copy_from_slice(
            self.predecessor
                .unwrap_or_else(|| ObjectDigest::from_bytes([0; 32]))
                .as_bytes(),
        );
        bytes[74..106].copy_from_slice(entry.receipt().as_bytes());
        Ok(LifecycleRetentionLedgerReceiptV1::commit(&bytes))
    }
}

/// Retains the exact observation proving a live runtime suspended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleSuspendObservationV1 {
    operation: OperationId,
    operation_revision: Revision,
    operation_record: LifecycleRecordDigestV1,
    fence: LiveRuntimeFenceV1,
    observation: LifecycleSuspendObservationDigestV1,
    observed_at: LifecycleTimeV1,
}

impl LifecycleSuspendObservationV1 {
    /// Derives an exact terminal suspend observation from one operation record.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] unless `operation` is a
    /// successful terminal memory-suspend with the same exact runtime fence.
    pub fn from_operation(
        operation: &super::LifecycleOperationV1,
        fence: LiveRuntimeFenceV1,
        observation: LifecycleSuspendObservationDigestV1,
        observed_at: LifecycleTimeV1,
    ) -> Result<Self, LifecycleModelError> {
        if !matches!(
            operation.intent(),
            super::LifecycleIntentV1::SuspendMemory { fence: expected, .. } if *expected == fence
        ) || operation.phase() != super::LifecyclePhaseV1::Terminal
            || operation.terminal_result() != Some(super::LifecycleTerminalResultV1::Succeeded)
            || operation.finished_at() != Some(observed_at)
        {
            return Err(LifecycleModelError::InvalidModel);
        }
        let encoded = super::encode_operation_record_v1(operation)?;
        let operation_record = super::format::record_digest(&encoded)?;
        Ok(Self {
            operation: operation.operation_id(),
            operation_revision: operation.record_revision(),
            operation_record,
            fence,
            observation,
            observed_at,
        })
    }

    pub(super) fn from_stored(
        operation: OperationId,
        operation_revision: Revision,
        operation_record: LifecycleRecordDigestV1,
        fence: LiveRuntimeFenceV1,
        observation: LifecycleSuspendObservationDigestV1,
        observed_at: LifecycleTimeV1,
    ) -> Result<Self, LifecycleModelError> {
        if operation.as_bytes() == &[0; 16]
            || operation_revision.get() == 0
            || operation_revision.get() == u64::MAX
        {
            return Err(LifecycleModelError::CorruptEncoding);
        }
        Ok(Self {
            operation,
            operation_revision,
            operation_record,
            fence,
            observation,
            observed_at,
        })
    }

    /// Returns the operation owning this terminal observation.
    #[must_use]
    pub const fn operation(self) -> OperationId {
        self.operation
    }

    /// Returns the exact terminal operation revision.
    #[must_use]
    pub const fn operation_revision(self) -> Revision {
        self.operation_revision
    }

    /// Returns the exact terminal operation-record commitment.
    #[must_use]
    pub const fn operation_record(self) -> LifecycleRecordDigestV1 {
        self.operation_record
    }

    /// Returns the exact live runtime fence.
    #[must_use]
    pub const fn fence(self) -> LiveRuntimeFenceV1 {
        self.fence
    }

    /// Returns the suspended-state observation commitment.
    #[must_use]
    pub const fn observation(self) -> LifecycleSuspendObservationDigestV1 {
        self.observation
    }

    /// Returns the durable observation time.
    #[must_use]
    pub const fn observed_at(self) -> LifecycleTimeV1 {
        self.observed_at
    }
}

/// Retains exact resource inventory observed for one fenced boot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleBootInventoryV1 {
    operation: OperationId,
    operation_revision: Revision,
    operation_record: LifecycleRecordDigestV1,
    step: u32,
    step_result: LifecycleStepResultDigestV1,
    fence: LiveRuntimeFenceV1,
    domains: LifecycleBootInventoryDomainsV1,
    resources: Vec<LifecycleResourceV1>,
    inventory: LifecycleBootInventoryDigestV1,
    observed_at: LifecycleTimeV1,
}

impl LifecycleBootInventoryV1 {
    /// Derives one post-commit boot inventory from an exact successful step.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] unless semantic commit is
    /// already durable and `step` names an applied post-commit forward step.
    pub fn from_operation(
        operation: &super::LifecycleOperationV1,
        step: u32,
        fence: LiveRuntimeFenceV1,
        domains: LifecycleBootInventoryDomainsV1,
        resources: Vec<LifecycleResourceV1>,
        observed_at: LifecycleTimeV1,
    ) -> Result<Self, LifecycleModelError> {
        let step_record = operation
            .steps()
            .get(usize::try_from(step).map_err(|_| LifecycleModelError::InvalidModel)?)
            .filter(|record| {
                record.index() == step
                    && record.class() == super::LifecycleStepClassV1::PostCommitForward
                    && record.state() == super::LifecycleStepStateV1::Applied
            })
            .ok_or(LifecycleModelError::InvalidModel)?;
        let step_result = step_record
            .result()
            .ok_or(LifecycleModelError::InvalidModel)?;
        if operation.method_semantic_commit().is_none()
            || !matches!(
                operation.phase(),
                super::LifecyclePhaseV1::Completing
                    | super::LifecyclePhaseV1::Residual
                    | super::LifecyclePhaseV1::Terminal
            )
        {
            return Err(LifecycleModelError::InvalidModel);
        }
        let encoded = super::encode_operation_record_v1(operation)?;
        let operation_record = super::format::record_digest(&encoded)?;
        let inventory = domains.inventory_digest(fence, &resources);
        Self::new(
            operation.operation_id(),
            operation.record_revision(),
            operation_record,
            step,
            step_result,
            fence,
            domains,
            resources,
            inventory,
            observed_at,
        )
    }

    /// Constructs one bounded canonical boot inventory.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] for an empty, excessive,
    /// duplicate, or unordered inventory.
    pub(super) fn new(
        operation: OperationId,
        operation_revision: Revision,
        operation_record: LifecycleRecordDigestV1,
        step: u32,
        step_result: LifecycleStepResultDigestV1,
        fence: LiveRuntimeFenceV1,
        domains: LifecycleBootInventoryDomainsV1,
        resources: Vec<LifecycleResourceV1>,
        inventory: LifecycleBootInventoryDigestV1,
        observed_at: LifecycleTimeV1,
    ) -> Result<Self, LifecycleModelError> {
        if operation.as_bytes() == &[0; 16]
            || operation_revision.get() == 0
            || operation_revision.get() == u64::MAX
            || resources.is_empty()
            || resources.len() > MAXIMUM_LIFECYCLE_EXPECTATIONS
            || !resources.windows(2).all(|pair| pair[0] < pair[1])
            || inventory != domains.inventory_digest(fence, &resources)
        {
            return Err(LifecycleModelError::InvalidModel);
        }
        Ok(Self {
            operation,
            operation_revision,
            operation_record,
            step,
            step_result,
            fence,
            domains,
            resources,
            inventory,
            observed_at,
        })
    }

    /// Returns the operation owning the post-commit observation.
    #[must_use]
    pub const fn operation(&self) -> OperationId {
        self.operation
    }

    /// Returns the exact joined operation revision.
    #[must_use]
    pub const fn operation_revision(&self) -> Revision {
        self.operation_revision
    }

    /// Returns the exact joined operation record commitment.
    #[must_use]
    pub const fn operation_record(&self) -> LifecycleRecordDigestV1 {
        self.operation_record
    }

    /// Returns the post-commit boot step index.
    #[must_use]
    pub const fn step(&self) -> u32 {
        self.step
    }

    /// Returns the exact successful boot-step result commitment.
    #[must_use]
    pub const fn step_result(&self) -> LifecycleStepResultDigestV1 {
        self.step_result
    }

    /// Returns the six complete LIFE-06 domain inventory commitments.
    #[must_use]
    pub const fn domains(&self) -> LifecycleBootInventoryDomainsV1 {
        self.domains
    }

    /// Borrows the canonical observed resource set.
    #[must_use]
    pub fn resources(&self) -> &[LifecycleResourceV1] {
        &self.resources
    }

    /// Returns the exact live boot fence.
    #[must_use]
    pub const fn fence(&self) -> LiveRuntimeFenceV1 {
        self.fence
    }

    /// Returns the complete inventory commitment.
    #[must_use]
    pub const fn inventory(&self) -> LifecycleBootInventoryDigestV1 {
        self.inventory
    }

    /// Returns the durable observation time.
    #[must_use]
    pub const fn observed_at(&self) -> LifecycleTimeV1 {
        self.observed_at
    }
}

fn controller_graph_is_closed(
    dependencies: &[LifecycleResourceV1],
    edges: &[super::LifecycleDependencyEdgeV1],
    postorder: &[LifecycleResourceV1],
) -> bool {
    dependencies.len() == postorder.len()
        && super::semantic::dependency_postorder_is_complete(edges, postorder)
        && postorder.iter().enumerate().all(|(index, resource)| {
            dependencies.binary_search(resource).is_ok() && !postorder[..index].contains(resource)
        })
        && edges.iter().all(|edge| {
            let dependent = postorder
                .iter()
                .position(|value| *value == edge.dependent());
            let dependency = postorder
                .iter()
                .position(|value| *value == edge.dependency());
            dependent
                .zip(dependency)
                .is_some_and(|(dependent, dependency)| dependent < dependency)
        })
}

fn controller_dependency_snapshot_digest(
    sandbox: SandboxId,
    fence: LiveRuntimeFenceV1,
    manifest: LifecycleSnapshotManifestDigestV1,
    retention: LifecycleRetentionLedgerDigestV1,
    dependencies: &[LifecycleResourceV1],
    edges: &[super::LifecycleDependencyEdgeV1],
    postorder: &[LifecycleResourceV1],
) -> ObjectDigest {
    let desired = fence.desired();
    let mut hasher = Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.controller-dependency-snapshot.v1\0")
        .chain_update(sandbox.as_bytes())
        .chain_update([desired.resource().code()])
        .chain_update(desired.resource().as_bytes())
        .chain_update(desired.expected_generation().get().to_be_bytes())
        .chain_update(desired.resource_revision().get().to_be_bytes())
        .chain_update(desired.resource_state().digest().as_bytes())
        .chain_update(fence.incarnation().as_bytes())
        .chain_update(fence.assignment_epoch().get().to_be_bytes())
        .chain_update(fence.namespace_generation().get().to_be_bytes())
        .chain_update(manifest.digest().as_bytes())
        .chain_update(retention.digest().as_bytes())
        .chain_update((dependencies.len() as u64).to_be_bytes());
    for dependency in dependencies {
        hasher = hasher
            .chain_update([dependency.code()])
            .chain_update(dependency.as_bytes());
    }
    hasher = hasher.chain_update((edges.len() as u64).to_be_bytes());
    for edge in edges {
        hasher = hasher
            .chain_update([edge.dependent().code()])
            .chain_update(edge.dependent().as_bytes())
            .chain_update([edge.dependency().code()])
            .chain_update(edge.dependency().as_bytes());
    }
    hasher = hasher.chain_update((postorder.len() as u64).to_be_bytes());
    for resource in postorder {
        hasher = hasher
            .chain_update([resource.code()])
            .chain_update(resource.as_bytes());
    }
    ObjectDigest::from_bytes(hasher.finalize().into())
}
