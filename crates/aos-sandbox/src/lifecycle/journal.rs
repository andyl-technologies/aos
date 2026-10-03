//! Inert lifecycle journal namespace and ownership records.
//!
//! The types reserve a future shared-journal integration surface while keeping
//! this source partition disconnected from the journal implementation.

use std::collections::BTreeMap;

use aos_sandbox_core::{ObjectDigest, OperationId, ProjectId, ResourceId, Revision, SandboxId};
use sha2::{Digest as _, Sha256};

use super::{
    LifecycleControllerDependencySnapshotV1, LifecycleDependencyEdgeV1, LifecycleModelError,
    LifecycleRecordDigestV1, LifecycleReplayVerificationV1, LifecycleResourceV1,
    LifecycleRetentionLedgerDigestV1, LifecycleSnapshotManifestDigestV1, LiveRuntimeFenceV1,
};

const MAGIC: &[u8; 8] = b"AOSLIFJ1";
const VERSION: u16 = 1;
const BODY_BYTES: usize = 224;
const RECORD_BYTES: usize = BODY_BYTES + 32;
const MAXIMUM_LIFECYCLE_JOURNAL_RECORDS: usize = 262_144;

/// Identifies the dormant lifecycle journal namespace format.
pub const LIFECYCLE_JOURNAL_NAMESPACE_V1: &str = "aos.sandbox.lifecycle.v1";

/// Names the real shared-journal keyspace used by lifecycle records.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum LifecycleJournalRecordKindV1 {
    /// Stores a complete lifecycle operation snapshot.
    Operation = 1,
    /// Stores caller/project/method idempotency bindings.
    Idempotency = 2,
    /// Stores attempt-local effect evidence.
    Effect = 3,
    /// Stores a closed lifecycle auxiliary atomic-join member.
    Auxiliary = 4,
    /// Stores a materialized lifecycle replay checkpoint.
    Checkpoint = 5,
}

impl LifecycleJournalRecordKindV1 {
    /// Maps this dormant record kind to the existing shared journal namespace.
    #[must_use]
    pub const fn record_namespace(self) -> crate::journal::RecordNamespace {
        match self {
            Self::Operation => crate::journal::RecordNamespace::Operation,
            Self::Idempotency => crate::journal::RecordNamespace::Idempotency,
            Self::Effect => crate::journal::RecordNamespace::Effect,
            Self::Auxiliary => crate::journal::RecordNamespace::DesiredState,
            Self::Checkpoint => crate::journal::RecordNamespace::RuntimeGeneration,
        }
    }
}

/// Binds one operation record to an owned namespace and predecessor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleJournalOwnershipRecordV1 {
    kind: LifecycleJournalRecordKindV1,
    project: ProjectId,
    namespace: ResourceId,
    operation: Option<OperationId>,
    revision: Revision,
    predecessor: Option<ObjectDigest>,
    operation_record: Option<LifecycleRecordDigestV1>,
    owned_record: ObjectDigest,
    atomic_join: Option<ResourceId>,
    replay_authority: ObjectDigest,
    replay_floor: Option<Revision>,
}

impl LifecycleJournalOwnershipRecordV1 {
    /// Constructs one non-authorizing namespace record.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] for sentinel identities,
    /// a broken first-record predecessor shape, or a floor above this revision.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: LifecycleJournalRecordKindV1,
        project: ProjectId,
        namespace: ResourceId,
        operation: Option<OperationId>,
        revision: Revision,
        predecessor: Option<ObjectDigest>,
        operation_record: Option<LifecycleRecordDigestV1>,
        owned_record: ObjectDigest,
        atomic_join: Option<ResourceId>,
        replay_authority: ObjectDigest,
        replay_floor: Option<Revision>,
    ) -> Result<Self, LifecycleModelError> {
        if project.as_bytes() == &[0; 16]
            || namespace.as_bytes() == &[0; 16]
            || operation.is_some_and(|operation| operation.as_bytes() == &[0; 16])
            || owned_record.as_bytes() == &[0; 32]
            || replay_authority.as_bytes() == &[0; 32]
            || atomic_join.is_some_and(|join| join.as_bytes() == &[0; 16])
            || matches!(kind, LifecycleJournalRecordKindV1::Auxiliary) != atomic_join.is_some()
            || matches!(kind, LifecycleJournalRecordKindV1::Checkpoint) == operation.is_some()
            || operation.is_some() != operation_record.is_some()
            || revision.get() == 0
            || revision.get() == u64::MAX
            || (revision.get() == 1) != predecessor.is_none()
            || replay_floor.is_some_and(|floor| {
                floor.get() == 0 || floor.get() == u64::MAX || floor.get() > revision.get()
            })
        {
            return Err(LifecycleModelError::InvalidModel);
        }
        Ok(Self {
            kind,
            project,
            namespace,
            operation,
            revision,
            predecessor,
            operation_record,
            owned_record,
            atomic_join,
            replay_authority,
            replay_floor,
        })
    }

    /// Returns the owning project.
    #[must_use]
    pub const fn project(self) -> ProjectId {
        self.project
    }

    /// Returns the isolated namespace identity.
    #[must_use]
    pub const fn namespace(self) -> ResourceId {
        self.namespace
    }

    /// Returns the namespace-local monotone revision.
    #[must_use]
    pub const fn revision(self) -> Revision {
        self.revision
    }

    /// Returns the exact shared-journal family.
    #[must_use]
    pub const fn kind(self) -> LifecycleJournalRecordKindV1 {
        self.kind
    }

    /// Returns the owned operation identity.
    #[must_use]
    pub const fn operation(self) -> Option<OperationId> {
        self.operation
    }

    /// Returns the exact predecessor record commitment.
    #[must_use]
    pub const fn predecessor(self) -> Option<ObjectDigest> {
        self.predecessor
    }

    /// Returns the complete lifecycle operation-record commitment.
    #[must_use]
    pub const fn operation_record(self) -> Option<LifecycleRecordDigestV1> {
        self.operation_record
    }

    /// Returns the complete owned operation, auxiliary, or checkpoint record.
    #[must_use]
    pub const fn owned_record(self) -> ObjectDigest {
        self.owned_record
    }

    /// Returns the closed auxiliary atomic join when this is a join member.
    #[must_use]
    pub const fn atomic_join(self) -> Option<ResourceId> {
        self.atomic_join
    }

    /// Returns the opaque checkpoint-verifier authority commitment.
    #[must_use]
    pub const fn replay_authority(self) -> ObjectDigest {
        self.replay_authority
    }

    /// Returns the trusted replay floor carried by this record.
    #[must_use]
    pub const fn replay_floor(self) -> Option<Revision> {
        self.replay_floor
    }

    /// Returns the complete canonical journal-custody commitment.
    #[must_use]
    pub fn complete_digest(self) -> ObjectDigest {
        journal_digest(&encode_body(self))
    }
}

/// Carries verified dormant lifecycle journal custody.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleJournalVerifierV1 {
    authority: ObjectDigest,
    replay: LifecycleReplayVerificationV1,
}

impl LifecycleJournalVerifierV1 {
    pub(crate) fn from_verified_authority(
        authority: ObjectDigest,
        accepted_records: Vec<ObjectDigest>,
        accepted_checkpoints: Vec<ObjectDigest>,
    ) -> Result<Self, LifecycleModelError> {
        Ok(Self {
            authority,
            replay: LifecycleReplayVerificationV1::from_verified_authority(
                authority,
                accepted_records,
                accepted_checkpoints,
            )?,
        })
    }

    /// Returns the verifier-issued protected replay brand.
    #[must_use]
    pub const fn replay(&self) -> &LifecycleReplayVerificationV1 {
        &self.replay
    }

    /// Returns the journal-custody authority commitment.
    #[must_use]
    pub const fn authority(&self) -> ObjectDigest {
        self.authority
    }

    /// Issues an inert controller-graph snapshot after journal-side verification.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidModel`] unless the graph is closed,
    /// ordered, and bound to the exact sandbox, manifest, ledger, and live fence.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn issue_dependency_snapshot(
        &self,
        sandbox: SandboxId,
        live_fence: LiveRuntimeFenceV1,
        dependencies: Vec<LifecycleResourceV1>,
        dependency_edges: Vec<LifecycleDependencyEdgeV1>,
        postorder: Vec<LifecycleResourceV1>,
        manifest: LifecycleSnapshotManifestDigestV1,
        retention_ledger: LifecycleRetentionLedgerDigestV1,
    ) -> Result<LifecycleControllerDependencySnapshotV1, LifecycleModelError> {
        LifecycleControllerDependencySnapshotV1::from_verified_controller(
            sandbox,
            live_fence,
            dependencies,
            dependency_edges,
            postorder,
            manifest,
            retention_ledger,
        )
    }
}

/// Replays exact lifecycle journal ownership lineages without append authority.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LifecycleJournalHistoryV1 {
    latest: BTreeMap<
        (ProjectId, ResourceId, LifecycleJournalRecordKindV1),
        LifecycleJournalOwnershipRecordV1,
    >,
    retained_records: usize,
}

impl LifecycleJournalHistoryV1 {
    /// Replays canonical custody records under one verified journal boundary.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError`] for corrupt bytes, authority mismatch,
    /// forked lineage, or the fixed retained-record ceiling.
    pub fn replay<'a>(
        records: impl IntoIterator<Item = &'a [u8]>,
        verifier: &LifecycleJournalVerifierV1,
    ) -> Result<Self, LifecycleModelError> {
        let mut history = Self::default();
        for encoded in records {
            history.append(
                decode_lifecycle_journal_record_v1(encoded, verifier)?,
                verifier,
            )?;
        }
        Ok(history)
    }

    /// Appends one already verified custody record to its exact lineage.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleModelError::InvalidTransition`] for a skipped,
    /// forked, duplicate, or over-capacity append.
    pub fn append(
        &mut self,
        record: LifecycleJournalOwnershipRecordV1,
        verifier: &LifecycleJournalVerifierV1,
    ) -> Result<(), LifecycleModelError> {
        let key = (record.project, record.namespace, record.kind);
        if record.replay_authority != verifier.authority
            || self.retained_records >= MAXIMUM_LIFECYCLE_JOURNAL_RECORDS
        {
            return Err(LifecycleModelError::InvalidTransition);
        }
        match self.latest.get(&key) {
            Some(previous)
                if previous
                    .revision
                    .checked_next()
                    .is_ok_and(|revision| revision == record.revision)
                    && record.predecessor == Some(previous.complete_digest()) => {}
            None if record.revision.get() == 1 && record.predecessor.is_none() => {}
            _ => return Err(LifecycleModelError::InvalidTransition),
        }
        self.latest.insert(key, record);
        self.retained_records += 1;
        Ok(())
    }
}

/// Encodes one fixed-size lifecycle journal custody record.
///
/// # Errors
///
/// Returns [`LifecycleModelError::Allocation`] if checked allocation fails.
pub fn encode_lifecycle_journal_record_v1(
    record: LifecycleJournalOwnershipRecordV1,
) -> Result<Vec<u8>, LifecycleModelError> {
    let body = encode_body(record);
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(RECORD_BYTES)
        .map_err(|_| LifecycleModelError::Allocation)?;
    encoded.extend_from_slice(&body);
    encoded.extend_from_slice(journal_digest(&body).as_bytes());
    Ok(encoded)
}

/// Decodes one fixed-size verifier-bound lifecycle custody record.
///
/// # Errors
///
/// Returns [`LifecycleModelError::CorruptEncoding`] for malformed bytes or a
/// replay authority different from the supplied verifier.
pub fn decode_lifecycle_journal_record_v1(
    encoded: &[u8],
    verifier: &LifecycleJournalVerifierV1,
) -> Result<LifecycleJournalOwnershipRecordV1, LifecycleModelError> {
    if encoded.len() != RECORD_BYTES {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let (body, stored) = encoded.split_at(BODY_BYTES);
    if journal_digest(body).as_bytes() != stored {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let mut bytes = body;
    if take::<8>(&mut bytes)? != *MAGIC || u16::from_be_bytes(take(&mut bytes)?) != VERSION {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let kind = match take::<1>(&mut bytes)?[0] {
        1 => LifecycleJournalRecordKindV1::Operation,
        2 => LifecycleJournalRecordKindV1::Idempotency,
        3 => LifecycleJournalRecordKindV1::Effect,
        4 => LifecycleJournalRecordKindV1::Auxiliary,
        5 => LifecycleJournalRecordKindV1::Checkpoint,
        _ => return Err(LifecycleModelError::CorruptEncoding),
    };
    if take::<5>(&mut bytes)? != [0; 5] {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    let project = ProjectId::from_bytes(take(&mut bytes)?);
    let namespace = ResourceId::from_bytes(take(&mut bytes)?);
    let raw_operation = take::<16>(&mut bytes)?;
    let operation = (raw_operation != [0; 16]).then_some(OperationId::from_bytes(raw_operation));
    let revision = Revision::new(u64::from_be_bytes(take(&mut bytes)?));
    let predecessor = optional_digest(take(&mut bytes)?);
    let raw_operation_record = ObjectDigest::from_bytes(take(&mut bytes)?);
    let operation_record = (raw_operation_record.as_bytes() != &[0; 32])
        .then(|| LifecycleRecordDigestV1::from_stored(raw_operation_record))
        .transpose()?;
    let owned_record = ObjectDigest::from_bytes(take(&mut bytes)?);
    let raw_join = take::<16>(&mut bytes)?;
    let atomic_join = (raw_join != [0; 16]).then_some(ResourceId::from_bytes(raw_join));
    let replay_authority = ObjectDigest::from_bytes(take(&mut bytes)?);
    let replay_floor = optional_revision(u64::from_be_bytes(take(&mut bytes)?));
    if replay_authority != verifier.authority {
        return Err(LifecycleModelError::CorruptEncoding);
    }
    LifecycleJournalOwnershipRecordV1::new(
        kind,
        project,
        namespace,
        operation,
        revision,
        predecessor,
        operation_record,
        owned_record,
        atomic_join,
        replay_authority,
        replay_floor,
    )
    .map_err(|_| LifecycleModelError::CorruptEncoding)
}

fn encode_body(record: LifecycleJournalOwnershipRecordV1) -> [u8; BODY_BYTES] {
    let mut bytes = [0_u8; BODY_BYTES];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
    bytes[10] = record.kind as u8;
    bytes[16..32].copy_from_slice(record.project.as_bytes());
    bytes[32..48].copy_from_slice(record.namespace.as_bytes());
    if let Some(operation) = record.operation {
        bytes[48..64].copy_from_slice(operation.as_bytes());
    }
    bytes[64..72].copy_from_slice(&record.revision.get().to_be_bytes());
    if let Some(predecessor) = record.predecessor {
        bytes[72..104].copy_from_slice(predecessor.as_bytes());
    }
    if let Some(operation_record) = record.operation_record {
        bytes[104..136].copy_from_slice(operation_record.digest().as_bytes());
    }
    bytes[136..168].copy_from_slice(record.owned_record.as_bytes());
    if let Some(join) = record.atomic_join {
        bytes[168..184].copy_from_slice(join.as_bytes());
    }
    bytes[184..216].copy_from_slice(record.replay_authority.as_bytes());
    bytes[216..224].copy_from_slice(&record.replay_floor.map_or(0, Revision::get).to_be_bytes());
    bytes
}

fn journal_digest(bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.sandbox.lifecycle.journal-custody.v1\0")
            .chain_update(bytes)
            .finalize()
            .into(),
    )
}

fn optional_digest(bytes: [u8; 32]) -> Option<ObjectDigest> {
    (bytes != [0; 32]).then_some(ObjectDigest::from_bytes(bytes))
}

fn optional_revision(value: u64) -> Option<Revision> {
    (value != 0).then_some(Revision::new(value))
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], LifecycleModelError> {
    let (head, tail) = bytes
        .split_at_checked(N)
        .ok_or(LifecycleModelError::CorruptEncoding)?;
    *bytes = tail;
    head.try_into()
        .map_err(|_| LifecycleModelError::CorruptEncoding)
}
