//! Durable content-addressed publication of exact QEMU checkpoints.
//!
//! A complete production checkpoint is a version-four child-bearing root over
//! one canonical production manifest and bounded index pages:
//!
//! ```text
//! ExactCheckpointRootV4
//!   production-manifest -> ProductionExactClosureV4
//!   production-object-index-* -> ProductionCheckpointIndexV1
//!     object-<native-hash> -> opaque typed production object
//! ```
//!
//! Index pages expose every immutable child to generic closure walkers without
//! depending on one flat envelope's child ceiling. Native production hashes,
//! CAS identities, lengths, exact scenario/configuration, and aggregate bounds
//! are all authenticated before the root is published last.
//!
//! The compatibility single-node representation is one small root plus three
//! immutable children:
//!
//! ```text
//! ExactCheckpointRootV3
//!   snapshot-metadata -> DeviceStateV2(QemuVmSnapshotV1)
//!   scheduler-continuation -> DeviceStateV3(SingleSchedulerCheckpointV2)
//!   qemu-vmstate      -> DeviceStateV1(opaque qcow2 VMState bytes)
//! ```
//!
//! The metadata child binds the projected scheduler checkpoint. The scheduler
//! child retains every Apache-owned continuation needed for canonical resume.
//! The VMState child remains opaque and streams through [`BlobHandle`] without
//! a RAM-sized staging allocation. The generic root makes all three children
//! visible to storage closure walkers and is published only after durable
//! placement of every child. Legacy version-two roots remain readable for
//! migration and replay-oracle operations, but lack the scheduler child and
//! cannot resume a campaign attempt.

use std::collections::BTreeSet;
use std::fmt;
use std::io::{self, Read, Write};
use std::sync::Arc;

use crucible::{
    ContentHash, MAX_SINGLE_SCHEDULER_CHECKPOINT_BYTES, SingleSchedulerCheckpoint,
    SingleSchedulerCheckpointError,
};
use crucible_api::ProductionExactCheckpointClosure;
pub use crucible_campaign::ExactCheckpointId;
use crucible_cas::content_envelope::{ContentChild, ContentEnvelope, ContentEnvelopeError};
use crucible_cas::content_store::{
    BlobHandle, ContentId, ImmutableBlobBackend, ObjectKind, PutReceipt, StoreError,
};
use crucible_qemu::{
    MAX_QEMU_VM_SNAPSHOT_CANONICAL_BYTES, QemuReplayOracleCheck, QemuReplayOracleValidation,
    QemuVmRealizationError, QemuVmSnapshot, QemuVmSnapshotCodecError,
    validate_qemu_replay_oracle_promotion,
};
use thiserror::Error;

use crate::ExecutionCancellation;

const CHECKPOINT_CANCELLATION_READ_CHUNK_BYTES: usize = 1024 * 1024;

/// Canonical schema name of the child-bearing exact-checkpoint root.
pub const EXACT_CHECKPOINT_ROOT_SCHEMA: &str = "crucible.executor.exact-checkpoint-root";
/// Content-ID and envelope version of the complete production exact-checkpoint root.
pub const EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION: u32 = 4;
const LEGACY_EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION: u32 = 2;
const SINGLE_NODE_EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION: u32 = 3;
/// Content-ID version of canonical [`QemuVmSnapshot`] metadata bytes.
///
/// Version 1 of the `DeviceState` namespace is reserved for opaque QEMU
/// VMState. Version 2 keeps owner-decoded metadata type-separated while still
/// allowing generic closure walkers to treat it as an authenticated leaf.
pub const QEMU_VM_SNAPSHOT_METADATA_SCHEMA_VERSION: u32 = 2;
/// Content-ID version of opaque QEMU VMState bytes.
pub const QEMU_VMSTATE_SCHEMA_VERSION: u32 = 1;
/// Content-ID version of a complete canonical scheduler continuation.
pub const SCHEDULER_CONTINUATION_SCHEMA_VERSION: u32 = 3;

const SNAPSHOT_METADATA_ROLE: &str = "snapshot-metadata";
const QEMU_VMSTATE_ROLE: &str = "qemu-vmstate";
const SCHEDULER_CONTINUATION_ROLE: &str = "scheduler-continuation";
const LEGACY_ROOT_BODY_BYTES: usize = 80;
const ROOT_BODY_BYTES: usize = 88;
const MAX_ROOT_BYTES: u64 = 4 * 1024;

mod production;
pub use production::{
    LoadedProductionExactCheckpoint, PreparedProductionExactCheckpoint,
    ProductionExactCheckpointPublication,
};

/// A fully authenticated exact-checkpoint publication prepared without writes.
pub struct PreparedExactCheckpoint {
    root: ExactCheckpointId,
    root_source: BlobHandle,
    metadata_id: ContentId,
    metadata_source: BlobHandle,
    scheduler_id: Option<ContentId>,
    scheduler_source: Option<BlobHandle>,
    vmstate_id: ContentId,
    vmstate_source: BlobHandle,
    snapshot_identity: ContentHash,
    scenario: ContentHash,
    configuration: ContentHash,
}

/// Replay-validated replacement prepared from one exact raw checkpoint.
///
/// The source identity is retained separately from the replacement so an
/// operational owner can durably root both before publishing any replacement
/// bytes. Construction is possible only through
/// [`ExactCheckpointStore::prepare_replay_oracle_promotion`], which applies a
/// source-bound replay-oracle result to the authenticated source metadata.
pub struct PreparedReplayOraclePromotion {
    source: ExactCheckpointId,
    replacement: PreparedExactCheckpoint,
}

impl fmt::Debug for PreparedReplayOraclePromotion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedReplayOraclePromotion")
            .field("source", &self.source)
            .field("replacement", &self.replacement)
            .finish()
    }
}

impl PreparedReplayOraclePromotion {
    /// Returns the raw exact root compared by the replay oracle.
    #[must_use]
    pub const fn source(&self) -> ExactCheckpointId {
        self.source
    }

    /// Returns the replacement root containing matching oracle evidence.
    #[must_use]
    pub const fn promoted(&self) -> ExactCheckpointId {
        self.replacement.root()
    }

    pub(crate) const fn replacement(&self) -> &PreparedExactCheckpoint {
        &self.replacement
    }
}

impl fmt::Debug for PreparedExactCheckpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedExactCheckpoint")
            .field("root", &self.root)
            .field("metadata_id", &self.metadata_id)
            .field("scheduler_id", &self.scheduler_id)
            .field("vmstate_id", &self.vmstate_id)
            .field("snapshot_identity", &self.snapshot_identity)
            .field("scenario", &self.scenario)
            .field("configuration", &self.configuration)
            .field("vmstate_bytes", &self.vmstate_source.logical_length())
            .finish()
    }
}

impl PreparedExactCheckpoint {
    /// Returns the durable root identity that must be staged before publication.
    #[must_use]
    pub const fn root(&self) -> ExactCheckpointId {
        self.root
    }

    /// Returns the canonical snapshot-metadata child identity.
    #[must_use]
    pub const fn metadata_id(&self) -> ContentId {
        self.metadata_id
    }

    /// Returns the opaque VMState child identity.
    #[must_use]
    pub const fn vmstate_id(&self) -> ContentId {
        self.vmstate_id
    }

    /// Returns the aggregate QEMU snapshot identity bound by the root.
    #[must_use]
    pub const fn snapshot_identity(&self) -> ContentHash {
        self.snapshot_identity
    }

    /// Returns the exact semantic scenario materialized by the snapshot.
    #[must_use]
    pub const fn scenario(&self) -> ContentHash {
        self.scenario
    }

    /// Returns the exact modeled configuration materialized by the snapshot.
    #[must_use]
    pub const fn configuration(&self) -> ContentHash {
        self.configuration
    }

    /// Returns the declared opaque VMState byte length.
    #[must_use]
    pub fn vmstate_bytes(&self) -> u64 {
        self.vmstate_source.logical_length()
    }
}

/// Evidence that all exact-checkpoint objects received durable placement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExactCheckpointPublication {
    root: ExactCheckpointId,
    metadata: ContentId,
    scheduler: Option<ContentId>,
    vmstate: ContentId,
}

impl ExactCheckpointPublication {
    /// Returns the complete durable exact-checkpoint root.
    #[must_use]
    pub const fn root(self) -> ExactCheckpointId {
        self.root
    }

    /// Returns the durably placed snapshot metadata identity.
    #[must_use]
    pub const fn metadata(self) -> ContentId {
        self.metadata
    }

    /// Returns the complete scheduler-continuation identity, when retained.
    #[must_use]
    pub const fn scheduler(self) -> Option<ContentId> {
        self.scheduler
    }

    /// Returns the durably placed opaque VMState identity.
    #[must_use]
    pub const fn vmstate(self) -> ContentId {
        self.vmstate
    }
}

/// A loaded exact checkpoint whose metadata and root have been authenticated.
pub struct LoadedExactCheckpoint {
    root: ExactCheckpointId,
    snapshot: QemuVmSnapshot,
    scheduler_id: Option<ContentId>,
    scheduler: Option<SingleSchedulerCheckpoint>,
    vmstate_id: ContentId,
    vmstate: BlobHandle,
}

/// One live exact capture paired with its reopenable opaque VMState stream.
///
/// The QEMU session constructs this value only after pausing at an authenticated
/// scheduler boundary. The VMState source must remain reopenable and byte-stable
/// after the live process is reaped so the worker pool can hash and publish it
/// without retaining QEMU resource ownership.
pub struct CapturedExactCheckpoint {
    snapshot: QemuVmSnapshot,
    scheduler: Option<SingleSchedulerCheckpoint>,
    vmstate: BlobHandle,
}

/// Attempt-owned exact capture awaiting no-write immutable-store preparation.
///
/// The single-node variant preserves the compatibility v2/v3 path. Production
/// lifecycle execution returns the complete portable multi-node closure so the
/// worker publishes a version-four root through the same linear ledger phases.
pub enum CapturedAttemptCheckpoint {
    /// Compatibility QEMU snapshot, scheduler continuation, and VMState stream.
    SingleNode(Box<CapturedExactCheckpoint>),
    /// Complete production lifecycle manifest and immutable-object closure.
    Production(Box<ProductionExactCheckpointClosure>),
}

impl fmt::Debug for CapturedAttemptCheckpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SingleNode(capture) => formatter
                .debug_tuple("CapturedAttemptCheckpoint::SingleNode")
                .field(capture)
                .finish(),
            Self::Production(capture) => formatter
                .debug_struct("CapturedAttemptCheckpoint::Production")
                .field("identity", &capture.identity())
                .field("scenario", &capture.scenario())
                .field("configuration", &capture.configuration())
                .field("objects", &capture.objects().len())
                .finish(),
        }
    }
}

impl From<CapturedExactCheckpoint> for CapturedAttemptCheckpoint {
    fn from(capture: CapturedExactCheckpoint) -> Self {
        Self::SingleNode(Box::new(capture))
    }
}

impl From<ProductionExactCheckpointClosure> for CapturedAttemptCheckpoint {
    fn from(capture: ProductionExactCheckpointClosure) -> Self {
        Self::Production(Box::new(capture))
    }
}

impl CapturedAttemptCheckpoint {
    /// Returns the semantic scenario authenticated by this capture.
    #[must_use]
    pub fn scenario(&self) -> ContentHash {
        match self {
            Self::SingleNode(capture) => capture.snapshot().checkpoint().scenario_ref,
            Self::Production(capture) => capture.scenario(),
        }
    }

    /// Returns the modeled configuration authenticated at the capture boundary.
    #[must_use]
    pub fn configuration(&self) -> ContentHash {
        match self {
            Self::SingleNode(capture) => capture.snapshot().checkpoint().configuration,
            Self::Production(capture) => capture.configuration(),
        }
    }

    pub(crate) fn reopenable_copy(&self) -> Self {
        match self {
            Self::SingleNode(capture) => Self::SingleNode(Box::new(capture.reopenable_copy())),
            Self::Production(capture) => Self::Production(capture.clone()),
        }
    }
}

/// No-write-prepared exact capture ready for durable root staging.
#[derive(Debug)]
pub enum PreparedAttemptCheckpoint {
    /// Compatibility v2/v3 single-node root.
    SingleNode(Box<PreparedExactCheckpoint>),
    /// Complete v4 production root.
    Production(Box<PreparedProductionExactCheckpoint>),
}

impl PreparedAttemptCheckpoint {
    /// Returns the exact root that must be staged before immutable publication.
    #[must_use]
    pub const fn root(&self) -> ExactCheckpointId {
        match self {
            Self::SingleNode(checkpoint) => checkpoint.root(),
            Self::Production(checkpoint) => checkpoint.root(),
        }
    }

    /// Returns the semantic scenario authenticated by this preparation.
    #[must_use]
    pub fn scenario(&self) -> ContentHash {
        match self {
            Self::SingleNode(checkpoint) => checkpoint.scenario(),
            Self::Production(checkpoint) => checkpoint.scenario(),
        }
    }

    /// Returns the modeled configuration authenticated at the capture boundary.
    #[must_use]
    pub fn configuration(&self) -> ContentHash {
        match self {
            Self::SingleNode(checkpoint) => checkpoint.configuration(),
            Self::Production(checkpoint) => checkpoint.configuration(),
        }
    }

    pub(crate) fn native_retirement(
        &self,
    ) -> Option<crucible_api::ProductionExactCheckpointRetirement> {
        match self {
            Self::SingleNode(_) => None,
            Self::Production(checkpoint) => checkpoint.native_retirement(),
        }
    }
}

/// Exact checkpoint returned by an execution before immutable publication.
///
/// The internal prepared form is deliberately opaque. Only the pool-owned
/// handoff can mint proof that the exact root was durably staged while QEMU was
/// still live; an external execution model may return only a captured value.
#[derive(Debug)]
pub struct AttemptCheckpointResult(AttemptCheckpointResultState);

#[derive(Debug)]
pub(crate) enum AttemptCheckpointResultState {
    Captured(CapturedAttemptCheckpoint),
    Prepared(PreparedAttemptCheckpoint),
}

impl AttemptCheckpointResult {
    /// Returns the semantic scenario authenticated by this checkpoint result.
    #[must_use]
    pub fn scenario(&self) -> ContentHash {
        match &self.0 {
            AttemptCheckpointResultState::Captured(checkpoint) => checkpoint.scenario(),
            AttemptCheckpointResultState::Prepared(checkpoint) => checkpoint.scenario(),
        }
    }

    /// Returns the modeled configuration authenticated at the capture boundary.
    #[must_use]
    pub fn configuration(&self) -> ContentHash {
        match &self.0 {
            AttemptCheckpointResultState::Captured(checkpoint) => checkpoint.configuration(),
            AttemptCheckpointResultState::Prepared(checkpoint) => checkpoint.configuration(),
        }
    }

    pub(crate) const fn from_prepared(checkpoint: PreparedAttemptCheckpoint) -> Self {
        Self(AttemptCheckpointResultState::Prepared(checkpoint))
    }

    pub(crate) fn into_state(self) -> AttemptCheckpointResultState {
        self.0
    }
}

impl From<CapturedAttemptCheckpoint> for AttemptCheckpointResult {
    fn from(checkpoint: CapturedAttemptCheckpoint) -> Self {
        Self(AttemptCheckpointResultState::Captured(checkpoint))
    }
}

impl From<CapturedExactCheckpoint> for AttemptCheckpointResult {
    fn from(checkpoint: CapturedExactCheckpoint) -> Self {
        Self(AttemptCheckpointResultState::Captured(checkpoint.into()))
    }
}

impl From<ProductionExactCheckpointClosure> for AttemptCheckpointResult {
    fn from(checkpoint: ProductionExactCheckpointClosure) -> Self {
        Self(AttemptCheckpointResultState::Captured(checkpoint.into()))
    }
}

/// Durable publication receipt for either accepted exact-root generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptCheckpointPublication {
    /// Compatibility v2/v3 single-node publication.
    SingleNode(ExactCheckpointPublication),
    /// Complete v4 production publication.
    Production(ProductionExactCheckpointPublication),
}

impl AttemptCheckpointPublication {
    /// Returns the durably published exact root.
    #[must_use]
    pub const fn root(self) -> ExactCheckpointId {
        match self {
            Self::SingleNode(publication) => publication.root(),
            Self::Production(publication) => publication.root(),
        }
    }
}

impl fmt::Debug for CapturedExactCheckpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapturedExactCheckpoint")
            .field("snapshot", &self.snapshot.id())
            .field("configuration", &self.snapshot.checkpoint().configuration)
            .field("has_scheduler_continuation", &self.scheduler.is_some())
            .field("vmstate_bytes", &self.vmstate.logical_length())
            .finish()
    }
}

impl CapturedExactCheckpoint {
    /// Binds legacy QEMU metadata to opaque VMState without a scheduler continuation.
    ///
    /// The resulting version-two root remains loadable for migration and
    /// replay-oracle operations but cannot resume a campaign attempt. New live
    /// capture paths use [`Self::new_with_scheduler`].
    #[must_use]
    pub const fn new(snapshot: QemuVmSnapshot, vmstate: BlobHandle) -> Self {
        Self {
            snapshot,
            scheduler: None,
            vmstate,
        }
    }

    /// Binds a complete scheduler continuation to QEMU and Apache capture state.
    ///
    /// The caller must already have validated the continuation against the
    /// authenticated scenario. Store preparation additionally checks every
    /// projection available in the materialized checkpoint before publishing
    /// the version-three exact root.
    #[must_use]
    pub const fn new_with_scheduler(
        snapshot: QemuVmSnapshot,
        scheduler: SingleSchedulerCheckpoint,
        vmstate: BlobHandle,
    ) -> Self {
        Self {
            snapshot,
            scheduler: Some(scheduler),
            vmstate,
        }
    }

    /// Attaches the complete scheduler continuation captured at this boundary.
    ///
    /// Store preparation validates the scheduler's scenario, frontier,
    /// projected state, and event-log offset against the retained QEMU
    /// checkpoint before any immutable write.
    #[must_use]
    pub fn with_scheduler(mut self, scheduler: SingleSchedulerCheckpoint) -> Self {
        self.scheduler = Some(scheduler);
        self
    }

    /// Returns the captured scheduler and Apache continuation metadata.
    #[must_use]
    pub const fn snapshot(&self) -> &QemuVmSnapshot {
        &self.snapshot
    }

    /// Returns the complete modeled scheduler continuation, when retained.
    #[must_use]
    pub const fn scheduler(&self) -> Option<&SingleSchedulerCheckpoint> {
        self.scheduler.as_ref()
    }

    /// Returns the declared opaque VMState byte length.
    #[must_use]
    pub fn vmstate_bytes(&self) -> u64 {
        self.vmstate.logical_length()
    }

    #[cfg(test)]
    pub(crate) fn vmstate_source(&self) -> BlobHandle {
        self.vmstate.clone()
    }

    pub(crate) fn reopenable_copy(&self) -> Self {
        Self {
            snapshot: self.snapshot.clone(),
            scheduler: self.scheduler.clone(),
            vmstate: self.vmstate.clone(),
        }
    }

    /// Consumes the capture into its metadata and reopenable VMState source.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        QemuVmSnapshot,
        Option<SingleSchedulerCheckpoint>,
        BlobHandle,
    ) {
        (self.snapshot, self.scheduler, self.vmstate)
    }
}

impl LoadedExactCheckpoint {
    /// Returns the complete exact-checkpoint root.
    #[must_use]
    pub const fn root(&self) -> ExactCheckpointId {
        self.root
    }

    /// Returns the authenticated scheduler and Apache continuation metadata.
    #[must_use]
    pub const fn snapshot(&self) -> &QemuVmSnapshot {
        &self.snapshot
    }

    /// Returns the complete scheduler continuation, when this is a v3 root.
    #[must_use]
    pub const fn scheduler(&self) -> Option<&SingleSchedulerCheckpoint> {
        self.scheduler.as_ref()
    }

    /// Returns the scheduler-continuation child identity, when present.
    #[must_use]
    pub const fn scheduler_id(&self) -> Option<ContentId> {
        self.scheduler_id
    }

    /// Returns the opaque VMState child identity.
    #[must_use]
    pub const fn vmstate_id(&self) -> ContentId {
        self.vmstate_id
    }

    /// Returns the exact declared VMState length.
    #[must_use]
    pub fn vmstate_bytes(&self) -> u64 {
        self.vmstate.logical_length()
    }

    /// Produces a no-write capture whose metadata contains a bound oracle match.
    ///
    /// The opaque VMState child is reused by content identity. The supplied
    /// replay result must have been minted for this exact pre-promotion
    /// snapshot; a result for different metadata or VMState cannot be applied.
    /// The returned capture can enter the ordinary no-write prepare and
    /// children-before-root publication phases.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when the replay result belongs to a
    /// different snapshot or did not prove a fat/thin runtime match.
    pub fn promote_replay_oracle_match(
        &self,
        check: QemuReplayOracleCheck,
    ) -> Result<CapturedExactCheckpoint, QemuVmRealizationError> {
        let snapshot = check.promote(&self.snapshot)?;
        Ok(match &self.scheduler {
            Some(scheduler) => CapturedExactCheckpoint::new_with_scheduler(
                snapshot,
                scheduler.clone(),
                self.vmstate.clone(),
            ),
            None => CapturedExactCheckpoint::new(snapshot, self.vmstate.clone()),
        })
    }

    /// Copies and authenticates the complete opaque VMState stream.
    ///
    /// A restore path must copy into staging storage and publish or execute the
    /// destination only after this method succeeds.
    ///
    /// # Errors
    ///
    /// Returns a store error if the stream cannot be reopened, has the wrong
    /// length or digest, or the destination write fails.
    pub fn copy_vmstate_to(
        &self,
        destination: &mut dyn Write,
    ) -> Result<u64, ExactCheckpointStoreError> {
        self.vmstate.copy_to(destination).map_err(Into::into)
    }
}

/// Durable immutable store for exact QEMU checkpoint closures.
pub struct ExactCheckpointStore {
    backend: Arc<dyn ImmutableBlobBackend>,
    maximum_checkpoint_bytes: u64,
}

impl ExactCheckpointStore {
    /// Admits a durable streaming immutable backend and checkpoint byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`ExactCheckpointStoreError::UnsupportedBackend`] unless the
    /// backend is durable and supports streaming reads, streaming puts, and
    /// conditional creation. A zero checkpoint ceiling is rejected.
    pub fn new(
        backend: Arc<dyn ImmutableBlobBackend>,
        maximum_checkpoint_bytes: u64,
    ) -> Result<Self, ExactCheckpointStoreError> {
        if maximum_checkpoint_bytes == 0 {
            return Err(ExactCheckpointStoreError::InvalidLimit);
        }
        let capabilities = backend.capabilities();
        for (available, capability) in [
            (capabilities.durable, "durable"),
            (capabilities.streaming_read, "streaming-read"),
            (capabilities.streaming_put, "streaming-put"),
            (capabilities.conditional_create, "conditional-create"),
        ] {
            if !available {
                return Err(ExactCheckpointStoreError::UnsupportedBackend { capability });
            }
        }
        Ok(Self {
            backend,
            maximum_checkpoint_bytes,
        })
    }

    /// Returns the configured aggregate per-checkpoint byte ceiling.
    #[must_use]
    pub const fn maximum_checkpoint_bytes(&self) -> u64 {
        self.maximum_checkpoint_bytes
    }

    /// Returns the legacy single-node VMState byte ceiling.
    ///
    /// For legacy v2/v3 roots this is the complete large-artifact ceiling. New
    /// production v4 roots apply the same configured value to their canonical
    /// manifest plus deduplicated production-object bytes.
    #[must_use]
    pub const fn maximum_vmstate_bytes(&self) -> u64 {
        self.maximum_checkpoint_bytes
    }

    /// Authenticates and prepares one legacy exact checkpoint without writes.
    ///
    /// The VMState source is streamed once to derive its content identity. It
    /// must remain reopenable and byte-stable until publication completes. The
    /// resulting version-two root has no complete scheduler continuation and
    /// cannot resume a campaign attempt. New live captures use
    /// [`Self::prepare_capture`] with a scheduler continuation.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or oversized VMState source, a malformed
    /// QEMU snapshot, a source read failure, or an internal envelope-bound
    /// violation. No immutable object is written on error or success.
    pub fn prepare(
        &self,
        snapshot: &QemuVmSnapshot,
        vmstate: BlobHandle,
    ) -> Result<PreparedExactCheckpoint, ExactCheckpointStoreError> {
        self.prepare_parts(snapshot, None, vmstate)
    }

    fn prepare_parts(
        &self,
        snapshot: &QemuVmSnapshot,
        scheduler: Option<&SingleSchedulerCheckpoint>,
        vmstate: BlobHandle,
    ) -> Result<PreparedExactCheckpoint, ExactCheckpointStoreError> {
        validate_vmstate_length(vmstate.logical_length(), self.maximum_checkpoint_bytes)?;

        let metadata_bytes = snapshot.to_canonical_bytes()?;
        if metadata_bytes.len() as u64 > MAX_QEMU_VM_SNAPSHOT_CANONICAL_BYTES {
            return Err(ExactCheckpointStoreError::ArtifactLimit {
                artifact: "snapshot-metadata",
                length: metadata_bytes.len() as u64,
                maximum: MAX_QEMU_VM_SNAPSHOT_CANONICAL_BYTES,
            });
        }
        let metadata_id = ContentId::for_bytes(
            ObjectKind::DeviceState,
            QEMU_VM_SNAPSHOT_METADATA_SCHEMA_VERSION,
            &metadata_bytes,
        );
        let vmstate_id = ContentId::for_source(
            ObjectKind::DeviceState,
            QEMU_VMSTATE_SCHEMA_VERSION,
            &vmstate,
        )
        .map_err(map_checkpoint_store_error)?;
        let (scheduler_id, scheduler_source, scheduler_bytes) = match scheduler {
            Some(scheduler) => {
                validate_scheduler_checkpoint_basis(snapshot.checkpoint(), scheduler)?;
                let bytes = scheduler.canonical_bytes()?;
                let length = bytes.len() as u64;
                let maximum = MAX_SINGLE_SCHEDULER_CHECKPOINT_BYTES as u64;
                if length > maximum {
                    return Err(ExactCheckpointStoreError::ArtifactLimit {
                        artifact: SCHEDULER_CONTINUATION_ROLE,
                        length,
                        maximum,
                    });
                }
                let id = ContentId::for_bytes(
                    ObjectKind::DeviceState,
                    SCHEDULER_CONTINUATION_SCHEMA_VERSION,
                    &bytes,
                );
                (Some(id), Some(BlobHandle::from_bytes(bytes)), Some(length))
            }
            None => (None, None, None),
        };

        let snapshot_identity = snapshot.id();
        let scenario = snapshot.checkpoint().scenario_ref;
        let configuration = snapshot.checkpoint().configuration;
        let body = encode_root_body(
            snapshot_identity,
            configuration,
            metadata_bytes.len() as u64,
            scheduler_bytes,
            vmstate.logical_length(),
        );
        let mut children = BTreeSet::from([
            ContentChild::new(SNAPSHOT_METADATA_ROLE, metadata_id)?,
            ContentChild::new(QEMU_VMSTATE_ROLE, vmstate_id)?,
        ]);
        if let Some(scheduler_id) = scheduler_id {
            children.insert(ContentChild::new(
                SCHEDULER_CONTINUATION_ROLE,
                scheduler_id,
            )?);
        }
        let schema_version = if scheduler_id.is_some() {
            SINGLE_NODE_EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION
        } else {
            LEGACY_EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION
        };
        let root_envelope =
            ContentEnvelope::new(EXACT_CHECKPOINT_ROOT_SCHEMA, schema_version, children, body)?;
        let root_bytes = root_envelope.canonical_bytes();
        let root = ExactCheckpointId::try_from(root_envelope.content_id(ObjectKind::ExactManifest))
            .map_err(|_| invalid_root("root identity"))?;

        Ok(PreparedExactCheckpoint {
            root,
            root_source: BlobHandle::from_bytes(root_bytes),
            metadata_id,
            metadata_source: BlobHandle::from_bytes(metadata_bytes),
            scheduler_id,
            scheduler_source,
            vmstate_id,
            vmstate_source: vmstate,
            snapshot_identity,
            scenario,
            configuration,
        })
    }

    /// Authenticates and prepares one completed live capture without writes.
    ///
    /// # Errors
    ///
    /// Returns the same bounded metadata, source, envelope, or store errors as
    /// [`Self::prepare`].
    pub fn prepare_capture(
        &self,
        capture: CapturedExactCheckpoint,
    ) -> Result<PreparedExactCheckpoint, ExactCheckpointStoreError> {
        let (snapshot, scheduler, vmstate) = capture.into_parts();
        self.prepare_parts(&snapshot, scheduler.as_ref(), vmstate)
    }

    /// Authenticates either accepted attempt capture without immutable writes.
    ///
    /// # Errors
    ///
    /// Returns the corresponding single-node or production preparation error.
    pub fn prepare_attempt_checkpoint(
        &self,
        capture: CapturedAttemptCheckpoint,
    ) -> Result<PreparedAttemptCheckpoint, ExactCheckpointStoreError> {
        match capture {
            CapturedAttemptCheckpoint::SingleNode(capture) => self
                .prepare_capture(*capture)
                .map(Box::new)
                .map(PreparedAttemptCheckpoint::SingleNode),
            CapturedAttemptCheckpoint::Production(capture) => self
                .prepare_production_closure(*capture)
                .map(Box::new)
                .map(PreparedAttemptCheckpoint::Production),
        }
    }

    /// Authenticates and prepares a capture under one execution cancellation signal.
    ///
    /// Complete large-object reads observe `cancellation` between at-most-one-
    /// MiB chunks. The prepared streams retain the same signal so publication
    /// cannot continue silently after cancellation wins.
    ///
    /// # Errors
    ///
    /// Returns [`ExactCheckpointStoreError::Canceled`] when cancellation wins,
    /// or the corresponding single-node or production preparation error.
    pub(crate) fn prepare_attempt_checkpoint_with_cancellation(
        &self,
        capture: CapturedAttemptCheckpoint,
        cancellation: &ExecutionCancellation,
    ) -> Result<PreparedAttemptCheckpoint, ExactCheckpointStoreError> {
        if cancellation.is_canceled() {
            return Err(ExactCheckpointStoreError::Canceled);
        }
        match capture {
            CapturedAttemptCheckpoint::SingleNode(capture) => {
                let (snapshot, scheduler, vmstate) = capture.into_parts();
                let vmstate = cancellation_blob_handle(vmstate, cancellation.clone());
                let mut prepared = self.prepare_parts(&snapshot, scheduler.as_ref(), vmstate)?;
                prepared.root_source =
                    cancellation_blob_handle(prepared.root_source, cancellation.clone());
                prepared.metadata_source =
                    cancellation_blob_handle(prepared.metadata_source, cancellation.clone());
                prepared.scheduler_source = prepared
                    .scheduler_source
                    .map(|source| cancellation_blob_handle(source, cancellation.clone()));
                Ok(PreparedAttemptCheckpoint::SingleNode(Box::new(prepared)))
            }
            CapturedAttemptCheckpoint::Production(capture) => self
                .prepare_production_closure_with_cancellation(*capture, cancellation)
                .map(Box::new)
                .map(PreparedAttemptCheckpoint::Production),
        }
    }

    /// Publishes either prepared attempt checkpoint through root-last ordering.
    ///
    /// # Errors
    ///
    /// Returns the corresponding single-node or production publication error.
    pub fn publish_attempt_checkpoint(
        &self,
        prepared: &PreparedAttemptCheckpoint,
    ) -> Result<AttemptCheckpointPublication, ExactCheckpointStoreError> {
        match prepared {
            PreparedAttemptCheckpoint::SingleNode(prepared) => self
                .publish(prepared)
                .map(AttemptCheckpointPublication::SingleNode),
            PreparedAttemptCheckpoint::Production(prepared) => self
                .publish_production_closure(prepared)
                .map(AttemptCheckpointPublication::Production),
        }
    }

    /// Prepares a source-bound replay-oracle promotion without store writes.
    ///
    /// The source root and metadata are authenticated first. The supplied
    /// comparison capability must name that exact metadata identity and prove
    /// a fat/thin runtime match. The returned replacement reuses the source's
    /// authenticated VMState stream by content identity.
    ///
    /// # Errors
    ///
    /// Returns a checkpoint-store error when the source closure is unavailable
    /// or invalid, and a realization error when `check` belongs to another
    /// source or does not prove a match.
    pub fn prepare_replay_oracle_promotion(
        &self,
        source: ExactCheckpointId,
        check: QemuReplayOracleCheck,
    ) -> Result<PreparedReplayOraclePromotion, PrepareReplayOraclePromotionError> {
        let loaded = self.load(source)?;
        if loaded.snapshot().replay_oracle_validation() != QemuReplayOracleValidation::NotRun {
            return Err(ExactCheckpointStoreError::InvalidRoot {
                reason: "replay-oracle promotion source is not raw",
            }
            .into());
        }
        let capture = loaded.promote_replay_oracle_match(check)?;
        let replacement = self.prepare_capture(capture)?;
        Ok(PreparedReplayOraclePromotion {
            source,
            replacement,
        })
    }

    /// Authenticates a complete durable raw-to-matched promotion pair.
    ///
    /// Both roots and metadata are loaded by exact content identity. The pair
    /// must share one opaque VMState child, and the promoted metadata may differ
    /// from the raw source only by matching replay-oracle evidence.
    ///
    /// # Errors
    ///
    /// Returns an error when either closure is unavailable or invalid, the
    /// roots alias, VMState differs, or metadata is not an exact promotion.
    pub fn authenticate_replay_oracle_promotion(
        &self,
        source: ExactCheckpointId,
        promoted: ExactCheckpointId,
    ) -> Result<(), PrepareReplayOraclePromotionError> {
        if source == promoted {
            return Err(ExactCheckpointStoreError::InvalidRoot {
                reason: "replay-oracle promotion aliases its source",
            }
            .into());
        }
        let source = self.load(source)?;
        let promoted = self.load(promoted)?;
        if source.vmstate_id() != promoted.vmstate_id()
            || source.scheduler_id() != promoted.scheduler_id()
        {
            return Err(ExactCheckpointStoreError::InvalidRoot {
                reason: "replay-oracle promotion changed continuation identity",
            }
            .into());
        }
        validate_qemu_replay_oracle_promotion(source.snapshot(), promoted.snapshot())?;
        Ok(())
    }

    /// Publishes prepared children and then their durable root.
    ///
    /// The caller must first stage [`PreparedExactCheckpoint::root`] in its
    /// durable operational ledger. A failure can leave unreachable immutable
    /// children, but never publishes the root before all children have durable
    /// placement. Retrying the same prepared value is idempotent.
    ///
    /// # Errors
    ///
    /// Returns a store error, an invalid-placement error, or a local byte-limit
    /// error. A successful result proves at least one durable placement for all
    /// prepared logical objects.
    pub fn publish(
        &self,
        prepared: &PreparedExactCheckpoint,
    ) -> Result<ExactCheckpointPublication, ExactCheckpointStoreError> {
        validate_vmstate_length(
            prepared.vmstate_source.logical_length(),
            self.maximum_checkpoint_bytes,
        )?;
        require_durable_receipt(
            self.backend
                .put_if_absent(prepared.metadata_id, &prepared.metadata_source)
                .map_err(map_checkpoint_store_error)?,
            prepared.metadata_id,
            prepared.metadata_source.logical_length(),
        )?;
        if let (Some(scheduler_id), Some(scheduler_source)) =
            (prepared.scheduler_id, prepared.scheduler_source.as_ref())
        {
            require_durable_receipt(
                self.backend
                    .put_if_absent(scheduler_id, scheduler_source)
                    .map_err(map_checkpoint_store_error)?,
                scheduler_id,
                scheduler_source.logical_length(),
            )?;
        }
        require_durable_receipt(
            self.backend
                .put_if_absent(prepared.vmstate_id, &prepared.vmstate_source)
                .map_err(map_checkpoint_store_error)?,
            prepared.vmstate_id,
            prepared.vmstate_source.logical_length(),
        )?;
        require_durable_receipt(
            self.backend
                .put_if_absent(prepared.root.content_id(), &prepared.root_source)
                .map_err(map_checkpoint_store_error)?,
            prepared.root.content_id(),
            prepared.root_source.logical_length(),
        )?;

        Ok(ExactCheckpointPublication {
            root: prepared.root,
            metadata: prepared.metadata_id,
            scheduler: prepared.scheduler_id,
            vmstate: prepared.vmstate_id,
        })
    }

    /// Loads and validates one complete exact-checkpoint root.
    ///
    /// Root and metadata bytes are fully authenticated during this call. The
    /// returned VMState handle is length-bounded; the restore path must consume
    /// it through [`LoadedExactCheckpoint::copy_vmstate_to`] so deferred digest
    /// authentication completes before QEMU execution.
    ///
    /// # Errors
    ///
    /// Returns an error for absence, corrupt bytes, an incompatible envelope,
    /// missing or extraneous children, metadata semantic mismatch, or a local
    /// byte-limit violation.
    pub fn load(
        &self,
        root: ExactCheckpointId,
    ) -> Result<LoadedExactCheckpoint, ExactCheckpointStoreError> {
        let root_handle = self.backend.read(root.content_id(), None)?;
        if root_handle.logical_length() > MAX_ROOT_BYTES {
            return Err(ExactCheckpointStoreError::ArtifactLimit {
                artifact: "root",
                length: root_handle.logical_length(),
                maximum: MAX_ROOT_BYTES,
            });
        }
        let root_bytes = root_handle.read_all(MAX_ROOT_BYTES)?;
        let envelope = ContentEnvelope::from_canonical_bytes(&root_bytes)?;
        if envelope.schema_name() != EXACT_CHECKPOINT_ROOT_SCHEMA
            || !matches!(
                envelope.schema_version(),
                LEGACY_EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION
                    | SINGLE_NODE_EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION
            )
        {
            return Err(invalid_root("incompatible root schema"));
        }
        if envelope.content_id(ObjectKind::ExactManifest) != root.content_id() {
            return Err(invalid_root("root content identity mismatch"));
        }
        let (metadata_id, scheduler_id, vmstate_id) = decode_children(&envelope)?;
        let body = decode_root_body(envelope.schema_version(), envelope.body())?;
        if scheduler_id.is_some() != body.scheduler_bytes.is_some() {
            return Err(invalid_root("scheduler child/body presence mismatch"));
        }

        let metadata = self.backend.read(metadata_id, None)?;
        if metadata.logical_length() != body.metadata_bytes
            || metadata.logical_length() > MAX_QEMU_VM_SNAPSHOT_CANONICAL_BYTES
        {
            return Err(invalid_root("snapshot metadata length mismatch"));
        }
        let metadata_bytes = metadata.read_all(MAX_QEMU_VM_SNAPSHOT_CANONICAL_BYTES)?;
        let snapshot = QemuVmSnapshot::from_canonical_bytes(&metadata_bytes)?;
        if snapshot.id() != body.snapshot_identity
            || snapshot.checkpoint().configuration != body.configuration
        {
            return Err(invalid_root("snapshot semantic basis mismatch"));
        }

        let scheduler = match (scheduler_id, body.scheduler_bytes) {
            (Some(scheduler_id), Some(expected_bytes)) => {
                let source = self.backend.read(scheduler_id, None)?;
                let maximum = MAX_SINGLE_SCHEDULER_CHECKPOINT_BYTES as u64;
                if source.logical_length() != expected_bytes || source.logical_length() > maximum {
                    return Err(invalid_root("scheduler continuation length mismatch"));
                }
                let bytes = source.read_all(maximum)?;
                let scheduler = SingleSchedulerCheckpoint::from_canonical_bytes(&bytes)?;
                validate_scheduler_checkpoint_basis(snapshot.checkpoint(), &scheduler)?;
                Some(scheduler)
            }
            (None, None) => None,
            _ => return Err(invalid_root("scheduler continuation is incomplete")),
        };

        let vmstate = self.backend.read(vmstate_id, None)?;
        validate_vmstate_length(vmstate.logical_length(), self.maximum_checkpoint_bytes)?;
        if vmstate.logical_length() != body.vmstate_bytes {
            return Err(invalid_root("VMState length mismatch"));
        }

        Ok(LoadedExactCheckpoint {
            root,
            snapshot,
            scheduler_id,
            scheduler,
            vmstate_id,
            vmstate,
        })
    }
}

/// Failure while preparing a source-bound replay-oracle replacement.
#[derive(Debug, Error)]
pub enum PrepareReplayOraclePromotionError {
    /// The immutable source or replacement could not be authenticated/prepared.
    #[error(transparent)]
    Checkpoint(#[from] ExactCheckpointStoreError),
    /// The comparison did not prove a match for the exact source metadata.
    #[error(transparent)]
    ReplayOracle(#[from] QemuVmRealizationError),
}

/// Failure while preparing, publishing, or loading an exact QEMU checkpoint.
#[derive(Debug, Error)]
pub enum ExactCheckpointStoreError {
    /// The owning execution canceled checkpoint preparation or publication.
    #[error("exact-checkpoint operation was canceled")]
    Canceled,
    /// The configured per-checkpoint byte ceiling was zero.
    #[error("exact-checkpoint byte limit must be nonzero")]
    InvalidLimit,
    /// The immutable backend lacks a required safety capability.
    #[error("exact-checkpoint store lacks required backend capability {capability}")]
    UnsupportedBackend {
        /// Missing capability name.
        capability: &'static str,
    },
    /// One artifact was empty or exceeded a local hard byte limit.
    #[error(
        "exact-checkpoint {artifact} has {length} bytes outside the admitted maximum {maximum}"
    )]
    ArtifactLimit {
        /// Logical artifact role.
        artifact: &'static str,
        /// Declared or encoded bytes.
        length: u64,
        /// Admitted maximum bytes.
        maximum: u64,
    },
    /// Root structure or semantic bindings were inconsistent.
    #[error("exact-checkpoint root is invalid: {reason}")]
    InvalidRoot {
        /// Stable rejection reason.
        reason: &'static str,
    },
    /// A backend claimed success without exact durable placement evidence.
    #[error("exact-checkpoint placement receipt for {id} is not exact and durable")]
    InvalidReceipt {
        /// Logical object whose receipt was invalid.
        id: ContentId,
    },
    /// The underlying immutable store failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The generic root envelope was malformed or over limit.
    #[error(transparent)]
    Envelope(#[from] ContentEnvelopeError),
    /// QEMU snapshot metadata failed canonical authentication.
    #[error(transparent)]
    Snapshot(#[from] QemuVmSnapshotCodecError),
    /// The complete modeled scheduler continuation failed authentication.
    #[error(transparent)]
    Scheduler(#[from] SingleSchedulerCheckpointError),
    /// The complete production continuation failed scenario-aware authentication.
    #[error(transparent)]
    Production(#[from] crucible_api::LifecycleApiError),
    /// Attempt-local native checkpoint retirement failed.
    #[error(transparent)]
    NativeRetirement(#[from] crucible_api::ProductionExactCheckpointRetirementError),
}

fn map_checkpoint_store_error(error: StoreError) -> ExactCheckpointStoreError {
    match error {
        StoreError::StreamIo { source, .. } if is_checkpoint_cancellation_io(&source) => {
            ExactCheckpointStoreError::Canceled
        }
        error => ExactCheckpointStoreError::Store(error),
    }
}

fn cancellation_blob_handle(source: BlobHandle, cancellation: ExecutionCancellation) -> BlobHandle {
    BlobHandle::new(Arc::new(CancellationBlobSource {
        source,
        cancellation,
    }))
}

struct CancellationBlobSource {
    source: BlobHandle,
    cancellation: ExecutionCancellation,
}

impl crucible_cas::content_store::BlobSource for CancellationBlobSource {
    fn logical_length(&self) -> u64 {
        self.source.logical_length()
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        if self.cancellation.is_canceled() {
            return Err(StoreError::StreamIo {
                operation: "open-canceled-exact-checkpoint-source",
                source: checkpoint_cancellation_io(),
            });
        }
        Ok(Box::new(CancellationReader {
            source: self.source.open()?,
            cancellation: self.cancellation.clone(),
        }))
    }
}

struct CancellationReader {
    source: Box<dyn Read + Send>,
    cancellation: ExecutionCancellation,
}

impl Read for CancellationReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.cancellation.is_canceled() {
            return Err(io::Error::other(CheckpointCancellationIo));
        }
        let limit = buffer.len().min(CHECKPOINT_CANCELLATION_READ_CHUNK_BYTES);
        let read = self.source.read(&mut buffer[..limit])?;
        if self.cancellation.is_canceled() {
            return Err(io::Error::other(CheckpointCancellationIo));
        }
        Ok(read)
    }
}

#[derive(Debug)]
struct CheckpointCancellationIo;

impl fmt::Display for CheckpointCancellationIo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("checkpoint canceled")
    }
}

impl std::error::Error for CheckpointCancellationIo {}

fn checkpoint_cancellation_io() -> io::Error {
    io::Error::other(CheckpointCancellationIo)
}

fn is_checkpoint_cancellation_io(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|source| source.is::<CheckpointCancellationIo>())
}

impl ExactCheckpointStoreError {
    /// Returns whether retrying the same retained phase may repair the failure.
    ///
    /// Only explicit backend availability and I/O failures are retryable. A
    /// malformed capture, corrupt content, quota rejection, poisoned owner, or
    /// incompatible capability is stable and must be canceled or quarantined
    /// rather than retried forever.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Store(
                StoreError::Unavailable | StoreError::Io { .. } | StoreError::StreamIo { .. }
            )
        ) || matches!(self, Self::NativeRetirement(error) if error.is_retryable())
    }
}

struct RootBody {
    snapshot_identity: ContentHash,
    configuration: ContentHash,
    metadata_bytes: u64,
    scheduler_bytes: Option<u64>,
    vmstate_bytes: u64,
}

fn encode_root_body(
    snapshot_identity: ContentHash,
    configuration: ContentHash,
    metadata_bytes: u64,
    scheduler_bytes: Option<u64>,
    vmstate_bytes: u64,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(if scheduler_bytes.is_some() {
        ROOT_BODY_BYTES
    } else {
        LEGACY_ROOT_BODY_BYTES
    });
    body.extend_from_slice(&snapshot_identity.bytes);
    body.extend_from_slice(&configuration.bytes);
    body.extend_from_slice(&metadata_bytes.to_be_bytes());
    if let Some(scheduler_bytes) = scheduler_bytes {
        body.extend_from_slice(&scheduler_bytes.to_be_bytes());
    }
    body.extend_from_slice(&vmstate_bytes.to_be_bytes());
    body
}

fn decode_root_body(
    schema_version: u32,
    bytes: &[u8],
) -> Result<RootBody, ExactCheckpointStoreError> {
    let expected = match schema_version {
        LEGACY_EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION => LEGACY_ROOT_BODY_BYTES,
        SINGLE_NODE_EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION => ROOT_BODY_BYTES,
        _ => return Err(invalid_root("root schema version is unsupported")),
    };
    if bytes.len() != expected {
        return Err(invalid_root("root body length mismatch"));
    }
    let mut snapshot_identity = [0_u8; 32];
    snapshot_identity.copy_from_slice(&bytes[..32]);
    let mut configuration = [0_u8; 32];
    configuration.copy_from_slice(&bytes[32..64]);
    let metadata_bytes = u64::from_be_bytes(
        bytes[64..72]
            .try_into()
            .map_err(|_| invalid_root("metadata length encoding is invalid"))?,
    );
    let (scheduler_bytes, vmstate_offset) =
        if schema_version == SINGLE_NODE_EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION {
            (
                Some(u64::from_be_bytes(bytes[72..80].try_into().map_err(
                    |_| invalid_root("scheduler length encoding is invalid"),
                )?)),
                80,
            )
        } else {
            (None, 72)
        };
    let vmstate_bytes = u64::from_be_bytes(
        bytes[vmstate_offset..vmstate_offset + 8]
            .try_into()
            .map_err(|_| invalid_root("VMState length encoding is invalid"))?,
    );
    Ok(RootBody {
        snapshot_identity: ContentHash {
            bytes: snapshot_identity,
        },
        configuration: ContentHash {
            bytes: configuration,
        },
        metadata_bytes,
        scheduler_bytes,
        vmstate_bytes,
    })
}

fn decode_children(
    envelope: &ContentEnvelope,
) -> Result<(ContentId, Option<ContentId>, ContentId), ExactCheckpointStoreError> {
    let expected = if envelope.schema_version() == SINGLE_NODE_EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION
    {
        3
    } else {
        2
    };
    if envelope.children().len() != expected {
        return Err(invalid_root("root contains the wrong child count"));
    }
    let mut metadata = None;
    let mut scheduler = None;
    let mut vmstate = None;
    for child in envelope.children() {
        match child.role() {
            SNAPSHOT_METADATA_ROLE => metadata = Some(child.id()),
            SCHEDULER_CONTINUATION_ROLE => scheduler = Some(child.id()),
            QEMU_VMSTATE_ROLE => vmstate = Some(child.id()),
            _ => return Err(invalid_root("root contains an unknown child role")),
        }
    }
    let metadata = metadata.ok_or_else(|| invalid_root("root has no snapshot metadata child"))?;
    let vmstate = vmstate.ok_or_else(|| invalid_root("root has no VMState child"))?;
    require_id_kind(
        metadata,
        ObjectKind::DeviceState,
        QEMU_VM_SNAPSHOT_METADATA_SCHEMA_VERSION,
        "snapshot metadata child",
    )?;
    require_id_kind(
        vmstate,
        ObjectKind::DeviceState,
        QEMU_VMSTATE_SCHEMA_VERSION,
        "VMState child",
    )?;
    if let Some(scheduler) = scheduler {
        require_id_kind(
            scheduler,
            ObjectKind::DeviceState,
            SCHEDULER_CONTINUATION_SCHEMA_VERSION,
            "scheduler continuation child",
        )?;
    }
    Ok((metadata, scheduler, vmstate))
}

fn require_id_kind(
    id: ContentId,
    kind: ObjectKind,
    version: u32,
    role: &'static str,
) -> Result<(), ExactCheckpointStoreError> {
    if id.kind() != kind || id.schema_version() != version {
        return Err(invalid_root(role));
    }
    Ok(())
}

pub(crate) fn validate_scheduler_checkpoint_basis(
    checkpoint: &crucible::Checkpoint,
    scheduler: &SingleSchedulerCheckpoint,
) -> Result<(), ExactCheckpointStoreError> {
    let Some(materialized) = checkpoint.state.as_ref() else {
        return Err(invalid_root(
            "scheduler continuation requires materialized checkpoint state",
        ));
    };
    let scheduler_event_segments = scheduler
        .event_log_segment_dependencies()
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if scheduler.scenario() != checkpoint.scenario_ref
        || scheduler.frontier() != checkpoint.virtual_time
        || scheduler.scheduler_state()? != materialized.scheduler
        || scheduler.future_decision_rng_state() != &materialized.decision_rng
        || scheduler.event_log_offset() != materialized.event_log
        || scheduler_event_segments.len() != materialized.event_log_segments.len()
        || !scheduler_event_segments
            .iter()
            .copied()
            .eq(materialized.event_log_segments.iter().copied())
    {
        return Err(invalid_root(
            "scheduler continuation does not match checkpoint projections",
        ));
    }
    Ok(())
}

fn validate_vmstate_length(length: u64, maximum: u64) -> Result<(), ExactCheckpointStoreError> {
    if length == 0 || length > maximum {
        return Err(ExactCheckpointStoreError::ArtifactLimit {
            artifact: "qemu-vmstate",
            length,
            maximum,
        });
    }
    Ok(())
}

fn require_durable_receipt(
    receipt: PutReceipt,
    expected: ContentId,
    expected_length: u64,
) -> Result<(), ExactCheckpointStoreError> {
    let exact_durable = receipt.id == expected
        && receipt.is_durable()
        && receipt
            .placements
            .iter()
            .filter(|placement| placement.durable)
            .all(|placement| placement.logical_length == expected_length);
    if !exact_durable {
        return Err(ExactCheckpointStoreError::InvalidReceipt { id: expected });
    }
    Ok(())
}

const fn invalid_root(reason: &'static str) -> ExactCheckpointStoreError {
    ExactCheckpointStoreError::InvalidRoot { reason }
}

#[cfg(test)]
#[path = "exact_checkpoint_store/tests.rs"]
mod tests;
