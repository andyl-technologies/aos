//! Durable content-addressed publication of exact QEMU checkpoints.
//!
//! An exact checkpoint is one small child-bearing root plus two immutable
//! children:
//!
//! ```text
//! ExactCheckpointRootV2
//!   snapshot-metadata -> DeviceStateV2(QemuVmSnapshotV1)
//!   qemu-vmstate      -> DeviceStateV1(opaque qcow2 VMState bytes)
//! ```
//!
//! The metadata child binds the scheduler checkpoint and every Apache-owned
//! continuation. The VMState child remains opaque and streams through
//! [`BlobHandle`] without a RAM-sized staging allocation. The generic root
//! makes both children visible to storage closure walkers and is published
//! only after durable placement of both children.

use std::collections::BTreeSet;
use std::fmt;
use std::io::Write;
use std::sync::Arc;

use crucible::ContentHash;
pub use crucible_campaign::ExactCheckpointId;
use crucible_cas::content_envelope::{ContentChild, ContentEnvelope, ContentEnvelopeError};
use crucible_cas::content_store::{
    BlobHandle, ContentId, ImmutableBlobBackend, ObjectKind, PutReceipt, StoreError,
};
use crucible_qemu::{
    MAX_QEMU_VM_SNAPSHOT_CANONICAL_BYTES, QemuReplayOracleCheck, QemuVmRealizationError,
    QemuVmSnapshot, QemuVmSnapshotCodecError,
};
use thiserror::Error;

/// Canonical schema name of the child-bearing exact-checkpoint root.
pub const EXACT_CHECKPOINT_ROOT_SCHEMA: &str = "crucible.executor.exact-checkpoint-root";
/// Content-ID and envelope version of the exact-checkpoint root.
pub const EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION: u32 = 2;
/// Content-ID version of canonical [`QemuVmSnapshot`] metadata bytes.
///
/// Version 1 of the `DeviceState` namespace is reserved for opaque QEMU
/// VMState. Version 2 keeps owner-decoded metadata type-separated while still
/// allowing generic closure walkers to treat it as an authenticated leaf.
pub const QEMU_VM_SNAPSHOT_METADATA_SCHEMA_VERSION: u32 = 2;
/// Content-ID version of opaque QEMU VMState bytes.
pub const QEMU_VMSTATE_SCHEMA_VERSION: u32 = 1;

const SNAPSHOT_METADATA_ROLE: &str = "snapshot-metadata";
const QEMU_VMSTATE_ROLE: &str = "qemu-vmstate";
const ROOT_BODY_BYTES: usize = 80;
const MAX_ROOT_BYTES: u64 = 4 * 1024;

/// A fully authenticated exact-checkpoint publication prepared without writes.
pub struct PreparedExactCheckpoint {
    root: ExactCheckpointId,
    root_source: BlobHandle,
    metadata_id: ContentId,
    metadata_source: BlobHandle,
    vmstate_id: ContentId,
    vmstate_source: BlobHandle,
    snapshot_identity: ContentHash,
    configuration: ContentHash,
}

impl fmt::Debug for PreparedExactCheckpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedExactCheckpoint")
            .field("root", &self.root)
            .field("metadata_id", &self.metadata_id)
            .field("vmstate_id", &self.vmstate_id)
            .field("snapshot_identity", &self.snapshot_identity)
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
    vmstate: BlobHandle,
}

impl fmt::Debug for CapturedExactCheckpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapturedExactCheckpoint")
            .field("snapshot", &self.snapshot.id())
            .field("configuration", &self.snapshot.checkpoint().configuration)
            .field("vmstate_bytes", &self.vmstate.logical_length())
            .finish()
    }
}

impl CapturedExactCheckpoint {
    /// Binds authenticated QEMU/Apache continuation metadata to opaque VMState.
    #[must_use]
    pub const fn new(snapshot: QemuVmSnapshot, vmstate: BlobHandle) -> Self {
        Self { snapshot, vmstate }
    }

    /// Returns the captured scheduler and Apache continuation metadata.
    #[must_use]
    pub const fn snapshot(&self) -> &QemuVmSnapshot {
        &self.snapshot
    }

    /// Returns the declared opaque VMState byte length.
    #[must_use]
    pub fn vmstate_bytes(&self) -> u64 {
        self.vmstate.logical_length()
    }

    pub(crate) fn vmstate_source(&self) -> BlobHandle {
        self.vmstate.clone()
    }

    /// Consumes the capture into its metadata and reopenable VMState source.
    #[must_use]
    pub fn into_parts(self) -> (QemuVmSnapshot, BlobHandle) {
        (self.snapshot, self.vmstate)
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
        Ok(CapturedExactCheckpoint::new(snapshot, self.vmstate.clone()))
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
    maximum_vmstate_bytes: u64,
}

impl ExactCheckpointStore {
    /// Admits a durable streaming immutable backend and VMState byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`ExactCheckpointStoreError::UnsupportedBackend`] unless the
    /// backend is durable and supports streaming reads, streaming puts, and
    /// conditional creation. A zero VMState ceiling is rejected.
    pub fn new(
        backend: Arc<dyn ImmutableBlobBackend>,
        maximum_vmstate_bytes: u64,
    ) -> Result<Self, ExactCheckpointStoreError> {
        if maximum_vmstate_bytes == 0 {
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
            maximum_vmstate_bytes,
        })
    }

    /// Returns the configured per-checkpoint VMState byte ceiling.
    #[must_use]
    pub const fn maximum_vmstate_bytes(&self) -> u64 {
        self.maximum_vmstate_bytes
    }

    /// Authenticates and prepares one exact checkpoint without store writes.
    ///
    /// The VMState source is streamed once to derive its content identity. It
    /// must remain reopenable and byte-stable until publication completes.
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
        validate_vmstate_length(vmstate.logical_length(), self.maximum_vmstate_bytes)?;

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
        )?;

        let snapshot_identity = snapshot.id();
        let configuration = snapshot.checkpoint().configuration;
        let body = encode_root_body(
            snapshot_identity,
            configuration,
            metadata_bytes.len() as u64,
            vmstate.logical_length(),
        );
        let children = BTreeSet::from([
            ContentChild::new(SNAPSHOT_METADATA_ROLE, metadata_id)?,
            ContentChild::new(QEMU_VMSTATE_ROLE, vmstate_id)?,
        ]);
        let root_envelope = ContentEnvelope::new(
            EXACT_CHECKPOINT_ROOT_SCHEMA,
            EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION,
            children,
            body,
        )?;
        let root_bytes = root_envelope.canonical_bytes();
        let root = ExactCheckpointId::try_from(root_envelope.content_id(ObjectKind::ExactManifest))
            .map_err(|_| invalid_root("root identity"))?;

        Ok(PreparedExactCheckpoint {
            root,
            root_source: BlobHandle::from_bytes(root_bytes),
            metadata_id,
            metadata_source: BlobHandle::from_bytes(metadata_bytes),
            vmstate_id,
            vmstate_source: vmstate,
            snapshot_identity,
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
        let (snapshot, vmstate) = capture.into_parts();
        self.prepare(&snapshot, vmstate)
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
    /// three logical objects.
    pub fn publish(
        &self,
        prepared: &PreparedExactCheckpoint,
    ) -> Result<ExactCheckpointPublication, ExactCheckpointStoreError> {
        validate_vmstate_length(
            prepared.vmstate_source.logical_length(),
            self.maximum_vmstate_bytes,
        )?;
        require_durable_receipt(
            self.backend
                .put_if_absent(prepared.metadata_id, &prepared.metadata_source)?,
            prepared.metadata_id,
            prepared.metadata_source.logical_length(),
        )?;
        require_durable_receipt(
            self.backend
                .put_if_absent(prepared.vmstate_id, &prepared.vmstate_source)?,
            prepared.vmstate_id,
            prepared.vmstate_source.logical_length(),
        )?;
        require_durable_receipt(
            self.backend
                .put_if_absent(prepared.root.content_id(), &prepared.root_source)?,
            prepared.root.content_id(),
            prepared.root_source.logical_length(),
        )?;

        Ok(ExactCheckpointPublication {
            root: prepared.root,
            metadata: prepared.metadata_id,
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
            || envelope.schema_version() != EXACT_CHECKPOINT_ROOT_SCHEMA_VERSION
        {
            return Err(invalid_root("incompatible root schema"));
        }
        if envelope.content_id(ObjectKind::ExactManifest) != root.content_id() {
            return Err(invalid_root("root content identity mismatch"));
        }
        let (metadata_id, vmstate_id) = decode_children(&envelope)?;
        let body = decode_root_body(envelope.body())?;

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

        let vmstate = self.backend.read(vmstate_id, None)?;
        validate_vmstate_length(vmstate.logical_length(), self.maximum_vmstate_bytes)?;
        if vmstate.logical_length() != body.vmstate_bytes {
            return Err(invalid_root("VMState length mismatch"));
        }

        Ok(LoadedExactCheckpoint {
            root,
            snapshot,
            vmstate_id,
            vmstate,
        })
    }
}

/// Failure while preparing, publishing, or loading an exact QEMU checkpoint.
#[derive(Debug, Error)]
pub enum ExactCheckpointStoreError {
    /// The configured per-checkpoint VMState ceiling was zero.
    #[error("exact-checkpoint VMState limit must be nonzero")]
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
        )
    }
}

struct RootBody {
    snapshot_identity: ContentHash,
    configuration: ContentHash,
    metadata_bytes: u64,
    vmstate_bytes: u64,
}

fn encode_root_body(
    snapshot_identity: ContentHash,
    configuration: ContentHash,
    metadata_bytes: u64,
    vmstate_bytes: u64,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(ROOT_BODY_BYTES);
    body.extend_from_slice(&snapshot_identity.bytes);
    body.extend_from_slice(&configuration.bytes);
    body.extend_from_slice(&metadata_bytes.to_be_bytes());
    body.extend_from_slice(&vmstate_bytes.to_be_bytes());
    body
}

fn decode_root_body(bytes: &[u8]) -> Result<RootBody, ExactCheckpointStoreError> {
    let bytes: &[u8; ROOT_BODY_BYTES] = bytes
        .try_into()
        .map_err(|_| invalid_root("root body length mismatch"))?;
    let mut snapshot_identity = [0_u8; 32];
    snapshot_identity.copy_from_slice(&bytes[..32]);
    let mut configuration = [0_u8; 32];
    configuration.copy_from_slice(&bytes[32..64]);
    let metadata_bytes = u64::from_be_bytes(
        bytes[64..72]
            .try_into()
            .map_err(|_| invalid_root("metadata length encoding is invalid"))?,
    );
    let vmstate_bytes = u64::from_be_bytes(
        bytes[72..80]
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
        vmstate_bytes,
    })
}

fn decode_children(
    envelope: &ContentEnvelope,
) -> Result<(ContentId, ContentId), ExactCheckpointStoreError> {
    if envelope.children().len() != 2 {
        return Err(invalid_root("root must contain exactly two children"));
    }
    let mut metadata = None;
    let mut vmstate = None;
    for child in envelope.children() {
        match child.role() {
            SNAPSHOT_METADATA_ROLE => metadata = Some(child.id()),
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
    Ok((metadata, vmstate))
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
