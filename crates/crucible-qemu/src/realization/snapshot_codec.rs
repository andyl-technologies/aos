//! Canonical codec for inseparable QEMU VMState and Apache continuations.

use super::QemuVmSnapshot;
use crate::{
    QemuHostIoCheckpoint, QemuHostIoCheckpointCodecError, QemuNodeCheckpointCodecError,
    QemuNodeContinuationCheckpoint, QemuReplayOracleValidation,
};
use crucible::{Checkpoint, ContentHash};

use crate::checkpoint::bounded_cbor::{BoundedCborError, HARD_FAT_CHECKPOINT_BYTES, admit_input};

const MAGIC: &[u8] = b"crucible.qemu-vm-snapshot.v2\0";
const MAX_BYTES: u64 = HARD_FAT_CHECKPOINT_BYTES;

impl QemuVmSnapshot {
    /// Encodes the VMState metadata and every paired Apache continuation.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmSnapshotCodecError`] if a binding or aggregate identity
    /// is invalid, a nested owner cannot encode, or the result exceeds the hard
    /// checkpoint ceiling.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, QemuVmSnapshotCodecError> {
        encode_snapshot(self, MAX_BYTES)
    }

    /// Encodes the snapshot under an authored fat-checkpoint byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmSnapshotCodecError`] under the same conditions as
    /// [`Self::to_canonical_bytes`], and when the canonical envelope exceeds
    /// `fat_checkpoint_bytes`.
    pub fn to_canonical_bytes_with_limit(
        &self,
        fat_checkpoint_bytes: u64,
    ) -> Result<Vec<u8>, QemuVmSnapshotCodecError> {
        encode_snapshot(self, fat_checkpoint_bytes)
    }

    /// Decodes and authenticates a complete QEMU exact snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmSnapshotCodecError`] for unsupported, malformed,
    /// over-limit, binding-mismatched, identity-mismatched, noncanonical, or
    /// nested restore-invalid state.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, QemuVmSnapshotCodecError> {
        Self::from_canonical_bytes_with_limit(bytes, MAX_BYTES)
    }

    /// Decodes a snapshot under the same authored ceiling used for storage.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmSnapshotCodecError`] under the same conditions as
    /// [`Self::from_canonical_bytes`], and before decoding when `bytes` exceeds
    /// `fat_checkpoint_bytes`.
    pub fn from_canonical_bytes_with_limit(
        bytes: &[u8],
        fat_checkpoint_bytes: u64,
    ) -> Result<Self, QemuVmSnapshotCodecError> {
        let fat_checkpoint_bytes = fat_checkpoint_bytes.min(HARD_FAT_CHECKPOINT_BYTES);
        admit_input(bytes, "QEMU VM snapshot", fat_checkpoint_bytes)
            .map_err(map_bounded_cbor_error)?;
        let mut reader = SnapshotReader::new(bytes)?;
        let checkpoint_bytes = reader.blob("scheduler checkpoint")?;
        let host_io_bytes = reader.blob("host-I/O checkpoint")?;
        let node_bytes = reader.blob("node continuation")?;
        let replay_oracle_validation = reader.replay_oracle()?;
        let live_capture = reader.boolean("live-capture flag")?;
        let stored_identity = reader.fixed::<32>("snapshot identity")?;
        reader.finish()?;
        let identity = snapshot_identity_from_bytes(
            checkpoint_bytes,
            host_io_bytes,
            node_bytes,
            replay_oracle_validation,
            live_capture,
        )?;
        if identity.bytes != stored_identity {
            return Err(QemuVmSnapshotCodecError::Identity);
        }
        let mut nested_bytes = admit_nested_bytes(0, checkpoint_bytes.len(), fat_checkpoint_bytes)?;
        let checkpoint = Checkpoint::from_compact_binary(checkpoint_bytes)
            .map_err(|_| QemuVmSnapshotCodecError::Checkpoint)?;
        let host_limit = fat_checkpoint_bytes.saturating_sub(nested_bytes);
        nested_bytes = admit_nested_bytes(nested_bytes, host_io_bytes.len(), fat_checkpoint_bytes)?;
        let host_io = QemuHostIoCheckpoint::from_canonical_bytes_with_limit(
            host_io_bytes,
            checkpoint.id,
            host_limit,
        )
        .map_err(map_host_io_error)?;
        let node_limit = fat_checkpoint_bytes.saturating_sub(nested_bytes);
        admit_nested_bytes(nested_bytes, node_bytes.len(), fat_checkpoint_bytes)?;
        let node = QemuNodeContinuationCheckpoint::from_compact_binary_with_limit(
            node_bytes,
            checkpoint.id,
            node_limit,
        )
        .map_err(map_node_error)?;
        let snapshot = Self {
            checkpoint,
            host_io,
            node,
            replay_oracle_validation,
            live_capture,
            identity: ContentHash {
                bytes: stored_identity,
            },
        };
        validate_execution_binding(&snapshot)?;
        if encode_snapshot(&snapshot, fat_checkpoint_bytes)?.as_slice() != bytes {
            return Err(QemuVmSnapshotCodecError::Noncanonical);
        }
        Ok(snapshot)
    }
}

pub(super) fn encode_snapshot(
    snapshot: &QemuVmSnapshot,
    maximum: u64,
) -> Result<Vec<u8>, QemuVmSnapshotCodecError> {
    let maximum = maximum.min(HARD_FAT_CHECKPOINT_BYTES);
    validate_execution_binding(snapshot)?;
    let checkpoint = snapshot.checkpoint.to_compact_binary();
    let mut nested_bytes = admit_nested_bytes(0, checkpoint.len(), maximum)?;
    let host_limit = maximum.saturating_sub(nested_bytes);
    let host_io = snapshot
        .host_io
        .to_canonical_bytes_with_limit(host_limit)
        .map_err(map_host_io_error)?;
    nested_bytes = admit_nested_bytes(nested_bytes, host_io.len(), maximum)?;
    let node = snapshot
        .node
        .to_compact_binary_with_limit(maximum.saturating_sub(nested_bytes))
        .map_err(map_node_error)?;
    admit_nested_bytes(nested_bytes, node.len(), maximum)?;
    let identity = snapshot_identity_from_bytes(
        &checkpoint,
        &host_io,
        &node,
        snapshot.replay_oracle_validation,
        snapshot.live_capture,
    )?;
    if identity != snapshot.identity {
        return Err(QemuVmSnapshotCodecError::Identity);
    }
    encode_snapshot_binary(
        &checkpoint,
        &host_io,
        &node,
        snapshot.replay_oracle_validation,
        snapshot.live_capture,
        snapshot.identity,
        maximum,
    )
}

fn encode_snapshot_binary(
    checkpoint: &[u8],
    host_io: &[u8],
    node: &[u8],
    replay_oracle: QemuReplayOracleValidation,
    live_capture: bool,
    identity: ContentHash,
    maximum: u64,
) -> Result<Vec<u8>, QemuVmSnapshotCodecError> {
    let replay_bytes = match replay_oracle {
        QemuReplayOracleValidation::NotRun => 1,
        QemuReplayOracleValidation::Mismatch { .. } => 65,
        QemuReplayOracleValidation::Match { .. } => 33,
    };
    let fixed = MAGIC
        .len()
        .checked_add(8 * 3 + replay_bytes + 1 + 32)
        .ok_or_else(|| {
            resource(
                "QEMU VM snapshot",
                0,
                u64::MAX,
                maximum,
                HARD_FAT_CHECKPOINT_BYTES,
            )
        })?;
    let total = [checkpoint.len(), host_io.len(), node.len()]
        .into_iter()
        .try_fold(fixed, |current, requested| {
            current.checked_add(requested).ok_or_else(|| {
                resource(
                    "QEMU VM snapshot",
                    current as u64,
                    requested as u64,
                    maximum,
                    HARD_FAT_CHECKPOINT_BYTES,
                )
            })
        })?;
    let total_u64 = u64::try_from(total).map_err(|_| {
        resource(
            "QEMU VM snapshot",
            0,
            u64::MAX,
            maximum,
            HARD_FAT_CHECKPOINT_BYTES,
        )
    })?;
    if total_u64 > maximum {
        return Err(resource(
            "QEMU VM snapshot",
            0,
            total_u64,
            maximum,
            HARD_FAT_CHECKPOINT_BYTES,
        ));
    }

    let mut bytes = Vec::new();
    bytes.try_reserve_exact(total).map_err(|_| {
        resource(
            "QEMU VM snapshot",
            0,
            total_u64,
            maximum,
            HARD_FAT_CHECKPOINT_BYTES,
        )
    })?;
    bytes.extend_from_slice(MAGIC);
    append_blob(&mut bytes, checkpoint)?;
    append_blob(&mut bytes, host_io)?;
    append_blob(&mut bytes, node)?;
    match replay_oracle {
        QemuReplayOracleValidation::NotRun => bytes.push(0),
        QemuReplayOracleValidation::Mismatch {
            fat_hash,
            thin_hash,
        } => {
            bytes.push(1);
            bytes.extend_from_slice(&fat_hash.bytes);
            bytes.extend_from_slice(&thin_hash.bytes);
        }
        QemuReplayOracleValidation::Match { runtime_hash } => {
            bytes.push(2);
            bytes.extend_from_slice(&runtime_hash.bytes);
        }
    }
    bytes.push(u8::from(live_capture));
    bytes.extend_from_slice(&identity.bytes);
    if bytes.len() != total {
        return Err(QemuVmSnapshotCodecError::Malformed);
    }
    Ok(bytes)
}

fn append_blob(bytes: &mut Vec<u8>, blob: &[u8]) -> Result<(), QemuVmSnapshotCodecError> {
    let length = u64::try_from(blob.len()).map_err(|_| {
        resource(
            "QEMU VM snapshot nested bytes",
            bytes.len() as u64,
            u64::MAX,
            MAX_BYTES,
            HARD_FAT_CHECKPOINT_BYTES,
        )
    })?;
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(blob);
    Ok(())
}

struct SnapshotReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SnapshotReader<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, QemuVmSnapshotCodecError> {
        if !bytes.starts_with(MAGIC) {
            return Err(QemuVmSnapshotCodecError::Version);
        }
        Ok(Self {
            bytes,
            offset: MAGIC.len(),
        })
    }

    fn fixed<const N: usize>(
        &mut self,
        _field: &'static str,
    ) -> Result<[u8; N], QemuVmSnapshotCodecError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(QemuVmSnapshotCodecError::Malformed)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(QemuVmSnapshotCodecError::Malformed)?;
        self.offset = end;
        value
            .try_into()
            .map_err(|_| QemuVmSnapshotCodecError::Malformed)
    }

    fn byte(&mut self, field: &'static str) -> Result<u8, QemuVmSnapshotCodecError> {
        Ok(self.fixed::<1>(field)?[0])
    }

    fn blob(&mut self, field: &'static str) -> Result<&'a [u8], QemuVmSnapshotCodecError> {
        let length = u64::from_le_bytes(self.fixed::<8>(field)?);
        let length = usize::try_from(length).map_err(|_| {
            resource(
                field,
                self.offset as u64,
                length,
                MAX_BYTES,
                HARD_FAT_CHECKPOINT_BYTES,
            )
        })?;
        let end = self
            .offset
            .checked_add(length)
            .ok_or(QemuVmSnapshotCodecError::Malformed)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(QemuVmSnapshotCodecError::Malformed)?;
        self.offset = end;
        Ok(value)
    }

    fn replay_oracle(&mut self) -> Result<QemuReplayOracleValidation, QemuVmSnapshotCodecError> {
        match self.byte("replay-oracle tag")? {
            0 => Ok(QemuReplayOracleValidation::NotRun),
            1 => Ok(QemuReplayOracleValidation::Mismatch {
                fat_hash: ContentHash {
                    bytes: self.fixed::<32>("fat replay hash")?,
                },
                thin_hash: ContentHash {
                    bytes: self.fixed::<32>("thin replay hash")?,
                },
            }),
            2 => Ok(QemuReplayOracleValidation::Match {
                runtime_hash: ContentHash {
                    bytes: self.fixed::<32>("runtime replay hash")?,
                },
            }),
            _ => Err(QemuVmSnapshotCodecError::Malformed),
        }
    }

    fn boolean(&mut self, field: &'static str) -> Result<bool, QemuVmSnapshotCodecError> {
        match self.byte(field)? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(QemuVmSnapshotCodecError::Malformed),
        }
    }

    fn finish(self) -> Result<(), QemuVmSnapshotCodecError> {
        if self.offset != self.bytes.len() {
            return Err(QemuVmSnapshotCodecError::Noncanonical);
        }
        Ok(())
    }
}

/// Failure to encode or authenticate a complete QEMU VM snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum QemuVmSnapshotCodecError {
    /// The envelope version is unsupported.
    #[error("unsupported QEMU VM snapshot version")]
    Version,
    /// The snapshot cannot be serialized or decoded.
    #[error("malformed QEMU VM snapshot")]
    Malformed,
    /// The scheduler checkpoint is invalid.
    #[error("invalid scheduler checkpoint in QEMU VM snapshot")]
    Checkpoint,
    /// The host-I/O continuation is invalid.
    #[error("invalid host-I/O continuation in QEMU VM snapshot")]
    HostIo,
    /// The scheduler-facing node continuation is invalid.
    #[error("invalid node continuation in QEMU VM snapshot")]
    Node,
    /// VMState and Apache continuations do not share one identity.
    #[error("QEMU VM snapshot execution binding mismatch")]
    ExecutionBinding,
    /// The aggregate identity does not authenticate the snapshot fields.
    #[error("QEMU VM snapshot aggregate identity mismatch")]
    Identity,
    /// A bounded nested or envelope allocation cannot be admitted.
    #[error(
        "QEMU VM snapshot resource `{field}` exceeds its bound: current={current}, requested={requested}, configured={configured}, hard={hard}"
    )]
    ResourceLimit {
        /// Resource field that rejected the operation.
        field: &'static str,
        /// Bytes or entries already retained by the operation.
        current: u64,
        /// Additional bytes or entries requested.
        requested: u64,
        /// Active configured ceiling.
        configured: u64,
        /// Compiled hard ceiling.
        hard: u64,
    },
    /// The accepted representation is not byte-canonical.
    #[error("noncanonical QEMU VM snapshot")]
    Noncanonical,
}

fn validate_execution_binding(snapshot: &QemuVmSnapshot) -> Result<(), QemuVmSnapshotCodecError> {
    if snapshot.host_io.execution_binding() != snapshot.checkpoint.id
        || snapshot.node.execution_binding() != snapshot.checkpoint.id
    {
        return Err(QemuVmSnapshotCodecError::ExecutionBinding);
    }
    Ok(())
}

pub(super) fn canonical_snapshot_identity(
    checkpoint: &Checkpoint,
    host_io: &QemuHostIoCheckpoint,
    node: &QemuNodeContinuationCheckpoint,
    replay_oracle_validation: QemuReplayOracleValidation,
    live_capture: bool,
) -> Result<ContentHash, QemuVmSnapshotCodecError> {
    let checkpoint = checkpoint.to_compact_binary();
    let host_io = host_io.to_canonical_bytes().map_err(map_host_io_error)?;
    let node = node.to_compact_binary().map_err(map_node_error)?;
    snapshot_identity_from_bytes(
        &checkpoint,
        &host_io,
        &node,
        replay_oracle_validation,
        live_capture,
    )
}

fn snapshot_identity_from_bytes(
    checkpoint: &[u8],
    host_io: &[u8],
    node: &[u8],
    replay_oracle_validation: QemuReplayOracleValidation,
    live_capture: bool,
) -> Result<ContentHash, QemuVmSnapshotCodecError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crucible.qemu.exact-snapshot.v5\0");
    hash_blob(&mut hasher, checkpoint)?;
    hash_blob(&mut hasher, host_io)?;
    hash_blob(&mut hasher, node)?;
    match replay_oracle_validation {
        QemuReplayOracleValidation::NotRun => {
            hasher.update(&[0]);
        }
        QemuReplayOracleValidation::Mismatch {
            fat_hash,
            thin_hash,
        } => {
            hasher.update(&[1]);
            hasher.update(&fat_hash.bytes);
            hasher.update(&thin_hash.bytes);
        }
        QemuReplayOracleValidation::Match { runtime_hash } => {
            hasher.update(&[2]);
            hasher.update(&runtime_hash.bytes);
        }
    };
    hasher.update(&[u8::from(live_capture)]);
    Ok(ContentHash {
        bytes: *hasher.finalize().as_bytes(),
    })
}

fn hash_blob(hasher: &mut blake3::Hasher, bytes: &[u8]) -> Result<(), QemuVmSnapshotCodecError> {
    let length = u64::try_from(bytes.len()).map_err(|_| {
        resource(
            "snapshot identity material",
            0,
            u64::MAX,
            MAX_BYTES,
            HARD_FAT_CHECKPOINT_BYTES,
        )
    })?;
    hasher.update(&length.to_le_bytes());
    hasher.update(bytes);
    Ok(())
}

fn admit_nested_bytes(
    current: u64,
    requested: usize,
    configured: u64,
) -> Result<u64, QemuVmSnapshotCodecError> {
    let requested = u64::try_from(requested).map_err(|_| {
        resource(
            "QEMU VM snapshot nested bytes",
            current,
            u64::MAX,
            configured,
            HARD_FAT_CHECKPOINT_BYTES,
        )
    })?;
    let total = current.checked_add(requested).ok_or_else(|| {
        resource(
            "QEMU VM snapshot nested bytes",
            current,
            requested,
            configured,
            HARD_FAT_CHECKPOINT_BYTES,
        )
    })?;
    if total > configured {
        return Err(resource(
            "QEMU VM snapshot nested bytes",
            current,
            requested,
            configured,
            HARD_FAT_CHECKPOINT_BYTES,
        ));
    }
    Ok(total)
}

fn map_bounded_cbor_error(error: BoundedCborError) -> QemuVmSnapshotCodecError {
    match error {
        BoundedCborError::Malformed => QemuVmSnapshotCodecError::Malformed,
        BoundedCborError::ResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        } => resource(field, current, requested, configured, hard),
    }
}

fn map_host_io_error(error: QemuHostIoCheckpointCodecError) -> QemuVmSnapshotCodecError {
    match error {
        QemuHostIoCheckpointCodecError::ResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        } => resource(field, current, requested, configured, hard),
        _ => QemuVmSnapshotCodecError::HostIo,
    }
}

fn map_node_error(error: QemuNodeCheckpointCodecError) -> QemuVmSnapshotCodecError {
    match error {
        QemuNodeCheckpointCodecError::ResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        } => resource(field, current, requested, configured, hard),
        _ => QemuVmSnapshotCodecError::Node,
    }
}

const fn resource(
    field: &'static str,
    current: u64,
    requested: u64,
    configured: u64,
    hard: u64,
) -> QemuVmSnapshotCodecError {
    QemuVmSnapshotCodecError::ResourceLimit {
        field,
        current,
        requested,
        configured,
        hard,
    }
}

#[cfg(test)]
mod tests;
