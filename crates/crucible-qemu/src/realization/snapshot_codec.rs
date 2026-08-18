//! Canonical codec for inseparable QEMU VMState and Apache continuations.

use serde::{Deserialize, Serialize};

use super::{QemuVmSnapshot, exact_snapshot_identity};
use crate::{QemuHostIoCheckpoint, QemuNodeContinuationCheckpoint, QemuReplayOracleValidation};
use crucible::{Checkpoint, ContentHash};

const MAGIC: &[u8] = b"crucible.qemu-vm-snapshot.v1\0";
const MAX_BYTES: usize = 1_610_612_736;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotWire {
    checkpoint: Vec<u8>,
    host_io: Vec<u8>,
    node: Vec<u8>,
    replay_oracle: ReplayOracleWire,
    live_capture: bool,
    identity: [u8; 32],
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(tag = "status", deny_unknown_fields)]
enum ReplayOracleWire {
    NotRun,
    Mismatch {
        fat_hash: [u8; 32],
        thin_hash: [u8; 32],
    },
    Match {
        runtime_hash: [u8; 32],
    },
}

impl From<QemuReplayOracleValidation> for ReplayOracleWire {
    fn from(validation: QemuReplayOracleValidation) -> Self {
        match validation {
            QemuReplayOracleValidation::NotRun => Self::NotRun,
            QemuReplayOracleValidation::Mismatch {
                fat_hash,
                thin_hash,
            } => Self::Mismatch {
                fat_hash: fat_hash.bytes,
                thin_hash: thin_hash.bytes,
            },
            QemuReplayOracleValidation::Match { runtime_hash } => Self::Match {
                runtime_hash: runtime_hash.bytes,
            },
        }
    }
}

impl From<ReplayOracleWire> for QemuReplayOracleValidation {
    fn from(validation: ReplayOracleWire) -> Self {
        match validation {
            ReplayOracleWire::NotRun => Self::NotRun,
            ReplayOracleWire::Mismatch {
                fat_hash,
                thin_hash,
            } => Self::Mismatch {
                fat_hash: ContentHash { bytes: fat_hash },
                thin_hash: ContentHash { bytes: thin_hash },
            },
            ReplayOracleWire::Match { runtime_hash } => Self::Match {
                runtime_hash: ContentHash {
                    bytes: runtime_hash,
                },
            },
        }
    }
}

impl QemuVmSnapshot {
    /// Encodes the VMState metadata and every paired Apache continuation.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmSnapshotCodecError`] if a binding or aggregate identity
    /// is invalid, a nested owner cannot encode, or the result exceeds the hard
    /// checkpoint ceiling.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, QemuVmSnapshotCodecError> {
        validate_snapshot(self)?;
        let wire = SnapshotWire {
            checkpoint: self.checkpoint.to_compact_binary(),
            host_io: self
                .host_io
                .to_canonical_bytes()
                .map_err(|_| QemuVmSnapshotCodecError::Nested)?,
            node: self
                .node
                .to_compact_binary()
                .map_err(|_| QemuVmSnapshotCodecError::Nested)?,
            replay_oracle: self.replay_oracle_validation.into(),
            live_capture: self.live_capture,
            identity: self.identity.bytes,
        };
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&wire, &mut payload)
            .map_err(|_| QemuVmSnapshotCodecError::Malformed)?;
        if payload.len() > MAX_BYTES {
            return Err(QemuVmSnapshotCodecError::Limit);
        }
        let mut bytes = Vec::with_capacity(MAGIC.len() + payload.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }

    /// Decodes and authenticates a complete QEMU exact snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmSnapshotCodecError`] for unsupported, malformed,
    /// over-limit, binding-mismatched, identity-mismatched, noncanonical, or
    /// nested restore-invalid state.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, QemuVmSnapshotCodecError> {
        let payload = bytes
            .strip_prefix(MAGIC)
            .ok_or(QemuVmSnapshotCodecError::Version)?;
        if payload.len() > MAX_BYTES {
            return Err(QemuVmSnapshotCodecError::Limit);
        }
        let wire: SnapshotWire =
            ciborium::de::from_reader(payload).map_err(|_| QemuVmSnapshotCodecError::Malformed)?;
        let checkpoint = Checkpoint::from_compact_binary(&wire.checkpoint)
            .map_err(|_| QemuVmSnapshotCodecError::Checkpoint)?;
        let host_io = QemuHostIoCheckpoint::from_canonical_bytes(&wire.host_io, checkpoint.id)
            .map_err(|_| QemuVmSnapshotCodecError::HostIo)?;
        let node = QemuNodeContinuationCheckpoint::from_compact_binary(&wire.node, checkpoint.id)
            .map_err(|_| QemuVmSnapshotCodecError::Node)?;
        let replay_oracle_validation = wire.replay_oracle.into();
        let snapshot = Self {
            checkpoint,
            host_io,
            node,
            replay_oracle_validation,
            live_capture: wire.live_capture,
            identity: ContentHash {
                bytes: wire.identity,
            },
        };
        validate_snapshot(&snapshot)?;
        if snapshot.to_canonical_bytes()?.as_slice() != bytes {
            return Err(QemuVmSnapshotCodecError::Noncanonical);
        }
        Ok(snapshot)
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
    /// A nested owner checkpoint is invalid.
    #[error("invalid nested QEMU VM snapshot state")]
    Nested,
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
    /// The snapshot exceeds a compiled resource ceiling.
    #[error("QEMU VM snapshot exceeds its size limit")]
    Limit,
    /// The accepted representation is not byte-canonical.
    #[error("noncanonical QEMU VM snapshot")]
    Noncanonical,
}

fn validate_snapshot(snapshot: &QemuVmSnapshot) -> Result<(), QemuVmSnapshotCodecError> {
    if snapshot.host_io.execution_binding() != snapshot.checkpoint.id
        || snapshot.node.execution_binding() != snapshot.checkpoint.id
    {
        return Err(QemuVmSnapshotCodecError::ExecutionBinding);
    }
    let identity = exact_snapshot_identity(
        &snapshot.checkpoint,
        &snapshot.host_io,
        &snapshot.node,
        snapshot.replay_oracle_validation,
        snapshot.live_capture,
    )?;
    if identity != snapshot.identity {
        return Err(QemuVmSnapshotCodecError::Identity);
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
    let host_io = host_io
        .to_canonical_bytes()
        .map_err(|_| QemuVmSnapshotCodecError::HostIo)?;
    let node = node
        .to_compact_binary()
        .map_err(|_| QemuVmSnapshotCodecError::Nested)?;
    let mut material = Vec::new();
    material.extend_from_slice(b"crucible.qemu.exact-snapshot.v4\0");
    append_blob(&mut material, &checkpoint)?;
    append_blob(&mut material, &host_io)?;
    append_blob(&mut material, &node)?;
    match replay_oracle_validation {
        QemuReplayOracleValidation::NotRun => material.push(0),
        QemuReplayOracleValidation::Mismatch {
            fat_hash,
            thin_hash,
        } => {
            material.push(1);
            material.extend_from_slice(&fat_hash.bytes);
            material.extend_from_slice(&thin_hash.bytes);
        }
        QemuReplayOracleValidation::Match { runtime_hash } => {
            material.push(2);
            material.extend_from_slice(&runtime_hash.bytes);
        }
    }
    material.push(u8::from(live_capture));
    Ok(ContentHash::from_bytes(&material))
}

fn append_blob(material: &mut Vec<u8>, bytes: &[u8]) -> Result<(), QemuVmSnapshotCodecError> {
    let length = u64::try_from(bytes.len()).map_err(|_| QemuVmSnapshotCodecError::Limit)?;
    material.extend_from_slice(&length.to_le_bytes());
    material.extend_from_slice(bytes);
    Ok(())
}
