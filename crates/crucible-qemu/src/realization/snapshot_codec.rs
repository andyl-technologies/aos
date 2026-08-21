//! Canonical codec for inseparable QEMU VMState and Apache continuations.

use serde::{Deserialize, Serialize};

use super::QemuVmSnapshot;
use crate::{
    QemuHostIoCheckpoint, QemuHostIoCheckpointCodecError, QemuNodeCheckpointCodecError,
    QemuNodeContinuationCheckpoint, QemuReplayOracleValidation,
};
use crucible::{Checkpoint, ContentHash};

use crate::checkpoint::bounded_cbor::{
    BoundedCborError, HARD_FAT_CHECKPOINT_BYTES, admit_input, encode_prefixed,
};

const MAGIC: &[u8] = b"crucible.qemu-vm-snapshot.v1\0";
const MAX_BYTES: u64 = HARD_FAT_CHECKPOINT_BYTES;

/// Maximum canonical byte length of one complete QEMU VM snapshot metadata record.
pub const MAX_QEMU_VM_SNAPSHOT_CANONICAL_BYTES: u64 = MAX_BYTES;

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
        encode_snapshot(self, MAX_BYTES)
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
        admit_input(bytes, "QEMU VM snapshot", MAX_BYTES).map_err(map_bounded_cbor_error)?;
        let wire: SnapshotWire =
            ciborium::de::from_reader(payload).map_err(|_| QemuVmSnapshotCodecError::Malformed)?;
        let replay_oracle_validation = wire.replay_oracle.into();
        let identity = snapshot_identity_from_bytes(
            &wire.checkpoint,
            &wire.host_io,
            &wire.node,
            replay_oracle_validation,
            wire.live_capture,
        )?;
        if identity.bytes != wire.identity {
            return Err(QemuVmSnapshotCodecError::Identity);
        }
        let checkpoint = Checkpoint::from_compact_binary(&wire.checkpoint)
            .map_err(|_| QemuVmSnapshotCodecError::Checkpoint)?;
        let host_io = QemuHostIoCheckpoint::from_canonical_bytes(&wire.host_io, checkpoint.id)
            .map_err(map_host_io_error)?;
        let node = QemuNodeContinuationCheckpoint::from_compact_binary(&wire.node, checkpoint.id)
            .map_err(map_node_error)?;
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
        validate_execution_binding(&snapshot)?;
        if snapshot.to_canonical_bytes()?.as_slice() != bytes {
            return Err(QemuVmSnapshotCodecError::Noncanonical);
        }
        Ok(snapshot)
    }
}

pub(super) fn encode_snapshot(
    snapshot: &QemuVmSnapshot,
    maximum: u64,
) -> Result<Vec<u8>, QemuVmSnapshotCodecError> {
    validate_execution_binding(snapshot)?;
    let checkpoint = snapshot.checkpoint.to_compact_binary();
    let host_io = snapshot
        .host_io
        .to_canonical_bytes()
        .map_err(map_host_io_error)?;
    let node = snapshot.node.to_compact_binary().map_err(map_node_error)?;
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
    let wire = SnapshotWire {
        checkpoint,
        host_io,
        node,
        replay_oracle: snapshot.replay_oracle_validation.into(),
        live_capture: snapshot.live_capture,
        identity: snapshot.identity.bytes,
    };
    encode_prefixed(&wire, MAGIC, "QEMU VM snapshot", maximum).map_err(map_bounded_cbor_error)
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
    hasher.update(b"crucible.qemu.exact-snapshot.v4\0");
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
mod tests {
    use std::collections::BTreeMap;

    use crucible::CheckpointKind;

    use super::*;

    #[test]
    fn production_envelope_reports_typed_aggregate_limit() {
        let snapshot = snapshot_fixture("typed-limit");
        assert!(matches!(
            encode_snapshot(&snapshot, 64),
            Err(QemuVmSnapshotCodecError::ResourceLimit {
                field: "QEMU VM snapshot",
                configured: 64,
                hard: 68_719_476_736,
                ..
            })
        ));
    }

    #[test]
    fn production_envelope_round_trips_full_network_frame_capacity() {
        const MAX_QUEUE_FRAMES: usize = 1_048_576;

        let mut snapshot = snapshot_fixture("full-network-capacity");
        snapshot.node.network_transport = crate::QemuNetworkTransportCheckpoint {
            inbound: crate::checkpoint::tests::synthetic_compact_ring(
                MAX_QUEUE_FRAMES,
                0,
                crucible_shmem::SLOT_NET_ROUTER as u32,
            ),
            outbound: crucible_shmem::SpscRingSnapshot { frames: Vec::new() },
            queue_capacity: MAX_QUEUE_FRAMES as u32,
            router_slot: crucible_shmem::SLOT_NET_ROUTER as u32,
            next_router_inbound_sequence: MAX_QUEUE_FRAMES as u64,
            next_host_outbound_sequence: 0,
            next_plugin_outbound_sequence: 0,
        };
        snapshot.identity = canonical_snapshot_identity(
            &snapshot.checkpoint,
            &snapshot.host_io,
            &snapshot.node,
            snapshot.replay_oracle_validation,
            snapshot.live_capture,
        )
        .unwrap_or_else(|error| panic!("authenticate full-capacity snapshot: {error}"));

        let bytes = snapshot
            .to_canonical_bytes()
            .unwrap_or_else(|error| panic!("encode full-capacity VM snapshot: {error}"));
        let restored = QemuVmSnapshot::from_canonical_bytes(&bytes)
            .unwrap_or_else(|error| panic!("decode full-capacity VM snapshot: {error}"));
        assert_eq!(
            restored.node.network_transport.inbound.frames.len(),
            MAX_QUEUE_FRAMES
        );
        assert_eq!(restored, snapshot);
    }

    fn snapshot_fixture(label: &str) -> QemuVmSnapshot {
        let definition = crucible::ScenarioDef::from_canonical_material(
            "crucible.test.qemu.snapshot-codec",
            label,
        );
        let configuration = crucible::Configuration::genesis(definition);
        let checkpoint = Checkpoint::from_recorded_configuration(
            &configuration,
            None,
            crucible::VirtualTime::default(),
            BTreeMap::new(),
            CheckpointKind::Fat,
            BTreeMap::new(),
        )
        .unwrap_or_else(|error| panic!("build canonical checkpoint: {error}"));
        QemuVmSnapshot::diskless(checkpoint, QemuReplayOracleValidation::NotRun)
            .unwrap_or_else(|error| panic!("build diskless snapshot: {error}"))
    }
}
