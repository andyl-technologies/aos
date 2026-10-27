//! Canonical continuation for one scheduler-owned block or 9p sub-node.
//!
//! The continuation holds the nested device snapshot plus the bridge's
//! undelivered completions. Delivered completions are retired from the bridge
//! and the device before any checkpoint can observe them, so the completion
//! lists are bounded by in-flight requests rather than by run length.
//!
//! ```text
//! b"crucible.device-scheduling-subnode.v3\0" || CBOR {
//!     sub_node, sub_node_kind, target, device_id,
//!     device_kind, device: nested canonical snapshot bytes,
//!     block_chunks: [(identity, bytes)] ascending by identity,
//!     modeled:  [{ modeled_icount, src_node, seq, payload }] in key order,
//!     resolved: [{ modeled_icount, modeled_src_node, modeled_seq,
//!                  delivery_icount, src_node, seq, payload?, decisions }]
//!               in (delivery_icount, src_node, seq) order,
//! }
//! ```
//!
//! Every resolved entry names exactly one modeled entry and every modeled entry
//! has exactly one resolved entry.
//!
//! A block snapshot names its overlay chunks by identity only. This scheduler
//! double has no object store of its own, so the continuation carries exactly
//! the chunk objects its block snapshot names, and decoding binds them back as
//! the snapshot's chunk source. Each chunk is authenticated when restored.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{DeviceSchedulingSubNode, ModeledCompletion, PendingCompletion, ScheduledDevice};
use crate::Schedule;

const MAGIC: &[u8] = b"crucible.device-scheduling-subnode.v3\0";
const MAX_BYTES: usize = 1_073_741_824;

/// Complete mutable continuation of one scheduler-owned I/O sub-node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceSchedulingSubNodeCheckpoint {
    sub_node: String,
    sub_node_kind: u8,
    target: String,
    device_id: String,
    device: DeviceCheckpoint,
    modeled: Vec<ModeledCompletion>,
    resolved: Vec<PendingCompletion>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum DeviceCheckpoint {
    Block(Box<crucible_device::BlockSnapshot>),
    Ninep(Box<crucible_device::NinepSnapshot>),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointWire {
    sub_node: String,
    sub_node_kind: u8,
    target: String,
    device_id: String,
    device_kind: u8,
    device: Vec<u8>,
    block_chunks: BlockChunkObjects,
    modeled: Vec<ModeledWire>,
    resolved: Vec<ResolvedWire>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModeledWire {
    modeled_icount: u64,
    src_node: u32,
    seq: u32,
    payload: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolvedWire {
    modeled_icount: u64,
    modeled_src_node: u32,
    modeled_seq: u32,
    delivery_icount: u64,
    src_node: u32,
    seq: u32,
    payload: Option<Vec<u8>>,
    decisions: Vec<u8>,
}

impl DeviceSchedulingSubNode {
    /// Captures every mutable device and scheduler-bridge field.
    #[must_use]
    pub fn checkpoint(&self) -> DeviceSchedulingSubNodeCheckpoint {
        DeviceSchedulingSubNodeCheckpoint {
            sub_node: self.sub_node.node.name.clone(),
            sub_node_kind: scheduling_kind_tag(self.sub_node.kind),
            target: self.target.name.clone(),
            device_id: self.device_id.name.clone(),
            device: match &self.device {
                ScheduledDevice::Block(device) => {
                    DeviceCheckpoint::Block(Box::new(device.snapshot()))
                }
                ScheduledDevice::Ninep(device) => {
                    DeviceCheckpoint::Ninep(Box::new(device.snapshot()))
                }
            },
            modeled: self.modeled.values().cloned().collect(),
            resolved: self.resolved.values().cloned().collect(),
        }
    }

    /// Restores a checkpoint into this sub-node without replacing immutable artifacts.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceSchedulingSubNodeCheckpointError`] if the checkpoint names
    /// another admitted sub-node, has the wrong concrete device kind, contains
    /// noncanonical completion ordering, or the nested device rejects its state.
    pub fn restore_checkpoint(
        &mut self,
        checkpoint: &DeviceSchedulingSubNodeCheckpoint,
    ) -> Result<(), DeviceSchedulingSubNodeCheckpointError> {
        checkpoint.validate()?;
        if checkpoint.sub_node != self.sub_node.node.name
            || checkpoint.sub_node_kind != scheduling_kind_tag(self.sub_node.kind)
            || checkpoint.target != self.target.name
            || checkpoint.device_id != self.device_id.name
        {
            return Err(DeviceSchedulingSubNodeCheckpointError::Identity);
        }

        match (&mut self.device, &checkpoint.device) {
            (ScheduledDevice::Block(device), DeviceCheckpoint::Block(snapshot)) => device
                .restore_snapshot(snapshot)
                .map_err(DeviceSchedulingSubNodeCheckpointError::Device)?,
            (ScheduledDevice::Ninep(device), DeviceCheckpoint::Ninep(snapshot)) => device
                .restore_snapshot(snapshot)
                .map_err(DeviceSchedulingSubNodeCheckpointError::Device)?,
            _ => return Err(DeviceSchedulingSubNodeCheckpointError::Kind),
        }
        // Validation proved both lists strictly ordered by these keys.
        self.modeled = checkpoint
            .modeled
            .iter()
            .map(|completion| (completion.key(), completion.clone()))
            .collect();
        self.resolved = checkpoint
            .resolved
            .iter()
            .map(|completion| (completion.delivery_key(), completion.clone()))
            .collect();
        Ok(())
    }
}

impl DeviceSchedulingSubNodeCheckpoint {
    /// Encodes the complete sub-node continuation canonically.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceSchedulingSubNodeCheckpointError`] for invalid bridge
    /// ordering, a nested device codec failure, serialization failure, or a
    /// checkpoint larger than the compiled ceiling.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, DeviceSchedulingSubNodeCheckpointError> {
        self.validate()?;
        let (device_kind, device, block_chunks) = match &self.device {
            DeviceCheckpoint::Block(snapshot) => (
                1,
                snapshot
                    .to_canonical_bytes()
                    .map_err(|_| DeviceSchedulingSubNodeCheckpointError::Nested)?,
                block_chunk_objects(snapshot)?,
            ),
            DeviceCheckpoint::Ninep(snapshot) => (
                2,
                snapshot
                    .to_canonical_bytes()
                    .map_err(|_| DeviceSchedulingSubNodeCheckpointError::Nested)?,
                Vec::new(),
            ),
        };
        let wire = CheckpointWire {
            sub_node: self.sub_node.clone(),
            sub_node_kind: self.sub_node_kind,
            target: self.target.clone(),
            device_id: self.device_id.clone(),
            device_kind,
            device,
            block_chunks,
            modeled: self
                .modeled
                .iter()
                .map(|completion| ModeledWire {
                    modeled_icount: completion.modeled_icount,
                    src_node: completion.src_node,
                    seq: completion.seq,
                    payload: completion.payload.clone(),
                })
                .collect(),
            resolved: self
                .resolved
                .iter()
                .map(|completion| ResolvedWire {
                    modeled_icount: completion.modeled_key.0,
                    modeled_src_node: completion.modeled_key.1,
                    modeled_seq: completion.modeled_key.2,
                    delivery_icount: completion.delivery_icount,
                    src_node: completion.src_node,
                    seq: completion.seq,
                    payload: completion.payload.clone(),
                    decisions: Schedule::from_decisions(completion.decisions.clone())
                        .to_compact_binary(),
                })
                .collect(),
        };
        let mut payload = Vec::new();
        ciborium::ser::into_writer(&wire, &mut payload)
            .map_err(|_| DeviceSchedulingSubNodeCheckpointError::Malformed)?;
        if payload.len() > MAX_BYTES {
            return Err(DeviceSchedulingSubNodeCheckpointError::Limit);
        }
        let mut bytes = Vec::with_capacity(MAGIC.len() + payload.len());
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }

    /// Decodes and validates a complete sub-node continuation.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceSchedulingSubNodeCheckpointError`] for unsupported,
    /// malformed, over-limit, invalid, or noncanonical state.
    pub fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<Self, DeviceSchedulingSubNodeCheckpointError> {
        let payload = bytes
            .strip_prefix(MAGIC)
            .ok_or(DeviceSchedulingSubNodeCheckpointError::Version)?;
        if payload.len() > MAX_BYTES {
            return Err(DeviceSchedulingSubNodeCheckpointError::Limit);
        }
        let wire: CheckpointWire = ciborium::de::from_reader(payload)
            .map_err(|_| DeviceSchedulingSubNodeCheckpointError::Malformed)?;
        let device = match wire.device_kind {
            1 => {
                let mut snapshot =
                    crucible_device::BlockSnapshot::from_canonical_bytes(&wire.device)
                        .map_err(|_| DeviceSchedulingSubNodeCheckpointError::Nested)?;
                bind_block_chunk_objects(&mut snapshot, wire.block_chunks)?;
                DeviceCheckpoint::Block(Box::new(snapshot))
            }
            2 if wire.block_chunks.is_empty() => DeviceCheckpoint::Ninep(Box::new(
                crucible_device::NinepSnapshot::from_canonical_bytes(&wire.device)
                    .map_err(|_| DeviceSchedulingSubNodeCheckpointError::Nested)?,
            )),
            _ => return Err(DeviceSchedulingSubNodeCheckpointError::Kind),
        };
        let modeled = wire
            .modeled
            .into_iter()
            .map(|completion| ModeledCompletion {
                modeled_icount: completion.modeled_icount,
                src_node: completion.src_node,
                seq: completion.seq,
                payload: completion.payload,
            })
            .collect();
        let resolved = wire
            .resolved
            .into_iter()
            .map(|completion| {
                let decisions = Schedule::from_compact_binary(&completion.decisions)
                    .map_err(|_| DeviceSchedulingSubNodeCheckpointError::Decisions)?;
                Ok(PendingCompletion {
                    modeled_key: (
                        completion.modeled_icount,
                        completion.modeled_src_node,
                        completion.modeled_seq,
                    ),
                    delivery_icount: completion.delivery_icount,
                    src_node: completion.src_node,
                    seq: completion.seq,
                    payload: completion.payload,
                    decisions: decisions.decision_history().to_vec(),
                })
            })
            .collect::<Result<Vec<_>, DeviceSchedulingSubNodeCheckpointError>>()?;
        let checkpoint = Self {
            sub_node: wire.sub_node,
            sub_node_kind: wire.sub_node_kind,
            target: wire.target,
            device_id: wire.device_id,
            device,
            modeled,
            resolved,
        };
        checkpoint.validate()?;
        if checkpoint.canonical_bytes()?.as_slice() != bytes {
            return Err(DeviceSchedulingSubNodeCheckpointError::Noncanonical);
        }
        Ok(checkpoint)
    }

    fn validate(&self) -> Result<(), DeviceSchedulingSubNodeCheckpointError> {
        if self.sub_node.is_empty() || self.target.is_empty() || self.device_id.is_empty() {
            return Err(DeviceSchedulingSubNodeCheckpointError::Identity);
        }
        if !matches!(self.sub_node_kind, 2 | 3) {
            return Err(DeviceSchedulingSubNodeCheckpointError::Kind);
        }
        if self
            .modeled
            .windows(2)
            .any(|pair| pair[0].key() >= pair[1].key())
            || self
                .resolved
                .windows(2)
                .any(|pair| pair[0].delivery_key() >= pair[1].delivery_key())
        {
            return Err(DeviceSchedulingSubNodeCheckpointError::Ordering);
        }

        // Delivered completions are retired, so the two lists join one to one.
        let modeled_keys = self
            .modeled
            .iter()
            .map(ModeledCompletion::key)
            .collect::<BTreeSet<_>>();
        let resolved_keys = self
            .resolved
            .iter()
            .map(|completion| completion.modeled_key)
            .collect::<BTreeSet<_>>();
        if resolved_keys.len() != self.resolved.len() || resolved_keys != modeled_keys {
            return Err(DeviceSchedulingSubNodeCheckpointError::Join);
        }
        Ok(())
    }
}

/// Inline block overlay chunk objects as `(identity, bytes)`, ascending by identity.
type BlockChunkObjects = Vec<([u8; 32], Vec<u8>)>;

/// Collects the chunk objects a block snapshot names, ascending by identity.
fn block_chunk_objects(
    snapshot: &crucible_device::BlockSnapshot,
) -> Result<BlockChunkObjects, DeviceSchedulingSubNodeCheckpointError> {
    let chunks = snapshot
        .overlay
        .chunks()
        .map_err(|_| DeviceSchedulingSubNodeCheckpointError::Nested)?;
    let mut objects = std::collections::BTreeMap::new();
    for chunk in chunks {
        let mut bytes = Vec::new();
        if let Some(identity) = snapshot
            .overlay
            .read_chunk(chunk.index, &mut bytes)
            .map_err(DeviceSchedulingSubNodeCheckpointError::Device)?
        {
            objects.insert(identity, bytes);
        }
    }
    Ok(objects.into_iter().collect())
}

/// Binds decoded chunk objects as the block snapshot's chunk source.
///
/// The objects must be strictly ascending and exactly the set the snapshot
/// names; their content is authenticated when the snapshot is restored.
fn bind_block_chunk_objects(
    snapshot: &mut crucible_device::BlockSnapshot,
    objects: BlockChunkObjects,
) -> Result<(), DeviceSchedulingSubNodeCheckpointError> {
    let named = snapshot
        .overlay_chunk_identities()
        .map_err(|_| DeviceSchedulingSubNodeCheckpointError::Nested)?;
    if objects.len() != named.len()
        || objects
            .iter()
            .zip(&named)
            .any(|((identity, _), expected)| identity != expected)
    {
        return Err(DeviceSchedulingSubNodeCheckpointError::Nested);
    }
    let source: std::collections::BTreeMap<[u8; 32], Vec<u8>> = objects.into_iter().collect();
    snapshot.bind_overlay_source(std::sync::Arc::new(source));
    Ok(())
}

/// Failure to encode, decode, validate, or restore one I/O sub-node continuation.
#[derive(Debug, thiserror::Error)]
pub enum DeviceSchedulingSubNodeCheckpointError {
    /// The envelope version is unsupported.
    #[error("unsupported device scheduling sub-node checkpoint version")]
    Version,
    /// The envelope or a primitive field is malformed.
    #[error("malformed device scheduling sub-node checkpoint")]
    Malformed,
    /// The nested block or 9p snapshot is invalid.
    #[error("invalid nested device snapshot")]
    Nested,
    /// A recorded decision sequence is invalid.
    #[error("invalid device completion decision sequence")]
    Decisions,
    /// The checkpoint names another admitted sub-node.
    #[error("device scheduling sub-node checkpoint identity mismatch")]
    Identity,
    /// The concrete device or scheduler-node kind is invalid.
    #[error("device scheduling sub-node checkpoint kind mismatch")]
    Kind,
    /// Modeled or resolved completions are not in strict canonical order.
    #[error("device scheduling sub-node completions are not canonically ordered")]
    Ordering,
    /// Resolved completions do not name the modeled completions one to one.
    #[error("device scheduling sub-node resolved and modeled completions do not join")]
    Join,
    /// The checkpoint exceeds the compiled byte ceiling.
    #[error("device scheduling sub-node checkpoint exceeds its size limit")]
    Limit,
    /// The accepted representation is not byte-canonical.
    #[error("noncanonical device scheduling sub-node checkpoint")]
    Noncanonical,
    /// The instantiated device rejected the restored mutable state.
    #[error("device scheduling sub-node rejected restored state: {0}")]
    Device(#[source] crucible_device::DeviceError),
}

const fn scheduling_kind_tag(kind: crate::SchedulingNodeKind) -> u8 {
    match kind {
        crate::SchedulingNodeKind::Vm => 1,
        crate::SchedulingNodeKind::Disk => 2,
        crate::SchedulingNodeKind::NineP => 3,
        crate::SchedulingNodeKind::Network => 4,
        crate::SchedulingNodeKind::ControlPlane => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeviceId, NodeId, SchedulerNodeId, Seed};
    use crucible_device::{BaseImage, BlockDevice, BlockLatency, BlockRequest, IoCore};

    fn disk() -> DeviceSchedulingSubNode {
        let core = IoCore::new(7, 16, 16).unwrap_or_else(|error| panic!("io core: {error}"));
        DeviceSchedulingSubNode::new(
            SchedulerNodeId {
                node: NodeId {
                    name: "disk".into(),
                },
                kind: crate::SchedulingNodeKind::Disk,
            },
            NodeId { name: "vm".into() },
            DeviceId {
                name: "disk".into(),
            },
            BlockDevice::new(core, BaseImage::new(vec![0; 32]), BlockLatency::default()),
            Seed::from_u64(7),
        )
    }

    fn pending_checkpoint() -> DeviceSchedulingSubNodeCheckpoint {
        let mut disk = disk();
        disk.submit_fifo(0, &BlockRequest::read(1, 0, 4))
            .unwrap_or_else(|error| panic!("submit: {error}"));
        disk.checkpoint()
    }

    #[test]
    fn resolved_completion_without_its_modeled_completion_is_rejected() {
        let mut checkpoint = pending_checkpoint();
        assert_eq!(checkpoint.modeled.len(), 1);
        checkpoint.modeled.clear();

        assert!(matches!(
            checkpoint.canonical_bytes(),
            Err(DeviceSchedulingSubNodeCheckpointError::Join)
        ));
    }

    #[test]
    fn modeled_completion_without_a_resolved_completion_is_rejected() {
        let mut checkpoint = pending_checkpoint();
        checkpoint.resolved.clear();

        assert!(matches!(
            disk().restore_checkpoint(&checkpoint),
            Err(DeviceSchedulingSubNodeCheckpointError::Join)
        ));
    }

    #[test]
    fn previous_envelope_version_is_rejected() {
        let bytes = pending_checkpoint()
            .canonical_bytes()
            .unwrap_or_else(|error| panic!("encode: {error}"));
        let payload = bytes
            .strip_prefix(MAGIC)
            .unwrap_or_else(|| panic!("current magic prefix"));
        let mut previous = b"crucible.device-scheduling-subnode.v2\0".to_vec();
        previous.extend_from_slice(payload);

        assert!(matches!(
            DeviceSchedulingSubNodeCheckpoint::from_canonical_bytes(&previous),
            Err(DeviceSchedulingSubNodeCheckpointError::Version)
        ));
    }
}
