//! Paired QEMU VMState and host-I/O checkpoint metadata.
//!
//! QEMU serializes guest and GPL-side device state into VMState. Apache-side
//! device continuations remain outside that process and are captured here. A
//! single execution binding joins the two halves so neither can be restored
//! with state from another checkpoint.

use crucible::{ContentHash, NodeId, PreemptionDecision, VirtualTime};
use crucible_device::{BlockSnapshot, NinepRequestOpportunity, NinepSnapshot};
use crucible_shmem::{RegionHeaderSnapshot, SpscRingSnapshot};

/// Complete host block-device continuation paired with QEMU VMState.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLiveBlockIoServicerCheckpoint {
    pub(crate) execution_binding: ContentHash,
    pub(crate) storage_device: Option<ContentHash>,
    pub(crate) region_header: RegionHeaderSnapshot,
    pub(crate) vm_slot: u32,
    pub(crate) size_bytes: u64,
    pub(crate) device: BlockSnapshot,
    pub(crate) requests: SpscRingSnapshot,
    pub(crate) responses: SpscRingSnapshot,
    pub(crate) frames_processed: usize,
    pub(crate) frames_delivered: usize,
}

/// Complete host 9p-device continuation paired with QEMU VMState.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLive9pIoServicerCheckpoint {
    pub(crate) execution_binding: ContentHash,
    pub(crate) tree: ContentHash,
    pub(crate) region_header: RegionHeaderSnapshot,
    pub(crate) vm_slot: u32,
    pub(crate) device: NinepSnapshot,
    pub(crate) requests: SpscRingSnapshot,
    pub(crate) responses: SpscRingSnapshot,
    pub(crate) pending_fault_opportunities: Vec<(u64, NinepRequestOpportunity, bool)>,
    pub(crate) frames_processed: usize,
    pub(crate) frames_delivered: usize,
}

impl QemuLive9pIoServicerCheckpoint {
    /// Returns the QEMU execution checkpoint paired with this host continuation.
    #[must_use]
    pub const fn execution_binding(&self) -> ContentHash {
        self.execution_binding
    }

    /// Returns the immutable filesystem-tree identity used by this continuation.
    #[must_use]
    pub const fn tree(&self) -> ContentHash {
        self.tree
    }
}

impl QemuLiveBlockIoServicerCheckpoint {
    /// Returns the QEMU execution checkpoint paired with this host continuation.
    #[must_use]
    pub const fn execution_binding(&self) -> ContentHash {
        self.execution_binding
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn set_storage_device(&mut self, storage_device: Option<ContentHash>) {
        self.storage_device = storage_device;
    }

    #[cfg(target_os = "linux")]
    pub(crate) const fn storage_device(&self) -> Option<ContentHash> {
        self.storage_device
    }
}

/// Complete Apache-side I/O continuation paired with one QEMU VMState snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuHostIoCheckpoint {
    pub(crate) execution_binding: ContentHash,
    pub(crate) block: Option<QemuLiveBlockIoServicerCheckpoint>,
    pub(crate) ninep: Option<QemuLive9pIoServicerCheckpoint>,
    #[cfg(target_os = "linux")]
    pub(crate) accelerator: Option<crate::QemuLiveAcceleratorCheckpoint>,
}

/// Scheduler-facing continuation owned by the Apache QEMU node wrapper.
///
/// QEMU VMState does not contain host queues or scheduler decisions that have
/// not yet crossed the process boundary. Those values must therefore travel
/// with the VMState and host-device checkpoint as a third, inseparable part.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuNodeContinuationCheckpoint {
    pub(crate) execution_binding: ContentHash,
    pub(crate) last_observed_time: VirtualTime,
    pub(crate) logical_time_calibration: crate::QemuLogicalTimeCalibration,
    pub(crate) console_observation_boundary: VirtualTime,
    pub(crate) pending_preemption: Option<PreemptionDecision>,
    pub(crate) pending_network_outputs: Vec<crate::QemuNodeEmittedFrame>,
    pub(crate) next_fault_command_sequence: u64,
    pub(crate) next_fault_event_sequence: u64,
}

impl QemuNodeContinuationCheckpoint {
    /// Returns the QEMU VMState identity paired with this continuation.
    #[must_use]
    pub const fn execution_binding(&self) -> ContentHash {
        self.execution_binding
    }

    /// Returns the exact scheduler-visible node time at capture.
    #[must_use]
    pub const fn last_observed_time(&self) -> VirtualTime {
        self.last_observed_time
    }

    /// Returns the plugin logical/raw time pair captured with VMState.
    #[must_use]
    pub const fn logical_time_calibration(&self) -> crate::QemuLogicalTimeCalibration {
        self.logical_time_calibration
    }

    /// Returns the first fault-command sequence available after restore.
    #[must_use]
    pub const fn next_fault_command_sequence(&self) -> u64 {
        self.next_fault_command_sequence
    }

    /// Returns the next per-node fault event sequence required after restore.
    #[must_use]
    pub const fn next_fault_event_sequence(&self) -> u64 {
        self.next_fault_event_sequence
    }

    /// Encodes the complete scheduler-facing continuation canonically.
    #[must_use]
    pub fn to_compact_binary(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"crucible.qemu-node-continuation.v1\0");
        bytes.extend_from_slice(&self.execution_binding.bytes);
        bytes.extend_from_slice(&self.last_observed_time.ticks.to_le_bytes());
        bytes.extend_from_slice(&self.logical_time_calibration.logical_icount.to_le_bytes());
        bytes.extend_from_slice(&self.logical_time_calibration.raw_icount.to_le_bytes());
        bytes.extend_from_slice(&self.console_observation_boundary.ticks.to_le_bytes());
        match &self.pending_preemption {
            Some(preemption) => {
                bytes.push(1);
                write_node_continuation_blob(&mut bytes, &preemption.to_compact_binary());
            }
            None => bytes.push(0),
        }
        write_node_continuation_count(&mut bytes, self.pending_network_outputs.len());
        for frame in &self.pending_network_outputs {
            write_node_continuation_blob(&mut bytes, frame.source.name.as_bytes());
            write_node_continuation_blob(&mut bytes, frame.destination.name.as_bytes());
            bytes.extend_from_slice(&frame.emit_icount.retired.to_le_bytes());
            bytes.extend_from_slice(&frame.sequence.to_le_bytes());
            write_node_continuation_blob(&mut bytes, &frame.payload);
        }
        bytes.extend_from_slice(&self.next_fault_command_sequence.to_le_bytes());
        bytes.extend_from_slice(&self.next_fault_event_sequence.to_le_bytes());
        bytes
    }

    /// Decodes and validates a scheduler-facing continuation.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeCheckpointCodecError`] for unsupported, malformed,
    /// over-limit, binding-mismatched, or trailing state.
    pub fn from_compact_binary(
        bytes: &[u8],
        execution_binding: ContentHash,
    ) -> Result<Self, QemuNodeCheckpointCodecError> {
        const MAGIC: &[u8] = b"crucible.qemu-node-continuation.v1\0";
        let mut reader = NodeContinuationReader::new(bytes, MAGIC)?;
        let observed_binding = ContentHash {
            bytes: reader.fixed::<32>("execution binding")?,
        };
        if observed_binding != execution_binding {
            return Err(QemuNodeCheckpointCodecError::ExecutionBinding);
        }
        let last_observed_time = VirtualTime {
            ticks: reader.u64("last observed time")?,
        };
        let logical_time_calibration = crate::QemuLogicalTimeCalibration {
            logical_icount: reader.u64("logical icount")?,
            raw_icount: reader.u64("raw icount")?,
        };
        if logical_time_calibration.raw_icount > logical_time_calibration.logical_icount {
            return Err(QemuNodeCheckpointCodecError::LogicalTime);
        }
        let console_observation_boundary = VirtualTime {
            ticks: reader.u64("console boundary")?,
        };
        let pending_preemption = match reader.byte("preemption tag")? {
            0 => None,
            1 => Some(
                PreemptionDecision::from_compact_binary(reader.blob("preemption")?)
                    .map_err(|_| QemuNodeCheckpointCodecError::Preemption)?,
            ),
            _ => return Err(QemuNodeCheckpointCodecError::Malformed("preemption tag")),
        };
        let frame_count = reader.count("pending frame count", MAX_NODE_CONTINUATION_FRAMES)?;
        let mut pending_network_outputs = Vec::with_capacity(frame_count);
        for _ in 0..frame_count {
            let source = NodeId {
                name: reader.string("frame source")?,
            };
            let destination = NodeId {
                name: reader.string("frame destination")?,
            };
            let emit_icount = crucible::Icount {
                retired: reader.u64("frame emit icount")?,
            };
            let sequence = reader.u64("frame sequence")?;
            let payload = reader
                .blob_bounded("frame payload", MAX_NODE_CONTINUATION_PAYLOAD_BYTES)?
                .to_vec();
            pending_network_outputs.push(crate::QemuNodeEmittedFrame {
                source,
                destination,
                emit_icount,
                sequence,
                payload,
            });
        }
        let checkpoint = Self {
            execution_binding: observed_binding,
            last_observed_time,
            logical_time_calibration,
            console_observation_boundary,
            pending_preemption,
            pending_network_outputs,
            next_fault_command_sequence: reader.u64("fault command sequence")?,
            next_fault_event_sequence: reader.u64("fault event sequence")?,
        };
        reader.finish()?;
        if checkpoint.next_fault_command_sequence < 2 || checkpoint.next_fault_event_sequence == 0 {
            return Err(QemuNodeCheckpointCodecError::FaultSequence);
        }
        Ok(checkpoint)
    }
}

const MAX_NODE_CONTINUATION_FRAMES: usize = 1 << 20;
const MAX_NODE_CONTINUATION_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

/// Failure to decode a persisted QEMU node continuation.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum QemuNodeCheckpointCodecError {
    /// The codec version or magic does not match.
    #[error("unsupported QEMU node continuation format")]
    Unsupported,
    /// A named field is malformed or truncated.
    #[error("malformed QEMU node continuation field: {0}")]
    Malformed(&'static str),
    /// A collection or payload exceeds its compiled bound.
    #[error("QEMU node continuation field exceeds its bound: {0}")]
    Limit(&'static str),
    /// The decoded continuation belongs to another execution.
    #[error("QEMU node continuation execution binding mismatch")]
    ExecutionBinding,
    /// Logical time is behind raw QEMU time.
    #[error("QEMU node continuation has invalid logical time calibration")]
    LogicalTime,
    /// A pending preemption decision is malformed.
    #[error("QEMU node continuation has an invalid preemption decision")]
    Preemption,
    /// Fault transport sequence cursors are invalid.
    #[error("QEMU node continuation has invalid fault sequence cursors")]
    FaultSequence,
    /// Bytes follow the complete encoded value.
    #[error("QEMU node continuation has trailing bytes")]
    Trailing,
}

fn write_node_continuation_count(bytes: &mut Vec<u8>, count: usize) {
    bytes.extend_from_slice(&(count as u64).to_le_bytes());
}

fn write_node_continuation_blob(bytes: &mut Vec<u8>, value: &[u8]) {
    write_node_continuation_count(bytes, value.len());
    bytes.extend_from_slice(value);
}

struct NodeContinuationReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> NodeContinuationReader<'a> {
    fn new(bytes: &'a [u8], magic: &[u8]) -> Result<Self, QemuNodeCheckpointCodecError> {
        if !bytes.starts_with(magic) {
            return Err(QemuNodeCheckpointCodecError::Unsupported);
        }
        Ok(Self {
            bytes,
            offset: magic.len(),
        })
    }

    fn take(
        &mut self,
        length: usize,
        role: &'static str,
    ) -> Result<&'a [u8], QemuNodeCheckpointCodecError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(QemuNodeCheckpointCodecError::Limit(role))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(QemuNodeCheckpointCodecError::Malformed(role))?;
        self.offset = end;
        Ok(value)
    }

    fn fixed<const N: usize>(
        &mut self,
        role: &'static str,
    ) -> Result<[u8; N], QemuNodeCheckpointCodecError> {
        let mut value = [0_u8; N];
        value.copy_from_slice(self.take(N, role)?);
        Ok(value)
    }

    fn byte(&mut self, role: &'static str) -> Result<u8, QemuNodeCheckpointCodecError> {
        Ok(self.take(1, role)?[0])
    }

    fn u64(&mut self, role: &'static str) -> Result<u64, QemuNodeCheckpointCodecError> {
        Ok(u64::from_le_bytes(self.fixed(role)?))
    }

    fn count(
        &mut self,
        role: &'static str,
        maximum: usize,
    ) -> Result<usize, QemuNodeCheckpointCodecError> {
        let count = usize::try_from(self.u64(role)?)
            .map_err(|_| QemuNodeCheckpointCodecError::Limit(role))?;
        if count > maximum {
            return Err(QemuNodeCheckpointCodecError::Limit(role));
        }
        Ok(count)
    }

    fn blob(&mut self, role: &'static str) -> Result<&'a [u8], QemuNodeCheckpointCodecError> {
        self.blob_bounded(role, MAX_NODE_CONTINUATION_PAYLOAD_BYTES)
    }

    fn blob_bounded(
        &mut self,
        role: &'static str,
        maximum: usize,
    ) -> Result<&'a [u8], QemuNodeCheckpointCodecError> {
        let length = self.count(role, maximum)?;
        self.take(length, role)
    }

    fn string(&mut self, role: &'static str) -> Result<String, QemuNodeCheckpointCodecError> {
        String::from_utf8(self.blob(role)?.to_vec())
            .map_err(|_| QemuNodeCheckpointCodecError::Malformed(role))
    }

    fn finish(self) -> Result<(), QemuNodeCheckpointCodecError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(QemuNodeCheckpointCodecError::Trailing)
        }
    }
}

impl QemuHostIoCheckpoint {
    /// Builds a checkpoint for a runtime with no shared-memory host devices.
    #[must_use]
    pub const fn without_devices(execution_binding: ContentHash) -> Self {
        Self {
            execution_binding,
            block: None,
            ninep: None,
            #[cfg(target_os = "linux")]
            accelerator: None,
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) const fn with_devices(
        execution_binding: ContentHash,
        block: Option<QemuLiveBlockIoServicerCheckpoint>,
        ninep: Option<QemuLive9pIoServicerCheckpoint>,
        accelerator: Option<crate::QemuLiveAcceleratorCheckpoint>,
    ) -> Self {
        Self {
            execution_binding,
            block,
            ninep,
            accelerator,
        }
    }

    /// Returns the QEMU VMState identity paired with this host continuation.
    #[must_use]
    pub const fn execution_binding(&self) -> ContentHash {
        self.execution_binding
    }

    /// Returns the block continuation when the captured runtime owned one.
    #[must_use]
    pub const fn block(&self) -> Option<&QemuLiveBlockIoServicerCheckpoint> {
        self.block.as_ref()
    }

    /// Returns the 9p continuation when the captured runtime owned one.
    #[must_use]
    pub const fn ninep(&self) -> Option<&QemuLive9pIoServicerCheckpoint> {
        self.ninep.as_ref()
    }

    /// Returns the accelerator continuation when the captured runtime owned one.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub const fn accelerator(&self) -> Option<&crate::QemuLiveAcceleratorCheckpoint> {
        self.accelerator.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible::{Icount, IrqVector, PreemptionKind, VcpuId};

    #[test]
    fn node_continuation_codec_round_trips_complete_state() {
        let binding = ContentHash::from_bytes(b"node-continuation-binding");
        let checkpoint = QemuNodeContinuationCheckpoint {
            execution_binding: binding,
            last_observed_time: VirtualTime { ticks: 70 },
            logical_time_calibration: crate::QemuLogicalTimeCalibration {
                logical_icount: 70,
                raw_icount: 65,
            },
            console_observation_boundary: VirtualTime { ticks: 69 },
            pending_preemption: Some(PreemptionDecision {
                node: NodeId {
                    name: String::from("vm-0"),
                },
                at: Icount { retired: 71 },
                kind: PreemptionKind::InterruptAt {
                    target_vcpu: VcpuId { index: 1 },
                    irq: IrqVector { vector: 32 },
                },
            }),
            pending_network_outputs: vec![crate::QemuNodeEmittedFrame {
                source: NodeId {
                    name: String::from("vm-0"),
                },
                destination: NodeId {
                    name: String::from("vm-1"),
                },
                emit_icount: Icount { retired: 68 },
                sequence: 4,
                payload: vec![1, 2, 3],
            }],
            next_fault_command_sequence: 7,
            next_fault_event_sequence: 9,
        };
        let bytes = checkpoint.to_compact_binary();
        let restored = QemuNodeContinuationCheckpoint::from_compact_binary(&bytes, binding)
            .unwrap_or_else(|error| panic!("node continuation should decode: {error}"));
        assert_eq!(restored, checkpoint);
        assert_eq!(restored.to_compact_binary(), bytes);
    }

    #[test]
    fn node_continuation_codec_rejects_wrong_binding_and_trailing_bytes() {
        let binding = ContentHash::from_bytes(b"node-continuation-binding");
        let checkpoint = QemuNodeContinuationCheckpoint {
            execution_binding: binding,
            last_observed_time: VirtualTime { ticks: 1 },
            logical_time_calibration: crate::QemuLogicalTimeCalibration {
                logical_icount: 1,
                raw_icount: 1,
            },
            console_observation_boundary: VirtualTime { ticks: 1 },
            pending_preemption: None,
            pending_network_outputs: Vec::new(),
            next_fault_command_sequence: 2,
            next_fault_event_sequence: 1,
        };
        let mut bytes = checkpoint.to_compact_binary();
        assert_eq!(
            QemuNodeContinuationCheckpoint::from_compact_binary(
                &bytes,
                ContentHash::from_bytes(b"wrong")
            ),
            Err(QemuNodeCheckpointCodecError::ExecutionBinding)
        );
        bytes.push(0);
        assert_eq!(
            QemuNodeContinuationCheckpoint::from_compact_binary(&bytes, binding),
            Err(QemuNodeCheckpointCodecError::Trailing)
        );
    }
}
