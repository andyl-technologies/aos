//! Paired QEMU VMState and host-I/O checkpoint metadata.
//!
//! QEMU serializes guest and GPL-side device state into VMState. Apache-side
//! device continuations remain outside that process and are captured here. A
//! single execution binding joins the two halves so neither can be restored
//! with state from another checkpoint.

use crucible::{ContentHash, NodeId, PreemptionDecision, VirtualTime};
use crucible_device::{BlockSnapshot, NinepRequestOpportunity, NinepSnapshot};
use crucible_shmem::{RegionHeaderSnapshot, SpscRingSnapshot};

pub(crate) mod bounded_cbor;
mod host_io_codec;
pub use host_io_codec::QemuHostIoCheckpointCodecError;
mod node_codec;
pub use node_codec::QemuNodeCheckpointCodecError;
use node_codec::{
    MAX_NETWORK_QUEUE_FRAMES, MAX_NODE_CONTINUATION_BYTES, MAX_NODE_CONTINUATION_FRAMES,
    MAX_NODE_CONTINUATION_PAYLOAD_BYTES, MAX_NODE_CONTINUATION_RING_BYTES, NodeContinuationReader,
    admit_node_resource, checked_node_encoded_len, map_ring_decode_error, map_ring_encode_error,
    ring_canonical_len, write_node_continuation_blob, write_node_continuation_bytes,
    write_node_continuation_count,
};

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

/// Complete host-visible network-ring continuation paired with QEMU VMState.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuNetworkTransportCheckpoint {
    pub(crate) inbound: SpscRingSnapshot,
    pub(crate) outbound: SpscRingSnapshot,
    pub(crate) queue_capacity: u32,
    pub(crate) router_slot: u32,
    pub(crate) next_router_inbound_sequence: u64,
    pub(crate) next_host_outbound_sequence: u64,
    pub(crate) next_plugin_outbound_sequence: u64,
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
    pub(crate) network_transport: QemuNetworkTransportCheckpoint,
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

    /// Returns the next plugin-owned network TX sequence after restore.
    #[must_use]
    pub const fn next_plugin_network_output_sequence(&self) -> u64 {
        self.network_transport.next_plugin_outbound_sequence()
    }

    /// Returns the canonical retained inbound head and its attempt count.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeCheckpointCodecError::NetworkTransport`] when retained
    /// state is malformed or appears away from the unique ring head.
    pub fn retained_network_inbound_head(
        &self,
    ) -> Result<Option<(crucible_shmem::FrameDeliveryKey, u32)>, QemuNodeCheckpointCodecError> {
        let Some(key) = self.network_transport.retained_inbound_head()? else {
            return Ok(None);
        };
        let attempts = self
            .network_transport
            .inbound
            .frames
            .first()
            .filter(|frame| frame.delivery_key() == key)
            .map(crucible_shmem::SnapshotFrameEntry::delivery_attempts)
            .ok_or(QemuNodeCheckpointCodecError::NetworkTransport)?;
        Ok(Some((key, attempts)))
    }

    /// Encodes the complete scheduler-facing continuation canonically.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeCheckpointCodecError`] if a retained network ring is
    /// malformed, a field exceeds its configured bound, or the exact output
    /// allocation cannot be admitted.
    pub fn to_compact_binary(&self) -> Result<Vec<u8>, QemuNodeCheckpointCodecError> {
        self.network_transport.validate()?;
        let inbound_len =
            ring_canonical_len(&self.network_transport.inbound, "network inbound ring")?;
        let outbound_len =
            ring_canonical_len(&self.network_transport.outbound, "network outbound ring")?;
        admit_node_resource(
            "network inbound ring",
            0,
            inbound_len,
            MAX_NODE_CONTINUATION_RING_BYTES,
        )?;
        admit_node_resource(
            "network outbound ring",
            0,
            outbound_len,
            MAX_NODE_CONTINUATION_RING_BYTES,
        )?;
        admit_node_resource(
            "pending frame count",
            0,
            self.pending_network_outputs.len(),
            MAX_NODE_CONTINUATION_FRAMES as u64,
        )?;
        let preemption = self
            .pending_preemption
            .as_ref()
            .map(PreemptionDecision::to_compact_binary);
        if let Some(preemption) = preemption.as_deref() {
            admit_node_resource(
                "preemption",
                0,
                preemption.len(),
                MAX_NODE_CONTINUATION_PAYLOAD_BYTES as u64,
            )?;
        }
        let encoded_len = self.encoded_len(preemption.as_deref(), inbound_len, outbound_len)?;

        let mut bytes = Vec::new();
        bytes.try_reserve_exact(encoded_len).map_err(|_| {
            QemuNodeCheckpointCodecError::ResourceLimit {
                field: "node continuation",
                current: 0,
                requested: encoded_len as u64,
                configured: MAX_NODE_CONTINUATION_BYTES,
                hard: MAX_NODE_CONTINUATION_BYTES,
            }
        })?;
        write_node_continuation_bytes(
            &mut bytes,
            b"crucible.qemu-node-continuation.v6\0",
            "node continuation",
        )?;
        write_node_continuation_bytes(
            &mut bytes,
            &self.execution_binding.bytes,
            "execution binding",
        )?;
        write_node_continuation_bytes(
            &mut bytes,
            &self.last_observed_time.ticks.to_le_bytes(),
            "last observed time",
        )?;
        write_node_continuation_bytes(
            &mut bytes,
            &self.logical_time_calibration.logical_icount.to_le_bytes(),
            "logical icount",
        )?;
        write_node_continuation_bytes(
            &mut bytes,
            &self.logical_time_calibration.raw_icount.to_le_bytes(),
            "raw icount",
        )?;
        write_node_continuation_bytes(
            &mut bytes,
            &self.console_observation_boundary.ticks.to_le_bytes(),
            "console boundary",
        )?;
        match preemption {
            Some(preemption) => {
                write_node_continuation_bytes(&mut bytes, &[1], "preemption tag")?;
                write_node_continuation_blob(&mut bytes, &preemption, "preemption")?;
            }
            None => write_node_continuation_bytes(&mut bytes, &[0], "preemption tag")?,
        }
        write_node_continuation_count(
            &mut bytes,
            self.pending_network_outputs.len(),
            "pending frame count",
        )?;
        for frame in &self.pending_network_outputs {
            write_node_continuation_blob(&mut bytes, frame.source.name.as_bytes(), "frame source")?;
            write_node_continuation_blob(
                &mut bytes,
                frame.destination.name.as_bytes(),
                "frame destination",
            )?;
            write_node_continuation_bytes(
                &mut bytes,
                &frame.emit_icount.retired.to_le_bytes(),
                "frame emit icount",
            )?;
            write_node_continuation_bytes(
                &mut bytes,
                &frame.sequence.to_le_bytes(),
                "frame sequence",
            )?;
            write_node_continuation_blob(&mut bytes, &frame.payload, "frame payload")?;
        }
        write_node_continuation_bytes(
            &mut bytes,
            &self.network_transport.queue_capacity.to_le_bytes(),
            "network queue capacity",
        )?;
        write_node_continuation_bytes(
            &mut bytes,
            &self.network_transport.router_slot.to_le_bytes(),
            "network router slot",
        )?;
        write_node_continuation_count(&mut bytes, inbound_len, "network inbound ring")?;
        self.network_transport
            .inbound
            .append_canonical_bytes(&mut bytes)
            .map_err(|error| map_ring_encode_error(error, "network inbound ring"))?;
        write_node_continuation_count(&mut bytes, outbound_len, "network outbound ring")?;
        self.network_transport
            .outbound
            .append_canonical_bytes(&mut bytes)
            .map_err(|error| map_ring_encode_error(error, "network outbound ring"))?;
        write_node_continuation_bytes(
            &mut bytes,
            &self
                .network_transport
                .next_router_inbound_sequence
                .to_le_bytes(),
            "network inbound sequence",
        )?;
        write_node_continuation_bytes(
            &mut bytes,
            &self
                .network_transport
                .next_host_outbound_sequence
                .to_le_bytes(),
            "network host outbound sequence",
        )?;
        write_node_continuation_bytes(
            &mut bytes,
            &self
                .network_transport
                .next_plugin_outbound_sequence
                .to_le_bytes(),
            "network plugin outbound sequence",
        )?;
        write_node_continuation_bytes(
            &mut bytes,
            &self.next_fault_command_sequence.to_le_bytes(),
            "fault command sequence",
        )?;
        write_node_continuation_bytes(
            &mut bytes,
            &self.next_fault_event_sequence.to_le_bytes(),
            "fault event sequence",
        )?;
        debug_assert_eq!(bytes.len(), encoded_len);
        Ok(bytes)
    }

    fn encoded_len(
        &self,
        preemption: Option<&[u8]>,
        inbound_len: usize,
        outbound_len: usize,
    ) -> Result<usize, QemuNodeCheckpointCodecError> {
        let mut length = b"crucible.qemu-node-continuation.v6\0".len() + 32 + 32 + 1 + 8;
        if let Some(preemption) = preemption {
            length = checked_node_encoded_len(length, 8 + preemption.len(), "preemption")?;
        }
        for frame in &self.pending_network_outputs {
            for (role, blob) in [
                ("frame source", frame.source.name.as_bytes()),
                ("frame destination", frame.destination.name.as_bytes()),
                ("frame payload", frame.payload.as_slice()),
            ] {
                admit_node_resource(
                    role,
                    0,
                    blob.len(),
                    MAX_NODE_CONTINUATION_PAYLOAD_BYTES as u64,
                )?;
                length = checked_node_encoded_len(length, 8 + blob.len(), role)?;
            }
            length = checked_node_encoded_len(length, 16, "pending frame coordinates")?;
        }
        length = checked_node_encoded_len(length, 8, "network transport header")?;
        length = checked_node_encoded_len(length, 8 + inbound_len, "network inbound ring")?;
        length = checked_node_encoded_len(length, 8 + outbound_len, "network outbound ring")?;
        checked_node_encoded_len(length, 40, "network and fault sequence cursors")
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
        const MAGIC: &[u8] = b"crucible.qemu-node-continuation.v6\0";
        admit_node_resource(
            "node continuation",
            0,
            bytes.len(),
            MAX_NODE_CONTINUATION_BYTES,
        )?;
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
        let mut pending_network_outputs = Vec::new();
        pending_network_outputs
            .try_reserve_exact(frame_count)
            .map_err(|_| QemuNodeCheckpointCodecError::ResourceLimit {
                field: "pending frame count",
                current: 0,
                requested: frame_count as u64,
                configured: MAX_NODE_CONTINUATION_FRAMES as u64,
                hard: MAX_NODE_CONTINUATION_FRAMES as u64,
            })?;
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
                .owned_blob_bounded("frame payload", MAX_NODE_CONTINUATION_PAYLOAD_BYTES as u64)?;
            pending_network_outputs.push(crate::QemuNodeEmittedFrame {
                source,
                destination,
                emit_icount,
                sequence,
                payload,
            });
        }
        let queue_capacity = reader.u32("network queue capacity")?;
        let router_slot = reader.u32("network router slot")?;
        if queue_capacity > MAX_NETWORK_QUEUE_FRAMES {
            return Err(QemuNodeCheckpointCodecError::ResourceLimit {
                field: "network queue capacity",
                current: 0,
                requested: u64::from(queue_capacity),
                configured: u64::from(MAX_NETWORK_QUEUE_FRAMES),
                hard: u64::from(MAX_NETWORK_QUEUE_FRAMES),
            });
        }
        if queue_capacity == 0 || !queue_capacity.is_power_of_two() {
            return Err(QemuNodeCheckpointCodecError::NetworkTransport);
        }
        let inbound = SpscRingSnapshot::from_canonical_bytes(
            reader.blob_bounded("network inbound ring", MAX_NODE_CONTINUATION_RING_BYTES)?,
            queue_capacity as usize,
        )
        .map_err(|error| map_ring_decode_error(error, "network inbound ring", queue_capacity))?;
        let outbound = SpscRingSnapshot::from_canonical_bytes(
            reader.blob_bounded("network outbound ring", MAX_NODE_CONTINUATION_RING_BYTES)?,
            queue_capacity as usize,
        )
        .map_err(|error| map_ring_decode_error(error, "network outbound ring", queue_capacity))?;
        let network_transport = QemuNetworkTransportCheckpoint {
            inbound,
            outbound,
            queue_capacity,
            router_slot,
            next_router_inbound_sequence: reader.u64("network inbound sequence")?,
            next_host_outbound_sequence: reader.u64("network host outbound sequence")?,
            next_plugin_outbound_sequence: reader.u64("network plugin outbound sequence")?,
        };
        network_transport.validate()?;
        let checkpoint = Self {
            execution_binding: observed_binding,
            last_observed_time,
            logical_time_calibration,
            console_observation_boundary,
            pending_preemption,
            pending_network_outputs,
            network_transport,
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
#[path = "checkpoint/tests.rs"]
pub(crate) mod tests;
