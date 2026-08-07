//! Paired QEMU VMState and host-I/O checkpoint metadata.
//!
//! QEMU serializes guest and GPL-side device state into VMState. Apache-side
//! device continuations remain outside that process and are captured here. A
//! single execution binding joins the two halves so neither can be restored
//! with state from another checkpoint.

use crucible::{ContentHash, PreemptionDecision, VirtualTime};
use crucible_device::BlockSnapshot;
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
}

impl QemuHostIoCheckpoint {
    /// Builds a checkpoint for a runtime with no shared-memory block device.
    #[must_use]
    pub const fn without_block(execution_binding: ContentHash) -> Self {
        Self {
            execution_binding,
            block: None,
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) const fn with_block(
        execution_binding: ContentHash,
        block: QemuLiveBlockIoServicerCheckpoint,
    ) -> Self {
        Self {
            execution_binding,
            block: Some(block),
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
}
