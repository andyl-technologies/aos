//! QEMU per-quantum shared-memory hot path.
//!
//! RFC-0010 T-QEMU-12 requires the QEMU node step to be a shared-memory-only
//! cycle: observe the plugin-published node report, publish the scheduler's
//! ceiling, wake the parked plugin through the node-slot futex word, observe a
//! a plugin report at the authorized boundary in the same shared-memory slot,
//! and move frame records through SPSC rings. This module encodes that host-side data flow over
//! caller-supplied shared-memory ABI objects; it does not allocate private
//! shadow slots or use QMP/plugin IPC for per-quantum progress.

use crucible::{
    AdvanceOutcome, BackendInput, BasicBlockCoverageConfig, ContentHash, ExecutionFingerprint,
    ExecutionHorizon, Icount, NodeId, SchedulerError, SchedulerNodeId, SchedulerSendAuthorizer,
    SchedulingNodeKind,
};
use crucible_shmem::{
    AdvanceCeiling, FingerprintSample, FingerprintSampleSlot, FrameDeliveryKey, FrameEntry,
    FrameEntryError, LookaheadGateError, NodeSlot, NodeSlotError, NodeSlotSnapshot, RingHeader,
    STATUS_IDLE, SchedulerWakePublicationError, SpscRingError, authorize_advance_ceiling,
    validate_frame_delivery_is_future,
};
use thiserror::Error;

use crate::quantum_boundary::{QuantumBoundary, classify_quantum_boundary};
use crate::{
    QemuAsyncQuantumCompletion, QemuNodeChannelError, QemuNodeEmittedFrame, QemuNodeIdleState,
    QemuNodePendingQuantum, QemuShmemHotPathChannel,
};

const QUANTUM_FINGERPRINT_DOMAIN: &str = "crucible.qemu.quantum-shmem-fingerprint.v1";
const DEFAULT_ROUTER_SLOT: u32 = 31;

/// Configuration for one QEMU shared-memory quantum hot-path adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuQuantumShmemConfig {
    /// Logical node represented by the VM slot.
    pub node: NodeId,
    /// Logical router node used as the outbound frame destination.
    pub router: NodeId,
    /// Physical VM slot index in the shared-memory region.
    pub vm_slot: u32,
    /// Physical router slot index in the shared-memory region.
    pub router_slot: u32,
    /// Fixed icount shift used for virtual-time publication.
    pub shift_bits: u8,
    /// Observation-only basic-block coverage policy for the host drain.
    pub coverage: BasicBlockCoverageConfig,
}

impl QemuQuantumShmemConfig {
    /// Builds a default single-VM hot-path configuration.
    #[must_use]
    pub fn new(node: NodeId, vm_slot: u32) -> Self {
        Self {
            node,
            router: NodeId {
                name: String::from("net-router"),
            },
            vm_slot,
            router_slot: DEFAULT_ROUTER_SLOT,
            shift_bits: 0,
            coverage: BasicBlockCoverageConfig::off(),
        }
    }

    /// Returns this configuration with a different router node identity.
    #[must_use]
    pub fn with_router(mut self, router: NodeId, router_slot: u32) -> Self {
        self.router = router;
        self.router_slot = router_slot;
        self
    }

    /// Returns this configuration with a different fixed icount shift.
    #[must_use]
    pub const fn with_shift_bits(mut self, shift_bits: u8) -> Self {
        self.shift_bits = shift_bits;
        self
    }

    /// Returns this configuration with a registration-time coverage policy.
    #[must_use]
    pub const fn with_coverage(mut self, coverage: BasicBlockCoverageConfig) -> Self {
        self.coverage = coverage;
        self
    }
}

/// Borrowed shared-memory ABI objects for one QEMU node.
pub struct QemuQuantumShmemView<'a> {
    node_slot: &'a NodeSlot,
    fingerprint_sample: &'a FingerprintSampleSlot,
    inbound_ring: &'a RingHeader,
    inbound_entries: &'a mut [FrameEntry],
    outbound_ring: &'a RingHeader,
    outbound_entries: &'a mut [FrameEntry],
}

impl<'a> QemuQuantumShmemView<'a> {
    /// Borrows the mapped shared-memory node slot and directed rings for one VM.
    ///
    /// # Errors
    ///
    /// Returns [`QemuQuantumError`] when either ring slice is empty or not sized
    /// to a power-of-two SPSC capacity.
    pub fn new(
        node_slot: &'a NodeSlot,
        fingerprint_sample: &'a FingerprintSampleSlot,
        inbound_ring: &'a RingHeader,
        inbound_entries: &'a mut [FrameEntry],
        outbound_ring: &'a RingHeader,
        outbound_entries: &'a mut [FrameEntry],
    ) -> Result<Self, QemuQuantumError> {
        validate_queue_capacity(inbound_entries.len(), "inbound ring")?;
        validate_queue_capacity(outbound_entries.len(), "outbound ring")?;
        Ok(Self {
            node_slot,
            fingerprint_sample,
            inbound_ring,
            inbound_entries,
            outbound_ring,
            outbound_entries,
        })
    }
}

/// A frame delivered from the router toward this QEMU node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuInboundFrame {
    /// The icount at which the frame becomes eligible for QEMU injection.
    pub delivery_icount: Icount,
    /// The producing physical node slot.
    pub src_node: u32,
    /// Per-producer deterministic frame sequence.
    pub sequence: u32,
    /// Frame payload.
    pub payload: Vec<u8>,
}

/// An inbound frame whose delivery icount is due for the QEMU injection layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuDueInboundFrame {
    /// The logical destination VM node.
    pub destination: NodeId,
    /// The icount at which the frame becomes eligible for injection.
    pub delivery_icount: Icount,
    /// The producing physical node slot.
    pub src_node: u32,
    /// Per-producer deterministic frame sequence.
    pub sequence: u32,
    /// Frame payload.
    pub payload: Vec<u8>,
}

impl QemuDueInboundFrame {
    /// Returns the deterministic delivery key used for guest-visible ordering.
    #[must_use]
    pub fn delivery_key(&self) -> FrameDeliveryKey {
        FrameDeliveryKey {
            delivery_icount: self.delivery_icount.retired,
            src_node: self.src_node,
            seq: self.sequence,
        }
    }
}

/// A frame emitted by the guest-side plugin path toward the router ring.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuOutboundFrame {
    /// The emitting node icount.
    pub emit_icount: Icount,
    /// Per-emitter deterministic frame sequence.
    pub sequence: u32,
    /// Frame payload.
    pub payload: Vec<u8>,
}

/// A shared-memory observation of the node's device-I/O freeze flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuDeviceIoFreezeObservation {
    /// Node icount associated with this slot snapshot.
    pub current_icount: Icount,
    /// Whether the plugin had a device-I/O burst or request in flight.
    pub device_io_active: bool,
    /// Slot publish generation observed with the flag.
    pub publish_generation: u32,
}

/// Device-I/O freeze evidence observed across one QEMU quantum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuDeviceIoFreezeReport {
    /// Device-I/O freeze state before publishing the scheduler ceiling.
    pub initial: QemuDeviceIoFreezeObservation,
    /// Device-I/O freeze state after the plugin's completion report.
    pub final_state: QemuDeviceIoFreezeObservation,
}

impl QemuDeviceIoFreezeReport {
    /// Returns whether the slot reported an active device-I/O hold in this quantum.
    #[must_use]
    pub const fn was_active(&self) -> bool {
        self.initial.device_io_active || self.final_state.device_io_active
    }
}

/// The channel plane used by one operation in the quantum hot path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QemuQuantumOperationPlane {
    /// Shared-memory node slots, SPSC rings, and futex words.
    SharedMemory,
    /// Plugin IPC control channel.
    PluginIpcControl,
    /// QMP machine-control channel.
    QmpMachineControl,
}

/// One observable operation in the QEMU quantum data path.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum QemuQuantumOperation {
    /// Read the plugin-published node report from the node slot.
    ReadNodeReport,
    /// Compute a scheduler ceiling from the requested horizon and lookahead.
    ComputeSchedulerCeiling,
    /// Store `max_advance_icount` into the node slot.
    StoreSchedulerCeiling,
    /// Wake the plugin through the node-slot futex word.
    FutexWake,
    /// Observe the plugin report at the authorized boundary from the same node slot.
    ObservePluginReport,
    /// Read the completion report from the node slot.
    ReadCompletionReport,
    /// Enqueue a router-to-VM frame into the inbound SPSC ring.
    EnqueueInboundFrame,
    /// Drain currently due inbound frame records from the inbound SPSC ring.
    DrainDueInboundFrames,
    /// Enqueue a plugin-emitted VM-to-router frame into the outbound SPSC ring.
    EnqueueOutboundFrame,
    /// Dequeue a VM-to-router frame from the outbound SPSC ring.
    DequeueOutboundFrame,
    /// A forbidden plugin IPC operation, used by hot-path checks and tests.
    PluginIpcControlFrame {
        /// Operation name observed on the control channel.
        operation: &'static str,
    },
    /// A forbidden QMP operation, used by hot-path checks and tests.
    QmpCommand {
        /// QMP command observed on the hot path.
        command: &'static str,
    },
}

impl QemuQuantumOperation {
    /// Returns the channel plane touched by this operation.
    #[must_use]
    pub const fn plane(&self) -> QemuQuantumOperationPlane {
        match self {
            Self::ReadNodeReport
            | Self::ComputeSchedulerCeiling
            | Self::StoreSchedulerCeiling
            | Self::FutexWake
            | Self::ObservePluginReport
            | Self::ReadCompletionReport
            | Self::EnqueueInboundFrame
            | Self::DrainDueInboundFrames
            | Self::EnqueueOutboundFrame
            | Self::DequeueOutboundFrame => QemuQuantumOperationPlane::SharedMemory,
            Self::PluginIpcControlFrame { .. } => QemuQuantumOperationPlane::PluginIpcControl,
            Self::QmpCommand { .. } => QemuQuantumOperationPlane::QmpMachineControl,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::ReadNodeReport => "read-node-report",
            Self::ComputeSchedulerCeiling => "compute-scheduler-ceiling",
            Self::StoreSchedulerCeiling => "store-scheduler-ceiling",
            Self::FutexWake => "futex-wake",
            Self::ObservePluginReport => "observe-plugin-report",
            Self::ReadCompletionReport => "read-completion-report",
            Self::EnqueueInboundFrame => "enqueue-inbound-frame",
            Self::DrainDueInboundFrames => "drain-due-inbound-frames",
            Self::EnqueueOutboundFrame => "enqueue-outbound-frame",
            Self::DequeueOutboundFrame => "dequeue-outbound-frame",
            Self::PluginIpcControlFrame { operation } => operation,
            Self::QmpCommand { command } => command,
        }
    }
}

/// A published quantum that is waiting for an authorized boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuPendingQuantum {
    /// Initial node report read before publishing the scheduler ceiling.
    pub initial_state: QemuNodeIdleState,
    /// Horizon requested by the authoritative scheduler.
    pub requested_horizon: Icount,
    /// Scheduler-published ceiling.
    ///
    /// An already-enqueued inbound frame can cap this below
    /// [`Self::requested_horizon`]. The resulting completion is reported as a
    /// pause at the delivery boundary so the frame can become visible before
    /// the backend continues toward the original horizon in a fresh quantum.
    pub ceiling: Icount,
    /// Earliest delivery icount still valid for this scheduler pass.
    pub passed_delivery_floor: Icount,
    /// Device-I/O freeze state before publishing the scheduler ceiling.
    pub initial_device_io_freeze: QemuDeviceIoFreezeObservation,
    /// Node-slot publish generation observed before the wake.
    pub report_generation: u32,
    operation_start: usize,
    due_before_wake: Vec<QemuDueInboundFrame>,
}

/// A detailed report for one completed QEMU scheduler quantum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuQuantumReport {
    /// Initial node report read before publishing the scheduler ceiling.
    pub initial_state: QemuNodeIdleState,
    /// Scheduler-published ceiling.
    pub ceiling: Icount,
    /// Final node report after the plugin published completion state.
    pub final_state: QemuNodeIdleState,
    /// Backend-facing advance outcome for this quantum.
    pub outcome: AdvanceOutcome,
    /// Inbound frame records due for the QEMU injection layer.
    pub due_inbound_frames: Vec<QemuDueInboundFrame>,
    /// Outbound frames drained toward the router during this quantum.
    pub emitted_frames: Vec<QemuNodeEmittedFrame>,
    /// Device-I/O freeze state observed across this quantum.
    pub device_io_freeze: QemuDeviceIoFreezeReport,
    /// Operations performed by this quantum.
    pub operations: Vec<QemuQuantumOperation>,
}

/// Host-side QEMU shared-memory hot-path adapter.
pub struct QemuQuantumShmemHotPath<'a> {
    config: QemuQuantumShmemConfig,
    view: QemuQuantumShmemView<'a>,
    operation_log: Vec<QemuQuantumOperation>,
    next_router_inbound_sequence: u64,
    send_authorizer: &'a dyn SchedulerSendAuthorizer,
}

impl<'a> QemuQuantumShmemHotPath<'a> {
    /// Binds a QEMU quantum adapter to externally supplied shared-memory state.
    ///
    /// # Errors
    ///
    /// Returns [`QemuQuantumError`] when the fixed icount shift is outside the
    /// shared-memory ABI range.
    pub fn new(
        config: QemuQuantumShmemConfig,
        view: QemuQuantumShmemView<'a>,
        send_authorizer: &'a dyn SchedulerSendAuthorizer,
    ) -> Result<Self, QemuQuantumError> {
        if config.shift_bits >= 64 {
            return Err(QemuQuantumError::InvalidShift {
                shift_bits: config.shift_bits,
            });
        }
        Ok(Self {
            config,
            view,
            operation_log: Vec::new(),
            next_router_inbound_sequence: 0,
            send_authorizer,
        })
    }

    /// Returns a stable snapshot of the bound node slot.
    #[must_use]
    pub fn node_snapshot(&self) -> NodeSlotSnapshot {
        self.view.node_slot.snapshot()
    }

    /// Arms the shared slot for a quiesced VMState restore without waking QEMU.
    ///
    /// # Errors
    ///
    /// Returns [`QemuQuantumError`] when the restored instruction counter is
    /// behind the shared slot's currently published counter.
    pub fn arm_vmstate_restore_ceiling(
        &self,
        restored_icount: u64,
    ) -> Result<(), QemuQuantumError> {
        self.view
            .node_slot
            .arm_external_state_restore_ceiling(restored_icount)
            .map_err(|source| QemuQuantumError::NodeSlot {
                operation: "arm VMState restore ceiling",
                source,
            })
    }

    /// Returns the recorded operation log.
    #[must_use]
    pub fn operation_log(&self) -> &[QemuQuantumOperation] {
        &self.operation_log
    }

    /// Enqueues a deterministic inbound frame through the shared-memory ring.
    ///
    /// # Errors
    ///
    /// Returns [`QemuQuantumError`] when the frame is too large, is already late
    /// relative to the bound node slot, or cannot be enqueued.
    pub fn enqueue_inbound_frame(
        &mut self,
        frame: QemuInboundFrame,
    ) -> Result<(), QemuQuantumError> {
        let entry = self.inbound_entry_from_frame(frame)?;
        self.publish_inbound_entry_and_wake(&entry)?;
        Ok(())
    }

    /// Enqueues a plugin-emitted outbound frame through the shared-memory ring.
    ///
    /// # Errors
    ///
    /// Returns [`QemuQuantumError`] when the frame is too large or cannot be
    /// enqueued into the outbound ring.
    pub fn enqueue_outbound_frame_from_plugin(
        &mut self,
        frame: QemuOutboundFrame,
    ) -> Result<(), QemuQuantumError> {
        self.authorize_outbound_send("enqueue outbound frame")?;
        let entry = FrameEntry::new(
            frame.emit_icount.retired,
            self.config.vm_slot,
            frame.sequence,
            &frame.payload,
        )
        .map_err(|source| QemuQuantumError::FrameEntry { source })?;
        self.record(QemuQuantumOperation::EnqueueOutboundFrame);
        self.view
            .outbound_ring
            .enqueue(self.view.outbound_entries, &entry)
            .map_err(|source| QemuQuantumError::SpscRing {
                operation: "enqueue outbound frame",
                source,
            })
    }

    /// Starts one scheduler quantum by publishing the ceiling and futex wake.
    ///
    /// The bounded wait for the plugin's later publish is owned by T-QEMU-14;
    /// this method returns the pending token needed to finish the quantum after
    /// that report is present in shared memory.
    ///
    /// # Errors
    ///
    /// Returns [`QemuQuantumError`] when the requested horizon violates
    /// lookahead or the node slot rejects the scheduler ceiling.
    pub fn start_quantum(
        &mut self,
        horizon: ExecutionHorizon,
    ) -> Result<QemuPendingQuantum, QemuQuantumError> {
        let operation_start = self.operation_log.len();
        self.record(QemuQuantumOperation::ReadNodeReport);
        let initial_snapshot = self.view.node_slot.snapshot();
        let initial_state = idle_state_from_snapshot(initial_snapshot);
        let initial_device_io_freeze = device_io_freeze_from_snapshot(initial_snapshot);
        let passed_delivery_floor = initial_state.current_icount;
        let due_before_wake = self.drain_due_inbound_since(
            passed_delivery_floor.retired,
            initial_state.current_icount.retired,
        )?;

        self.record(QemuQuantumOperation::ComputeSchedulerCeiling);
        let earliest_delivery = self
            .view
            .inbound_ring
            .peek_delivery_icount(self.view.inbound_entries)
            .map_err(|source| QemuQuantumError::SpscRing {
                operation: "peek inbound delivery icount",
                source,
            })?;
        let effective_ceiling = earliest_delivery
            .map_or(horizon.icount.retired, |delivery_icount| {
                horizon.icount.retired.min(delivery_icount)
            });
        let ceiling = authorize_qemu_delivery_ceiling(
            initial_state.current_icount.retired,
            effective_ceiling,
            earliest_delivery,
        )
        .map_err(|source| QemuQuantumError::Lookahead { source })?;

        self.record(QemuQuantumOperation::StoreSchedulerCeiling);
        self.record(QemuQuantumOperation::FutexWake);
        self.view
            .node_slot
            .publish_scheduler_inbox_and_ceiling(
                self.config.vm_slot,
                self.config.router_slot,
                self.view.inbound_ring,
                self.view.inbound_entries,
                &[],
                ceiling,
            )
            .map_err(|source| QemuQuantumError::SchedulerWakePublication {
                operation: "publish scheduler inbox and ceiling",
                source,
            })?;

        Ok(QemuPendingQuantum {
            initial_state,
            requested_horizon: horizon.icount,
            ceiling: Icount {
                retired: effective_ceiling,
            },
            passed_delivery_floor,
            initial_device_io_freeze,
            report_generation: initial_snapshot.publish_gen,
            operation_start,
            due_before_wake,
        })
    }

    /// Finishes a pending quantum after the plugin has published shared-memory state.
    ///
    /// # Errors
    ///
    /// Returns [`QemuQuantumError`] when no later plugin report is visible yet,
    /// the report is incomplete, or a frame ring operation fails.
    pub fn finish_quantum(
        &mut self,
        pending: QemuPendingQuantum,
    ) -> Result<QemuQuantumReport, QemuQuantumError> {
        self.poll_quantum(&pending)
    }

    /// Polls a pending quantum without consuming its retry token.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::finish_quantum`]. In particular,
    /// [`QemuQuantumError::PluginReportNotPublished`] leaves `pending` valid for
    /// another bounded host-I/O wait and poll.
    pub fn poll_quantum(
        &mut self,
        pending: &QemuPendingQuantum,
    ) -> Result<QemuQuantumReport, QemuQuantumError> {
        self.record(QemuQuantumOperation::ObservePluginReport);
        let final_snapshot = self.view.node_slot.snapshot();
        let final_state = idle_state_from_snapshot(final_snapshot);
        if matches!(
            classify_quantum_boundary(&final_state, pending.ceiling.retired),
            QuantumBoundary::Pending
        ) {
            return Err(QemuQuantumError::PluginReportNotPublished {
                current_icount: final_snapshot.current_icount,
                ceiling: pending.ceiling.retired,
            });
        }

        self.record(QemuQuantumOperation::ReadCompletionReport);
        let final_device_io_freeze = device_io_freeze_from_snapshot(final_snapshot);
        let mut due_inbound_frames = pending.due_before_wake.clone();
        due_inbound_frames.extend(self.drain_due_inbound_since(
            final_state.current_icount.retired,
            final_state.current_icount.retired,
        )?);
        due_inbound_frames.sort_by_key(QemuDueInboundFrame::delivery_key);
        let emitted_frames = self.drain_emitted_outbound()?;
        let outcome = quantum_outcome(pending.requested_horizon, pending.ceiling, final_state)?;
        let operations = self.operation_log[pending.operation_start..].to_vec();
        assert_qemu_quantum_hot_path_is_shmem_only(&operations)?;

        Ok(QemuQuantumReport {
            initial_state: pending.initial_state,
            ceiling: pending.ceiling,
            final_state,
            outcome,
            due_inbound_frames,
            emitted_frames,
            device_io_freeze: QemuDeviceIoFreezeReport {
                initial: pending.initial_device_io_freeze,
                final_state: final_device_io_freeze,
            },
            operations,
        })
    }

    /// Runs one quantum when the plugin report is already available.
    ///
    /// This helper is useful for tests and already-quiesced cases. A production
    /// async driver should call [`Self::start_quantum`], wait with its bounded
    /// real-time policy, then call [`Self::finish_quantum`].
    ///
    /// # Errors
    ///
    /// Returns [`QemuQuantumError`] when either phase fails.
    pub fn run_one_quantum(
        &mut self,
        horizon: ExecutionHorizon,
    ) -> Result<QemuQuantumReport, QemuQuantumError> {
        let pending = self.start_quantum(horizon)?;
        self.finish_quantum(pending)
    }

    fn current_icount_from_slot(&self) -> Icount {
        Icount {
            retired: self.view.node_slot.snapshot().current_icount,
        }
    }

    fn drain_due_inbound_since(
        &mut self,
        passed_delivery_floor_icount: u64,
        current_icount: u64,
    ) -> Result<Vec<QemuDueInboundFrame>, QemuQuantumError> {
        if passed_delivery_floor_icount > current_icount {
            return Err(QemuQuantumError::InvalidDeliveryWindow {
                passed_delivery_floor_icount,
                current_icount,
            });
        }

        self.record(QemuQuantumOperation::DrainDueInboundFrames);
        let due_entries =
            self.preview_due_inbound_since(passed_delivery_floor_icount, current_icount)?;
        let mut frames = Vec::with_capacity(due_entries.len());
        for expected in due_entries {
            let Some(entry) = self
                .view
                .inbound_ring
                .dequeue(self.view.inbound_entries)
                .map_err(|source| QemuQuantumError::SpscRing {
                    operation: "dequeue inbound frame",
                    source,
                })?
            else {
                return Err(QemuQuantumError::DequeuedUnexpectedDelivery {
                    expected: expected.delivery_key(),
                    actual: FrameDeliveryKey {
                        delivery_icount: current_icount,
                        src_node: 0,
                        seq: 0,
                    },
                });
            };
            if entry.delivery_key() != expected.delivery_key() {
                return Err(QemuQuantumError::DequeuedUnexpectedDelivery {
                    expected: expected.delivery_key(),
                    actual: entry.delivery_key(),
                });
            }
            frames.push(self.due_inbound_frame_from_entry(entry)?);
        }
        frames.sort_by_key(QemuDueInboundFrame::delivery_key);
        Ok(frames)
    }

    fn preview_due_inbound_since(
        &self,
        passed_delivery_floor_icount: u64,
        current_icount: u64,
    ) -> Result<Vec<FrameEntry>, QemuQuantumError> {
        let capacity = inbound_ring_capacity(self.view.inbound_entries)?;
        let read_idx = self.view.inbound_ring.read_index();
        let write_idx = self.view.inbound_ring.write_index();
        let live = inbound_live_count(read_idx, write_idx, capacity)?;
        let mut frames = Vec::new();

        for offset in 0..live {
            let slot = ((read_idx.wrapping_add(offset)) & (capacity - 1)) as usize;
            let entry = self.view.inbound_entries[slot].clone();
            if entry.delivery_icount < passed_delivery_floor_icount {
                return Err(QemuQuantumError::DeliveryAlreadyPassed {
                    passed_delivery_floor_icount,
                    current_icount,
                    frame: entry.delivery_key(),
                });
            }
            if entry.delivery_icount > current_icount {
                break;
            }
            frames.push(entry);
        }
        Ok(frames)
    }

    fn drain_emitted_outbound(&mut self) -> Result<Vec<QemuNodeEmittedFrame>, QemuQuantumError> {
        let mut frames = Vec::new();
        while let Some(frame) = self.dequeue_authorized_emitted_outbound()? {
            frames.push(frame);
        }
        Ok(frames)
    }

    fn dequeue_authorized_emitted_outbound(
        &mut self,
    ) -> Result<Option<QemuNodeEmittedFrame>, QemuQuantumError> {
        let Some(_) = self
            .view
            .outbound_ring
            .peek(self.view.outbound_entries)
            .map_err(|source| QemuQuantumError::SpscRing {
                operation: "peek outbound frame",
                source,
            })?
        else {
            return Ok(None);
        };

        self.authorize_outbound_send("dequeue outbound frame")?;
        self.record(QemuQuantumOperation::DequeueOutboundFrame);
        let Some(entry) = self
            .view
            .outbound_ring
            .dequeue(self.view.outbound_entries)
            .map_err(|source| QemuQuantumError::SpscRing {
                operation: "dequeue outbound frame",
                source,
            })?
        else {
            return Ok(None);
        };
        Ok(Some(self.emitted_frame_from_entry(entry)?))
    }

    fn due_inbound_frame_from_entry(
        &self,
        entry: FrameEntry,
    ) -> Result<QemuDueInboundFrame, QemuQuantumError> {
        let payload = entry
            .payload()
            .map_err(|source| QemuQuantumError::FrameEntry { source })?
            .to_vec();
        Ok(QemuDueInboundFrame {
            destination: self.config.node.clone(),
            delivery_icount: Icount {
                retired: entry.delivery_icount,
            },
            src_node: entry.src_node,
            sequence: entry.seq,
            payload,
        })
    }

    fn emitted_frame_from_entry(
        &self,
        entry: FrameEntry,
    ) -> Result<QemuNodeEmittedFrame, QemuQuantumError> {
        let payload = entry
            .payload()
            .map_err(|source| QemuQuantumError::FrameEntry { source })?
            .to_vec();
        Ok(QemuNodeEmittedFrame {
            source: self.config.node.clone(),
            destination: self.config.router.clone(),
            emit_icount: Icount {
                retired: entry.delivery_icount,
            },
            sequence: u64::from(entry.seq),
            payload,
        })
    }

    fn inbound_entry_from_frame(
        &self,
        frame: QemuInboundFrame,
    ) -> Result<FrameEntry, QemuQuantumError> {
        let entry = FrameEntry::new(
            frame.delivery_icount.retired,
            frame.src_node,
            frame.sequence,
            &frame.payload,
        )
        .map_err(|source| QemuQuantumError::FrameEntry { source })?;
        let current_icount = self.view.node_slot.snapshot().current_icount;
        validate_frame_delivery_is_future(&entry, current_icount)
            .map_err(|source| QemuQuantumError::Lookahead { source })?;
        Ok(entry)
    }

    fn publish_inbound_entry_and_wake(
        &mut self,
        entry: &FrameEntry,
    ) -> Result<(), QemuQuantumError> {
        self.record(QemuQuantumOperation::EnqueueInboundFrame);
        self.record(QemuQuantumOperation::StoreSchedulerCeiling);
        self.record(QemuQuantumOperation::FutexWake);
        let snapshot = self.view.node_slot.snapshot();
        let ceiling =
            authorize_advance_ceiling(snapshot.current_icount, snapshot.max_advance_icount, None)
                .map_err(|source| QemuQuantumError::Lookahead { source })?;
        self.view
            .node_slot
            .publish_scheduler_inbox_and_ceiling(
                self.config.vm_slot,
                entry.src_node,
                self.view.inbound_ring,
                self.view.inbound_entries,
                std::slice::from_ref(entry),
                ceiling,
            )
            .map_err(|source| QemuQuantumError::SchedulerWakePublication {
                operation: "publish inbound frame and scheduler ceiling",
                source,
            })?;
        Ok(())
    }

    fn authorize_outbound_send(&self, operation: &'static str) -> Result<(), QemuQuantumError> {
        let producer = qemu_scheduler_node(&self.config.node, SchedulingNodeKind::Vm);
        let consumer = qemu_scheduler_node(&self.config.router, SchedulingNodeKind::Network);
        self.send_authorizer
            .authorize_cross_node_send(&producer, &consumer)
            .map_err(|source| QemuQuantumError::SchedulerSendAuthorization { operation, source })?;
        Ok(())
    }

    fn record(&mut self, operation: QemuQuantumOperation) {
        self.operation_log.push(operation);
    }

    fn next_router_inbound_sequence(&self) -> Result<u32, QemuQuantumError> {
        u32::try_from(self.next_router_inbound_sequence).map_err(|_| {
            QemuQuantumError::InboundSequenceOverflow {
                next_sequence: self.next_router_inbound_sequence,
            }
        })
    }

    fn commit_router_inbound_sequence(&mut self) -> Result<(), QemuQuantumError> {
        self.next_router_inbound_sequence = self
            .next_router_inbound_sequence
            .checked_add(1)
            .ok_or(QemuQuantumError::InboundSequenceOverflow {
                next_sequence: self.next_router_inbound_sequence,
            })?;
        Ok(())
    }
}

impl QemuShmemHotPathChannel for QemuQuantumShmemHotPath<'_> {
    fn current_icount(&mut self) -> Result<Icount, QemuNodeChannelError> {
        self.record(QemuQuantumOperation::ReadNodeReport);
        Ok(self.current_icount_from_slot())
    }

    fn logical_time_calibration(
        &mut self,
    ) -> Result<crate::QemuLogicalTimeCalibration, QemuNodeChannelError> {
        self.record(QemuQuantumOperation::ReadNodeReport);
        let snapshot = self.node_snapshot();
        let calibration = crate::QemuLogicalTimeCalibration {
            logical_icount: snapshot.current_icount,
            raw_icount: snapshot.logical_time_raw_icount,
        };
        let _offset = calibration.offset()?;
        Ok(calibration)
    }

    fn start_quantum(
        &mut self,
        horizon: ExecutionHorizon,
    ) -> Result<QemuNodePendingQuantum, QemuNodeChannelError> {
        QemuQuantumShmemHotPath::start_quantum(self, horizon)
            .map(QemuNodePendingQuantum::new)
            .map_err(QemuNodeChannelError::from)
    }

    fn poll_quantum(
        &mut self,
        pending: &mut QemuNodePendingQuantum,
    ) -> Result<QemuAsyncQuantumCompletion, QemuNodeChannelError> {
        let pending = pending.downcast_mut::<QemuPendingQuantum>("finish_quantum")?;
        QemuQuantumShmemHotPath::poll_quantum(self, pending)
            .map(QemuAsyncQuantumCompletion::from)
            .map_err(QemuNodeChannelError::from)
    }

    fn publish_preemption_command(
        &mut self,
        command: crucible_shmem::SchedulerPreemptionCommand,
    ) -> Result<(), QemuNodeChannelError> {
        self.view
            .node_slot
            .publish_preemption_command(command)
            .map(|_| ())
            .map_err(|source| {
                QemuNodeChannelError::new("publish_preemption_command", source.to_string())
            })
    }

    fn enqueue_fault_command(
        &mut self,
        _header: crucible_shmem::FaultCommandHeaderV1,
        _payload: &[u8],
    ) -> Result<(), QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "enqueue_fault_command",
            "the borrowed quantum view does not own the mapped fault transport",
        ))
    }

    fn dequeue_fault_result(
        &mut self,
    ) -> Result<Option<crucible_shmem::DequeuedFaultResult>, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "dequeue_fault_result",
            "the borrowed quantum view does not own the mapped fault transport",
        ))
    }

    fn dequeue_fault_event(
        &mut self,
    ) -> Result<Option<crucible_shmem::DequeuedFaultEvent>, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "dequeue_fault_event",
            "the borrowed quantum view does not own the mapped fault transport",
        ))
    }

    fn fault_event_pending(&mut self) -> Result<bool, QemuNodeChannelError> {
        Err(QemuNodeChannelError::new(
            "fault_event_pending",
            "the borrowed quantum view does not own the mapped fault transport",
        ))
    }

    fn deliver_frame(&mut self, input: BackendInput) -> Result<(), QemuNodeChannelError> {
        let delivery_icount = Icount {
            retired: self.current_icount_from_slot().retired.saturating_add(1),
        };
        self.deliver_frame_at(input, delivery_icount)
    }

    fn deliver_frame_at(
        &mut self,
        // crucible-lint: allow host-nondeterminism-state -- the erased channel preserves the scheduler-owned input and exact delivery point.
        input: BackendInput,
        delivery_icount: Icount,
    ) -> Result<(), QemuNodeChannelError> {
        let sequence = self
            .next_router_inbound_sequence()
            .map_err(QemuNodeChannelError::from)?;
        let entry = self
            .inbound_entry_from_frame(QemuInboundFrame {
                delivery_icount,
                src_node: self.config.router_slot,
                sequence,
                payload: input.payload,
            })
            .map_err(QemuNodeChannelError::from)?;
        self.publish_inbound_entry_and_wake(&entry)
            .map_err(QemuNodeChannelError::from)?;
        self.commit_router_inbound_sequence()
            .map_err(QemuNodeChannelError::from)
    }

    fn emit_frame(&mut self) -> Result<Option<QemuNodeEmittedFrame>, QemuNodeChannelError> {
        self.dequeue_authorized_emitted_outbound()
            .map_err(QemuNodeChannelError::from)
    }

    fn idle_state(&mut self) -> Result<QemuNodeIdleState, QemuNodeChannelError> {
        self.record(QemuQuantumOperation::ReadNodeReport);
        Ok(idle_state_from_snapshot(self.view.node_slot.snapshot()))
    }

    fn execution_fingerprint(&mut self) -> Result<ExecutionFingerprint, QemuNodeChannelError> {
        self.record(QemuQuantumOperation::ReadNodeReport);
        let snapshot = self.view.node_slot.snapshot();
        let material = format!(
            "node={}\ncurrent_icount={}\ncurrent_ns={}\nmax_advance_icount={}\nidle_wake_icount={}\nstatus={}\ndevice_io_active={}\ninbound_read_idx={}\ninbound_write_idx={}\noutbound_read_idx={}\noutbound_write_idx={}\n",
            self.config.node.name,
            snapshot.current_icount,
            snapshot.current_ns,
            snapshot.max_advance_icount,
            snapshot.idle_wake_icount,
            snapshot.status,
            snapshot.device_io_active,
            self.view.inbound_ring.read_index(),
            self.view.inbound_ring.write_index(),
            self.view.outbound_ring.read_index(),
            self.view.outbound_ring.write_index(),
        );
        Ok(ExecutionFingerprint {
            hash: ContentHash::from_canonical_material(QUANTUM_FINGERPRINT_DOMAIN, &material),
        })
    }

    fn fingerprint_sample(&mut self) -> Result<FingerprintSample, QemuNodeChannelError> {
        self.record(QemuQuantumOperation::ReadNodeReport);
        self.view.fingerprint_sample.snapshot().ok_or_else(|| {
            QemuNodeChannelError::retryable(
                "fingerprint_sample",
                "the plugin has not published a black-box fingerprint sample",
            )
        })
    }
}

impl From<QemuQuantumError> for QemuNodeChannelError {
    fn from(error: QemuQuantumError) -> Self {
        if matches!(error, QemuQuantumError::PluginReportNotPublished { .. }) {
            Self::retryable("qemu_quantum_shmem_hot_path", error.to_string())
        } else {
            Self::new("qemu_quantum_shmem_hot_path", error.to_string())
        }
    }
}

/// Asserts that every operation in a quantum touched only shared memory.
///
/// # Errors
///
/// Returns [`QemuQuantumError::NonShmemHotPathOperation`] when a QMP or plugin
/// IPC operation is present in the supplied operation log.
pub fn assert_qemu_quantum_hot_path_is_shmem_only(
    operations: &[QemuQuantumOperation],
) -> Result<(), QemuQuantumError> {
    for operation in operations {
        let plane = operation.plane();
        if plane != QemuQuantumOperationPlane::SharedMemory {
            return Err(QemuQuantumError::NonShmemHotPathOperation {
                operation: operation.name(),
                plane,
            });
        }
    }
    Ok(())
}

fn validate_queue_capacity(capacity: usize, ring: &'static str) -> Result<(), QemuQuantumError> {
    if capacity == 0 || !capacity.is_power_of_two() {
        Err(QemuQuantumError::InvalidQueueCapacity { capacity, ring })
    } else {
        Ok(())
    }
}

fn inbound_ring_capacity(entries: &[FrameEntry]) -> Result<u64, QemuQuantumError> {
    if entries.is_empty() || !entries.len().is_power_of_two() {
        Err(QemuQuantumError::SpscRing {
            operation: "preview inbound frame",
            source: SpscRingError::InvalidCapacity {
                capacity: entries.len(),
            },
        })
    } else {
        Ok(entries.len() as u64)
    }
}

fn inbound_live_count(
    read_idx: u64,
    write_idx: u64,
    capacity: u64,
) -> Result<u64, QemuQuantumError> {
    let live = write_idx
        .checked_sub(read_idx)
        .ok_or_else(|| corrupt_inbound_indices(read_idx, write_idx, capacity))?;
    if live > capacity {
        Err(corrupt_inbound_indices(read_idx, write_idx, capacity))
    } else {
        Ok(live)
    }
}

fn corrupt_inbound_indices(read_idx: u64, write_idx: u64, capacity: u64) -> QemuQuantumError {
    QemuQuantumError::SpscRing {
        operation: "preview inbound frame",
        source: SpscRingError::CorruptIndices {
            read_idx,
            write_idx,
            capacity,
        },
    }
}

fn authorize_qemu_delivery_ceiling(
    current_icount: u64,
    max_advance_icount: u64,
    earliest_possible_delivery_icount: Option<u64>,
) -> Result<AdvanceCeiling, LookaheadGateError> {
    if earliest_possible_delivery_icount == Some(max_advance_icount) {
        authorize_advance_ceiling(current_icount, max_advance_icount, None)
    } else {
        authorize_advance_ceiling(
            current_icount,
            max_advance_icount,
            earliest_possible_delivery_icount,
        )
    }
}

pub(crate) fn idle_state_from_snapshot(snapshot: NodeSlotSnapshot) -> QemuNodeIdleState {
    QemuNodeIdleState {
        current_icount: Icount {
            retired: snapshot.current_icount,
        },
        next_deadline: (snapshot.status == STATUS_IDLE).then_some(Icount {
            retired: snapshot.idle_wake_icount,
        }),
    }
}

fn device_io_freeze_from_snapshot(snapshot: NodeSlotSnapshot) -> QemuDeviceIoFreezeObservation {
    QemuDeviceIoFreezeObservation {
        current_icount: Icount {
            retired: snapshot.current_icount,
        },
        device_io_active: snapshot.device_io_active != 0,
        publish_generation: snapshot.publish_gen,
    }
}

fn qemu_scheduler_node(node: &NodeId, kind: SchedulingNodeKind) -> SchedulerNodeId {
    SchedulerNodeId {
        node: node.clone(),
        kind,
    }
}

fn quantum_outcome(
    requested_horizon: Icount,
    published_ceiling: Icount,
    final_state: QemuNodeIdleState,
) -> Result<AdvanceOutcome, QemuQuantumError> {
    if final_state.current_icount.retired >= requested_horizon.retired {
        return Ok(AdvanceOutcome::ReachedHorizon);
    }
    if (published_ceiling.retired < requested_horizon.retired
        && final_state.current_icount.retired >= published_ceiling.retired)
        || final_state.next_deadline.is_some()
    {
        return Ok(AdvanceOutcome::Paused {
            at: final_state.current_icount,
        });
    }
    Err(QemuQuantumError::IncompleteQuantumReport {
        current_icount: final_state.current_icount.retired,
        ceiling: published_ceiling.retired,
    })
}

/// An error produced by the QEMU quantum shared-memory hot path.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum QemuQuantumError {
    /// A borrowed SPSC ring slice was not a nonzero power-of-two capacity.
    #[error("QEMU quantum {ring} capacity {capacity} is not a nonzero power of two")]
    InvalidQueueCapacity {
        /// Ring name.
        ring: &'static str,
        /// Rejected capacity.
        capacity: usize,
    },
    /// The fixed icount shift was outside the shared-memory ABI range.
    #[error("QEMU quantum icount shift {shift_bits} is invalid")]
    InvalidShift {
        /// Rejected shift.
        shift_bits: u8,
    },
    /// A frame entry could not be built or read.
    #[error("QEMU quantum frame-entry error: {source}")]
    FrameEntry {
        /// Underlying frame-entry error.
        source: FrameEntryError,
    },
    /// The scheduler-facing router input sequence space is exhausted.
    #[error("QEMU quantum inbound router sequence overflow at {next_sequence}")]
    InboundSequenceOverflow {
        /// The next sequence that cannot be represented in a frame key.
        next_sequence: u64,
    },
    /// A shared-memory SPSC ring operation failed.
    #[error("QEMU quantum SPSC operation {operation} failed: {source}")]
    SpscRing {
        /// Ring operation being attempted.
        operation: &'static str,
        /// Underlying ring error.
        source: SpscRingError,
    },
    /// The lookahead gate rejected a ceiling or frame delivery.
    #[error("QEMU quantum lookahead rejected request: {source}")]
    Lookahead {
        /// Underlying lookahead error.
        source: LookaheadGateError,
    },
    /// The caller supplied an impossible delivery window.
    #[error(
        "QEMU quantum inbound delivery floor {passed_delivery_floor_icount} is after current icount {current_icount}"
    )]
    InvalidDeliveryWindow {
        /// The earliest delivery icount still valid for this scheduler pass.
        passed_delivery_floor_icount: u64,
        /// Current consumer icount observed in the node slot.
        current_icount: u64,
    },
    /// An inbound frame should already have been visible to the guest.
    #[error(
        "QEMU quantum inbound frame {frame:?} is behind delivery floor {passed_delivery_floor_icount} at current icount {current_icount}"
    )]
    DeliveryAlreadyPassed {
        /// The earliest delivery icount still valid for this scheduler pass.
        passed_delivery_floor_icount: u64,
        /// Current consumer icount observed in the node slot.
        current_icount: u64,
        /// The late frame's deterministic delivery key.
        frame: FrameDeliveryKey,
    },
    /// A post-preview dequeue did not consume the frame that was validated.
    #[error("QEMU quantum inbound commit dequeued frame {actual:?} after previewing {expected:?}")]
    DequeuedUnexpectedDelivery {
        /// The expected deterministic delivery key.
        expected: FrameDeliveryKey,
        /// The actual deterministic delivery key.
        actual: FrameDeliveryKey,
    },
    /// The node-slot handoff rejected a state transition.
    #[error("QEMU quantum node-slot operation {operation} failed: {source}")]
    NodeSlot {
        /// Node-slot operation being attempted.
        operation: &'static str,
        /// Underlying node-slot error.
        source: NodeSlotError,
    },
    /// The ordered scheduler inbox/ceiling/wake publication failed.
    #[error("QEMU quantum scheduler wake operation {operation} failed: {source}")]
    SchedulerWakePublication {
        /// Ordered scheduler wake operation being attempted.
        operation: &'static str,
        /// Underlying ordered scheduler wake error.
        source: SchedulerWakePublicationError,
    },
    /// Scheduler topology state rejected a VM-to-router send.
    #[error("QEMU quantum scheduler send authorization for {operation} failed: {source}")]
    SchedulerSendAuthorization {
        /// Operation being attempted.
        operation: &'static str,
        /// Underlying scheduler authorization error.
        source: SchedulerError,
    },
    /// No later plugin report is visible in the shared-memory node slot yet.
    #[error(
        "QEMU quantum plugin report is not yet visible at icount {current_icount} before ceiling {ceiling}"
    )]
    PluginReportNotPublished {
        /// Current icount in the still-stale node report.
        current_icount: u64,
        /// Requested ceiling.
        ceiling: u64,
    },
    /// The plugin did not publish a terminal state for the requested quantum.
    #[error("QEMU quantum report stopped at icount {current_icount} before ceiling {ceiling}")]
    IncompleteQuantumReport {
        /// Current icount in the plugin report.
        current_icount: u64,
        /// Requested ceiling.
        ceiling: u64,
    },
    /// A QMP or plugin IPC operation appeared in the per-quantum hot path.
    #[error("QEMU quantum hot path operation {operation} used forbidden plane {plane:?}")]
    NonShmemHotPathOperation {
        /// Forbidden operation name.
        operation: &'static str,
        /// Forbidden operation plane.
        plane: QemuQuantumOperationPlane,
    },
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    mod completion;
    mod network_delivery;
    use crucible_shmem::{AdvanceCeiling, FrameEntry, NodeSlot, STATUS_IDLE, STATUS_RUNNING};

    const QUANTUM_SOURCE: &str = include_str!("quantum.rs");
    static ALLOW_ALL_SENDS: AllowAllSchedulerSendAuthorizer = AllowAllSchedulerSendAuthorizer;

    struct AllowAllSchedulerSendAuthorizer;

    impl crucible::SchedulerSendAuthorizer for AllowAllSchedulerSendAuthorizer {
        fn authorize_cross_node_send(
            &self,
            producer: &crucible::SchedulerNodeId,
            consumer: &crucible::SchedulerNodeId,
        ) -> Result<crucible::SchedulerSendAuthorization, crucible::SchedulerError> {
            Ok(crucible::SchedulerSendAuthorization {
                producer: producer.clone(),
                consumer: consumer.clone(),
                topology_epoch: 0,
            })
        }
    }

    #[test]
    fn qemu_quantum_binds_external_shmem_and_finishes_after_plugin_report() {
        let slot = NodeSlot::default();
        let inbound_ring = RingHeader::new();
        let outbound_ring = RingHeader::new();
        let mut inbound_entries = frame_entries(8);
        let mut outbound_entries = frame_entries(8);
        let mut hot_path = hot_path(
            &slot,
            &inbound_ring,
            &mut inbound_entries,
            &outbound_ring,
            &mut outbound_entries,
        );

        let pending = match hot_path.start_quantum(horizon(10)) {
            Ok(pending) => pending,
            Err(error) => panic!("quantum start should publish ceiling: {error}"),
        };
        assert_eq!(slot.snapshot().max_advance_icount, 10);
        assert_eq!(slot.snapshot().current_icount, 0);
        assert!(
            hot_path
                .operation_log()
                .contains(&QemuQuantumOperation::FutexWake)
        );

        if let Err(error) = slot.publish_reached_icount(10, 0) {
            panic!("plugin report should publish through shared node slot: {error}");
        }
        let report = match hot_path.finish_quantum(pending) {
            Ok(report) => report,
            Err(error) => panic!("quantum finish should observe plugin report: {error}"),
        };

        assert_eq!(report.initial_state.current_icount, icount(0));
        assert_eq!(report.ceiling, icount(10));
        assert_eq!(report.final_state.current_icount, icount(10));
        assert_eq!(report.outcome, AdvanceOutcome::ReachedHorizon);
        assert!(report.due_inbound_frames.is_empty());
        assert!(report.emitted_frames.is_empty());
        assert!(assert_qemu_quantum_hot_path_is_shmem_only(&report.operations).is_ok());
        assert!(
            report
                .operations
                .contains(&QemuQuantumOperation::ReadNodeReport)
        );
        assert!(
            report
                .operations
                .contains(&QemuQuantumOperation::StoreSchedulerCeiling)
        );
        assert!(report.operations.contains(&QemuQuantumOperation::FutexWake));
        assert!(
            report
                .operations
                .contains(&QemuQuantumOperation::ObservePluginReport)
        );
        assert_eq!(slot.snapshot().status, STATUS_RUNNING);
    }

    #[test]
    fn qemu_quantum_start_uses_ordered_scheduler_wake_handoff() {
        let source = function_source("pub fn start_quantum(");
        assert_source_order(
            source,
            &[
                "self.record(QemuQuantumOperation::StoreSchedulerCeiling);",
                "self.record(QemuQuantumOperation::FutexWake);",
                ".publish_scheduler_inbox_and_ceiling(",
                "self.config.vm_slot,",
                "self.config.router_slot,",
                "self.view.inbound_ring,",
                "self.view.inbound_entries,",
                "&[],",
                "ceiling,",
            ],
            "QEMU start_quantum must publish RUN through the ordered inbox/ceiling/wake helper",
        );
    }

    #[test]
    fn qemu_quantum_inbound_uses_ordered_scheduler_wake_handoff() {
        let source = function_source("fn publish_inbound_entry_and_wake(");
        assert_source_order(
            source,
            &[
                "self.record(QemuQuantumOperation::EnqueueInboundFrame);",
                "self.record(QemuQuantumOperation::StoreSchedulerCeiling);",
                "self.record(QemuQuantumOperation::FutexWake);",
                ".publish_scheduler_inbox_and_ceiling(",
                "self.config.vm_slot,",
                "entry.src_node,",
                "self.view.inbound_ring,",
                "self.view.inbound_entries,",
                "std::slice::from_ref(entry),",
                "ceiling,",
            ],
            "QEMU inbound publication must publish the nonempty inbox frame through the ordered helper",
        );
    }

    #[test]
    fn qemu_quantum_rejects_finish_before_reaching_a_boundary() {
        let slot = NodeSlot::default();
        let inbound_ring = RingHeader::new();
        let outbound_ring = RingHeader::new();
        let mut inbound_entries = frame_entries(8);
        let mut outbound_entries = frame_entries(8);
        let mut hot_path = hot_path(
            &slot,
            &inbound_ring,
            &mut inbound_entries,
            &outbound_ring,
            &mut outbound_entries,
        );

        let pending = match hot_path.start_quantum(horizon(10)) {
            Ok(pending) => pending,
            Err(error) => panic!("quantum start should publish ceiling: {error}"),
        };
        let result = hot_path.finish_quantum(pending);

        assert!(matches!(
            result,
            Err(QemuQuantumError::PluginReportNotPublished {
                current_icount: 0,
                ceiling: 10,
            })
        ));
    }

    #[test]
    fn qemu_quantum_reports_idle_before_horizon() {
        let slot = NodeSlot::default();
        let inbound_ring = RingHeader::new();
        let outbound_ring = RingHeader::new();
        let mut inbound_entries = frame_entries(8);
        let mut outbound_entries = frame_entries(8);
        let mut hot_path = hot_path(
            &slot,
            &inbound_ring,
            &mut inbound_entries,
            &outbound_ring,
            &mut outbound_entries,
        );

        let pending = match hot_path.start_quantum(horizon(10)) {
            Ok(pending) => pending,
            Err(error) => panic!("quantum start should publish ceiling: {error}"),
        };
        if let Err(error) = slot.publish_idle(4, 12, 0) {
            panic!("plugin idle report should publish through shared node slot: {error}");
        }
        let report = match hot_path.finish_quantum(pending) {
            Ok(report) => report,
            Err(error) => panic!("idle quantum should finish: {error}"),
        };

        assert_eq!(report.outcome, AdvanceOutcome::Paused { at: icount(4) });
        assert_eq!(report.final_state.current_icount, icount(4));
        assert_eq!(report.final_state.next_deadline, Some(icount(12)));
        assert_eq!(slot.snapshot().status, STATUS_IDLE);
        assert_eq!(slot.snapshot().idle_wake_icount, 12);
    }

    #[test]
    fn qemu_quantum_accepts_exact_delivery_horizon_in_total_order() {
        let slot = NodeSlot::default();
        let inbound_ring = RingHeader::new();
        let outbound_ring = RingHeader::new();
        let mut inbound_entries = frame_entries(8);
        let mut outbound_entries = frame_entries(8);
        let mut hot_path = hot_path(
            &slot,
            &inbound_ring,
            &mut inbound_entries,
            &outbound_ring,
            &mut outbound_entries,
        );
        let enqueue = hot_path.enqueue_inbound_frame(QemuInboundFrame {
            delivery_icount: icount(5),
            src_node: 9,
            sequence: 4,
            payload: b"second".to_vec(),
        });
        assert!(enqueue.is_ok());
        let enqueue = hot_path.enqueue_inbound_frame(QemuInboundFrame {
            delivery_icount: icount(5),
            src_node: 1,
            sequence: 7,
            payload: b"first".to_vec(),
        });
        assert!(enqueue.is_ok());
        let enqueue = hot_path.enqueue_inbound_frame(QemuInboundFrame {
            delivery_icount: icount(5),
            src_node: 9,
            sequence: 5,
            payload: b"third".to_vec(),
        });
        assert!(enqueue.is_ok());

        let result = hot_path.start_quantum(horizon(5));

        let pending = match result {
            Ok(pending) => pending,
            Err(error) => panic!("exact delivery horizon should be authorized: {error}"),
        };
        if let Err(error) = slot.publish_reached_icount(5, 0) {
            panic!("plugin should reach exact delivery icount: {error}");
        }
        let report = match hot_path.finish_quantum(pending) {
            Ok(report) => report,
            Err(error) => panic!("exact delivery quantum should finish: {error}"),
        };

        assert_eq!(
            report
                .due_inbound_frames
                .iter()
                .map(QemuDueInboundFrame::delivery_key)
                .collect::<Vec<_>>(),
            vec![
                frame(5, 1, 7, b"first").delivery_key(),
                frame(5, 9, 4, b"second").delivery_key(),
                frame(5, 9, 5, b"third").delivery_key(),
            ]
        );
        assert_eq!(
            report
                .due_inbound_frames
                .iter()
                .map(|frame| frame.payload.as_slice())
                .collect::<Vec<_>>(),
            vec![
                b"first".as_slice(),
                b"second".as_slice(),
                b"third".as_slice(),
            ]
        );
        assert_eq!(inbound_ring.read_index(), 3);
    }

    #[test]
    fn qemu_quantum_accepts_frame_published_at_current_boundary() {
        let slot = NodeSlot::default();
        if let Err(error) = slot.publish_scheduler_ceiling(ceiling(5, 5)) {
            panic!("test ceiling should publish: {error}");
        }
        if let Err(error) = slot.publish_reached_icount(5, 0) {
            panic!("test current icount should publish: {error}");
        }
        let inbound_ring = RingHeader::new();
        let outbound_ring = RingHeader::new();
        let mut inbound_entries = frame_entries(8);
        let mut outbound_entries = frame_entries(8);
        let mut hot_path = hot_path(
            &slot,
            &inbound_ring,
            &mut inbound_entries,
            &outbound_ring,
            &mut outbound_entries,
        );

        let enqueue = hot_path.enqueue_inbound_frame(QemuInboundFrame {
            delivery_icount: icount(5),
            src_node: 31,
            sequence: 1,
            payload: b"current-boundary".to_vec(),
        });
        assert!(enqueue.is_ok());
        let pending = match hot_path.start_quantum(horizon(5)) {
            Ok(pending) => pending,
            Err(error) => panic!("current-boundary delivery should be authorized: {error}"),
        };
        if let Err(error) = slot.publish_reached_icount(5, 0) {
            panic!("plugin should remain at the exact delivery boundary: {error}");
        }
        let report = match hot_path.finish_quantum(pending) {
            Ok(report) => report,
            Err(error) => panic!("current-boundary delivery should finish: {error}"),
        };

        assert_eq!(report.due_inbound_frames.len(), 1);
        assert_eq!(
            report.due_inbound_frames[0].delivery_key(),
            frame(5, 31, 1, b"current-boundary").delivery_key()
        );
        assert_eq!(inbound_ring.read_index(), 1);
    }

    #[test]
    fn qemu_quantum_caps_horizon_at_next_possible_frame_delivery() {
        let slot = NodeSlot::default();
        let inbound_ring = RingHeader::new();
        let outbound_ring = RingHeader::new();
        let mut inbound_entries = frame_entries(8);
        let mut outbound_entries = frame_entries(8);
        let mut hot_path = hot_path(
            &slot,
            &inbound_ring,
            &mut inbound_entries,
            &outbound_ring,
            &mut outbound_entries,
        );
        let enqueue = hot_path.enqueue_inbound_frame(QemuInboundFrame {
            delivery_icount: icount(5),
            src_node: 31,
            sequence: 7,
            payload: vec![1, 2, 3],
        });
        assert!(enqueue.is_ok());

        let pending = match hot_path.start_quantum(horizon(6)) {
            Ok(pending) => pending,
            Err(error) => panic!("pending delivery should cap the quantum: {error}"),
        };
        assert_eq!(pending.requested_horizon, icount(6));
        assert_eq!(pending.ceiling, icount(5));
        if let Err(error) = slot.publish_reached_icount(5, 0) {
            panic!("plugin should stop at the delivery boundary: {error}");
        }
        let report = match hot_path.finish_quantum(pending) {
            Ok(report) => report,
            Err(error) => panic!("delivery-capped quantum should finish: {error}"),
        };

        assert_eq!(report.ceiling, icount(5));
        assert_eq!(report.outcome, AdvanceOutcome::Paused { at: icount(5) });
        assert_eq!(report.due_inbound_frames.len(), 1);
        assert_eq!(inbound_ring.read_index(), 1);
    }

    #[test]
    fn qemu_quantum_rejects_late_inbound_frame_without_consuming() {
        let slot = NodeSlot::default();
        if let Err(error) = slot.publish_scheduler_ceiling(ceiling(0, 5)) {
            panic!("test ceiling should publish: {error}");
        }
        if let Err(error) = slot.publish_reached_icount(5, 0) {
            panic!("test current icount should publish: {error}");
        }
        let inbound_ring = RingHeader::new();
        let outbound_ring = RingHeader::new();
        let mut inbound_entries = frame_entries(8);
        let mut outbound_entries = frame_entries(8);
        enqueue_raw(
            &inbound_ring,
            &mut inbound_entries,
            frame(4, 31, 7, b"late"),
        );
        let mut hot_path = hot_path(
            &slot,
            &inbound_ring,
            &mut inbound_entries,
            &outbound_ring,
            &mut outbound_entries,
        );

        let result = hot_path.start_quantum(horizon(5));

        assert_eq!(
            result,
            Err(QemuQuantumError::DeliveryAlreadyPassed {
                passed_delivery_floor_icount: 5,
                current_icount: 5,
                frame: frame(4, 31, 7, b"late").delivery_key(),
            })
        );
        assert_eq!(inbound_ring.read_index(), 0);
    }

    #[test]
    fn qemu_quantum_rejects_mid_quantum_late_frame_without_consuming() {
        let slot = NodeSlot::default();
        let inbound_ring = RingHeader::new();
        let outbound_ring = RingHeader::new();
        let mut inbound_entries = frame_entries(8);
        let mut outbound_entries = frame_entries(8);
        let mut hot_path = hot_path(
            &slot,
            &inbound_ring,
            &mut inbound_entries,
            &outbound_ring,
            &mut outbound_entries,
        );

        let pending = match hot_path.start_quantum(horizon(10)) {
            Ok(pending) => pending,
            Err(error) => panic!("quantum should start with no known inbound frame: {error}"),
        };
        enqueue_raw(
            &inbound_ring,
            hot_path.view.inbound_entries,
            frame(5, 31, 7, b"late-mid-quantum"),
        );
        if let Err(error) = slot.publish_reached_icount(10, 0) {
            panic!("plugin report should publish through shared node slot: {error}");
        }

        assert_eq!(
            hot_path.finish_quantum(pending),
            Err(QemuQuantumError::DeliveryAlreadyPassed {
                passed_delivery_floor_icount: 10,
                current_icount: 10,
                frame: frame(5, 31, 7, b"late-mid-quantum").delivery_key(),
            })
        );
        assert_eq!(inbound_ring.read_index(), 0);
    }

    #[test]
    fn qemu_quantum_reports_device_io_freeze_across_burst_release() {
        let slot = NodeSlot::default();
        slot.mark_device_io_active();
        let inbound_ring = RingHeader::new();
        let outbound_ring = RingHeader::new();
        let mut inbound_entries = frame_entries(8);
        let mut outbound_entries = frame_entries(8);
        let mut hot_path = hot_path(
            &slot,
            &inbound_ring,
            &mut inbound_entries,
            &outbound_ring,
            &mut outbound_entries,
        );

        let pending = match hot_path.start_quantum(horizon(10)) {
            Ok(pending) => pending,
            Err(error) => panic!("device-I/O freeze quantum should start: {error}"),
        };
        slot.clear_device_io_active();
        if let Err(error) = slot.publish_reached_icount(10, 0) {
            panic!("plugin report should publish through shared node slot: {error}");
        }
        let report = match hot_path.finish_quantum(pending) {
            Ok(report) => report,
            Err(error) => panic!("device-I/O freeze quantum should finish: {error}"),
        };

        assert_eq!(
            report.device_io_freeze,
            QemuDeviceIoFreezeReport {
                initial: QemuDeviceIoFreezeObservation {
                    current_icount: icount(0),
                    device_io_active: true,
                    publish_generation: 2,
                },
                final_state: QemuDeviceIoFreezeObservation {
                    current_icount: icount(10),
                    device_io_active: false,
                    publish_generation: 6,
                },
            }
        );
        assert!(report.device_io_freeze.was_active());
    }

    #[test]
    fn qemu_quantum_drains_plugin_emitted_frames_toward_router() {
        let slot = NodeSlot::default();
        let inbound_ring = RingHeader::new();
        let outbound_ring = RingHeader::new();
        let mut inbound_entries = frame_entries(8);
        let mut outbound_entries = frame_entries(8);
        let mut hot_path = hot_path(
            &slot,
            &inbound_ring,
            &mut inbound_entries,
            &outbound_ring,
            &mut outbound_entries,
        );
        let enqueue = hot_path.enqueue_outbound_frame_from_plugin(QemuOutboundFrame {
            emit_icount: icount(3),
            sequence: 9,
            payload: vec![8, 9],
        });
        assert!(enqueue.is_ok());
        let pending = match hot_path.start_quantum(horizon(3)) {
            Ok(pending) => pending,
            Err(error) => panic!("quantum start should publish ceiling: {error}"),
        };
        if let Err(error) = slot.publish_reached_icount(3, 0) {
            panic!("plugin report should publish through shared node slot: {error}");
        }

        let report = match hot_path.finish_quantum(pending) {
            Ok(report) => report,
            Err(error) => panic!("quantum should drain emitted frame: {error}"),
        };

        assert_eq!(
            report.emitted_frames,
            vec![QemuNodeEmittedFrame {
                source: node_id("vm-a"),
                destination: node_id("net-router"),
                emit_icount: icount(3),
                sequence: 9,
                payload: vec![8, 9],
            }]
        );
        assert!(
            hot_path
                .operation_log()
                .contains(&QemuQuantumOperation::EnqueueOutboundFrame)
        );
        assert!(
            report
                .operations
                .contains(&QemuQuantumOperation::DequeueOutboundFrame)
        );
        assert!(assert_qemu_quantum_hot_path_is_shmem_only(hot_path.operation_log()).is_ok());
    }

    #[test]
    fn qemu_quantum_outbound_enqueue_uses_scheduler_send_authorizer() {
        let scheduler = pending_topology_scheduler();
        let slot = NodeSlot::default();
        let inbound_ring = RingHeader::new();
        let outbound_ring = RingHeader::new();
        let mut inbound_entries = frame_entries(8);
        let mut outbound_entries = frame_entries(8);
        let mut hot_path = hot_path_with_send_authorizer(
            &slot,
            &inbound_ring,
            &mut inbound_entries,
            &outbound_ring,
            &mut outbound_entries,
            &scheduler,
        );

        let result = hot_path.enqueue_outbound_frame_from_plugin(QemuOutboundFrame {
            emit_icount: icount(3),
            sequence: 9,
            payload: vec![8, 9],
        });

        assert!(matches!(
            &result,
            Err(QemuQuantumError::SchedulerSendAuthorization {
                operation: "enqueue outbound frame",
                ..
            })
        ));
        assert!(
            result
                .expect_err("enqueue should be frozen")
                .to_string()
                .contains("cross-node sends frozen")
        );
        assert_eq!(
            hot_path
                .view
                .outbound_ring
                .peek(hot_path.view.outbound_entries),
            Ok(None)
        );
    }

    #[test]
    fn qemu_quantum_outbound_dequeue_uses_scheduler_send_authorizer() {
        let scheduler = pending_topology_scheduler();
        let slot = NodeSlot::default();
        let inbound_ring = RingHeader::new();
        let outbound_ring = RingHeader::new();
        let mut inbound_entries = frame_entries(8);
        let mut outbound_entries = frame_entries(8);
        enqueue_raw(
            &outbound_ring,
            &mut outbound_entries,
            frame(3, 0, 9, b"frozen"),
        );
        let mut hot_path = hot_path_with_send_authorizer(
            &slot,
            &inbound_ring,
            &mut inbound_entries,
            &outbound_ring,
            &mut outbound_entries,
            &scheduler,
        );

        let result = QemuShmemHotPathChannel::emit_frame(&mut hot_path);

        assert!(matches!(
            &result,
            Err(QemuNodeChannelError {
                operation: "qemu_quantum_shmem_hot_path",
                ..
            })
        ));
        assert!(
            result
                .expect_err("dequeue should be frozen")
                .to_string()
                .contains("cross-node sends frozen")
        );
        assert_eq!(hot_path.view.outbound_ring.read_index(), 0);
        assert!(
            !hot_path
                .operation_log()
                .contains(&QemuQuantumOperation::DequeueOutboundFrame)
        );
    }

    #[test]
    fn qemu_quantum_hot_path_rejects_qmp_or_plugin_ipc_operations() {
        let result = assert_qemu_quantum_hot_path_is_shmem_only(&[
            QemuQuantumOperation::ReadNodeReport,
            QemuQuantumOperation::PluginIpcControlFrame {
                operation: "run-quantum",
            },
        ]);
        assert!(matches!(
            result,
            Err(QemuQuantumError::NonShmemHotPathOperation {
                operation: "run-quantum",
                plane: QemuQuantumOperationPlane::PluginIpcControl,
            })
        ));

        let result = assert_qemu_quantum_hot_path_is_shmem_only(&[
            QemuQuantumOperation::StoreSchedulerCeiling,
            QemuQuantumOperation::QmpCommand {
                command: "cont-until",
            },
        ]);
        assert!(matches!(
            result,
            Err(QemuQuantumError::NonShmemHotPathOperation {
                operation: "cont-until",
                plane: QemuQuantumOperationPlane::QmpMachineControl,
            })
        ));
    }

    #[test]
    fn qemu_quantum_implements_existing_shmem_hot_path_trait() {
        let slot = NodeSlot::default();
        if let Err(error) = slot.publish_scheduler_ceiling(ceiling(0, 6)) {
            panic!("initial ceiling should publish: {error}");
        }
        if let Err(error) = slot.publish_reached_icount(6, 0) {
            panic!("initial reached icount should publish: {error}");
        }
        let inbound_ring = RingHeader::new();
        let outbound_ring = RingHeader::new();
        let mut inbound_entries = frame_entries(8);
        let mut outbound_entries = frame_entries(8);
        let mut hot_path = hot_path(
            &slot,
            &inbound_ring,
            &mut inbound_entries,
            &outbound_ring,
            &mut outbound_entries,
        );

        let outcome = match QemuShmemHotPathChannel::advance_to_horizon(&mut hot_path, horizon(6)) {
            Ok(outcome) => outcome,
            Err(error) => panic!("trait advance should use quantum path: {error}"),
        };
        assert_eq!(outcome, AdvanceOutcome::ReachedHorizon);
        assert_eq!(
            QemuShmemHotPathChannel::current_icount(&mut hot_path),
            Ok(icount(6))
        );
        assert!(
            hot_path
                .operation_log()
                .iter()
                .all(|operation| operation.plane() == QemuQuantumOperationPlane::SharedMemory)
        );
    }

    fn hot_path<'a>(
        slot: &'a NodeSlot,
        inbound_ring: &'a RingHeader,
        inbound_entries: &'a mut [FrameEntry],
        outbound_ring: &'a RingHeader,
        outbound_entries: &'a mut [FrameEntry],
    ) -> QemuQuantumShmemHotPath<'a> {
        hot_path_with_send_authorizer(
            slot,
            inbound_ring,
            inbound_entries,
            outbound_ring,
            outbound_entries,
            &ALLOW_ALL_SENDS,
        )
    }

    fn hot_path_with_send_authorizer<'a>(
        slot: &'a NodeSlot,
        inbound_ring: &'a RingHeader,
        inbound_entries: &'a mut [FrameEntry],
        outbound_ring: &'a RingHeader,
        outbound_entries: &'a mut [FrameEntry],
        send_authorizer: &'a dyn crucible::SchedulerSendAuthorizer,
    ) -> QemuQuantumShmemHotPath<'a> {
        static FINGERPRINT_SAMPLE: FingerprintSampleSlot = FingerprintSampleSlot::new();
        let view = match QemuQuantumShmemView::new(
            slot,
            &FINGERPRINT_SAMPLE,
            inbound_ring,
            inbound_entries,
            outbound_ring,
            outbound_entries,
        ) {
            Ok(view) => view,
            Err(error) => panic!("view should bind to shared-memory objects: {error}"),
        };
        let config =
            QemuQuantumShmemConfig::new(node_id("vm-a"), 0).with_router(node_id("net-router"), 31);
        match QemuQuantumShmemHotPath::new(config, view, send_authorizer) {
            Ok(hot_path) => hot_path,
            Err(error) => panic!("hot path should construct: {error}"),
        }
    }

    fn pending_topology_scheduler() -> crucible::SingleScheduler {
        let vm = qemu_scheduler_node(&node_id("vm-a"), SchedulingNodeKind::Vm);
        let router = qemu_scheduler_node(&node_id("net-router"), SchedulingNodeKind::Network);
        let scenario = crucible::SchedulerLivenessScenario::from_canonical_material(
            "qemu-outbound-send-freeze",
            crucible::Shift::new(0).expect("test shift should be valid"),
            8,
            crucible::SimInstant { nanos: 40 },
            vec![crucible::SchedulerScenarioNode {
                id: vm.clone(),
                counter: crucible::NodeCounter { ticks: 0 },
                activity: crucible::SchedulerNodeActivity::Runnable,
                network_lookahead: crucible::NetworkLookahead::Infinite,
                exact_local_event: crucible::ExactLocalEvent::NoArmedTimer,
            }],
            Vec::new(),
        )
        .with_effective_topology_edges(vec![crucible::SchedulerLookaheadEdge::new(
            vm.clone(),
            router.clone(),
            crucible::SimDuration { nanos: 20 },
        )]);
        let mut scheduler =
            crucible::SingleScheduler::new(scenario).expect("scenario should build");
        scheduler.queue_topology_change(crucible::SchedulerTopologyChange::new(
            1,
            crucible::SchedulerTopologyChangeTrigger::LatencyChange,
            vec![crucible::SchedulerLookaheadEdge::new(
                vm,
                router,
                crucible::SimDuration { nanos: 5 },
            )],
        ));
        scheduler
    }

    fn frame_entries(count: usize) -> Vec<FrameEntry> {
        vec![FrameEntry::default(); count]
    }

    fn enqueue_raw(ring: &RingHeader, entries: &mut [FrameEntry], frame: FrameEntry) {
        if let Err(error) = ring.enqueue(entries, &frame) {
            panic!("test frame should enqueue: {error}");
        }
    }

    fn frame(delivery_icount: u64, src_node: u32, seq: u32, payload: &[u8]) -> FrameEntry {
        match FrameEntry::new(delivery_icount, src_node, seq, payload) {
            Ok(frame) => frame,
            Err(error) => panic!("test frame should fit: {error}"),
        }
    }

    fn horizon(retired: u64) -> ExecutionHorizon {
        ExecutionHorizon {
            icount: icount(retired),
        }
    }

    fn ceiling(current_icount: u64, max_advance_icount: u64) -> AdvanceCeiling {
        match authorize_advance_ceiling(current_icount, max_advance_icount, None) {
            Ok(ceiling) => ceiling,
            Err(error) => panic!("test ceiling should authorize: {error}"),
        }
    }

    fn icount(retired: u64) -> Icount {
        Icount { retired }
    }

    fn node_id(name: &str) -> NodeId {
        NodeId {
            name: name.to_owned(),
        }
    }

    fn assert_source_order(source: &str, needles: &[&str], context: &str) {
        let mut offset = 0;
        for needle in needles {
            let remaining = &source[offset..];
            let Some(relative) = remaining.find(needle) else {
                panic!("{context}: missing `{needle}` after byte offset {offset}");
            };
            offset += relative + needle.len();
        }
    }

    fn function_source(signature: &str) -> &str {
        let Some(start) = QUANTUM_SOURCE.find(signature) else {
            panic!("missing source signature `{signature}`");
        };
        let after_signature = &QUANTUM_SOURCE[start..];
        let Some(open_relative) = after_signature.find('{') else {
            panic!("missing body for source signature `{signature}`");
        };
        let open = start + open_relative;
        let mut depth = 0_i32;
        for (relative, ch) in QUANTUM_SOURCE[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return &QUANTUM_SOURCE[start..open + relative + ch.len_utf8()];
                    }
                }
                _ => {}
            }
        }

        panic!("unterminated source body for `{signature}`");
    }
}
