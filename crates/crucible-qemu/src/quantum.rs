//! QEMU per-quantum shared-memory hot path.
//!
//! RFC-0010 T-QEMU-12 requires the QEMU node step to be a shared-memory-only
//! cycle: observe the plugin-published node report, publish the scheduler's
//! ceiling, wake the parked plugin through the node-slot futex word, observe a
//! a plugin report at the authorized boundary in the same shared-memory slot,
//! and move frame records through SPSC rings. This module encodes that host-side data flow over
//! caller-supplied shared-memory ABI objects; it does not allocate private
//! shadow slots or use QMP/plugin IPC for per-quantum progress.

use std::collections::VecDeque;

use crucible::{
    AdvanceOutcome, BackendInput, BasicBlockCoverageConfig, ContentHash, ExecutionFingerprint,
    ExecutionHorizon, Icount, NodeId, SchedulerError, SchedulerNodeId, SchedulerSendAuthorizer,
    SchedulingNodeKind,
};
use crucible_shmem::{
    AdvanceCeiling, FingerprintSample, FingerprintSampleSlot, FrameDeliveryKey, FrameDeliveryState,
    FrameDeliveryStateError, FrameEntry, FrameEntryError, LookaheadGateError, NodeSlot,
    NodeSlotError, NodeSlotSnapshot, RingHeader, STATUS_IDLE, STATUS_RUNNING,
    SchedulerWakePublicationError, SpscRingError, authorize_advance_ceiling,
    validate_frame_delivery_is_future,
};
use thiserror::Error;

use crate::quantum_boundary::{QuantumBoundary, classify_quantum_boundary};
use crate::{
    QemuAdvanceCompletionFence, QemuAsyncQuantumCompletion, QemuNodeChannelError,
    QemuNodeEmittedFrame, QemuNodeIdleState, QemuNodePendingQuantum, QemuShmemHotPathChannel,
};

mod channel;
mod support;

pub use support::QemuQuantumError;
pub(crate) use support::idle_state_from_snapshot;
use support::{
    authorize_qemu_delivery_ceiling, completed_quantum_clamp_is_attested,
    device_io_freeze_from_snapshot, qemu_scheduler_node, quantum_outcome, validate_queue_capacity,
};

const QUANTUM_FINGERPRINT_DOMAIN: &str = "crucible.qemu.quantum-shmem-fingerprint.v1";
const DEFAULT_ROUTER_SLOT: u32 = 31;

mod inbound_delivery;
use inbound_delivery::inbound_delivery_ledger_from_view;

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
    /// Observe plugin-owned router-to-VM consumption without dequeuing.
    ObserveInboundConsumption,
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
            | Self::ObserveInboundConsumption
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
            Self::ObserveInboundConsumption => "observe-inbound-consumption",
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
    /// Device-I/O freeze state before publishing the scheduler ceiling.
    pub initial_device_io_freeze: QemuDeviceIoFreezeObservation,
    /// Node-slot publish generation observed before the wake.
    pub report_generation: u32,
    /// Control-boundary acknowledgement observed before the wake.
    ///
    /// A later odd acknowledgement attests that the host runtime completed its
    /// mandatory post-quantum clamp after the plugin published the clamped
    /// coordinate. This distinguishes that terminal state from a stale running
    /// report against the original scheduler ceiling.
    pub initial_control_boundary_ack: u32,
    /// Fresh plugin publication required because scheduler input capped this quantum.
    pub completion_fence: Option<QemuAdvanceCompletionFence>,
    operation_start: usize,
    inbound_consumption: QemuInboundConsumptionBaseline,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct QemuInboundConsumptionBaseline {
    read_idx: u64,
    write_idx: u64,
    delivery_keys: Vec<FrameDeliveryKey>,
    next_wake_icount: Option<u64>,
}

enum QemuInboundDeliveryLedger<'a> {
    Owned(VecDeque<FrameDeliveryKey>),
    Borrowed(&'a mut VecDeque<FrameDeliveryKey>),
}

impl QemuInboundDeliveryLedger<'_> {
    fn get(&self) -> &VecDeque<FrameDeliveryKey> {
        match self {
            Self::Owned(ledger) => ledger,
            Self::Borrowed(ledger) => ledger,
        }
    }

    fn get_mut(&mut self) -> &mut VecDeque<FrameDeliveryKey> {
        match self {
            Self::Owned(ledger) => ledger,
            Self::Borrowed(ledger) => ledger,
        }
    }
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
    /// Router-to-VM frames consumed and injected by the plugin this quantum.
    pub inbound_frames_consumed: usize,
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
    inbound_delivery_ledger: QemuInboundDeliveryLedger<'a>,
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
        let inbound_delivery_ledger = inbound_delivery_ledger_from_view(&view)?;
        Ok(Self {
            config,
            view,
            operation_log: Vec::new(),
            next_router_inbound_sequence: 0,
            inbound_delivery_ledger: QemuInboundDeliveryLedger::Owned(inbound_delivery_ledger),
            send_authorizer,
        })
    }

    pub(crate) fn new_with_inbound_delivery_ledger(
        config: QemuQuantumShmemConfig,
        view: QemuQuantumShmemView<'a>,
        inbound_delivery_ledger: &'a mut VecDeque<FrameDeliveryKey>,
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
            inbound_delivery_ledger: QemuInboundDeliveryLedger::Borrowed(inbound_delivery_ledger),
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
        self.inbound_delivery_ledger
            .get_mut()
            .push_back(entry.delivery_key());
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
        let inbound_consumption = self.snapshot_inbound_consumption()?;

        self.record(QemuQuantumOperation::ComputeSchedulerCeiling);
        let earliest_delivery = inbound_consumption
            .next_wake_icount
            .map(|icount| icount.max(initial_state.current_icount.retired));
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
            initial_device_io_freeze,
            report_generation: initial_snapshot.publish_gen,
            initial_control_boundary_ack: initial_snapshot.control_boundary_ack,
            completion_fence: earliest_delivery
                .filter(|delivery_icount| *delivery_icount <= horizon.icount.retired)
                .map(|_| QemuAdvanceCompletionFence {
                    initial_publish_generation: initial_snapshot.publish_gen,
                }),
            operation_start,
            inbound_consumption,
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
        let completed_clamp = completed_quantum_clamp_is_attested(pending, &final_snapshot);
        let mut final_state = idle_state_from_snapshot(final_snapshot);
        if completed_clamp
            && final_state.next_deadline.is_none()
            && final_snapshot.idle_wake_icount > final_snapshot.current_icount
        {
            // A release-acknowledged clamp may be followed immediately by a
            // vCPU-resume publication. Dispatch remains fenced at the completed
            // coordinate, and the attested retained timer is still the exact
            // reason the quantum paused. Preserve that boundary evidence rather
            // than making the scheduler depend on a later status re-read.
            final_state.next_deadline = Some(Icount {
                retired: final_snapshot.idle_wake_icount,
            });
        }
        if matches!(
            classify_quantum_boundary(&final_state, pending.ceiling.retired),
            QuantumBoundary::Pending
        ) && !completed_clamp
        {
            return Err(QemuQuantumError::PluginReportNotPublished {
                current_icount: final_snapshot.current_icount,
                ceiling: pending.ceiling.retired,
            });
        }

        self.record(QemuQuantumOperation::ReadCompletionReport);
        let final_device_io_freeze = device_io_freeze_from_snapshot(final_snapshot);
        let inbound_frames_consumed =
            self.observe_inbound_consumption(pending, final_state.current_icount.retired)?;
        let emitted_frames = self.drain_emitted_outbound()?;
        let outcome = if completed_clamp
            && final_state.current_icount.retired < pending.requested_horizon.retired
        {
            AdvanceOutcome::Paused {
                at: final_state.current_icount,
            }
        } else {
            quantum_outcome(pending.requested_horizon, pending.ceiling, final_state)?
        };
        let operations = self.operation_log[pending.operation_start..].to_vec();
        assert_qemu_quantum_hot_path_is_shmem_only(&operations)?;

        Ok(QemuQuantumReport {
            initial_state: pending.initial_state,
            ceiling: pending.ceiling,
            final_state,
            outcome,
            inbound_frames_consumed,
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

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::expect_used)]
mod tests;
