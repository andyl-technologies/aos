//! QEMU per-quantum shared-memory hot path.
//!
//! RFC-0010 T-QEMU-12 requires the QEMU node step to be a shared-memory-only
//! cycle: observe the plugin-published node report, publish the scheduler's
//! ceiling, wake the parked plugin through the node-slot futex word, observe a
//! later plugin report in the same shared-memory slot, and move frame records
//! through SPSC rings. This module encodes that host-side data flow over
//! caller-supplied shared-memory ABI objects; it does not allocate private
//! shadow slots or use QMP/plugin IPC for per-quantum progress.

use crucible::{
    AdvanceOutcome, BackendInput, ContentHash, ExecutionFingerprint, ExecutionHorizon, Icount,
    NodeId,
};
use crucible_shmem::{
    FrameEntry, FrameEntryError, LookaheadGateError, NodeSlot, NodeSlotError, NodeSlotSnapshot,
    RingHeader, STATUS_IDLE, SpscRingError, authorize_advance_ceiling,
    validate_frame_delivery_is_future,
};
use thiserror::Error;

use crate::{
    QemuNodeChannelError, QemuNodeEmittedFrame, QemuNodeIdleState, QemuShmemHotPathChannel,
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
}

/// Borrowed shared-memory ABI objects for one QEMU node.
pub struct QemuQuantumShmemView<'a> {
    node_slot: &'a NodeSlot,
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
        inbound_ring: &'a RingHeader,
        inbound_entries: &'a mut [FrameEntry],
        outbound_ring: &'a RingHeader,
        outbound_entries: &'a mut [FrameEntry],
    ) -> Result<Self, QemuQuantumError> {
        validate_queue_capacity(inbound_entries.len(), "inbound ring")?;
        validate_queue_capacity(outbound_entries.len(), "outbound ring")?;
        Ok(Self {
            node_slot,
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
    /// Observe a later plugin report from the same node slot.
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

/// A published quantum that is waiting for a plugin report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuPendingQuantum {
    /// Initial node report read before publishing the scheduler ceiling.
    pub initial_state: QemuNodeIdleState,
    /// Scheduler-published ceiling.
    pub ceiling: Icount,
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
    /// Operations performed by this quantum.
    pub operations: Vec<QemuQuantumOperation>,
}

/// Host-side QEMU shared-memory hot-path adapter.
pub struct QemuQuantumShmemHotPath<'a> {
    config: QemuQuantumShmemConfig,
    view: QemuQuantumShmemView<'a>,
    operation_log: Vec<QemuQuantumOperation>,
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
        })
    }

    /// Returns a stable snapshot of the bound node slot.
    #[must_use]
    pub fn node_snapshot(&self) -> NodeSlotSnapshot {
        self.view.node_slot.snapshot()
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

        self.record(QemuQuantumOperation::EnqueueInboundFrame);
        self.view
            .inbound_ring
            .enqueue(self.view.inbound_entries, &entry)
            .map_err(|source| QemuQuantumError::SpscRing {
                operation: "enqueue inbound frame",
                source,
            })?;
        self.record(QemuQuantumOperation::FutexWake);
        self.view
            .node_slot
            .wake_for_frame_delivery()
            .map_err(|source| QemuQuantumError::NodeSlot {
                operation: "wake for frame delivery",
                source: NodeSlotError::FutexWake { source },
            })?;
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
        let due_before_wake = self.drain_due_inbound(initial_state.current_icount.retired)?;

        self.record(QemuQuantumOperation::ComputeSchedulerCeiling);
        let earliest_delivery = self
            .view
            .inbound_ring
            .peek_delivery_icount(self.view.inbound_entries)
            .map_err(|source| QemuQuantumError::SpscRing {
                operation: "peek inbound delivery icount",
                source,
            })?;
        let ceiling = authorize_advance_ceiling(
            initial_state.current_icount.retired,
            horizon.icount.retired,
            earliest_delivery,
        )
        .map_err(|source| QemuQuantumError::Lookahead { source })?;

        self.record(QemuQuantumOperation::StoreSchedulerCeiling);
        self.record(QemuQuantumOperation::FutexWake);
        self.view
            .node_slot
            .publish_scheduler_ceiling(ceiling)
            .map_err(|source| QemuQuantumError::NodeSlot {
                operation: "publish scheduler ceiling",
                source,
            })?;

        Ok(QemuPendingQuantum {
            initial_state,
            ceiling: horizon.icount,
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
        self.record(QemuQuantumOperation::ObservePluginReport);
        let final_snapshot = self.view.node_slot.snapshot();
        if final_snapshot.publish_gen == pending.report_generation
            && final_snapshot.current_icount < pending.ceiling.retired
        {
            return Err(QemuQuantumError::PluginReportNotPublished {
                current_icount: final_snapshot.current_icount,
                ceiling: pending.ceiling.retired,
            });
        }

        self.record(QemuQuantumOperation::ReadCompletionReport);
        let final_state = idle_state_from_snapshot(final_snapshot);
        let mut due_inbound_frames = pending.due_before_wake;
        due_inbound_frames.extend(self.drain_due_inbound(final_state.current_icount.retired)?);
        let emitted_frames = self.drain_emitted_outbound()?;
        let outcome = quantum_outcome(pending.ceiling, final_state)?;
        let operations = self.operation_log[pending.operation_start..].to_vec();
        assert_qemu_quantum_hot_path_is_shmem_only(&operations)?;

        Ok(QemuQuantumReport {
            initial_state: pending.initial_state,
            ceiling: pending.ceiling,
            final_state,
            outcome,
            due_inbound_frames,
            emitted_frames,
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

    fn drain_due_inbound(
        &mut self,
        current_icount: u64,
    ) -> Result<Vec<QemuDueInboundFrame>, QemuQuantumError> {
        self.record(QemuQuantumOperation::DrainDueInboundFrames);
        let mut frames = Vec::new();
        loop {
            let Some(delivery_icount) = self
                .view
                .inbound_ring
                .peek_delivery_icount(self.view.inbound_entries)
                .map_err(|source| QemuQuantumError::SpscRing {
                    operation: "peek inbound delivery icount",
                    source,
                })?
            else {
                break;
            };
            if delivery_icount > current_icount {
                break;
            }
            let Some(entry) = self
                .view
                .inbound_ring
                .dequeue(self.view.inbound_entries)
                .map_err(|source| QemuQuantumError::SpscRing {
                    operation: "dequeue inbound frame",
                    source,
                })?
            else {
                break;
            };
            frames.push(self.due_inbound_frame_from_entry(entry)?);
        }
        Ok(frames)
    }

    fn drain_emitted_outbound(&mut self) -> Result<Vec<QemuNodeEmittedFrame>, QemuQuantumError> {
        let mut frames = Vec::new();
        loop {
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
                break;
            };
            frames.push(self.emitted_frame_from_entry(entry)?);
        }
        Ok(frames)
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
            sequence: u64::from(entry.seq),
            payload,
        })
    }

    fn record(&mut self, operation: QemuQuantumOperation) {
        self.operation_log.push(operation);
    }
}

impl QemuShmemHotPathChannel for QemuQuantumShmemHotPath<'_> {
    fn current_icount(&mut self) -> Result<Icount, QemuNodeChannelError> {
        self.record(QemuQuantumOperation::ReadNodeReport);
        Ok(self.current_icount_from_slot())
    }

    fn advance_to_horizon(
        &mut self,
        horizon: ExecutionHorizon,
    ) -> Result<AdvanceOutcome, QemuNodeChannelError> {
        self.run_one_quantum(horizon)
            .map(|report| report.outcome)
            .map_err(QemuNodeChannelError::from)
    }

    fn deliver_frame(&mut self, input: BackendInput) -> Result<(), QemuNodeChannelError> {
        let delivery_icount = Icount {
            retired: self.current_icount_from_slot().retired.saturating_add(1),
        };
        self.enqueue_inbound_frame(QemuInboundFrame {
            delivery_icount,
            src_node: self.config.router_slot,
            sequence: 0,
            payload: input.payload,
        })
        .map_err(QemuNodeChannelError::from)
    }

    fn emit_frame(&mut self) -> Result<Option<QemuNodeEmittedFrame>, QemuNodeChannelError> {
        self.record(QemuQuantumOperation::DequeueOutboundFrame);
        let frame = self
            .view
            .outbound_ring
            .dequeue(self.view.outbound_entries)
            .map_err(|source| {
                QemuNodeChannelError::from(QemuQuantumError::SpscRing {
                    operation: "dequeue outbound frame",
                    source,
                })
            })?;
        frame
            .map(|entry| self.emitted_frame_from_entry(entry))
            .transpose()
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
}

impl From<QemuQuantumError> for QemuNodeChannelError {
    fn from(error: QemuQuantumError) -> Self {
        Self::new("qemu_quantum_shmem_hot_path", error.to_string())
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

fn idle_state_from_snapshot(snapshot: NodeSlotSnapshot) -> QemuNodeIdleState {
    QemuNodeIdleState {
        current_icount: Icount {
            retired: snapshot.current_icount,
        },
        next_deadline: (snapshot.status == STATUS_IDLE).then_some(Icount {
            retired: snapshot.idle_wake_icount,
        }),
    }
}

fn quantum_outcome(
    horizon: Icount,
    final_state: QemuNodeIdleState,
) -> Result<AdvanceOutcome, QemuQuantumError> {
    if final_state.current_icount.retired >= horizon.retired {
        return Ok(AdvanceOutcome::ReachedHorizon);
    }
    if final_state.next_deadline.is_some() {
        return Ok(AdvanceOutcome::Paused {
            at: final_state.current_icount,
        });
    }
    Err(QemuQuantumError::IncompleteQuantumReport {
        current_icount: final_state.current_icount.retired,
        ceiling: horizon.retired,
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
    /// The node-slot handoff rejected a state transition.
    #[error("QEMU quantum node-slot operation {operation} failed: {source}")]
    NodeSlot {
        /// Node-slot operation being attempted.
        operation: &'static str,
        /// Underlying node-slot error.
        source: NodeSlotError,
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
mod tests {
    use super::*;
    use crucible_shmem::{AdvanceCeiling, FrameEntry, NodeSlot, STATUS_IDLE, STATUS_RUNNING};

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
    fn qemu_quantum_rejects_finish_before_shared_plugin_report_changes() {
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
    fn qemu_quantum_rejects_horizon_that_would_reach_possible_frame_delivery() {
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

        let result = hot_path.start_quantum(horizon(5));

        assert!(matches!(
            result,
            Err(QemuQuantumError::Lookahead {
                source: LookaheadGateError::AdvanceReachesPossibleDelivery {
                    max_advance_icount: 5,
                    earliest_possible_delivery_icount: 5,
                },
            })
        ));
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
        let view = match QemuQuantumShmemView::new(
            slot,
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
        match QemuQuantumShmemHotPath::new(config, view) {
            Ok(hot_path) => hot_path,
            Err(error) => panic!("hot path should construct: {error}"),
        }
    }

    fn frame_entries(count: usize) -> Vec<FrameEntry> {
        vec![FrameEntry::default(); count]
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
}
