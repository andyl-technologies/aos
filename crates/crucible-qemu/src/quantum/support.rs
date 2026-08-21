//! Validation, completion classification, and errors for QEMU quanta.

use super::*;

pub(super) fn validate_queue_capacity(
    capacity: usize,
    ring: &'static str,
) -> Result<(), QemuQuantumError> {
    if capacity == 0 || !capacity.is_power_of_two() {
        Err(QemuQuantumError::InvalidQueueCapacity { capacity, ring })
    } else {
        Ok(())
    }
}

pub(super) fn inbound_ring_capacity(entries: &[FrameEntry]) -> Result<u64, QemuQuantumError> {
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

pub(super) fn inbound_live_count(
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

pub(super) fn corrupt_inbound_indices(
    read_idx: u64,
    write_idx: u64,
    capacity: u64,
) -> QemuQuantumError {
    QemuQuantumError::SpscRing {
        operation: "preview inbound frame",
        source: SpscRingError::CorruptIndices {
            read_idx,
            write_idx,
            capacity,
        },
    }
}

pub(super) fn authorize_qemu_delivery_ceiling(
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

pub(super) fn device_io_freeze_from_snapshot(
    snapshot: NodeSlotSnapshot,
) -> QemuDeviceIoFreezeObservation {
    QemuDeviceIoFreezeObservation {
        current_icount: Icount {
            retired: snapshot.current_icount,
        },
        device_io_active: snapshot.device_io_active != 0,
        publish_generation: snapshot.publish_gen,
    }
}

/// Returns whether the live runtime attested a settled post-quantum clamp.
///
/// The runtime serializes lifecycle control with quantum execution. Its clamp
/// callback publishes the exact boundary before release-storing a fresh odd
/// acknowledgement. The acquire snapshot therefore turns a newer odd token,
/// the clamped ceiling, and an inactive device plane into completion proof even
/// if a following vCPU-resume edge has transiently republished `RUNNING`.
pub(super) fn completed_quantum_clamp_is_attested(
    pending: &QemuPendingQuantum,
    snapshot: &NodeSlotSnapshot,
) -> bool {
    let acknowledgement_distance = snapshot
        .control_boundary_ack
        .wrapping_sub(pending.initial_control_boundary_ack);
    let acknowledgement_is_new = snapshot.control_boundary_ack & 1 == 1
        && acknowledgement_distance != 0
        && acknowledgement_distance < (1_u32 << 31);
    let status_is_settled = snapshot.status == STATUS_IDLE
        || (snapshot.status == STATUS_RUNNING
            && snapshot.idle_wake_icount > snapshot.current_icount);

    acknowledgement_is_new
        && snapshot.publish_gen != pending.report_generation
        && snapshot.current_icount >= pending.initial_state.current_icount.retired
        && snapshot.current_icount <= pending.ceiling.retired
        && snapshot.max_advance_icount == snapshot.current_icount
        && snapshot.device_io_active == 0
        && status_is_settled
}

pub(super) fn qemu_scheduler_node(node: &NodeId, kind: SchedulingNodeKind) -> SchedulerNodeId {
    SchedulerNodeId {
        node: node.clone(),
        kind,
    }
}

pub(super) fn quantum_outcome(
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
    /// The plugin advanced the consumer index beyond the host-published batch.
    #[error(
        "QEMU quantum inbound consumer advanced from {initial_read_idx} past published write index {initial_write_idx} to {final_read_idx}"
    )]
    InboundConsumerAdvancedBeyondPublished {
        /// Consumer index observed before the scheduler wake.
        initial_read_idx: u64,
        /// Producer index observed before the scheduler wake.
        initial_write_idx: u64,
        /// Consumer index observed after the plugin completion report.
        final_read_idx: u64,
    },
    /// The producer index regressed relative to the active quantum's ledger.
    #[error(
        "QEMU quantum inbound producer index regressed from {initial_write_idx} to {final_write_idx}"
    )]
    InboundDeliveryLedgerIndexRegressed {
        /// Producer index captured before the scheduler wake.
        initial_write_idx: u64,
        /// Producer index captured after the plugin completion report.
        final_write_idx: u64,
    },
    /// Delivery-key ledger length arithmetic overflowed.
    #[error("QEMU quantum inbound delivery-key ledger length overflowed")]
    InboundDeliveryLedgerLengthOverflow,
    /// An untracked producer wrapped the ring before its keys could be observed.
    #[error(
        "QEMU quantum inbound producer published {produced} frames across capacity {capacity} without a complete delivery-key ledger"
    )]
    InboundDeliveryHistoryOverwritten {
        /// Number of entries published during the active quantum.
        produced: u64,
        /// Physical ring capacity available for retrospective key reads.
        capacity: u64,
    },
    /// The host delivery-key ledger disagreed with the shared ring.
    #[error(
        "QEMU quantum inbound delivery-key ledger has {ledger_live} live keys for {ring_live} live ring entries"
    )]
    InboundDeliveryLedgerMismatch {
        /// Number of live entries derived from the SPSC indices.
        ring_live: u64,
        /// Number of delivery keys retained by the host ledger.
        ledger_live: usize,
    },
    /// The plugin kept advancing the consumer index during every bounded snapshot attempt.
    #[error("QEMU inbound consumption snapshot remained unstable across capacity {capacity}")]
    InboundConsumptionSnapshotUnstable {
        /// Maximum live entries, and therefore maximum useful snapshot retries.
        capacity: u64,
    },
    /// The plugin consumed a frame before its scheduler-authorized coordinate.
    #[error(
        "QEMU quantum inbound frame {frame:?} was consumed before delivery at current icount {current_icount}"
    )]
    InboundFrameConsumedBeforeDelivery {
        /// Current plugin coordinate at completion.
        current_icount: u64,
        /// Prematurely consumed deterministic delivery key.
        frame: FrameDeliveryKey,
    },
    /// The plugin published completion without consuming a due inbound frame.
    #[error(
        "QEMU quantum inbound frame {frame:?} remained queued at delivery coordinate {current_icount}"
    )]
    InboundFrameNotConsumedAtDelivery {
        /// Current plugin coordinate at completion.
        current_icount: u64,
        /// Due deterministic delivery key still owned by the plugin.
        frame: FrameDeliveryKey,
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
