//! Stable per-node snapshots and logical-time conversion.

/// A stable acquire snapshot of a [`crate::NodeSlot`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeSlotSnapshot {
    /// The node's published current icount.
    pub current_icount: u64,
    /// The derived virtual-time nanoseconds for [`Self::current_icount`].
    pub current_ns: u64,
    /// The scheduler-published maximum advance icount.
    pub max_advance_icount: u64,
    /// The idle wake icount.
    pub idle_wake_icount: u64,
    /// The futex wake signal value.
    pub wake_signal: u32,
    /// The node status.
    pub status: u8,
    /// The node kind.
    pub kind: u8,
    /// Nonzero while device I/O is active.
    pub device_io_active: u8,
    /// Raw scheduler advance-stop condition from the current ABI.
    pub advance_stop_condition: u8,
    /// Stable even sequence for the paired scheduler advance publication.
    pub advance_publication_sequence: u64,
    /// The even publish generation observed for this snapshot.
    pub publish_gen: u32,
    /// Plugin acknowledgement count for drained QEMU control boundaries.
    pub control_boundary_ack: u32,
    /// Fault-command producer index bound to the acknowledged control request.
    pub control_boundary_fault_command_frontier: u64,
    /// Fingerprint request generation bound to the acknowledged control request.
    pub control_boundary_capture_request: u32,
    /// QEMU's raw retired-instruction count paired with the published logical time.
    pub logical_time_raw_icount: u64,
    /// Logical target carried by the most recent restore request.
    pub logical_time_restore_target: u64,
    /// Host-published logical-time restore request generation.
    pub logical_time_restore_request: u32,
    /// Plugin-published logical-time restore acknowledgement generation.
    pub logical_time_restore_ack: u32,
    /// Most recent plugin-validated actual virtual-timer callback witness.
    pub virtual_timer_witness: Option<VirtualTimerFireWitness>,
}

/// Exact native evidence for one completed `QEMU_CLOCK_VIRTUAL` callback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtualTimerFireWitness {
    /// QEMU witness generation.
    pub generation: u64,
    /// Armed exact timer expiry in virtual nanoseconds.
    pub deadline_ns: u64,
    /// Published logical idle-wake icount.
    pub deadline_icount: u64,
    /// Raw QEMU icount at arm.
    pub armed_raw_icount: u64,
    /// Saved expiry of the timer whose callback ran.
    pub fired_expire_ns: u64,
    /// Virtual time at actual callback invocation.
    pub fired_virtual_ns: u64,
    /// Raw QEMU icount at actual callback invocation.
    pub fired_raw_icount: u64,
    /// Actual-callback completion flag.
    pub completed: u32,
    /// Reserved field, zero in the current ABI.
    pub reserved: u32,
}

/// One host-published logical-time restore request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogicalTimeRestoreRequest {
    /// Monotonic transaction generation.
    pub generation: u32,
    /// Logical icount that must be reconstructed over restored raw icount.
    pub target_icount: u64,
}

/// Projects an exact logical tick onto QEMU's integer-nanosecond clock.
#[must_use]
pub const fn icount_to_virtual_ns(icount: u64) -> u64 {
    icount / crate::TICKS_PER_NS
}
