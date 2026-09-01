//! Stable per-node snapshots and logical-time conversion.

use super::*;

/// A stable acquire snapshot of a [`NodeSlot`].
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
    /// The even publish generation observed for this snapshot.
    pub publish_gen: u32,
    /// Plugin acknowledgement count for drained QEMU control boundaries.
    pub control_boundary_ack: u32,
    /// QEMU's raw retired-instruction count paired with the published logical time.
    pub logical_time_raw_icount: u64,
    /// Logical target carried by the most recent restore request.
    pub logical_time_restore_target: u64,
    /// Host-published logical-time restore request generation.
    pub logical_time_restore_request: u32,
    /// Plugin-published logical-time restore acknowledgement generation.
    pub logical_time_restore_ack: u32,
}

/// One host-published logical-time restore request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogicalTimeRestoreRequest {
    /// Monotonic transaction generation.
    pub generation: u32,
    /// Logical icount that must be reconstructed over restored raw icount.
    pub target_icount: u64,
}

/// Converts an icount into virtual nanoseconds with the fixed shift.
///
/// # Errors
///
/// Returns [`NodeSlotError::InvalidShift`] when `shift_bits >= 64`, and
/// [`NodeSlotError::VirtualTimeOverflow`] when the shifted value does not fit in
/// `u64`.
pub fn icount_to_virtual_ns(icount: u64, shift_bits: u8) -> Result<u64, NodeSlotError> {
    if shift_bits >= 64 {
        return Err(NodeSlotError::InvalidShift { shift_bits });
    }
    let nanos_per_icount = 1_u64 << shift_bits;
    icount
        .checked_mul(nanos_per_icount)
        .ok_or(NodeSlotError::VirtualTimeOverflow { icount, shift_bits })
}
