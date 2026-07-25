//! Shared-memory frame entries and per-node slot state.

use super::*;

#[path = "frame_node/frame_entry.rs"]
mod frame_entry;
#[path = "frame_node/futex.rs"]
mod futex;
#[path = "frame_node/preemption_mailbox.rs"]
mod preemption_mailbox;

pub use frame_entry::{
    FRAME_ENTRY_ALIGN, FRAME_ENTRY_DATA_OFFSET, FRAME_ENTRY_DELIVERY_ICOUNT_OFFSET,
    FRAME_ENTRY_LEN_OFFSET, FRAME_ENTRY_PAD_OFFSET, FRAME_ENTRY_SEQ_OFFSET, FRAME_ENTRY_SIZE,
    FRAME_ENTRY_SRC_NODE_OFFSET, FrameEntry,
};
pub use futex::{
    FutexError, FutexWait, FutexWaitOutcome, FutexWakeResult, RegionControlError, WakeAction,
};
pub use preemption_mailbox::{
    PreemptionMailboxError, PublishedPreemptionCommand, SchedulerPreemptionCommand,
    SchedulerPreemptionKind,
};

/// Node status: actively retiring instructions or processing an I/O burst.
pub const STATUS_RUNNING: u8 = 0;
/// Node status: idle, waiting for a timer, frame, or raised ceiling.
pub const STATUS_IDLE: u8 = 1;
/// Node status: simulation complete.
pub const STATUS_DONE: u8 = 2;

/// Node kind: a QEMU guest VM.
pub const KIND_VM: u8 = 0;
/// Node kind: a network-link or routing I/O node.
pub const KIND_NET: u8 = 1;
/// Node kind: a block-device I/O node.
pub const KIND_BLK: u8 = 2;
/// Node kind: a 9p-filesystem I/O node.
pub const KIND_9P: u8 = 3;

/// No scheduler-commanded preemption is published.
pub const PREEMPTION_KIND_NONE: u8 = 0;
/// The preemption command forces a deterministic vCPU switch.
pub const PREEMPTION_KIND_VCPU_SWITCH: u8 = 1;
/// The preemption command delivers an interrupt to one vCPU.
pub const PREEMPTION_KIND_INTERRUPT_AT: u8 = 2;

/// The advance-ceiling futex uses the cross-process operation, not private futexes.
pub const FUTEX_PRIVATE: bool = false;

/// A per-node shared-memory slot for clock and advance-ceiling handoff.
#[repr(C, align(128))]
pub struct NodeSlot {
    current_icount: AtomicU64,
    current_ns: AtomicU64,
    max_advance_icount: AtomicU64,
    idle_wake_icount: AtomicU64,
    wake_signal: AtomicU32,
    status: AtomicU8,
    kind: AtomicU8,
    device_io_active: AtomicU8,
    _pad0: u8,
    publish_gen: AtomicU32,
    _pad1: [u8; 4],
    device_completion_deadline_icount: AtomicU64,
    preemption_at_icount: AtomicU64,
    preemption_deadline_icount: AtomicU64,
    preemption_ceiling_icount: AtomicU64,
    preemption_published_sequence: AtomicU32,
    preemption_consumed_sequence: AtomicU32,
    preemption_arg0: AtomicU32,
    preemption_arg1: AtomicU32,
    preemption_kind: AtomicU8,
    _reserved: [u8; 31],
}

impl Clone for NodeSlot {
    fn clone(&self) -> Self {
        Self {
            current_icount: AtomicU64::new(self.current_icount.load(Ordering::Acquire)),
            current_ns: AtomicU64::new(self.current_ns.load(Ordering::Acquire)),
            max_advance_icount: AtomicU64::new(self.max_advance_icount.load(Ordering::Acquire)),
            idle_wake_icount: AtomicU64::new(self.idle_wake_icount.load(Ordering::Acquire)),
            wake_signal: AtomicU32::new(self.wake_signal.load(Ordering::Acquire)),
            status: AtomicU8::new(self.status.load(Ordering::Acquire)),
            kind: AtomicU8::new(self.kind.load(Ordering::Acquire)),
            device_io_active: AtomicU8::new(self.device_io_active.load(Ordering::Acquire)),
            _pad0: 0,
            publish_gen: AtomicU32::new(self.publish_gen.load(Ordering::Acquire)),
            _pad1: [0; 4],
            device_completion_deadline_icount: AtomicU64::new(
                self.device_completion_deadline_icount
                    .load(Ordering::Acquire),
            ),
            preemption_at_icount: AtomicU64::new(self.preemption_at_icount.load(Ordering::Acquire)),
            preemption_deadline_icount: AtomicU64::new(
                self.preemption_deadline_icount.load(Ordering::Acquire),
            ),
            preemption_ceiling_icount: AtomicU64::new(
                self.preemption_ceiling_icount.load(Ordering::Acquire),
            ),
            preemption_published_sequence: AtomicU32::new(
                self.preemption_published_sequence.load(Ordering::Acquire),
            ),
            preemption_consumed_sequence: AtomicU32::new(
                self.preemption_consumed_sequence.load(Ordering::Acquire),
            ),
            preemption_arg0: AtomicU32::new(self.preemption_arg0.load(Ordering::Acquire)),
            preemption_arg1: AtomicU32::new(self.preemption_arg1.load(Ordering::Acquire)),
            preemption_kind: AtomicU8::new(self.preemption_kind.load(Ordering::Acquire)),
            _reserved: [0; 31],
        }
    }
}

/// Byte offset of [`NodeSlot`]'s canonical current icount field.
pub const NODE_SLOT_CURRENT_ICOUNT_OFFSET: usize = core::mem::offset_of!(NodeSlot, current_icount);
/// Byte offset of [`NodeSlot`]'s derived current virtual-time field.
pub const NODE_SLOT_CURRENT_NS_OFFSET: usize = core::mem::offset_of!(NodeSlot, current_ns);
/// Byte offset of [`NodeSlot`]'s scheduler-published advance ceiling.
pub const NODE_SLOT_MAX_ADVANCE_ICOUNT_OFFSET: usize =
    core::mem::offset_of!(NodeSlot, max_advance_icount);
/// Byte offset of [`NodeSlot`]'s idle wake icount field.
pub const NODE_SLOT_IDLE_WAKE_ICOUNT_OFFSET: usize =
    core::mem::offset_of!(NodeSlot, idle_wake_icount);
/// Byte offset of [`NodeSlot`]'s futex wake-signal field.
pub const NODE_SLOT_WAKE_SIGNAL_OFFSET: usize = core::mem::offset_of!(NodeSlot, wake_signal);
/// Byte offset of [`NodeSlot`]'s status field.
pub const NODE_SLOT_STATUS_OFFSET: usize = core::mem::offset_of!(NodeSlot, status);
/// Byte offset of [`NodeSlot`]'s kind field.
pub const NODE_SLOT_KIND_OFFSET: usize = core::mem::offset_of!(NodeSlot, kind);
/// Byte offset of [`NodeSlot`]'s device-I/O-active field.
pub const NODE_SLOT_DEVICE_IO_ACTIVE_OFFSET: usize =
    core::mem::offset_of!(NodeSlot, device_io_active);
/// Byte offset of [`NodeSlot`]'s single-byte alignment padding.
pub const NODE_SLOT_PAD0_OFFSET: usize = core::mem::offset_of!(NodeSlot, _pad0);
/// Byte offset of [`NodeSlot`]'s publish-generation field.
pub const NODE_SLOT_PUBLISH_GEN_OFFSET: usize = core::mem::offset_of!(NodeSlot, publish_gen);
/// Byte offset of [`NodeSlot`]'s host-owned device-completion-deadline field.
pub const NODE_SLOT_DEVICE_COMPLETION_DEADLINE_ICOUNT_OFFSET: usize =
    core::mem::offset_of!(NodeSlot, device_completion_deadline_icount);
/// Byte offset of the scheduler-commanded preemption icount.
pub const NODE_SLOT_PREEMPTION_AT_ICOUNT_OFFSET: usize =
    core::mem::offset_of!(NodeSlot, preemption_at_icount);
/// Byte offset of the preemption authorization-window deadline.
pub const NODE_SLOT_PREEMPTION_DEADLINE_ICOUNT_OFFSET: usize =
    core::mem::offset_of!(NodeSlot, preemption_deadline_icount);
/// Byte offset of the preemption authorization-window ceiling.
pub const NODE_SLOT_PREEMPTION_CEILING_ICOUNT_OFFSET: usize =
    core::mem::offset_of!(NodeSlot, preemption_ceiling_icount);
/// Byte offset of the host-published preemption sequence.
pub const NODE_SLOT_PREEMPTION_PUBLISHED_SEQUENCE_OFFSET: usize =
    core::mem::offset_of!(NodeSlot, preemption_published_sequence);
/// Byte offset of the plugin-consumed preemption sequence.
pub const NODE_SLOT_PREEMPTION_CONSUMED_SEQUENCE_OFFSET: usize =
    core::mem::offset_of!(NodeSlot, preemption_consumed_sequence);
/// Byte offset of the first preemption-kind argument.
pub const NODE_SLOT_PREEMPTION_ARG0_OFFSET: usize =
    core::mem::offset_of!(NodeSlot, preemption_arg0);
/// Byte offset of the second preemption-kind argument.
pub const NODE_SLOT_PREEMPTION_ARG1_OFFSET: usize =
    core::mem::offset_of!(NodeSlot, preemption_arg1);
/// Byte offset of the preemption-kind discriminator.
pub const NODE_SLOT_PREEMPTION_KIND_OFFSET: usize =
    core::mem::offset_of!(NodeSlot, preemption_kind);
/// Byte offset of [`NodeSlot`]'s reserved forward-compatibility bytes.
pub const NODE_SLOT_RESERVED_OFFSET: usize = core::mem::offset_of!(NodeSlot, _reserved);
/// Wire size of one [`NodeSlot`].
pub const NODE_SLOT_SIZE: usize = core::mem::size_of::<NodeSlot>();
/// Wire alignment of one [`NodeSlot`].
pub const NODE_SLOT_ALIGN: usize = core::mem::align_of::<NodeSlot>();

pub(super) const _: () = assert!(NODE_SLOT_CURRENT_ICOUNT_OFFSET == 0);
pub(super) const _: () = assert!(NODE_SLOT_CURRENT_NS_OFFSET == 8);
pub(super) const _: () = assert!(NODE_SLOT_MAX_ADVANCE_ICOUNT_OFFSET == 16);
pub(super) const _: () = assert!(NODE_SLOT_IDLE_WAKE_ICOUNT_OFFSET == 24);
pub(super) const _: () = assert!(NODE_SLOT_WAKE_SIGNAL_OFFSET == 32);
pub(super) const _: () = assert!(NODE_SLOT_STATUS_OFFSET == 36);
pub(super) const _: () = assert!(NODE_SLOT_KIND_OFFSET == 37);
pub(super) const _: () = assert!(NODE_SLOT_DEVICE_IO_ACTIVE_OFFSET == 38);
pub(super) const _: () = assert!(NODE_SLOT_PAD0_OFFSET == 39);
pub(super) const _: () = assert!(NODE_SLOT_PUBLISH_GEN_OFFSET == 40);
pub(super) const _: () = assert!(core::mem::offset_of!(NodeSlot, _pad1) == 44);
pub(super) const _: () = assert!(NODE_SLOT_DEVICE_COMPLETION_DEADLINE_ICOUNT_OFFSET == 48);
pub(super) const _: () = assert!(NODE_SLOT_PREEMPTION_AT_ICOUNT_OFFSET == 56);
pub(super) const _: () = assert!(NODE_SLOT_PREEMPTION_DEADLINE_ICOUNT_OFFSET == 64);
pub(super) const _: () = assert!(NODE_SLOT_PREEMPTION_CEILING_ICOUNT_OFFSET == 72);
pub(super) const _: () = assert!(NODE_SLOT_PREEMPTION_PUBLISHED_SEQUENCE_OFFSET == 80);
pub(super) const _: () = assert!(NODE_SLOT_PREEMPTION_CONSUMED_SEQUENCE_OFFSET == 84);
pub(super) const _: () = assert!(NODE_SLOT_PREEMPTION_ARG0_OFFSET == 88);
pub(super) const _: () = assert!(NODE_SLOT_PREEMPTION_ARG1_OFFSET == 92);
pub(super) const _: () = assert!(NODE_SLOT_PREEMPTION_KIND_OFFSET == 96);
pub(super) const _: () = assert!(NODE_SLOT_RESERVED_OFFSET == 97);
pub(super) const _: () = assert!(NODE_SLOT_SIZE == 128);
pub(super) const _: () = assert!(NODE_SLOT_ALIGN == 128);

impl NodeSlot {
    /// Builds a zeroed node slot with `max_advance_icount` held at the boot barrier.
    #[must_use]
    pub const fn new(kind: u8) -> Self {
        Self::new_with_status(kind, STATUS_IDLE)
    }

    pub(super) const fn new_with_status(kind: u8, status: u8) -> Self {
        Self {
            current_icount: AtomicU64::new(0),
            current_ns: AtomicU64::new(0),
            max_advance_icount: AtomicU64::new(0),
            idle_wake_icount: AtomicU64::new(0),
            wake_signal: AtomicU32::new(0),
            status: AtomicU8::new(status),
            kind: AtomicU8::new(kind),
            device_io_active: AtomicU8::new(0),
            _pad0: 0,
            publish_gen: AtomicU32::new(0),
            _pad1: [0; 4],
            device_completion_deadline_icount: AtomicU64::new(0),
            preemption_at_icount: AtomicU64::new(0),
            preemption_deadline_icount: AtomicU64::new(0),
            preemption_ceiling_icount: AtomicU64::new(0),
            preemption_published_sequence: AtomicU32::new(0),
            preemption_consumed_sequence: AtomicU32::new(0),
            preemption_arg0: AtomicU32::new(0),
            preemption_arg1: AtomicU32::new(0),
            preemption_kind: AtomicU8::new(PREEMPTION_KIND_NONE),
            _reserved: [0; 31],
        }
    }

    /// Publishes a scheduler-computed advance ceiling and returns the wake action.
    ///
    /// The ceiling is release-stored so the governed node can acquire-load it
    /// before deciding whether more advancement is authorized.
    ///
    /// # Errors
    ///
    /// Returns [`NodeSlotError::CeilingBeforePublishedCurrent`] when the ceiling
    /// is already behind the slot's published current icount, or
    /// [`NodeSlotError::FutexWake`] when the non-private futex wake syscall
    /// fails.
    pub fn publish_scheduler_ceiling(
        &self,
        ceiling: AdvanceCeiling,
    ) -> Result<WakeAction, NodeSlotError> {
        self.validate_scheduler_ceiling(ceiling)?;

        self.publish_prevalidated_scheduler_ceiling(ceiling)
    }

    /// Publishes pending inbox frames, then the scheduler ceiling, then the wake.
    ///
    /// This borrowed-ring variant is for runtime adapters that hold one node
    /// slot and one inbound SPSC ring rather than a typed [`RegionAllocation`].
    /// It validates the ceiling and ring capacity before publishing any frame,
    /// release-publishes every frame to the inbox, release-publishes the
    /// ceiling, and only then increments the non-private futex wake word.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerWakePublicationError`] when the node slot rejects the
    /// ceiling, an input frame is stamped with a different source than
    /// `src_slot`, the inbox rejects the batch, or the futex wake fails.
    pub fn publish_scheduler_inbox_and_ceiling(
        &self,
        dst_slot: u32,
        src_slot: u32,
        inbox: &RingHeader,
        inbox_entries: &mut [FrameEntry],
        pending_inputs: &[FrameEntry],
        ceiling: AdvanceCeiling,
    ) -> Result<SchedulerWakePublication, SchedulerWakePublicationError> {
        self.validate_scheduler_ceiling(ceiling)?;
        for (input_index, frame) in pending_inputs.iter().enumerate() {
            validate_pending_input_source(input_index, src_slot, frame)?;
        }
        preflight_ring_enqueue_capacity(inbox, inbox_entries, pending_inputs.len())
            .map_err(RegionAllocationAccessError::from)?;

        for frame in pending_inputs {
            inbox
                .enqueue(inbox_entries, frame)
                .map_err(RegionAllocationAccessError::from)?;
        }

        let wake = self.publish_prevalidated_scheduler_ceiling(ceiling)?;
        Ok(SchedulerWakePublication {
            dst_slot,
            pending_input_count: pending_inputs.len(),
            max_advance_icount: ceiling.max_advance_icount,
            wake,
        })
    }

    /// Loads the scheduler-published ceiling with acquire ordering.
    #[must_use]
    pub fn load_node_ceiling(&self) -> u64 {
        self.max_advance_icount.load(Ordering::Acquire)
    }

    /// Publishes that this node has plugin-submitted device I/O in flight.
    pub fn mark_device_io_active(&self) {
        self.publish_device_io_active(true);
    }

    /// Publishes that this node no longer has plugin-submitted device I/O in flight.
    pub fn clear_device_io_active(&self) {
        self.publish_device_io_active(false);
    }

    /// Returns whether plugin-submitted device I/O is currently active.
    #[must_use]
    pub fn load_device_io_active(&self) -> bool {
        self.device_io_active.load(Ordering::Acquire) != 0
    }

    /// Checks whether a node may advance to `next_icount` under the current ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`NodeSlotError::NodeAdvancePastCeiling`] when `next_icount`
    /// exceeds the acquire-loaded scheduler ceiling.
    pub fn check_node_may_advance_to(&self, next_icount: u64) -> Result<(), NodeSlotError> {
        let max_advance_icount = self.load_node_ceiling();
        if next_icount > max_advance_icount {
            Err(NodeSlotError::NodeAdvancePastCeiling {
                next_icount,
                max_advance_icount,
            })
        } else {
            Ok(())
        }
    }

    /// Publishes the reached icount and derived virtual time while the node runs.
    ///
    /// # Errors
    ///
    /// Returns [`NodeSlotError`] when the reached icount exceeds the published
    /// ceiling or cannot be converted to virtual nanoseconds under `shift_bits`.
    pub fn publish_reached_icount(
        &self,
        reached_icount: u64,
        shift_bits: u8,
    ) -> Result<(), NodeSlotError> {
        self.check_node_may_advance_to(reached_icount)?;
        let current_ns = icount_to_virtual_ns(reached_icount, shift_bits)?;
        self.publish_state(reached_icount, current_ns, None, STATUS_RUNNING);
        Ok(())
    }

    /// Publishes that the node is idle and prepares the futex wait precondition.
    ///
    /// # Errors
    ///
    /// Returns [`NodeSlotError`] when `reached_icount` exceeds the published
    /// ceiling, `idle_wake_icount` is behind `reached_icount`, or virtual-time
    /// conversion fails under `shift_bits`.
    pub fn publish_idle(
        &self,
        reached_icount: u64,
        idle_wake_icount: u64,
        shift_bits: u8,
    ) -> Result<FutexWait, NodeSlotError> {
        self.check_node_may_advance_to(reached_icount)?;
        if idle_wake_icount < reached_icount {
            return Err(NodeSlotError::IdleWakeBeforeCurrent {
                current_icount: reached_icount,
                idle_wake_icount,
            });
        }

        let current_ns = icount_to_virtual_ns(reached_icount, shift_bits)?;
        self.publish_state(
            reached_icount,
            current_ns,
            Some(idle_wake_icount),
            STATUS_IDLE,
        );
        Ok(self.prepare_futex_wait())
    }

    /// Publishes that a node quiesced at a pause boundary.
    ///
    /// # Errors
    ///
    /// Returns [`NodeSlotError`] when virtual-time conversion fails under
    /// `shift_bits`.
    pub fn publish_pause_quiesced(
        &self,
        reached_icount: u64,
        shift_bits: u8,
    ) -> Result<(), NodeSlotError> {
        let current_ns = icount_to_virtual_ns(reached_icount, shift_bits)?;
        self.publish_state(
            reached_icount,
            current_ns,
            Some(reached_icount),
            STATUS_IDLE,
        );
        Ok(())
    }

    /// Marks a woken node as running.
    pub fn mark_running(&self) {
        self.publish_gen.fetch_add(1, Ordering::AcqRel);
        self.status.store(STATUS_RUNNING, Ordering::Release);
        self.publish_gen.fetch_add(1, Ordering::AcqRel);
    }

    /// Marks a node as done after it observes shutdown.
    pub fn mark_done(&self) {
        self.publish_gen.fetch_add(1, Ordering::AcqRel);
        self.status.store(STATUS_DONE, Ordering::Release);
        self.publish_gen.fetch_add(1, Ordering::AcqRel);
    }

    /// Returns a stable snapshot of the slot's published fields.
    #[must_use]
    pub fn snapshot(&self) -> NodeSlotSnapshot {
        loop {
            let before = self.publish_gen.load(Ordering::Acquire);
            if !before.is_multiple_of(2) {
                continue;
            }
            let snapshot = NodeSlotSnapshot {
                current_icount: self.current_icount.load(Ordering::Acquire),
                current_ns: self.current_ns.load(Ordering::Acquire),
                max_advance_icount: self.max_advance_icount.load(Ordering::Acquire),
                idle_wake_icount: self.idle_wake_icount.load(Ordering::Acquire),
                wake_signal: self.wake_signal.load(Ordering::Acquire),
                status: self.status.load(Ordering::Acquire),
                kind: self.kind.load(Ordering::Acquire),
                device_io_active: self.device_io_active.load(Ordering::Acquire),
                publish_gen: before,
            };
            let after = self.publish_gen.load(Ordering::Acquire);
            if before == after && after.is_multiple_of(2) {
                return snapshot;
            }
        }
    }

    /// Returns `true` when all forward-compatible reserved slot bytes are zero.
    #[must_use]
    pub fn reserved_bytes_are_zero(&self) -> bool {
        self._pad0 == 0
            && self._pad1.iter().all(|byte| *byte == 0)
            && self._reserved.iter().all(|byte| *byte == 0)
    }

    /// Publishes the host-computed device-completion deadline icount for this slot.
    ///
    /// This field is host-owned in the host-to-plugin direction: the host writes
    /// the exact icount at which a pending device completion for this VM will be
    /// delivered, and a time-owning plugin whose guest is blocked on device I/O
    /// idle-jumps virtual time to it. A value of zero means no device completion
    /// is pending. It is deliberately distinct from `idle_wake_icount` (which is
    /// plugin-published in the other direction) so the two directions never share
    /// one field.
    pub fn store_device_completion_deadline_icount(&self, icount: u64) {
        self.device_completion_deadline_icount
            .store(icount, Ordering::Release);
    }

    /// Returns the host-published device-completion deadline icount, or zero when
    /// no device completion is pending for this slot.
    #[must_use]
    pub fn device_completion_deadline_icount(&self) -> u64 {
        self.device_completion_deadline_icount
            .load(Ordering::Acquire)
    }

    fn publish_state(
        &self,
        current_icount: u64,
        current_ns: u64,
        idle_wake_icount: Option<u64>,
        status: u8,
    ) {
        self.publish_gen.fetch_add(1, Ordering::AcqRel);
        self.current_icount.store(current_icount, Ordering::Release);
        self.current_ns.store(current_ns, Ordering::Release);
        if let Some(idle_wake_icount) = idle_wake_icount {
            self.idle_wake_icount
                .store(idle_wake_icount, Ordering::Release);
        }
        self.status.store(status, Ordering::Release);
        self.publish_gen.fetch_add(1, Ordering::AcqRel);
    }

    fn publish_device_io_active(&self, active: bool) {
        self.publish_gen.fetch_add(1, Ordering::AcqRel);
        self.device_io_active
            .store(u8::from(active), Ordering::Release);
        self.publish_gen.fetch_add(1, Ordering::AcqRel);
    }

    pub(super) fn validate_scheduler_ceiling(
        &self,
        ceiling: AdvanceCeiling,
    ) -> Result<(), NodeSlotError> {
        let current_icount = self.current_icount.load(Ordering::Acquire);
        if ceiling.max_advance_icount < current_icount {
            Err(NodeSlotError::CeilingBeforePublishedCurrent {
                current_icount,
                max_advance_icount: ceiling.max_advance_icount,
            })
        } else {
            Ok(())
        }
    }

    pub(super) fn publish_prevalidated_scheduler_ceiling(
        &self,
        ceiling: AdvanceCeiling,
    ) -> Result<WakeAction, NodeSlotError> {
        self.max_advance_icount
            .store(ceiling.max_advance_icount, Ordering::Release);

        self.wake_after_signal_increment()
            .map_err(|source| NodeSlotError::FutexWake { source })
    }

    fn is_runnable_after_idle_publish(&self) -> bool {
        let status = self.status.load(Ordering::Acquire);
        let max_advance_icount = self.max_advance_icount.load(Ordering::Acquire);
        let idle_wake_icount = self.idle_wake_icount.load(Ordering::Acquire);
        status != STATUS_IDLE || max_advance_icount >= idle_wake_icount
    }

    pub(super) fn wake_after_signal_increment(&self) -> Result<WakeAction, FutexError> {
        let previous = self.wake_signal.fetch_add(1, Ordering::Release);
        let futex = self.futex_wake_nonprivate(1)?;
        Ok(WakeAction::Wake {
            previous,
            new: previous.wrapping_add(1),
            futex,
        })
    }
}

impl Default for NodeSlot {
    fn default() -> Self {
        Self::new(KIND_VM)
    }
}

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
