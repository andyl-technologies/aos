/// A shared-memory frame whose delivery time is carried in band.
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct FrameEntry {
    /// The consumer icount at which the frame becomes visible.
    pub delivery_icount: u64,
    /// The producer node id.
    pub src_node: u32,
    /// The per-producer sequence number.
    pub seq: u32,
    /// The number of valid bytes in [`FrameEntry::data`].
    pub len: u16,
    _pad: [u8; 6],
    /// The fixed-capacity frame payload buffer.
    pub data: [u8; MAX_FRAME_DATA],
}

/// Byte offset of [`FrameEntry`]'s delivery-icount field.
pub const FRAME_ENTRY_DELIVERY_ICOUNT_OFFSET: usize =
    core::mem::offset_of!(FrameEntry, delivery_icount);
/// Byte offset of [`FrameEntry`]'s source-node field.
pub const FRAME_ENTRY_SRC_NODE_OFFSET: usize = core::mem::offset_of!(FrameEntry, src_node);
/// Byte offset of [`FrameEntry`]'s producer-sequence field.
pub const FRAME_ENTRY_SEQ_OFFSET: usize = core::mem::offset_of!(FrameEntry, seq);
/// Byte offset of [`FrameEntry`]'s payload-length field.
pub const FRAME_ENTRY_LEN_OFFSET: usize = core::mem::offset_of!(FrameEntry, len);
/// Byte offset of [`FrameEntry`]'s reserved padding bytes.
pub const FRAME_ENTRY_PAD_OFFSET: usize = core::mem::offset_of!(FrameEntry, _pad);
/// Byte offset of [`FrameEntry`]'s payload data.
pub const FRAME_ENTRY_DATA_OFFSET: usize = core::mem::offset_of!(FrameEntry, data);
/// Wire size of one [`FrameEntry`].
pub const FRAME_ENTRY_SIZE: usize = core::mem::size_of::<FrameEntry>();
/// Wire alignment of one [`FrameEntry`].
pub const FRAME_ENTRY_ALIGN: usize = core::mem::align_of::<FrameEntry>();

const _: () = assert!(FRAME_ENTRY_DELIVERY_ICOUNT_OFFSET == 0);
const _: () = assert!(FRAME_ENTRY_SRC_NODE_OFFSET == 8);
const _: () = assert!(FRAME_ENTRY_SEQ_OFFSET == 12);
const _: () = assert!(FRAME_ENTRY_LEN_OFFSET == 16);
const _: () = assert!(FRAME_ENTRY_PAD_OFFSET == 18);
const _: () = assert!(FRAME_ENTRY_DATA_OFFSET == 24);
const _: () = assert!(FRAME_ENTRY_SIZE == FRAME_ENTRY_DATA_OFFSET + MAX_FRAME_DATA);
const _: () = assert!(FRAME_ENTRY_ALIGN == 8);
const _: () = assert!(core::mem::offset_of!(FrameEntry, delivery_icount) == 0);
const _: () = assert!(core::mem::offset_of!(FrameEntry, src_node) == 8);
const _: () = assert!(core::mem::offset_of!(FrameEntry, seq) == 12);
const _: () = assert!(core::mem::offset_of!(FrameEntry, len) == 16);
const _: () = assert!(core::mem::offset_of!(FrameEntry, data) == FRAME_ENTRY_DATA_OFFSET);
#[rustfmt::skip]
const _: () = assert!(core::mem::size_of::<FrameEntry>() == FRAME_ENTRY_DATA_OFFSET + MAX_FRAME_DATA);
const _: () = assert!(core::mem::align_of::<FrameEntry>() == 8);

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
    _reserved: [u8; 84],
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
            _reserved: [0; 84],
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
/// Byte offset of [`NodeSlot`]'s reserved forward-compatibility bytes.
pub const NODE_SLOT_RESERVED_OFFSET: usize = core::mem::offset_of!(NodeSlot, _reserved);
/// Wire size of one [`NodeSlot`].
pub const NODE_SLOT_SIZE: usize = core::mem::size_of::<NodeSlot>();
/// Wire alignment of one [`NodeSlot`].
pub const NODE_SLOT_ALIGN: usize = core::mem::align_of::<NodeSlot>();

const _: () = assert!(NODE_SLOT_CURRENT_ICOUNT_OFFSET == 0);
const _: () = assert!(NODE_SLOT_CURRENT_NS_OFFSET == 8);
const _: () = assert!(NODE_SLOT_MAX_ADVANCE_ICOUNT_OFFSET == 16);
const _: () = assert!(NODE_SLOT_IDLE_WAKE_ICOUNT_OFFSET == 24);
const _: () = assert!(NODE_SLOT_WAKE_SIGNAL_OFFSET == 32);
const _: () = assert!(NODE_SLOT_STATUS_OFFSET == 36);
const _: () = assert!(NODE_SLOT_KIND_OFFSET == 37);
const _: () = assert!(NODE_SLOT_DEVICE_IO_ACTIVE_OFFSET == 38);
const _: () = assert!(NODE_SLOT_PAD0_OFFSET == 39);
const _: () = assert!(NODE_SLOT_PUBLISH_GEN_OFFSET == 40);
const _: () = assert!(NODE_SLOT_RESERVED_OFFSET == 44);
const _: () = assert!(NODE_SLOT_SIZE == 128);
const _: () = assert!(NODE_SLOT_ALIGN == 128);

impl NodeSlot {
    /// Builds a zeroed node slot with `max_advance_icount` held at the boot barrier.
    #[must_use]
    pub const fn new(kind: u8) -> Self {
        Self::new_with_status(kind, STATUS_IDLE)
    }

    const fn new_with_status(kind: u8, status: u8) -> Self {
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
            _reserved: [0; 84],
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

    /// Computes the race-free futex wait decision after an idle publish.
    #[must_use]
    pub fn prepare_futex_wait(&self) -> FutexWait {
        let expected = self.wake_signal.load(Ordering::Acquire);
        if self.is_runnable_after_idle_publish() {
            FutexWait::Runnable
        } else {
            FutexWait::Wait { expected }
        }
    }

    /// Returns `true` if a futex wait on `expected` is still warranted.
    #[must_use]
    pub fn futex_wait_still_valid(&self, expected: u32) -> bool {
        self.wake_signal.load(Ordering::Acquire) == expected
            && !self.is_runnable_after_idle_publish()
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

    /// Wakes a node because an inbound frame became actionable.
    ///
    /// # Errors
    ///
    /// Returns [`FutexError`] when the Linux futex wake syscall fails for an
    /// unexpected reason. Non-Linux developer-tooling builds return a no-op
    /// success with zero woken waiters.
    pub fn wake_for_frame_delivery(&self) -> Result<WakeAction, FutexError> {
        self.wake_after_signal_increment()
    }

    /// Wakes a node because an in-flight device-I/O hold was released.
    ///
    /// # Errors
    ///
    /// Returns [`FutexError`] when the Linux futex wake syscall fails for an
    /// unexpected reason. Non-Linux developer-tooling builds return a no-op
    /// success with zero woken waiters.
    pub fn wake_for_device_io_release(&self) -> Result<WakeAction, FutexError> {
        self.wake_after_signal_increment()
    }

    /// Issues a non-private futex wake on this node's wake-signal word.
    ///
    /// # Errors
    ///
    /// Returns [`FutexError`] when the Linux futex syscall fails for a reason
    /// other than no waiters. Non-Linux developer-tooling builds return a
    /// no-op success with zero woken waiters.
    pub fn futex_wake_nonprivate(&self, max_waiters: u32) -> Result<FutexWakeResult, FutexError> {
        futex_wake_nonprivate(&self.wake_signal, max_waiters)
    }

    /// Waits on this node's wake-signal word using non-private `FUTEX_WAIT`.
    ///
    /// # Errors
    ///
    /// Returns [`FutexError`] when the Linux futex syscall fails for an
    /// unexpected reason. Non-Linux developer-tooling builds return
    /// [`FutexWaitOutcome::Noop`] after the race-free pre-check.
    pub fn futex_wait_nonprivate(&self, wait: FutexWait) -> Result<FutexWaitOutcome, FutexError> {
        match wait {
            FutexWait::Runnable => Ok(FutexWaitOutcome::Runnable),
            FutexWait::Wait { expected } => {
                if self.futex_wait_still_valid(expected) {
                    self.futex_wait_word_nonprivate(expected)
                } else {
                    Ok(FutexWaitOutcome::ValueChanged)
                }
            }
        }
    }

    /// Calls non-private `FUTEX_WAIT` directly on the wake-signal word.
    ///
    /// This is the safe syscall wrapper used after the race-free re-check. A
    /// concurrent wake that changes the word before the syscall parks returns
    /// [`FutexWaitOutcome::ValueChanged`].
    ///
    /// # Errors
    ///
    /// Returns [`FutexError`] when the Linux futex syscall fails for an
    /// unexpected reason. Non-Linux developer-tooling builds return
    /// [`FutexWaitOutcome::Noop`].
    pub fn futex_wait_word_nonprivate(
        &self,
        expected: u32,
    ) -> Result<FutexWaitOutcome, FutexError> {
        futex_wait_nonprivate(&self.wake_signal, expected)
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
        self._pad0 == 0 && self._reserved.iter().all(|byte| *byte == 0)
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

    fn validate_scheduler_ceiling(&self, ceiling: AdvanceCeiling) -> Result<(), NodeSlotError> {
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

    fn publish_prevalidated_scheduler_ceiling(
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

    fn wake_after_signal_increment(&self) -> Result<WakeAction, FutexError> {
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

/// A scheduler wake action for a parked node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WakeAction {
    /// The wake signal was incremented and a non-private futex wake was issued.
    Wake {
        /// The wake signal value before the release increment.
        previous: u32,
        /// The wake signal value after the release increment.
        new: u32,
        /// The result of issuing `FUTEX_WAKE` on the wake-signal word.
        futex: FutexWakeResult,
    },
}

/// A node-side futex wait decision after publishing an idle precondition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FutexWait {
    /// The node is already runnable and must not enter `FUTEX_WAIT`.
    Runnable,
    /// The node should wait on `wake_signal` while it still equals `expected`.
    Wait {
        /// The observed futex word used as the `FUTEX_WAIT` expected value.
        expected: u32,
    },
}

/// Result of a non-private futex wake syscall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FutexWakeResult {
    /// Number of waiters woken by the syscall.
    pub waiters_woken: u32,
    /// Whether the private futex flag was used.
    pub futex_private: bool,
}

/// Result of a non-private futex wait syscall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FutexWaitOutcome {
    /// The node was already runnable and no syscall was needed.
    Runnable,
    /// The futex word changed before the wait could park.
    ValueChanged,
    /// The wait was interrupted by a signal.
    Interrupted,
    /// The futex wait returned because a waker woke this waiter.
    Woken,
    /// The non-Linux developer-tooling shim compiled the wait path to a no-op.
    Noop,
}

/// A futex syscall error.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FutexError {
    /// The futex syscall failed unexpectedly.
    #[error("{operation} syscall failed with errno {errno}")]
    Syscall {
        /// The futex operation being attempted.
        operation: &'static str,
        /// The OS errno value.
        errno: i32,
    },
    /// The futex syscall returned an invalid nonnegative count.
    #[error("{operation} syscall returned invalid count {count}")]
    InvalidReturnCount {
        /// The futex operation being attempted.
        operation: &'static str,
        /// The raw return count.
        count: i64,
    },
}

/// An error produced while updating global region control flags.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RegionControlError {
    /// A slot wake failed while broadcasting a control-flag update.
    #[error("waking node slot {slot_index} for control flag failed")]
    WakeSlot {
        /// The index in the caller-provided slot iterator.
        slot_index: usize,
        /// The futex wake failure.
        #[source]
        source: FutexError,
    },
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

#[cfg(target_os = "linux")]
fn futex_wake_nonprivate(
    wake_signal: &AtomicU32,
    max_waiters: u32,
) -> Result<FutexWakeResult, FutexError> {
    // SAFETY: `wake_signal` is an aligned live `AtomicU32` valid for this syscall.
    let raw = unsafe {
        libc::syscall(
            libc::SYS_futex,
            wake_signal.as_ptr(),
            libc::FUTEX_WAKE,
            max_waiters,
        )
    };
    if raw < 0 {
        return Err(last_futex_error("FUTEX_WAKE"));
    }

    let waiters_woken = u32::try_from(raw).map_err(|_| FutexError::InvalidReturnCount {
        operation: "FUTEX_WAKE",
        count: raw,
    })?;
    Ok(FutexWakeResult {
        waiters_woken,
        futex_private: FUTEX_PRIVATE,
    })
}

#[cfg(not(target_os = "linux"))]
fn futex_wake_nonprivate(
    _wake_signal: &AtomicU32,
    _max_waiters: u32,
) -> Result<FutexWakeResult, FutexError> {
    Ok(FutexWakeResult {
        waiters_woken: 0,
        futex_private: FUTEX_PRIVATE,
    })
}

#[cfg(target_os = "linux")]
fn futex_wait_nonprivate(
    wake_signal: &AtomicU32,
    expected: u32,
) -> Result<FutexWaitOutcome, FutexError> {
    // SAFETY: `wake_signal` is aligned and live, and the null timeout is never dereferenced.
    let raw = unsafe {
        libc::syscall(
            libc::SYS_futex,
            wake_signal.as_ptr(),
            libc::FUTEX_WAIT,
            expected,
            core::ptr::null::<libc::timespec>(),
        )
    };
    if raw == 0 {
        return Ok(FutexWaitOutcome::Woken);
    }

    let errno = last_errno();
    match errno {
        libc::EAGAIN => Ok(FutexWaitOutcome::ValueChanged),
        libc::EINTR => Ok(FutexWaitOutcome::Interrupted),
        _ => Err(FutexError::Syscall {
            operation: "FUTEX_WAIT",
            errno,
        }),
    }
}

#[cfg(not(target_os = "linux"))]
fn futex_wait_nonprivate(
    _wake_signal: &AtomicU32,
    _expected: u32,
) -> Result<FutexWaitOutcome, FutexError> {
    Ok(FutexWaitOutcome::Noop)
}

#[cfg(target_os = "linux")]
fn last_futex_error(operation: &'static str) -> FutexError {
    FutexError::Syscall {
        operation,
        errno: last_errno(),
    }
}

#[cfg(target_os = "linux")]
fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

impl FrameEntry {
    /// Builds a frame entry with an in-band delivery icount.
    ///
    /// # Errors
    ///
    /// Returns [`FrameEntryError::PayloadLengthExceedsCapacity`] when `payload`
    /// is too large for [`MAX_FRAME_DATA`].
    pub fn new(
        delivery_icount: u64,
        src_node: u32,
        seq: u32,
        payload: &[u8],
    ) -> Result<Self, FrameEntryError> {
        if payload.len() > MAX_FRAME_DATA {
            return Err(FrameEntryError::PayloadLengthExceedsCapacity {
                len: payload.len(),
                capacity: MAX_FRAME_DATA,
            });
        }

        let mut data = [0; MAX_FRAME_DATA];
        data[..payload.len()].copy_from_slice(payload);

        Ok(Self {
            delivery_icount,
            src_node,
            seq,
            len: payload.len() as u16,
            _pad: [0; 6],
            data,
        })
    }

    /// Returns `true` when this frame is visible at `consumer_current_icount`.
    #[must_use]
    pub fn is_deliverable_at(&self, consumer_current_icount: u64) -> bool {
        self.delivery_icount <= consumer_current_icount
    }

    /// Returns the deterministic per-consumer delivery-order key.
    #[must_use]
    pub fn delivery_key(&self) -> FrameDeliveryKey {
        FrameDeliveryKey {
            delivery_icount: self.delivery_icount,
            src_node: self.src_node,
            seq: self.seq,
        }
    }

    /// Returns the valid payload bytes.
    ///
    /// # Errors
    ///
    /// Returns [`FrameEntryError::PayloadLengthExceedsCapacity`] when a frame
    /// read from shared memory advertises a length greater than
    /// [`MAX_FRAME_DATA`].
    pub fn payload(&self) -> Result<&[u8], FrameEntryError> {
        let len = usize::from(self.len);
        if len > MAX_FRAME_DATA {
            Err(FrameEntryError::PayloadLengthExceedsCapacity {
                len,
                capacity: MAX_FRAME_DATA,
            })
        } else {
            Ok(&self.data[..len])
        }
    }

    /// Returns `true` when the frame-entry padding bytes are zero.
    #[must_use]
    pub fn padding_bytes_are_zero(&self) -> bool {
        self._pad.iter().all(|byte| *byte == 0)
    }

    fn canonicalized_for_snapshot(&self) -> Result<Self, SpscRingError> {
        let len = usize::from(self.len);
        if len > MAX_FRAME_DATA {
            return Err(SpscRingError::InvalidFrameLength {
                len,
                capacity: MAX_FRAME_DATA,
            });
        }

        let mut canonical = self.clone();
        canonical._pad = [0; 6];
        canonical.data[len..].fill(0);
        Ok(canonical)
    }
}

impl Default for FrameEntry {
    fn default() -> Self {
        Self {
            delivery_icount: 0,
            src_node: 0,
            seq: 0,
            len: 0,
            _pad: [0; 6],
            data: [0; MAX_FRAME_DATA],
        }
    }
}
