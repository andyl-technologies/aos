//! `crucible-shmem` owns the shared-memory ABI.
//!
//! Spec index: RFC-0010 files 13.
//!
//! This L1 crate is the single source of truth for the `#[repr(C)]` region
//! layout, per-node clocks, status words, and SPSC frame queues described by
//! its indexed RFC-0010 file. It is an unsafe-boundary crate because future
//! implementations map shared memory and expose layout-checked accessors.
//!
//! Module map: the crate root owns the initial frame-entry layout, the
//! delivery-icount contract, and the per-node advance-ceiling slot. Future
//! modules will split region headers, status words, and SPSC frame queues.
//!
//! Unsafe boundary discipline: mmap, pointer, and atomic details stay private;
//! public callers use safe typed region accessors and safe SPSC push/pop
//! wrappers that uphold alignment, lifetime, and ordering invariants.
//!
//! Frame-entry wire layout:
//!
//! ```text
//! offset  size  field
//! 0       8     delivery_icount
//! 8       4     src_node
//! 12      4     seq
//! 16      2     len
//! 18      6     padding
//! 24      N     payload bytes
//! ```
//!
//! Per-node slot wire layout:
//!
//! ```text
//! offset  size  field
//! 0       8     current_icount
//! 8       8     current_ns
//! 16      8     max_advance_icount
//! 24      8     idle_wake_icount
//! 32      4     wake_signal
//! 36      1     status
//! 37      1     kind
//! 38      1     device_io_active
//! 39      1     padding
//! 40      4     publish_gen
//! 44      84    reserved
//! ```

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};

use thiserror::Error;

/// The maximum frame payload carried by a shared-memory [`FrameEntry`].
///
/// This RFC-fixed value is sector-aligned, leaves room for a 4 KiB block
/// response plus protocol headroom, and still fits in [`FrameEntry::len`].
pub const MAX_FRAME_DATA: usize = 4608;

const FRAME_ENTRY_DATA_OFFSET: usize = 24;
const _: () = assert!(MAX_FRAME_DATA <= u16::MAX as usize);

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

const _: () = assert!(core::mem::offset_of!(FrameEntry, delivery_icount) == 0);
const _: () = assert!(core::mem::offset_of!(FrameEntry, src_node) == 8);
const _: () = assert!(core::mem::offset_of!(FrameEntry, seq) == 12);
const _: () = assert!(core::mem::offset_of!(FrameEntry, len) == 16);
const _: () = assert!(core::mem::offset_of!(FrameEntry, data) == FRAME_ENTRY_DATA_OFFSET);
const _: () =
    assert!(core::mem::size_of::<FrameEntry>() == FRAME_ENTRY_DATA_OFFSET + MAX_FRAME_DATA);
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
/// Byte offset of [`NodeSlot`]'s publish-generation field.
pub const NODE_SLOT_PUBLISH_GEN_OFFSET: usize = core::mem::offset_of!(NodeSlot, publish_gen);
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
const _: () = assert!(NODE_SLOT_PUBLISH_GEN_OFFSET == 40);
const _: () = assert!(NODE_SLOT_SIZE == 128);
const _: () = assert!(NODE_SLOT_ALIGN == 128);

impl NodeSlot {
    /// Builds a zeroed node slot with `max_advance_icount` held at the boot barrier.
    #[must_use]
    pub const fn new(kind: u8) -> Self {
        Self {
            current_icount: AtomicU64::new(0),
            current_ns: AtomicU64::new(0),
            max_advance_icount: AtomicU64::new(0),
            idle_wake_icount: AtomicU64::new(0),
            wake_signal: AtomicU32::new(0),
            status: AtomicU8::new(STATUS_IDLE),
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
    /// is already behind the slot's published current icount.
    pub fn publish_scheduler_ceiling(
        &self,
        ceiling: AdvanceCeiling,
    ) -> Result<WakeAction, NodeSlotError> {
        let current_icount = self.current_icount.load(Ordering::Acquire);
        if ceiling.max_advance_icount < current_icount {
            return Err(NodeSlotError::CeilingBeforePublishedCurrent {
                current_icount,
                max_advance_icount: ceiling.max_advance_icount,
            });
        }

        self.max_advance_icount
            .store(ceiling.max_advance_icount, Ordering::Release);

        Ok(self.bump_wake_signal())
    }

    /// Loads the scheduler-published ceiling with acquire ordering.
    #[must_use]
    pub fn load_node_ceiling(&self) -> u64 {
        self.max_advance_icount.load(Ordering::Acquire)
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

    /// Wakes a node because an inbound frame became actionable.
    #[must_use]
    pub fn wake_for_frame_delivery(&self) -> WakeAction {
        self.bump_wake_signal()
    }

    /// Issues a non-private futex wake on this node's wake-signal word.
    ///
    /// # Errors
    ///
    /// Returns [`FutexError`] when the host is not Linux or the futex syscall
    /// fails for a reason other than no waiters.
    pub fn futex_wake_nonprivate(&self, max_waiters: u32) -> Result<FutexWakeResult, FutexError> {
        futex_wake_nonprivate(&self.wake_signal, max_waiters)
    }

    /// Waits on this node's wake-signal word using non-private `FUTEX_WAIT`.
    ///
    /// # Errors
    ///
    /// Returns [`FutexError`] when the host is not Linux or the futex syscall
    /// fails for an unexpected reason.
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
    /// Returns [`FutexError`] when the host is not Linux or the futex syscall
    /// fails for an unexpected reason.
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

    fn is_runnable_after_idle_publish(&self) -> bool {
        let status = self.status.load(Ordering::Acquire);
        let max_advance_icount = self.max_advance_icount.load(Ordering::Acquire);
        let idle_wake_icount = self.idle_wake_icount.load(Ordering::Acquire);
        status != STATUS_IDLE || max_advance_icount >= idle_wake_icount
    }

    fn bump_wake_signal(&self) -> WakeAction {
        let previous = self.wake_signal.fetch_add(1, Ordering::Release);
        WakeAction::Wake {
            previous,
            new: previous.wrapping_add(1),
        }
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
    /// The wake signal was incremented and a non-private futex wake is required.
    Wake {
        /// The wake signal value before the release increment.
        previous: u32,
        /// The wake signal value after the release increment.
        new: u32,
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
}

/// A futex syscall error.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FutexError {
    /// The non-private futex path is only available on Linux.
    #[error("non-private futex operations are only available on Linux")]
    UnsupportedPlatform,
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
    let raw = unsafe {
        // SAFETY: `wake_signal` is an aligned `AtomicU32` stored in a live
        // `NodeSlot`; its address is valid for the duration of the syscall.
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
    Err(FutexError::UnsupportedPlatform)
}

#[cfg(target_os = "linux")]
fn futex_wait_nonprivate(
    wake_signal: &AtomicU32,
    expected: u32,
) -> Result<FutexWaitOutcome, FutexError> {
    let raw = unsafe {
        // SAFETY: `wake_signal` is an aligned `AtomicU32` stored in a live
        // `NodeSlot`; the timeout pointer is null, so the kernel does not read a
        // userspace `timespec`.
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
    Err(FutexError::UnsupportedPlatform)
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
}

/// The deterministic order key for frames visible to one consumer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FrameDeliveryKey {
    /// The consumer icount at which the frame becomes visible.
    pub delivery_icount: u64,
    /// The producer node id.
    pub src_node: u32,
    /// The per-producer sequence number.
    pub seq: u32,
}

/// Returns all currently deliverable frames in deterministic visibility order.
#[must_use]
pub fn deliverable_frames_at(
    frames: &[FrameEntry],
    consumer_current_icount: u64,
) -> Vec<&FrameEntry> {
    let mut deliverable = frames
        .iter()
        .filter(|frame| frame.is_deliverable_at(consumer_current_icount))
        .collect::<Vec<_>>();

    deliverable.sort_by_key(|frame| frame.delivery_key());

    deliverable
}

/// An advance authorization bounded by the lookahead gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdvanceCeiling {
    current_icount: u64,
    max_advance_icount: u64,
}

impl AdvanceCeiling {
    /// Returns the consumer icount observed before authorization.
    #[must_use]
    pub fn current_icount(&self) -> u64 {
        self.current_icount
    }

    /// Returns the scheduler-authorized maximum icount the consumer may reach.
    #[must_use]
    pub fn max_advance_icount(&self) -> u64 {
        self.max_advance_icount
    }
}

/// Authorizes a max-advance ceiling under the conservative lookahead gate.
///
/// When `earliest_possible_delivery_icount` is present, the returned ceiling is
/// strictly before that icount. The scheduler must publish a fresh
/// authorization once the input group is present and deliverable.
///
/// # Errors
///
/// Returns [`LookaheadGateError::CeilingBeforeCurrent`] when `max_advance_icount`
/// is behind `current_icount`, and
/// [`LookaheadGateError::AdvanceReachesPossibleDelivery`] when the requested
/// ceiling would reach or pass an input that could become visible.
pub fn authorize_advance_ceiling(
    current_icount: u64,
    max_advance_icount: u64,
    earliest_possible_delivery_icount: Option<u64>,
) -> Result<AdvanceCeiling, LookaheadGateError> {
    if max_advance_icount < current_icount {
        return Err(LookaheadGateError::CeilingBeforeCurrent {
            current_icount,
            max_advance_icount,
        });
    }

    if let Some(earliest_possible_delivery_icount) = earliest_possible_delivery_icount
        && max_advance_icount >= earliest_possible_delivery_icount
    {
        return Err(LookaheadGateError::AdvanceReachesPossibleDelivery {
            max_advance_icount,
            earliest_possible_delivery_icount,
        });
    }

    Ok(AdvanceCeiling {
        current_icount,
        max_advance_icount,
    })
}

/// Verifies that a newly enqueued frame has not already missed its delivery.
///
/// # Errors
///
/// Returns [`LookaheadGateError::DeliveryAlreadyPassed`] when the consumer has
/// already reached or passed the frame's delivery icount.
pub fn validate_frame_delivery_is_future(
    frame: &FrameEntry,
    consumer_current_icount: u64,
) -> Result<(), LookaheadGateError> {
    if frame.delivery_icount <= consumer_current_icount {
        Err(LookaheadGateError::DeliveryAlreadyPassed {
            consumer_current_icount,
            frame: frame.delivery_key(),
        })
    } else {
        Ok(())
    }
}

/// A validation error for shared-memory frame entries.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FrameEntryError {
    /// The advertised payload length does not fit in [`MAX_FRAME_DATA`].
    #[error("frame payload length {len} exceeds capacity {capacity}")]
    PayloadLengthExceedsCapacity {
        /// The requested or advertised payload length.
        len: usize,
        /// The configured frame payload capacity.
        capacity: usize,
    },
}

/// A lookahead-gate validation error.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum LookaheadGateError {
    /// A scheduler attempted to publish a ceiling behind the consumer.
    #[error("max advance icount {max_advance_icount} is before current icount {current_icount}")]
    CeilingBeforeCurrent {
        /// The consumer icount observed before authorization.
        current_icount: u64,
        /// The requested maximum advance icount.
        max_advance_icount: u64,
    },
    /// A scheduler attempted to let a node reach an input's possible delivery.
    #[error(
        "max advance icount {max_advance_icount} reaches possible delivery icount {earliest_possible_delivery_icount}"
    )]
    AdvanceReachesPossibleDelivery {
        /// The requested maximum advance icount.
        max_advance_icount: u64,
        /// The earliest icount at which an input could become visible.
        earliest_possible_delivery_icount: u64,
    },
    /// A frame was enqueued after the consumer reached its delivery icount.
    #[error(
        "frame {frame:?} delivery icount is not in the future of consumer icount {consumer_current_icount}"
    )]
    DeliveryAlreadyPassed {
        /// The consumer icount observed when the frame was enqueued.
        consumer_current_icount: u64,
        /// The late frame's deterministic delivery key.
        frame: FrameDeliveryKey,
    },
}

/// An error produced by the per-node advance-ceiling slot.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum NodeSlotError {
    /// A process requested an invalid fixed icount shift.
    #[error("icount shift {shift_bits} cannot be represented as u64")]
    InvalidShift {
        /// The rejected shift value.
        shift_bits: u8,
    },
    /// The virtual-time nanosecond view overflowed `u64`.
    #[error("icount {icount} shifted by {shift_bits} bits overflows virtual nanoseconds")]
    VirtualTimeOverflow {
        /// The icount being converted.
        icount: u64,
        /// The fixed shift value.
        shift_bits: u8,
    },
    /// A scheduler attempted to publish a ceiling behind the node's current icount.
    #[error(
        "max advance icount {max_advance_icount} is before published current icount {current_icount}"
    )]
    CeilingBeforePublishedCurrent {
        /// The node's published current icount.
        current_icount: u64,
        /// The rejected maximum advance icount.
        max_advance_icount: u64,
    },
    /// A node attempted to advance past the scheduler-published ceiling.
    #[error("node attempted to advance to icount {next_icount} past ceiling {max_advance_icount}")]
    NodeAdvancePastCeiling {
        /// The icount the node attempted to reach.
        next_icount: u64,
        /// The scheduler-published ceiling.
        max_advance_icount: u64,
    },
    /// A node published an idle wake behind its current icount.
    #[error("idle wake icount {idle_wake_icount} is before current icount {current_icount}")]
    IdleWakeBeforeCurrent {
        /// The node's current icount.
        current_icount: u64,
        /// The rejected idle wake icount.
        idle_wake_icount: u64,
    },
}
