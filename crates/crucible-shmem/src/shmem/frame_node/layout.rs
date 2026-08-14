//! Per-node slot layout, constants, offsets, and assertions.

use super::*;

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
    pub(crate) current_icount: AtomicU64,
    pub(crate) current_ns: AtomicU64,
    pub(crate) max_advance_icount: AtomicU64,
    pub(crate) idle_wake_icount: AtomicU64,
    pub(crate) wake_signal: AtomicU32,
    pub(crate) status: AtomicU8,
    pub(crate) kind: AtomicU8,
    pub(crate) device_io_active: AtomicU8,
    pub(crate) _pad0: u8,
    pub(crate) publish_gen: AtomicU32,
    pub(crate) control_boundary_ack: AtomicU32,
    pub(crate) device_completion_deadline_icount: AtomicU64,
    pub(crate) preemption_at_icount: AtomicU64,
    pub(crate) preemption_deadline_icount: AtomicU64,
    pub(crate) preemption_ceiling_icount: AtomicU64,
    pub(crate) preemption_published_sequence: AtomicU32,
    pub(crate) preemption_consumed_sequence: AtomicU32,
    pub(crate) preemption_arg0: AtomicU32,
    pub(crate) preemption_arg1: AtomicU32,
    pub(crate) preemption_kind: AtomicU8,
    pub(crate) _pad2: [u8; 7],
    pub(crate) logical_time_raw_icount: AtomicU64,
    pub(crate) logical_time_restore_target: AtomicU64,
    pub(crate) logical_time_restore_request: AtomicU32,
    pub(crate) logical_time_restore_ack: AtomicU32,
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
            control_boundary_ack: AtomicU32::new(self.control_boundary_ack.load(Ordering::Acquire)),
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
            _pad2: [0; 7],
            logical_time_raw_icount: AtomicU64::new(
                self.logical_time_raw_icount.load(Ordering::Acquire),
            ),
            logical_time_restore_target: AtomicU64::new(
                self.logical_time_restore_target.load(Ordering::Acquire),
            ),
            logical_time_restore_request: AtomicU32::new(
                self.logical_time_restore_request.load(Ordering::Acquire),
            ),
            logical_time_restore_ack: AtomicU32::new(
                self.logical_time_restore_ack.load(Ordering::Acquire),
            ),
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
/// Byte offset of the plugin-published drained-control-boundary acknowledgement.
pub const NODE_SLOT_CONTROL_BOUNDARY_ACK_OFFSET: usize =
    core::mem::offset_of!(NodeSlot, control_boundary_ack);
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
/// Byte offset of the alignment padding before logical-time fields.
pub const NODE_SLOT_PAD2_OFFSET: usize = core::mem::offset_of!(NodeSlot, _pad2);
/// Byte offset of the plugin-published raw icount paired with logical time.
pub const NODE_SLOT_LOGICAL_TIME_RAW_ICOUNT_OFFSET: usize =
    core::mem::offset_of!(NodeSlot, logical_time_raw_icount);
/// Byte offset of the host-published logical-time restore target.
pub const NODE_SLOT_LOGICAL_TIME_RESTORE_TARGET_OFFSET: usize =
    core::mem::offset_of!(NodeSlot, logical_time_restore_target);
/// Byte offset of the host-published logical-time restore request generation.
pub const NODE_SLOT_LOGICAL_TIME_RESTORE_REQUEST_OFFSET: usize =
    core::mem::offset_of!(NodeSlot, logical_time_restore_request);
/// Byte offset of the plugin-published logical-time restore acknowledgement.
pub const NODE_SLOT_LOGICAL_TIME_RESTORE_ACK_OFFSET: usize =
    core::mem::offset_of!(NodeSlot, logical_time_restore_ack);
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
const _: () = assert!(NODE_SLOT_CONTROL_BOUNDARY_ACK_OFFSET == 44);
const _: () = assert!(NODE_SLOT_DEVICE_COMPLETION_DEADLINE_ICOUNT_OFFSET == 48);
const _: () = assert!(NODE_SLOT_PREEMPTION_AT_ICOUNT_OFFSET == 56);
const _: () = assert!(NODE_SLOT_PREEMPTION_DEADLINE_ICOUNT_OFFSET == 64);
const _: () = assert!(NODE_SLOT_PREEMPTION_CEILING_ICOUNT_OFFSET == 72);
const _: () = assert!(NODE_SLOT_PREEMPTION_PUBLISHED_SEQUENCE_OFFSET == 80);
const _: () = assert!(NODE_SLOT_PREEMPTION_CONSUMED_SEQUENCE_OFFSET == 84);
const _: () = assert!(NODE_SLOT_PREEMPTION_ARG0_OFFSET == 88);
const _: () = assert!(NODE_SLOT_PREEMPTION_ARG1_OFFSET == 92);
const _: () = assert!(NODE_SLOT_PREEMPTION_KIND_OFFSET == 96);
const _: () = assert!(NODE_SLOT_PAD2_OFFSET == 97);
const _: () = assert!(NODE_SLOT_LOGICAL_TIME_RAW_ICOUNT_OFFSET == 104);
const _: () = assert!(NODE_SLOT_LOGICAL_TIME_RESTORE_TARGET_OFFSET == 112);
const _: () = assert!(NODE_SLOT_LOGICAL_TIME_RESTORE_REQUEST_OFFSET == 120);
const _: () = assert!(NODE_SLOT_LOGICAL_TIME_RESTORE_ACK_OFFSET == 124);
const _: () = assert!(NODE_SLOT_SIZE == 128);
const _: () = assert!(NODE_SLOT_ALIGN == 128);
