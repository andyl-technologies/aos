//! Plugin-side shared-memory ordering facade.
//!
//! The plugin is single-threaded on its own side of the shared-memory ABI, but
//! the scheduler, router, and device executors live in other processes. This
//! module is the plugin's narrow funnel for shared-memory access: callers use
//! named operations whose underlying `crucible_shmem` methods carry the ABI's
//! acquire and release ordering. Plugin-local diagnostics may use relaxed
//! atomics only when they are not stored in the shared-memory region and do not
//! publish data to another process.

use crucible_shmem::{
    FrameEntry, FutexError, FutexWait, FutexWaitOutcome, NodeSlot, NodeSlotError,
    RegionControlAction, RegionHeader, RingHeader, SpscRingError, WakeAction,
};
#[cfg(unix)]
use crucible_shmem::{
    MappedSetupRegion, RegionHeaderSnapshot, RegionSetupValidationError, ValidatedSetupRegion,
};

/// Shared-memory operations the plugin is allowed to perform.
#[derive(Debug)]
pub struct PluginShmemOrdering;

impl PluginShmemOrdering {
    /// Observes the header control flags with acquire ordering.
    #[must_use]
    pub fn observe_control_action(header: &RegionHeader) -> RegionControlAction {
        header.control_action()
    }

    /// Observes the global shutdown flag with acquire ordering.
    #[must_use]
    pub fn observe_shutdown_requested(header: &RegionHeader) -> bool {
        header.shutdown_requested()
    }

    /// Takes an acquire snapshot of the setup-time mapped region header.
    #[cfg(unix)]
    #[must_use]
    pub fn setup_header_snapshot(mapped_region: &MappedSetupRegion) -> RegionHeaderSnapshot {
        mapped_region.header_snapshot()
    }

    /// Validates the setup-time mapped region header through the shmem ABI helper.
    ///
    /// # Errors
    ///
    /// Returns [`RegionSetupValidationError`] when the mapped header does not
    /// match the current shared-memory ABI or the setup-provided region length.
    #[cfg(unix)]
    pub fn validate_setup_header(
        mapped_region: &MappedSetupRegion,
    ) -> Result<ValidatedSetupRegion, RegionSetupValidationError> {
        mapped_region.validate_header()
    }

    /// Loads the scheduler-published advance ceiling with acquire ordering.
    #[must_use]
    pub fn load_scheduler_ceiling(slot: &NodeSlot) -> u64 {
        slot.load_node_ceiling()
    }

    /// Publishes the plugin's reached icount and derived virtual time.
    ///
    /// The underlying slot method release-stores the published node state so the
    /// scheduler can acquire-read a coherent handoff.
    ///
    /// # Errors
    ///
    /// Returns [`NodeSlotError`] when the reached icount exceeds the scheduler
    /// ceiling or virtual-time conversion fails.
    pub fn publish_reached_icount(
        slot: &NodeSlot,
        reached_icount: u64,
        shift_bits: u8,
    ) -> Result<(), NodeSlotError> {
        slot.publish_reached_icount(reached_icount, shift_bits)
    }

    /// Publishes the plugin's idle state and prepares a futex wait decision.
    ///
    /// The underlying slot method release-stores the idle state before returning
    /// the race-free wait precondition.
    ///
    /// # Errors
    ///
    /// Returns [`NodeSlotError`] when the reached icount or idle wake violates
    /// the scheduler ceiling contract, or virtual-time conversion fails.
    pub fn publish_idle_wait(
        slot: &NodeSlot,
        reached_icount: u64,
        idle_wake_icount: u64,
        shift_bits: u8,
    ) -> Result<FutexWait, NodeSlotError> {
        slot.publish_idle(reached_icount, idle_wake_icount, shift_bits)
    }

    /// Recomputes the race-free futex wait decision with acquire loads.
    #[must_use]
    pub fn prepare_futex_wait(slot: &NodeSlot) -> FutexWait {
        slot.prepare_futex_wait()
    }

    /// Waits on the shared wake-signal futex after the slot re-check.
    ///
    /// # Errors
    ///
    /// Returns [`FutexError`] when the non-private futex wait syscall fails.
    pub fn wait_on_wake_signal(
        slot: &NodeSlot,
        wait: FutexWait,
    ) -> Result<FutexWaitOutcome, FutexError> {
        slot.futex_wait_nonprivate(wait)
    }

    /// Publishes that the plugin has resumed running after a wake.
    pub fn mark_running_after_wake(slot: &NodeSlot) {
        slot.mark_running();
    }

    /// Publishes that the plugin observed shutdown and is done.
    pub fn mark_done_after_shutdown(slot: &NodeSlot) {
        slot.mark_done();
    }

    /// Loads the device-I/O-active flag with acquire ordering.
    #[must_use]
    pub fn device_io_active(slot: &NodeSlot) -> bool {
        slot.load_device_io_active()
    }

    /// Loads the host-published device-I/O completion deadline in icount units.
    ///
    /// The host block-I/O servicer stores the icount at which the earliest
    /// in-flight device request becomes deliverable (`ceil(vt(request) +
    /// latency)`). A value of `0` means no completion is pending or the prior
    /// deadline was retracted. The plugin reads this while `device_io_active`
    /// holds so it can idle-jump the guest directly to the completion instead of
    /// freezing to the scheduler ceiling.
    #[must_use]
    pub fn device_completion_deadline_icount(slot: &NodeSlot) -> u64 {
        slot.device_completion_deadline_icount()
    }

    /// Publishes that plugin-submitted device I/O is in flight.
    pub fn publish_device_io_active(slot: &NodeSlot) {
        slot.mark_device_io_active();
    }

    /// Clears the plugin-submitted device-I/O-active flag.
    pub fn clear_device_io_active(slot: &NodeSlot) {
        slot.clear_device_io_active();
    }

    /// Wakes an idle waiter after device I/O stops holding virtual time.
    ///
    /// # Errors
    ///
    /// Returns [`FutexError`] when the non-private futex wake syscall fails.
    pub fn wake_for_device_io_release(slot: &NodeSlot) -> Result<WakeAction, FutexError> {
        slot.wake_for_device_io_release()
    }

    /// Wakes an idle waiter after an inbound frame becomes deliverable.
    ///
    /// # Errors
    ///
    /// Returns [`FutexError`] when the non-private futex wake syscall fails.
    pub fn wake_for_frame_delivery(slot: &NodeSlot) -> Result<WakeAction, FutexError> {
        slot.wake_for_frame_delivery()
    }

    /// Enqueues one outbound frame with the SPSC release-publish protocol.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when the ring capacity or indices are invalid,
    /// or when the outbound ring is full.
    pub fn enqueue_outbound_frame(
        header: &RingHeader,
        entries: &mut [FrameEntry],
        frame: &FrameEntry,
    ) -> Result<(), SpscRingError> {
        header.enqueue(entries, frame)
    }

    /// Peeks an inbound delivery icount with the SPSC acquire-consume protocol.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when the ring capacity or indices are invalid.
    pub fn peek_inbound_delivery_icount(
        header: &RingHeader,
        entries: &[FrameEntry],
    ) -> Result<Option<u64>, SpscRingError> {
        header.peek_delivery_icount(entries)
    }

    /// Dequeues one inbound frame and release-frees the consumed slot.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when the ring capacity or indices are invalid.
    pub fn dequeue_inbound_frame(
        header: &RingHeader,
        entries: &[FrameEntry],
    ) -> Result<Option<FrameEntry>, SpscRingError> {
        header.dequeue(entries)
    }

    /// Reads the consumer-owned index through the ABI accessor.
    ///
    /// The ABI permits a consumer to read its own index relaxed, but this accessor
    /// uses the safe shared-memory method and does not weaken ordering at the
    /// plugin boundary.
    #[must_use]
    pub fn consumer_read_index(header: &RingHeader) -> u64 {
        header.read_index()
    }

    /// Reads the producer-owned write index with acquire ordering.
    ///
    /// The plugin uses this on inbound rings before inspecting entries that may
    /// have been published by another process.
    #[must_use]
    pub fn producer_write_index(header: &RingHeader) -> u64 {
        header.write_index()
    }
}

#[cfg(test)]
mod tests {
    use crucible_shmem::{
        FrameEntry, KIND_VM, NodeSlot, RegionConfig, RegionHeader, RegionLayout, RingHeader,
    };

    use super::PluginShmemOrdering;

    #[test]
    fn shmem_ordering_facade_publishes_idle_state_and_observes_ceiling() {
        let slot = NodeSlot::new(KIND_VM);
        let wait = match PluginShmemOrdering::publish_idle_wait(&slot, 0, 1, 0) {
            Ok(wait) => wait,
            Err(error) => {
                panic!("idle publish should use the safe slot ordering helper: {error}");
            }
        };

        assert_eq!(wait, crucible_shmem::FutexWait::Wait { expected: 0 });
        assert_eq!(PluginShmemOrdering::load_scheduler_ceiling(&slot), 0);
        let snapshot = slot.snapshot();
        assert_eq!(snapshot.current_icount, 0);
        assert_eq!(snapshot.idle_wake_icount, 1);
    }

    #[test]
    fn shmem_ordering_facade_enqueues_peeks_and_dequeues_spsc_frames() {
        let header = RingHeader::new();
        let mut entries = vec![FrameEntry::default(); 2];
        let frame = match FrameEntry::new(7, 2, 3, b"abc") {
            Ok(frame) => frame,
            Err(error) => panic!("test frame should fit in the SPSC entry: {error}"),
        };

        if let Err(error) =
            PluginShmemOrdering::enqueue_outbound_frame(&header, &mut entries, &frame)
        {
            panic!("facade enqueue should use release-publish SPSC helper: {error}");
        }
        assert_eq!(PluginShmemOrdering::producer_write_index(&header), 1);
        assert_eq!(
            PluginShmemOrdering::peek_inbound_delivery_icount(&header, &entries),
            Ok(Some(7))
        );
        assert_eq!(PluginShmemOrdering::consumer_read_index(&header), 0);

        let dequeued = match PluginShmemOrdering::dequeue_inbound_frame(&header, &entries) {
            Ok(Some(frame)) => frame,
            Ok(None) => panic!("one frame should be queued"),
            Err(error) => {
                panic!("facade dequeue should use acquire-consume SPSC helper: {error}");
            }
        };
        assert_eq!(dequeued.delivery_key(), frame.delivery_key());
        assert_eq!(PluginShmemOrdering::consumer_read_index(&header), 1);
    }

    #[test]
    fn shmem_ordering_facade_observes_shutdown_requested() {
        let layout = match RegionLayout::for_config(RegionConfig::new(1, 2, 0)) {
            Ok(layout) => layout,
            Err(error) => panic!("test region layout should be valid: {error}"),
        };
        let header = RegionHeader::new(layout);
        let slot = NodeSlot::new(KIND_VM);
        if let Err(error) = header.request_shutdown([&slot]) {
            panic!("test shutdown request should wake slot: {error}");
        }

        assert!(PluginShmemOrdering::observe_shutdown_requested(&header));
    }
}
