//! Shared fixtures for the idle-loop test suite (helpers and thread-local
//! accounting used by the case modules).

use super::super::*;

use std::cell::Cell;

use crucible_shmem::{
    AdvanceCeiling, KIND_VM, RegionConfig, RegionHeader, RegionLayout, RingHeader,
    authorize_advance_ceiling,
};

use crate::{
    CANONICAL_TIME_CONTROL_REGISTRATION_ORDER, CanonicalNetworkRx, CoverageCapabilities,
    NetworkRxDeliveryError, NetworkRxDeliveryOutcome, PluginArgs, PluginRegistrationSequence,
    PluginTimeControlOwnership,
};

thread_local! {
    static LAST_DIRECT_ADVANCE_NS: Cell<i64> = const { Cell::new(-1) };
    static BLOCKED_DIRECT_ADVANCE_NS: Cell<i64> = const { Cell::new(-1) };
}

pub(super) fn owned_clock(initial_icount: u64, icount_shift: u8) -> PluginVirtualClock {
    match PluginVirtualClock::new(initial_icount, icount_shift, ownership()) {
        Ok(clock) => clock,
        Err(error) => panic!("test clock should construct: {error}"),
    }
}

pub(super) fn deadline_reader(deadline: crate::QemuClockDeadlineFn) -> ExactDeadlineReader {
    match ExactDeadlineReader::require(Some(deadline)) {
        Ok(reader) => reader,
        Err(error) => panic!("test deadline reader should require symbol: {error}"),
    }
}

pub(super) fn queued_idle_advance() -> QueuedIdleAdvance {
    match QueuedIdleAdvance::require(Some(test_direct_advance)) {
        Ok(advance) => advance,
        Err(error) => panic!("test queued advance should require symbol: {error}"),
    }
}

pub(super) fn blocked_queued_idle_advance() -> QueuedIdleAdvance {
    match QueuedIdleAdvance::require(Some(test_blocked_direct_advance)) {
        Ok(advance) => advance,
        Err(error) => panic!("test blocked queued advance should require symbol: {error}"),
    }
}

pub(super) fn expect_pending(
    result: Result<IdleHotLoopResult, IdleHotLoopError>,
) -> PendingIdleAdvance {
    match result {
        Err(IdleHotLoopError::TimeAdvanceCompletionPending {
            pending_advance, ..
        }) => pending_advance,
        Ok(_result) => panic!("queued advance must not complete inside the idle callback"),
        Err(error) => panic!("queued advance should return a pending token: {error}"),
    }
}

pub(super) fn successful_completion(pending: PendingIdleAdvance) -> TimeAdvanceCompletion {
    let target = i64::try_from(pending.target_virtual_ns())
        .unwrap_or_else(|error| panic!("test target should fit QEMU ABI: {error}"));
    TimeAdvanceCompletion::from_qemu(0, target)
}

pub(super) extern "C" fn deadline_10() -> i64 {
    10
}

pub(super) extern "C" fn deadline_20() -> i64 {
    20
}

pub(super) extern "C" fn deadline_40() -> i64 {
    40
}

pub(super) extern "C" fn deadline_80() -> i64 {
    80
}

pub(super) extern "C" fn test_direct_advance(target_virtual_ns: i64) -> std::os::raw::c_int {
    set_last_direct_advance_ns(target_virtual_ns);
    0
}

pub(super) extern "C" fn test_blocked_direct_advance(
    target_virtual_ns: i64,
) -> std::os::raw::c_int {
    set_blocked_direct_advance_ns(target_virtual_ns);
    0
}

pub(super) fn set_last_direct_advance_ns(value: i64) {
    LAST_DIRECT_ADVANCE_NS.with(|cell| cell.set(value));
}

pub(super) fn last_direct_advance_ns() -> i64 {
    LAST_DIRECT_ADVANCE_NS.with(|cell| cell.get())
}

pub(super) fn set_blocked_direct_advance_ns(value: i64) {
    BLOCKED_DIRECT_ADVANCE_NS.with(|cell| cell.set(value));
}

pub(super) fn blocked_direct_advance_ns() -> i64 {
    BLOCKED_DIRECT_ADVANCE_NS.with(|cell| cell.get())
}

pub(super) fn ownership() -> PluginTimeControlOwnership {
    PluginTimeControlOwnership::acquired_after_registration(registration_ready())
}

pub(super) fn registration_ready() -> crate::PluginRegistrationReady {
    let mut sequence = PluginRegistrationSequence::new();
    let args = PluginArgs::parse("simfd=3,slot=0,fault_node_hash=1111111111111111111111111111111111111111111111111111111111111111,process_generation=1,network_tx_next_seq=0")
        .unwrap_or_else(|error| panic!("test args should parse: {error}"));
    let mut setup_ack = None;
    for step in CANONICAL_TIME_CONTROL_REGISTRATION_ORDER {
        let result = if step == crate::PluginRegistrationStep::RegisterCallbacks {
            sequence
                .register_callbacks_for_test(
                    &args,
                    Some(idle_loop_test_deadline),
                    Some(idle_loop_test_direct_advance),
                    CoverageCapabilities::none(),
                )
                .map(|_capabilities| ())
        } else if step == crate::PluginRegistrationStep::SendSetupAck {
            sequence.record_test_ready_setup_ack().map(|ack| {
                setup_ack = Some(ack);
            })
        } else if step == crate::PluginRegistrationStep::WaitBootBarrier {
            let ack = setup_ack
                .take()
                .unwrap_or_else(|| panic!("setup ack should precede boot barrier"));
            let slot = NodeSlot::new(KIND_VM);
            publish_ceiling(&slot, ceiling(0, crate::BOOT_BARRIER_FIRST_GUEST_ICOUNT));
            sequence.wait_boot_barrier(ack, &slot, 0).map(|_release| ())
        } else {
            sequence.record_step(step)
        };
        if let Err(error) = result {
            panic!("test registration step {step:?} should record: {error}");
        }
    }
    match sequence.finish() {
        Ok(ready) => ready,
        Err(error) => panic!("test registration should finish: {error}"),
    }
}

pub(super) extern "C" fn idle_loop_test_deadline() -> i64 {
    1
}

pub(super) extern "C" fn idle_loop_test_direct_advance(
    _target_virtual_ns: i64,
) -> std::os::raw::c_int {
    0
}

pub(super) fn ceiling(current_icount: u64, max_advance_icount: u64) -> AdvanceCeiling {
    match authorize_advance_ceiling(current_icount, max_advance_icount, None) {
        Ok(ceiling) => ceiling,
        Err(error) => panic!("test ceiling should authorize: {error}"),
    }
}

pub(super) fn publish_ceiling(slot: &NodeSlot, ceiling: AdvanceCeiling) {
    if let Err(error) = slot.publish_scheduler_ceiling(ceiling) {
        panic!("test ceiling should publish: {error}");
    }
}

pub(super) struct RecordingNetworkRxQueue<'a> {
    pub(super) slot: &'a NodeSlot,
    pub(super) queued_payloads: Vec<Vec<u8>>,
    pub(super) direct_advance_ns_at_queue: Vec<i64>,
    pub(super) slot_status_at_queue: Vec<u8>,
    pub(super) delivery_error_at: Option<usize>,
}

impl<'a> RecordingNetworkRxQueue<'a> {
    pub(super) fn for_slot(slot: &'a NodeSlot) -> Self {
        Self {
            slot,
            queued_payloads: Vec::new(),
            direct_advance_ns_at_queue: Vec::new(),
            slot_status_at_queue: Vec::new(),
            delivery_error_at: None,
        }
    }
}

impl CanonicalNetworkRx for RecordingNetworkRxQueue<'_> {
    fn try_deliver_rx(
        &mut self,
        payload: &[u8],
    ) -> Result<NetworkRxDeliveryOutcome, NetworkRxDeliveryError> {
        if self.delivery_error_at == Some(self.queued_payloads.len()) {
            return Err(NetworkRxDeliveryError::delivery("test delivery failure"));
        }
        self.direct_advance_ns_at_queue
            .push(last_direct_advance_ns());
        self.slot_status_at_queue.push(self.slot.snapshot().status);
        self.queued_payloads.push(payload.to_vec());
        Ok(NetworkRxDeliveryOutcome::Delivered)
    }
}

pub(super) fn header() -> RegionHeader {
    RegionHeader::new(layout())
}

pub(super) fn layout() -> RegionLayout {
    match RegionLayout::for_config(RegionConfig::new(2, 8, 0)) {
        Ok(layout) => layout,
        Err(error) => panic!("test region layout should be valid: {error}"),
    }
}

pub(super) fn empty_entries() -> Vec<FrameEntry> {
    vec![FrameEntry::default(); 4]
}

pub(super) fn enqueue(header: &RingHeader, entries: &mut [FrameEntry], frame: FrameEntry) {
    if let Err(error) = PluginShmemOrdering::enqueue_outbound_frame(header, entries, &frame) {
        panic!("test frame should enqueue: {error}");
    }
}

pub(super) fn frame(delivery_icount: u64, src_node: u32, seq: u32, payload: &[u8]) -> FrameEntry {
    match FrameEntry::new(delivery_icount, src_node, seq, payload) {
        Ok(frame) => frame,
        Err(error) => panic!("test frame should construct: {error}"),
    }
}
