//! Exact events that fall between a running vCPU's instruction boundaries.
//!
//! A running vCPU never moves its clock without a retirement (TIME-30). An
//! exact-event ceiling it cannot land on settles with the clock at its last
//! boundary below, and the event is taken at its first boundary at or after
//! the event tick, in whichever quantum reaches that boundary.

use super::*;

use crucible_shmem::TICKS_PER_INSTRUCTION;

/// The receiver's boundary below the event, at raw icount 1.
const BOUNDARY_BELOW: u64 = TICKS_PER_INSTRUCTION;

/// An exact event 24 ps past [`BOUNDARY_BELOW`], short of the next boundary.
const EVENT: u64 = BOUNDARY_BELOW + 24;

/// The receiver's first boundary at or after [`EVENT`], at raw icount 2.
const BOUNDARY_AFTER: u64 = 2 * TICKS_PER_INSTRUCTION;

fn publish_ceiling(slot: &NodeSlot, current: u64, ceiling: u64, stop: AdvanceStopCondition) {
    let ceiling = authorize_advance_ceiling(current, ceiling, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, stop)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
}

/// Builds a networked receiver whose inbound ring holds one frame at `delivery`.
fn receiver_with_frame<'a>(
    slot: &'a NodeSlot,
    delivery: u64,
    inbound_header: &'a RingHeader,
    inbound_entries: &'a mut [FrameEntry],
    outbound_header: &'a RingHeader,
    outbound_entries: &'a mut [FrameEntry],
) -> LiveVcpuTimeCallbackState {
    let frame = FrameEntry::new(delivery, SLOT_NET_ROUTER as u32, 0, b"between")
        .unwrap_or_else(|error| panic!("test inbound frame should build: {error}"));
    inbound_header
        .enqueue(inbound_entries, &frame)
        .unwrap_or_else(|error| panic!("test inbound frame should enqueue: {error}"));
    let outbound = MappedDirectedRingMut {
        descriptor: DirectedRing {
            index: 0,
            src_slot: 0,
            dst_slot: SLOT_NET_ROUTER as u32,
        },
        header: outbound_header,
        entries: outbound_entries,
    };
    let inbound = MappedDirectedRingMut {
        descriptor: DirectedRing {
            index: 1,
            src_slot: SLOT_NET_ROUTER as u32,
            dst_slot: 0,
        },
        header: inbound_header,
        entries: inbound_entries,
    };
    let rx_queue = QemuCanonicalNetworkRx::require(Some(test_net_inject))
        .unwrap_or_else(|error| panic!("test RX queue should build: {error}"));
    let state = test_live_state(471, 1, 0, slot)
        .and_then(|state| state.attach_network(0, outbound, inbound, rx_queue, 0))
        .unwrap_or_else(|error| panic!("live network callback state should build: {error}"));
    state
        .on_vcpu_init(0)
        .unwrap_or_else(|error| panic!("vCPU should initialize: {error}"));
    TEST_RX_INJECT_COUNT.store(0, Ordering::SeqCst);
    TEST_RX_INJECT_STATUS.store(0, Ordering::SeqCst);
    state
}

#[test]
fn a_running_receiver_settles_an_exact_event_and_takes_its_frame_at_the_next_boundary() {
    let _runtime_state = crate::runtime::isolate_runtime_state_for_test();
    let slot = NodeSlot::new(KIND_VM);
    publish_ceiling(&slot, 0, EVENT, AdvanceStopCondition::ExactEvent);
    let inbound_header = RingHeader::new();
    let outbound_header = RingHeader::new();
    let mut inbound_entries = vec![FrameEntry::default(); 4];
    let mut outbound_entries = vec![FrameEntry::default(); 4];
    let state = receiver_with_frame(
        &slot,
        EVENT,
        &inbound_header,
        &mut inbound_entries,
        &outbound_header,
        &mut outbound_entries,
    );
    TEST_ICOUNT_RAW.set(1);

    // The next retirement would end 26 ps past the event, so the running
    // vCPU has no budget and cannot cross to the event without retiring.
    assert_eq!(state.max_advance_icount(), Ok(1));
    state
        .publish_boundary_icount(1, true, "sim-settled-publication", Some(EVENT))
        .unwrap_or_else(|error| panic!("settlement should publish: {error}"));

    let settled = slot.snapshot();
    assert_eq!(settled.current_icount, BOUNDARY_BELOW);
    assert!(settled.settles_current_advance());
    assert_eq!(settled.settled_ceiling_tick, EVENT);
    assert_eq!(inbound_header.read_index(), 0);
    assert_eq!(TEST_RX_INJECT_COUNT.load(Ordering::SeqCst), 0);

    // The next quantum runs past the event to its first boundary at or after
    // it; the frame is injected there, not at the event tick.
    publish_ceiling(
        &slot,
        BOUNDARY_BELOW,
        BOUNDARY_AFTER,
        AdvanceStopCondition::Ceiling,
    );
    assert_eq!(state.max_advance_icount(), Ok(2));
    TEST_ICOUNT_RAW.set(2);
    state
        .publish_current_icount(2)
        .unwrap_or_else(|error| panic!("the next boundary should publish: {error}"));
    TEST_ICOUNT_RAW.set(0);

    assert_eq!(slot.snapshot().current_icount, BOUNDARY_AFTER);
    assert_eq!(inbound_header.read_index(), 1);
    assert_eq!(TEST_RX_INJECT_COUNT.load(Ordering::SeqCst), 1);
}

#[test]
fn a_zero_length_advance_publishes_its_boundary_and_takes_a_due_frame() {
    let _runtime_state = crate::runtime::isolate_runtime_state_for_test();
    let slot = NodeSlot::new(KIND_VM);
    // The host publishes an advance that ends at the node's current boundary,
    // where a frame is due. No retirement or time can move, yet the host
    // waits for a publication that answers this advance.
    publish_ceiling(&slot, 0, BOUNDARY_BELOW, AdvanceStopCondition::ExactEvent);
    let inbound_header = RingHeader::new();
    let outbound_header = RingHeader::new();
    let mut inbound_entries = vec![FrameEntry::default(); 4];
    let mut outbound_entries = vec![FrameEntry::default(); 4];
    let state = receiver_with_frame(
        &slot,
        BOUNDARY_BELOW,
        &inbound_header,
        &mut inbound_entries,
        &outbound_header,
        &mut outbound_entries,
    );
    TEST_ICOUNT_RAW.set(1);
    let before = slot.snapshot().publish_gen;

    assert_eq!(state.max_advance_icount(), Ok(1));

    let answered = slot.snapshot();
    assert_ne!(answered.publish_gen, before);
    assert_eq!(answered.current_icount, BOUNDARY_BELOW);
    assert_eq!(inbound_header.read_index(), 1);
    assert_eq!(TEST_RX_INJECT_COUNT.load(Ordering::SeqCst), 1);

    // The same advance is answered once; later budget queries stay silent.
    assert_eq!(state.max_advance_icount(), Ok(1));
    assert_eq!(slot.snapshot().publish_gen, answered.publish_gen);

    // A positive advance is answered by retirement, not here.
    publish_ceiling(
        &slot,
        BOUNDARY_BELOW,
        BOUNDARY_AFTER,
        AdvanceStopCondition::Ceiling,
    );
    assert_eq!(state.max_advance_icount(), Ok(2));
    assert_eq!(slot.snapshot().publish_gen, answered.publish_gen);
    TEST_ICOUNT_RAW.set(0);
}

#[test]
fn a_console_dispatch_zero_length_exact_event_publishes_and_takes_a_due_frame() {
    use crate::runtime::installed_console::{DispatchAdvance, DispatchResult};

    let _runtime_state = crate::runtime::isolate_runtime_state_for_test();
    let slot = NodeSlot::new(KIND_VM);
    // A console node reads its advance through the native seam. The stop byte
    // there is the exact event; the joined budget must keep that meaning and
    // answer the zero-length advance with a publication at the boundary.
    publish_ceiling(&slot, 0, BOUNDARY_BELOW, AdvanceStopCondition::ExactEvent);
    let inbound_header = RingHeader::new();
    let outbound_header = RingHeader::new();
    let mut inbound_entries = vec![FrameEntry::default(); 4];
    let mut outbound_entries = vec![FrameEntry::default(); 4];
    let state = receiver_with_frame(
        &slot,
        BOUNDARY_BELOW,
        &inbound_header,
        &mut inbound_entries,
        &outbound_header,
        &mut outbound_entries,
    );
    TEST_ICOUNT_RAW.set(1);
    let before = slot.snapshot().publish_gen;
    let mut result = DispatchResult {
        raw_ceiling: u64::MAX,
        raw_start: 1,
        logical_start: BOUNDARY_BELOW,
        logical_ceiling: u64::MAX,
        authorization: [0; 128],
        publication_unavailable: false,
    };

    state
        .console_dispatch_budget(&mut result, || {
            Ok(DispatchAdvance::Unowned {
                ceiling: BOUNDARY_BELOW,
            })
        })
        .unwrap_or_else(|error| panic!("the zero-length budget should join: {error}"));
    TEST_ICOUNT_RAW.set(0);

    let answered = slot.snapshot();
    assert!(!result.publication_unavailable);
    assert_eq!(result.raw_ceiling, 1);
    assert_eq!(result.logical_ceiling, BOUNDARY_BELOW);
    assert_ne!(answered.publish_gen, before);
    assert_eq!(answered.current_icount, BOUNDARY_BELOW);
    assert_eq!(inbound_header.read_index(), 1);
    assert_eq!(TEST_RX_INJECT_COUNT.load(Ordering::SeqCst), 1);
}

#[test]
fn a_zero_length_answer_keeps_the_idle_boundary_and_its_deadline() {
    let slot = NodeSlot::new(KIND_VM);
    publish_ceiling(
        &slot,
        0,
        10 * TICKS_PER_INSTRUCTION,
        AdvanceStopCondition::NextAuthenticatedIdle,
    );
    let state = test_live_state(473, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .on_vcpu_init(0)
        .unwrap_or_else(|error| panic!("vCPU should initialize: {error}"));
    TEST_ICOUNT_RAW.set(1);
    state
        .publish_current_icount(1)
        .unwrap_or_else(|error| panic!("the boundary should publish: {error}"));

    // Every vCPU halted at the boundary with a timer due later, and the host
    // took that idle publication as the end of its quantum.
    let wake = 7 * TICKS_PER_INSTRUCTION;
    slot.publish_idle(BOUNDARY_BELOW, wake)
        .unwrap_or_else(|error| panic!("the idle boundary should publish: {error}"));

    // The host's post-quantum clamp republishes the ceiling at the reached
    // boundary. Answering that zero-length advance must not report the
    // halted node as running or drop the deadline it is waiting for.
    publish_ceiling(
        &slot,
        BOUNDARY_BELOW,
        BOUNDARY_BELOW,
        AdvanceStopCondition::Ceiling,
    );
    let before = slot.snapshot().publish_gen;
    assert_eq!(state.max_advance_icount(), Ok(1));
    TEST_ICOUNT_RAW.set(0);

    let answered = slot.snapshot();
    assert_ne!(answered.publish_gen, before);
    assert_eq!(answered.current_icount, BOUNDARY_BELOW);
    assert_eq!(answered.status, STATUS_IDLE);
    assert_eq!(answered.idle_wake_icount, wake);
}

#[test]
fn a_zero_length_answer_keeps_a_running_node_running() {
    let slot = NodeSlot::new(KIND_VM);
    publish_ceiling(
        &slot,
        0,
        10 * TICKS_PER_INSTRUCTION,
        AdvanceStopCondition::Ceiling,
    );
    let state = test_live_state(474, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .on_vcpu_init(0)
        .unwrap_or_else(|error| panic!("vCPU should initialize: {error}"));
    TEST_ICOUNT_RAW.set(1);
    state
        .publish_current_icount(1)
        .unwrap_or_else(|error| panic!("the boundary should publish: {error}"));

    publish_ceiling(
        &slot,
        BOUNDARY_BELOW,
        BOUNDARY_BELOW,
        AdvanceStopCondition::Ceiling,
    );
    let before = slot.snapshot().publish_gen;
    assert_eq!(state.max_advance_icount(), Ok(1));
    TEST_ICOUNT_RAW.set(0);

    let answered = slot.snapshot();
    assert_ne!(answered.publish_gen, before);
    assert_eq!(answered.current_icount, BOUNDARY_BELOW);
    assert_eq!(answered.status, STATUS_RUNNING);
}

#[test]
fn a_running_guest_meets_a_device_deadline_at_its_next_boundary() {
    let slot = NodeSlot::new(KIND_VM);
    publish_ceiling(
        &slot,
        0,
        10 * TICKS_PER_INSTRUCTION,
        AdvanceStopCondition::Ceiling,
    );
    let state = test_live_state(472, 1, 0, &slot)
        .unwrap_or_else(|error| panic!("live callback state should build: {error}"));
    state
        .on_vcpu_init(0)
        .unwrap_or_else(|error| panic!("vCPU should initialize: {error}"));
    TEST_ICOUNT_RAW.set(1);
    state
        .publish_current_icount(1)
        .unwrap_or_else(|error| panic!("the boundary should publish: {error}"));

    // The completion is due 24 ps past the boundary at 50. Stopping at 50
    // would leave the guest short of it with no budget; it runs to 100.
    slot.mark_device_io_active();
    slot.store_device_completion_deadline_tick(EVENT);
    assert_eq!(state.max_advance_icount(), Ok(2));

    // A deadline on a boundary is met exactly there.
    slot.store_device_completion_deadline_tick(3 * TICKS_PER_INSTRUCTION);
    assert_eq!(state.max_advance_icount(), Ok(3));
    TEST_ICOUNT_RAW.set(0);
}
