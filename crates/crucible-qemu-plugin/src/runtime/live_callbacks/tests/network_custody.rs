//! Accepted-prefix ownership and uncertain RX checkpoint refusal regressions.

use std::cell::RefCell;
use std::collections::VecDeque;

use super::*;

thread_local! {
    static RX_RESULTS: RefCell<VecDeque<i32>> = const { RefCell::new(VecDeque::new()) };
    static RX_ATTEMPTS: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
}

extern "C" fn scripted_rx(payload: *const u8, payload_len: usize) -> i32 {
    // SAFETY: QemuCanonicalNetworkRx supplies the borrowed frame payload for
    // the complete synchronous call. The test copies it before returning.
    let payload = unsafe { std::slice::from_raw_parts(payload, payload_len) };
    RX_ATTEMPTS.with_borrow_mut(|attempts| attempts.push(payload.to_vec()));
    RX_RESULTS.with_borrow_mut(|results| results.pop_front().unwrap_or(0))
}

struct NetworkFixture {
    slot: NodeSlot,
    outbound: RingHeader,
    inbound: RingHeader,
    outbound_entries: Vec<FrameEntry>,
    inbound_entries: Vec<FrameEntry>,
}

impl NetworkFixture {
    fn new() -> Self {
        RX_RESULTS.with_borrow_mut(VecDeque::clear);
        RX_ATTEMPTS.with_borrow_mut(Vec::clear);

        Self {
            slot: NodeSlot::new(KIND_VM),
            outbound: RingHeader::new(),
            inbound: RingHeader::new(),
            outbound_entries: vec![FrameEntry::default(); 4],
            inbound_entries: vec![FrameEntry::default(); 4],
        }
    }

    fn enqueue(&mut self, sequence: u32, payload: &[u8]) -> FrameEntry {
        let frame = FrameEntry::new(20, SLOT_NET_ROUTER as u32, sequence, payload)
            .unwrap_or_else(|error| panic!("test frame should construct: {error}"));
        self.inbound
            .enqueue(&mut self.inbound_entries, &frame)
            .unwrap_or_else(|error| panic!("test frame should enqueue: {error}"));
        frame
    }

    fn state(&mut self) -> LiveVcpuTimeCallbackState {
        let rx_queue = QemuCanonicalNetworkRx::require(Some(scripted_rx))
            .unwrap_or_else(|error| panic!("scripted RX should attach: {error}"));
        let outbound = MappedDirectedRingMut {
            descriptor: DirectedRing {
                index: 0,
                src_slot: 0,
                dst_slot: SLOT_NET_ROUTER as u32,
            },
            header: &self.outbound,
            entries: &mut self.outbound_entries,
        };
        let inbound = MappedDirectedRingMut {
            descriptor: DirectedRing {
                index: 1,
                src_slot: SLOT_NET_ROUTER as u32,
                dst_slot: 0,
            },
            header: &self.inbound,
            entries: &mut self.inbound_entries,
        };

        test_live_state(149, 1, 0, &self.slot)
            .and_then(|state| state.attach_network(0, outbound, inbound, rx_queue, 0))
            .unwrap_or_else(|error| panic!("live network state should construct: {error}"))
    }
}

#[test]
fn live_later_frame_error_never_replays_the_accepted_prefix() {
    let mut fixture = NetworkFixture::new();
    fixture.enqueue(0, b"accepted");
    let second = fixture.enqueue(1, b"failed");
    let state = fixture.state();
    RX_RESULTS.with_borrow_mut(|results| results.extend([0, -libc::EIO, 0]));

    assert!(matches!(
        state.inject_due_network_inbound(20, 20),
        Err(LiveVcpuTimeCallbackError::NetworkRx {
            source: crate::NetworkRxError::Delivery { .. }
        })
    ));
    assert_eq!(fixture.inbound.read_index(), 1);
    assert!(!state.network_rx_commit_uncertain());
    let remaining = state
        .network_inbound_head_observe()
        .unwrap_or_else(|error| panic!("network fixture operation should succeed: {error}"))
        .unwrap_or_else(|| panic!("original network fixture state should be present"));
    assert_eq!(remaining.frame, second);
    assert_eq!(remaining.read_index, 1);

    assert_eq!(state.inject_due_network_inbound(20, 20), Ok(()));
    assert_eq!(fixture.inbound.read_index(), 2);
    assert_eq!(state.network_inbound_head_observe(), Ok(None));
    RX_ATTEMPTS.with_borrow(|attempts| {
        assert_eq!(
            attempts,
            &vec![b"accepted".to_vec(), b"failed".to_vec(), b"failed".to_vec()]
        );
    });
}

#[test]
fn registered_head_observation_rejects_foreign_owner_and_reused_frame_bytes() {
    let mut fixture = NetworkFixture::new();
    let frame = fixture.enqueue(0, b"head");
    fixture.enqueue(0, b"head");
    let state = fixture.state();
    let original = state
        .network_inbound_head_observe()
        .unwrap_or_else(|error| panic!("network fixture operation should succeed: {error}"))
        .unwrap_or_else(|| panic!("original network fixture state should be present"));
    assert_eq!(state.network_inbound_head_current(&original), Ok(true));

    let mut foreign = original.clone();
    foreign.owner_generation += 1;
    assert_eq!(state.network_inbound_head_current(&foreign), Ok(false));
    let mut replaced_payload = original.clone();
    replaced_payload.frame = FrameEntry::new(20, SLOT_NET_ROUTER as u32, 0, b"other")
        .unwrap_or_else(|error| panic!("network fixture operation should succeed: {error}"));
    assert_eq!(replaced_payload.frame.delivery_key(), frame.delivery_key());
    assert_eq!(
        state.network_inbound_head_current(&replaced_payload),
        Ok(false)
    );

    assert_eq!(
        PluginShmemOrdering::dequeue_inbound_frame(&fixture.inbound, &fixture.inbound_entries),
        Ok(Some(frame.clone()))
    );
    let successor = state
        .network_inbound_head_observe()
        .unwrap_or_else(|error| panic!("network fixture operation should succeed: {error}"))
        .unwrap_or_else(|| panic!("original network fixture state should be present"));
    assert_eq!(successor.frame, frame);
    assert_eq!(successor.read_index, 1);
    assert_eq!(state.network_inbound_head_current(&original), Ok(false));
    assert_eq!(state.network_inbound_head_current(&successor), Ok(true));
    RX_ATTEMPTS.with_borrow(|attempts| assert!(attempts.is_empty()));
}

#[test]
fn hot_fork_rejects_rx_poison_when_an_in_flight_callback_finishes_during_snapshot() {
    for action in [
        crate::QEMU_PLUGIN_HOT_FORK_BARRIER_HOLD,
        crate::QEMU_PLUGIN_HOT_FORK_BARRIER_QUERY,
    ] {
        let mut fixture = NetworkFixture::new();
        let frame = fixture.enqueue(0, b"accepted");
        let state = fixture.state();
        let callback = state
            .quiescence
            .enter()
            .unwrap_or_else(|| panic!("original network fixture state should be present"));
        if action == crate::QEMU_PLUGIN_HOT_FORK_BARRIER_QUERY {
            assert_eq!(state.quiescence.hold_hot_fork().in_flight, 1);
        }
        assert!(!state.network_rx_commit_uncertain());

        let result = crate::runtime::collect_hot_fork_state_with_network_rx_check(
            Some(&state),
            action,
            || {
                // Finish an admitted RX callback after the entry poison check
                // and before the barrier acquires its quiescence snapshot.
                let network = state
                    .network
                    .as_ref()
                    .unwrap_or_else(|| panic!("original network fixture state should be present"));
                let mut rx_queue = network.rx_queue;
                assert!(matches!(
                    network.rx.inject_due_frames_with_commit(
                        &mut rx_queue,
                        20,
                        20,
                        std::slice::from_ref(&frame),
                        |_| Err(InboundFrameError::CommittedBatchMismatch {
                            expected: vec![frame.delivery_key()],
                            actual: Vec::new(),
                        }),
                    ),
                    Err(crate::NetworkRxError::Commit { .. })
                ));
                drop(callback);

                let snapshot = if action == crate::QEMU_PLUGIN_HOT_FORK_BARRIER_HOLD {
                    state.quiescence.hold_hot_fork()
                } else {
                    state.quiescence.snapshot()
                };
                assert_eq!(snapshot.in_flight, 0);
                assert!(snapshot.hot_fork_held);
                Ok(snapshot)
            },
        );

        assert!(matches!(result, Err(status) if status == -libc::EPROTO));
        assert!(state.network_rx_commit_uncertain());
        assert_eq!(fixture.inbound.read_index(), 0);
        RX_ATTEMPTS.with_borrow(|attempts| {
            assert_eq!(attempts, &vec![b"accepted".to_vec()]);
        });

        let released = crate::runtime::collect_hot_fork_state_with_network_rx_check(
            Some(&state),
            crate::QEMU_PLUGIN_HOT_FORK_BARRIER_RELEASE,
            || Ok(state.quiescence.release_hot_fork()),
        )
        .unwrap_or_else(|error| panic!("network fixture operation should succeed: {error}"));
        assert!(!released.hot_fork_held);
        assert!(state.network_rx_commit_uncertain());
    }
}

#[test]
fn uncertain_guest_acceptance_refuses_replay_checkpoint_and_restore() {
    let mut fixture = NetworkFixture::new();
    let frame = fixture.enqueue(0, b"accepted");
    let state = fixture.state();
    let network = state
        .network
        .as_ref()
        .unwrap_or_else(|| panic!("original network fixture state should be present"));
    let mut rx_queue = network.rx_queue;

    assert!(matches!(
        network.rx.inject_due_frames_with_commit(
            &mut rx_queue,
            20,
            20,
            std::slice::from_ref(&frame),
            |_| Err(InboundFrameError::CommittedBatchMismatch {
                expected: vec![frame.delivery_key()],
                actual: Vec::new(),
            }),
        ),
        Err(crate::NetworkRxError::Commit { .. })
    ));
    assert!(state.network_rx_commit_uncertain());
    assert_eq!(fixture.inbound.read_index(), 0);

    assert_eq!(
        state.inject_due_network_inbound(20, 20),
        Err(LiveVcpuTimeCallbackError::NetworkRx {
            source: crate::NetworkRxError::CommitUncertain,
        })
    );

    state
        .header
        .get()
        .request_pause([&fixture.slot])
        .unwrap_or_else(|error| panic!("network fixture operation should succeed: {error}"));
    let before_pause = fixture.slot.snapshot();
    assert_eq!(
        state.publish_pause_for_boundary(0, true, false, None, "poisoned-test"),
        Err(LiveVcpuTimeCallbackError::NetworkRx {
            source: crate::NetworkRxError::CommitUncertain,
        })
    );
    assert_eq!(fixture.slot.snapshot(), before_pause);

    let control_request = fixture
        .slot
        .request_control_boundary(0, None)
        .unwrap_or_else(|error| panic!("network fixture operation should succeed: {error}"));
    assert_eq!(
        state.on_control_boundary(0),
        Err(LiveVcpuTimeCallbackError::NetworkRx {
            source: crate::NetworkRxError::CommitUncertain,
        })
    );
    assert_eq!(
        fixture.slot.snapshot().control_boundary_ack,
        control_request
    );

    for action in [
        crate::QEMU_PLUGIN_HOT_FORK_BARRIER_HOLD,
        crate::QEMU_PLUGIN_HOT_FORK_BARRIER_QUERY,
    ] {
        assert_eq!(
            crate::runtime::check_hot_fork_network_rx(Some(&state), action),
            Err(-libc::EPROTO)
        );
    }
    assert_eq!(
        crate::runtime::check_hot_fork_network_rx(
            Some(&state),
            crate::QEMU_PLUGIN_HOT_FORK_BARRIER_RELEASE,
        ),
        Ok(())
    );

    let generation = fixture
        .slot
        .arm_logical_time_restore(20)
        .unwrap_or_else(|error| panic!("network fixture operation should succeed: {error}"));
    assert_eq!(
        state.restore_logical_time_if_requested(0, true),
        Err(LiveVcpuTimeCallbackError::NetworkRx {
            source: crate::NetworkRxError::CommitUncertain,
        })
    );
    assert_ne!(fixture.slot.snapshot().logical_time_restore_ack, generation);
    assert!(state.network_rx_commit_uncertain());
    assert_eq!(fixture.inbound.read_index(), 0);
    RX_ATTEMPTS.with_borrow(|attempts| {
        assert_eq!(attempts, &vec![b"accepted".to_vec()]);
    });
}
