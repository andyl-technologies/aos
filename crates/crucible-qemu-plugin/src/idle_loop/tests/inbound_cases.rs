//! Idle-loop inbound-ring and late-frame ordering cases.

use super::super::*;




use super::support::*;
use crate::NetworkRxQueueError;
use crucible_shmem::{KIND_VM, RingHeader, STATUS_IDLE, STATUS_RUNNING};

#[test]
fn idle_loop_with_inbound_rings_does_not_consume_before_qemu_completion() {
    let slot = NodeSlot::new(KIND_VM);
    let clock = owned_clock(10, 1);
    let ring_a = RingHeader::new();
    let ring_b = RingHeader::new();
    let mut entries_a = empty_entries();
    let mut entries_b = empty_entries();
    enqueue(&ring_a, &mut entries_a, frame(20, 9, 4, b"third"));
    enqueue(&ring_a, &mut entries_a, frame(20, 1, 7, b"first"));
    enqueue(&ring_b, &mut entries_b, frame(20, 4, 1, b"second"));
    enqueue(&ring_b, &mut entries_b, frame(25, 4, 2, b"future"));
    publish_ceiling(&slot, ceiling(0, 10));

    let request = match PluginIdleHotLoop::begin_idle_with_inbound_rings(
        &slot,
        &clock,
        &deadline_reader(deadline_80),
        [
            InboundFrameRing::new(0, &ring_a, &entries_a),
            InboundFrameRing::new(1, &ring_b, &entries_b),
        ],
        None,
    ) {
        Ok(request) => request,
        Err(error) => panic!("idle begin should peek inbound rings: {error}"),
    };
    assert_eq!(request.plan().desired_wake_icount(), 20);
    assert_eq!(request.plan().cause(), IdleWakeCause::InboundFrame);

    publish_ceiling(&slot, ceiling(10, 20));
    let mut clock = clock;
    set_last_direct_advance_ns(-1);
    let pending = expect_pending(
        PluginIdleHotLoop::complete_after_scheduler_wake_from_inbound_rings(
            &slot,
            &mut clock,
            &queued_idle_advance(),
            request,
            [
                InboundFrameRing::new(0, &ring_a, &entries_a),
                InboundFrameRing::new(1, &ring_b, &entries_b),
            ],
        ),
    );

    assert_eq!(last_direct_advance_ns(), 40);
    assert_eq!(clock.current_icount(), 10);
    assert_eq!(ring_a.read_index(), 0);
    assert_eq!(ring_b.read_index(), 0);
    let snapshot = slot.snapshot();
    assert_eq!(snapshot.current_icount, 10);
    assert_eq!(snapshot.current_ns, 20);
    assert_eq!(snapshot.status, STATUS_IDLE);

    let result = PluginIdleHotLoop::complete_after_time_advance_from_inbound_rings(
        &slot,
        &mut clock,
        request,
        pending,
        successful_completion(pending),
        [
            InboundFrameRing::new(0, &ring_a, &entries_a),
            InboundFrameRing::new(1, &ring_b, &entries_b),
        ],
    )
    .unwrap_or_else(|error| panic!("completed idle turn should drain rings: {error}"));
    assert_eq!(clock.current_icount(), 20);
    assert_eq!(ring_a.read_index(), 2);
    assert_eq!(ring_b.read_index(), 1);
    assert_eq!(
        result
            .injected_frames()
            .iter()
            .map(FrameEntry::delivery_key)
            .collect::<Vec<_>>(),
        vec![
            frame(20, 1, 7, b"first").delivery_key(),
            frame(20, 4, 1, b"second").delivery_key(),
            frame(20, 9, 4, b"third").delivery_key(),
        ]
    );
}

#[test]
fn idle_loop_rx_injection_waits_for_qemu_completion() {
    let slot = NodeSlot::new(KIND_VM);
    let clock = owned_clock(10, 1);
    let ring_a = RingHeader::new();
    let ring_b = RingHeader::new();
    let mut entries_a = empty_entries();
    let mut entries_b = empty_entries();
    enqueue(&ring_a, &mut entries_a, frame(20, 9, 4, b"third"));
    enqueue(&ring_a, &mut entries_a, frame(20, 1, 7, b"first"));
    enqueue(&ring_b, &mut entries_b, frame(20, 4, 1, b"second"));
    publish_ceiling(&slot, ceiling(0, 10));

    let request = match PluginIdleHotLoop::begin_idle_with_inbound_rings(
        &slot,
        &clock,
        &deadline_reader(deadline_80),
        [
            InboundFrameRing::new(0, &ring_a, &entries_a),
            InboundFrameRing::new(1, &ring_b, &entries_b),
        ],
        None,
    ) {
        Ok(request) => request,
        Err(error) => panic!("idle begin should peek inbound rings: {error}"),
    };
    assert_eq!(slot.snapshot().status, STATUS_IDLE);

    publish_ceiling(&slot, ceiling(10, 20));
    let mut clock = clock;
    set_last_direct_advance_ns(-1);
    let network_rx = PluginNetworkRx::new();
    let mut rx_queue = RecordingNetworkRxQueue::for_slot(&slot);
    let pending = expect_pending(
        PluginIdleHotLoop::complete_after_scheduler_wake_from_inbound_rings_with_rx_injection(
            &slot,
            &mut clock,
            &queued_idle_advance(),
            request,
            [
                InboundFrameRing::new(0, &ring_a, &entries_a),
                InboundFrameRing::new(1, &ring_b, &entries_b),
            ],
            &network_rx,
            &mut rx_queue,
        ),
    );

    assert_eq!(last_direct_advance_ns(), 40);
    assert!(rx_queue.direct_advance_ns_at_queue.is_empty());
    assert!(rx_queue.slot_status_at_queue.is_empty());
    assert!(rx_queue.queued_payloads.is_empty());
    assert_eq!(rx_queue.flush_count, 0);
    assert_eq!(ring_a.read_index(), 0);
    assert_eq!(ring_b.read_index(), 0);
    assert_eq!(clock.current_icount(), 10);
    assert_eq!(slot.snapshot().status, STATUS_IDLE);

    let result =
        PluginIdleHotLoop::complete_after_time_advance_from_inbound_rings_with_rx_injection(
            &slot,
            &mut clock,
            request,
            pending,
            successful_completion(pending),
            [
                InboundFrameRing::new(0, &ring_a, &entries_a),
                InboundFrameRing::new(1, &ring_b, &entries_b),
            ],
            &network_rx,
            &mut rx_queue,
        )
        .unwrap_or_else(|error| panic!("completed idle turn should inject RX: {error}"));
    assert_eq!(rx_queue.direct_advance_ns_at_queue, vec![40, 40, 40]);
    assert_eq!(
        rx_queue.slot_status_at_queue,
        vec![STATUS_IDLE, STATUS_IDLE, STATUS_IDLE]
    );
    assert_eq!(
        rx_queue.queued_payloads,
        vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]
    );
    assert_eq!(rx_queue.flush_count, 1);
    assert_eq!(ring_a.read_index(), 2);
    assert_eq!(ring_b.read_index(), 1);
    assert_eq!(clock.current_icount(), 20);
    assert_eq!(slot.snapshot().status, STATUS_RUNNING);
    assert!(result.network_rx_injection().is_some());
}

#[test]
fn idle_loop_rx_queue_failure_does_not_commit_inbound_ring_reads() {
    let slot = NodeSlot::new(KIND_VM);
    let clock = owned_clock(10, 1);
    let ring = RingHeader::new();
    let mut entries = empty_entries();
    enqueue(&ring, &mut entries, frame(20, 1, 0, b"queued"));
    publish_ceiling(&slot, ceiling(0, 10));
    let request = match PluginIdleHotLoop::begin_idle_with_inbound_rings(
        &slot,
        &clock,
        &deadline_reader(deadline_80),
        [InboundFrameRing::new(0, &ring, &entries)],
        None,
    ) {
        Ok(request) => request,
        Err(error) => panic!("idle begin should peek inbound rings: {error}"),
    };

    publish_ceiling(&slot, ceiling(10, 20));
    let mut clock = clock;
    set_last_direct_advance_ns(-1);
    let network_rx = PluginNetworkRx::new();
    let mut rx_queue = RecordingNetworkRxQueue::for_slot(&slot);
    rx_queue.queue_error_at = Some(0);

    let pending = expect_pending(
        PluginIdleHotLoop::complete_after_scheduler_wake_from_inbound_rings_with_rx_injection(
            &slot,
            &mut clock,
            &queued_idle_advance(),
            request,
            [InboundFrameRing::new(0, &ring, &entries)],
            &network_rx,
            &mut rx_queue,
        ),
    );

    assert_eq!(last_direct_advance_ns(), 40);
    assert_eq!(clock.current_icount(), 10);
    assert_eq!(ring.read_index(), 0);
    assert!(rx_queue.queued_payloads.is_empty());
    assert_eq!(rx_queue.flush_count, 0);
    assert_eq!(slot.snapshot().status, STATUS_IDLE);

    assert_eq!(
        PluginIdleHotLoop::complete_after_time_advance_from_inbound_rings_with_rx_injection(
            &slot,
            &mut clock,
            request,
            pending,
            successful_completion(pending),
            [InboundFrameRing::new(0, &ring, &entries)],
            &network_rx,
            &mut rx_queue,
        ),
        Err(IdleHotLoopError::NetworkRxInjection {
            source: NetworkRxError::Queue {
                frame: frame(20, 1, 0, b"queued").delivery_key(),
                source: NetworkRxQueueError::queue("test queue failure"),
            },
        })
    );
    assert_eq!(clock.current_icount(), 20);
    assert_eq!(ring.read_index(), 0);
    assert_eq!(slot.snapshot().status, STATUS_IDLE);
}

#[test]
fn idle_loop_rejects_late_inbound_ring_before_direct_advance() {
    let slot = NodeSlot::new(KIND_VM);
    let mut clock = owned_clock(10, 1);
    let ring = RingHeader::new();
    let mut entries = empty_entries();
    enqueue(&ring, &mut entries, frame(9, 7, 2, b"late"));
    publish_ceiling(&slot, ceiling(10, 20));
    let request = IdleParkRequest {
        plan: IdleWakePlan {
            current_icount: 10,
            desired_wake_icount: 20,
            ceiling_icount: 20,
            timer_deadline_icount: None,
            inbound_delivery_icount: Some(9),
            device_completion_deadline_icount: None,
            device_io_holding_ticks: false,
            cause: IdleWakeCause::InboundFrame,
        },
        futex_wait: FutexWait::Runnable,
    };
    let before = slot.snapshot();
    set_blocked_direct_advance_ns(-1);

    assert_eq!(
        PluginIdleHotLoop::complete_after_scheduler_wake_from_inbound_rings(
            &slot,
            &mut clock,
            &blocked_queued_idle_advance(),
            request,
            [InboundFrameRing::new(3, &ring, &entries)]
        ),
        Err(IdleHotLoopError::InboundFrames {
            source: InboundFrameError::DeliveryAlreadyPassed {
                ring_index: Some(3),
                consumer_current_icount: 10,
                frame: frame(9, 7, 2, b"late").delivery_key(),
            },
        })
    );

    assert_eq!(clock.current_icount(), 10);
    assert_eq!(slot.snapshot(), before);
    assert_eq!(ring.read_index(), 0);
    assert_eq!(blocked_direct_advance_ns(), -1);
}

#[test]
fn idle_loop_rejects_late_materialized_frame_before_direct_advance() {
    let slot = NodeSlot::new(KIND_VM);
    let mut clock = owned_clock(10, 1);
    publish_ceiling(&slot, ceiling(10, 20));
    let request = IdleParkRequest {
        plan: IdleWakePlan {
            current_icount: 10,
            desired_wake_icount: 20,
            ceiling_icount: 20,
            timer_deadline_icount: None,
            inbound_delivery_icount: Some(9),
            device_completion_deadline_icount: None,
            device_io_holding_ticks: false,
            cause: IdleWakeCause::InboundFrame,
        },
        futex_wait: FutexWait::Runnable,
    };
    let before = slot.snapshot();
    set_blocked_direct_advance_ns(-1);

    assert_eq!(
        PluginIdleHotLoop::complete_after_scheduler_wake(
            &slot,
            &mut clock,
            &blocked_queued_idle_advance(),
            request,
            [frame(9, 7, 2, b"late")]
        ),
        Err(IdleHotLoopError::InboundFrames {
            source: InboundFrameError::DeliveryAlreadyPassed {
                ring_index: None,
                consumer_current_icount: 10,
                frame: frame(9, 7, 2, b"late").delivery_key(),
            },
        })
    );

    assert_eq!(clock.current_icount(), 10);
    assert_eq!(slot.snapshot(), before);
    assert_eq!(blocked_direct_advance_ns(), -1);
}

#[test]
fn idle_loop_rejects_late_inbound_ring_at_begin_without_publishing() {
    let slot = NodeSlot::new(KIND_VM);
    let clock = owned_clock(10, 1);
    let ring = RingHeader::new();
    let mut entries = empty_entries();
    enqueue(&ring, &mut entries, frame(9, 7, 2, b"late"));
    publish_ceiling(&slot, ceiling(0, 20));
    let before = slot.snapshot();

    assert_eq!(
        PluginIdleHotLoop::begin_idle_with_inbound_rings(
            &slot,
            &clock,
            &deadline_reader(deadline_80),
            [InboundFrameRing::new(6, &ring, &entries)],
            None
        ),
        Err(IdleHotLoopError::InboundFrames {
            source: InboundFrameError::DeliveryAlreadyPassed {
                ring_index: Some(6),
                consumer_current_icount: 10,
                frame: frame(9, 7, 2, b"late").delivery_key(),
            },
        })
    );

    assert_eq!(slot.snapshot(), before);
    assert_eq!(ring.read_index(), 0);
    assert_eq!(clock.current_icount(), 10);
}

#[test]
fn idle_loop_rejects_raw_late_inbound_delivery_before_publishing() {
    let slot = NodeSlot::new(KIND_VM);
    let clock = owned_clock(10, 1);
    publish_ceiling(&slot, ceiling(0, 20));
    let before = slot.snapshot();

    assert_eq!(
        PluginIdleHotLoop::begin_idle(
            &slot,
            &clock,
            &deadline_reader(deadline_80),
            Some(9),
            None
        ),
        Err(IdleHotLoopError::InboundFrames {
            source: InboundFrameError::DeliveryAlreadyPassed {
                ring_index: None,
                consumer_current_icount: 10,
                frame: FrameDeliveryKey {
                    delivery_icount: 9,
                    src_node: 0,
                    seq: 0,
                },
            },
        })
    );

    assert_eq!(slot.snapshot(), before);
    assert_eq!(clock.current_icount(), 10);
}

#[test]
fn idle_loop_rejects_release_before_scheduler_authorizes_wake() {
    let slot = NodeSlot::new(KIND_VM);
    let clock = owned_clock(10, 0);
    publish_ceiling(&slot, ceiling(0, 10));
    let request = match PluginIdleHotLoop::begin_idle(
        &slot,
        &clock,
        &deadline_reader(deadline_20),
        None,
        None,
    ) {
        Ok(request) => request,
        Err(error) => panic!("idle begin should succeed: {error}"),
    };
    let mut clock = clock;

    assert_eq!(
        PluginIdleHotLoop::complete_after_scheduler_wake(
            &slot,
            &mut clock,
            &queued_idle_advance(),
            request,
            []
        ),
        Err(IdleHotLoopError::WakeNotAuthorized {
            desired_wake_icount: 20,
            ceiling_icount: 10,
        })
    );
}

#[test]
fn idle_loop_direct_advance_range_failure_leaves_clock_and_slot_unchanged() {
    let slot = NodeSlot::new(KIND_VM);
    let mut clock = owned_clock(0, crate::MAX_PLUGIN_ICOUNT_SHIFT);
    publish_ceiling(&slot, ceiling(0, 1));
    let before = slot.snapshot();
    set_blocked_direct_advance_ns(-1);
    let request = IdleParkRequest {
        plan: IdleWakePlan {
            current_icount: 0,
            desired_wake_icount: 1,
            ceiling_icount: 1,
            timer_deadline_icount: Some(1),
            inbound_delivery_icount: None,
            device_completion_deadline_icount: None,
            device_io_holding_ticks: false,
            cause: IdleWakeCause::TimerDeadline,
        },
        futex_wait: FutexWait::Runnable,
    };

    assert_eq!(
        PluginIdleHotLoop::complete_after_scheduler_wake(
            &slot,
            &mut clock,
            &blocked_queued_idle_advance(),
            request,
            [frame(1, 1, 1, b"would-be-due")]
        ),
        Err(IdleHotLoopError::QueuedIdleAdvance {
            source: QueuedIdleAdvanceError::VirtualTimeOutOfRange {
                target_virtual_ns: i64::MAX as u64 + 1,
            },
        })
    );

    assert_eq!(clock.current_icount(), 0);
    assert_eq!(slot.snapshot(), before);
    assert_eq!(blocked_direct_advance_ns(), -1);
}

#[test]
fn idle_resume_boundary_republishes_running_without_advancing_time() {
    let slot = NodeSlot::new(KIND_VM);
    let clock = owned_clock(32, 2);
    publish_ceiling(&slot, ceiling(0, 32));

    if let Err(error) = PluginIdleHotLoop::publish_resume_boundary(&slot, &clock) {
        panic!("resume boundary should publish: {error}");
    }

    let snapshot = slot.snapshot();
    assert_eq!(snapshot.current_icount, 32);
    assert_eq!(snapshot.current_ns, 128);
    assert_eq!(snapshot.status, STATUS_RUNNING);
    assert_eq!(clock.current_icount(), 32);
}

#[test]
fn idle_timer_deadline_conversion_ceils_to_icount() {
    assert_eq!(
        timer_deadline_icount(ExactDeadlineReport::Armed { deadline_ns: 41 }, 3),
        Ok(Some(6))
    );
    assert_eq!(
        timer_deadline_icount(ExactDeadlineReport::NoArmedTimer, 3),
        Ok(None)
    );
    assert_eq!(
        timer_deadline_icount(ExactDeadlineReport::Armed { deadline_ns: 1 }, 64),
        Err(IdleHotLoopError::InvalidIcountShift { icount_shift: 64 })
    );
}

