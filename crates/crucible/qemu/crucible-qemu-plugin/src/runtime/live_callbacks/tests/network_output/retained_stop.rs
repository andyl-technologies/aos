//! Original output-stop retention, release, and terminal refusal regressions.

use super::*;
use crate::runtime::worker_quiescence::WORKER_REQUIRED;

#[test]
fn buffered_tx_preserves_an_unchanged_native_instruction_sample()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = OutputFixture::new()?;
    let state = fixture.state()?;
    state.publish_current_icount(20)?;
    TEST_ICOUNT_RAW.set(20);
    let pending = state.queued_idle_advance.enqueue(1_500)?;
    state.arm_idle_advance(20, 1_500, pending, None)?;

    state.on_network_tx(20, b"timer-frame")?;
    state.on_network_tx(20, b"second-frame")?;
    state.complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 1_500))?;
    assert!(state.preserve_network_output_stop(20, "test")?);

    assert_eq!(fixture.outbound.write_index(), 2);
    assert_eq!(fixture.outbound_entries[0].payload()?, b"timer-frame");
    assert_eq!(fixture.outbound_entries[0].delivery_icount, 1_500);
    assert_eq!(fixture.slot.snapshot().logical_time_raw_icount, 20);
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 1);
    let first = fixture.outbound.dequeue(&fixture.outbound_entries)?;
    assert_eq!(
        first.ok_or("missing first frame")?.payload()?,
        b"timer-frame"
    );
    assert!(state.preserve_network_output_stop(20, "test")?);
    let second = fixture.outbound.dequeue(&fixture.outbound_entries)?;
    assert_eq!(
        second.ok_or("missing second frame")?.payload()?,
        b"second-frame"
    );
    assert!(!state.preserve_network_output_stop(20, "test")?);
    TEST_ICOUNT_RAW.set(0);
    Ok(())
}

#[test]
fn buffered_tx_refuses_a_native_sample_which_advanced_after_idle_arm()
-> Result<(), Box<dyn std::error::Error>> {
    differing_buffered_tx_sample(false)
}

#[test]
fn buffered_tx_does_not_hide_a_cache_already_old_at_idle_arm()
-> Result<(), Box<dyn std::error::Error>> {
    differing_buffered_tx_sample(true)
}

fn differing_buffered_tx_sample(cache_already_old: bool) -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = OutputFixture::new()?;
    let state = fixture.state()?;
    state.publish_current_icount(20)?;
    TEST_ICOUNT_RAW.set(if cache_already_old { 94 } else { 20 });
    let pending = state.queued_idle_advance.enqueue(1_500)?;

    // The stale-arm case deliberately supplies an old request coordinate;
    // it does not establish that a genuine native idle callback can do so.
    // The other case violates the native no-retirement idle invariant later.
    state.arm_idle_advance(20, 1_500, pending, None)?;
    TEST_ICOUNT_RAW.set(94);
    let original = fixture.slot.snapshot();
    let offset = state.logical_icount_offset.load(Ordering::Acquire);
    let original_pending = {
        let owner = state.try_pending_idle_advance()?;
        let request = owner.as_ref().ok_or("missing original idle request")?;
        (request.generation, request.pending)
    };

    let tx = state.on_network_tx(94, b"original-native-sample");

    assert_eq!(
        tx,
        Err(LiveVcpuTimeCallbackError::IdleAdvanceRawIcountChanged {
            expected_raw_icount: 20,
            observed_raw_icount: 94,
        })
    );
    assert_eq!(fixture.slot.snapshot(), original);
    assert_eq!(state.logical_icount_offset.load(Ordering::Acquire), offset);
    assert_eq!(state.last_raw_icount.load(Ordering::Acquire), 20);
    let owner = state.try_pending_idle_advance()?;
    let request = owner.as_ref().ok_or("lost original idle request")?;
    assert_eq!((request.generation, request.pending), original_pending);
    assert_eq!(request.raw_icount_at_request, 20);
    assert_eq!(request.target_icount, 1_500);
    assert!(request.buffered_tx_payloads.is_empty());
    drop(owner);

    // A differing original sample must refuse before a frame or native stop
    // becomes visible; later guard refusal cannot recover discarded evidence.
    assert_eq!(fixture.outbound.write_index(), 0);
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 0);
    state.complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 1_500))?;
    assert!(!state.idle_advance_is_pending());
    assert_eq!(fixture.outbound.write_index(), 0);
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 0);
    TEST_ICOUNT_RAW.set(0);
    Ok(())
}

#[test]
fn buffered_tx_sample_check_preserves_busy_enqueue_rollback_and_rearm()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = OutputFixture::new()?;
    let state = fixture.state()?;
    state.publish_current_icount(20)?;
    TEST_ICOUNT_RAW.set(20);
    let original = fixture.slot.snapshot();
    TEST_QUEUED_ADVANCE_STATUS.set(-libc::EBUSY);

    assert!(!state.arm_and_enqueue_idle_advance_or_defer(20, 1_500, None)?);
    assert!(!state.idle_advance_is_pending());
    assert_eq!(fixture.slot.snapshot(), original);
    assert_eq!(fixture.outbound.write_index(), 0);
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 0);

    TEST_QUEUED_ADVANCE_STATUS.set(0);
    assert!(state.arm_and_enqueue_idle_advance_or_defer(20, 1_500, None)?);
    state.on_network_tx(20, b"after-busy-reservation")?;
    state.complete_idle_advance(TimeAdvanceCompletion::from_qemu(0, 1_500))?;

    assert_eq!(fixture.outbound.write_index(), 1);
    assert_eq!(
        fixture.outbound_entries[0].payload()?,
        b"after-busy-reservation"
    );
    assert_eq!(fixture.slot.snapshot().logical_time_raw_icount, 20);
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 1);
    TEST_ICOUNT_RAW.set(0);
    Ok(())
}

#[test]
fn buffered_tx_sample_mismatch_preserves_original_native_refusal_priority()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = OutputFixture::new()?;
    let state = fixture.state()?;
    state.publish_current_icount(20)?;
    TEST_ICOUNT_RAW.set(20);
    let pending = state.queued_idle_advance.enqueue(1_500)?;
    state.arm_idle_advance(20, 1_500, pending, None)?;
    state.retain_network_output_stop_refusal(-libc::EPERM);
    let original = fixture.slot.snapshot();

    let rejected = state.on_network_tx(94, b"after-original-refusal");

    assert_eq!(
        rejected,
        Err(LiveVcpuTimeCallbackError::CheckpointVmStopRejected {
            boundary: "network-output",
            status: -libc::EPERM,
        })
    );
    assert_eq!(fixture.slot.snapshot(), original);
    assert_eq!(fixture.outbound.write_index(), 0);
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 0);
    let owner = state.try_pending_idle_advance()?;
    let request = owner.as_ref().ok_or("lost original idle request")?;
    assert_eq!(request.pending, pending);
    assert_eq!(request.raw_icount_at_request, 20);
    assert!(request.buffered_tx_payloads.is_empty());
    TEST_ICOUNT_RAW.set(0);
    Ok(())
}

#[test]
fn idle_progress_and_control_callbacks_preserve_the_original_output_tuple()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = OutputFixture::new()?;
    let state = fixture.state()?;
    state.on_vcpu_init(0)?;
    state.on_network_tx(20, b"frame")?;

    state.publish_current_icount(20)?;
    state.on_vcpu_idle(0, 20)?;
    let request = fixture.slot.request_control_boundary(0, None)?;
    state.on_control_boundary(20)?;

    let stopped = fixture.slot.snapshot();
    assert_eq!(stopped.status, STATUS_IDLE);
    assert_eq!(stopped.current_icount, 1_000);
    assert_eq!(stopped.idle_wake_icount, 1_000);
    assert_eq!(stopped.logical_time_raw_icount, 20);
    assert_eq!(stopped.max_advance_icount, 2_000);
    assert_eq!(stopped.control_boundary_ack, request.wrapping_add(1));
    assert_eq!(fixture.outbound.read_index(), 0);
    assert_eq!(fixture.outbound.write_index(), 1);
    assert!(!state.idle_advance_is_pending());
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 1);
    Ok(())
}

#[test]
fn only_complete_original_consumption_releases_resume_and_new_output()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = OutputFixture::new()?;
    let state = fixture.state()?;
    state.on_vcpu_init(0)?;
    state.try_halted_vcpus()?.mark_halted(0)?;
    state.on_network_tx(20, b"first")?;
    state.on_network_tx(20, b"second")?;
    let next_ceiling = authorize_advance_ceiling(1_000, 2_500, None)?;
    fixture
        .slot
        .publish_scheduler_advance(next_ceiling, AdvanceStopCondition::Ceiling)?;
    let first = fixture.outbound.dequeue(&fixture.outbound_entries)?;
    assert!(first.is_some());

    state.on_vcpu_resume(0, 20)?;
    assert_eq!(fixture.slot.snapshot().status, STATUS_IDLE);
    assert_eq!(fixture.outbound.read_index(), 1);
    let second = fixture.outbound.dequeue(&fixture.outbound_entries)?;
    assert!(second.is_some());
    state.on_vcpu_resume(0, 20)?;

    assert_eq!(fixture.slot.snapshot().status, STATUS_RUNNING);
    state.on_network_tx(21, b"third")?;
    let stopped = fixture.slot.snapshot();
    assert_eq!(stopped.status, STATUS_IDLE);
    assert_eq!(stopped.current_icount, 1_050);
    assert_eq!(stopped.logical_time_raw_icount, 21);
    assert_eq!(fixture.outbound.read_index(), 2);
    assert_eq!(fixture.outbound.write_index(), 3);
    assert_eq!(fixture.outbound_entries[2].delivery_icount, 1_050);
    assert_eq!(fixture.outbound_entries[2].seq, 2);
    assert_eq!(fixture.outbound_entries[2].payload()?, b"third");
    Ok(())
}

#[test]
fn physical_progress_refuses_without_restamping_original_output()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = OutputFixture::new()?;
    let state = fixture.state()?;
    state.on_vcpu_init(0)?;
    state.on_network_tx(20, b"frame")?;
    let original = fixture.slot.snapshot();

    let expected = Err(LiveVcpuTimeCallbackError::NetworkOutputStopProgressed {
        logical_icount: 1_000,
        raw_icount: 20,
        observed_logical_icount: 1_050,
        observed_raw_icount: 21,
    });

    assert_eq!(state.on_vcpu_resume(0, 21), expected);
    assert_eq!(state.publish_current_icount(21), expected);
    assert_eq!(state.on_vcpu_idle(0, 21), expected);
    assert_eq!(state.on_network_tx(21, b"wrong-coordinate"), expected);

    assert_eq!(fixture.slot.snapshot(), original);
    assert_eq!(fixture.outbound.read_index(), 0);
    assert_eq!(fixture.outbound.write_index(), 1);
    assert_eq!(fixture.outbound_entries[0].delivery_icount, 1_000);
    assert_eq!(fixture.outbound_entries[0].payload()?, b"frame");
    assert_eq!(fixture.outbound_entries[1].payload()?, b"");
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 1);
    Ok(())
}

#[test]
fn native_admission_refusal_remains_original_after_consumer_progress()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = OutputFixture::new()?;
    let state = fixture.state()?;
    state.on_vcpu_init(0)?;
    TEST_REQUEST_VMSTOP_STATUS.set(-libc::EPERM);
    let rejection = state.on_network_tx(20, b"frame");
    TEST_REQUEST_VMSTOP_STATUS.set(0);
    let original = fixture.slot.snapshot();

    assert_eq!(state.on_network_tx(20, b"after-refusal"), rejection);
    assert_eq!(fixture.slot.snapshot(), original);
    assert_eq!(fixture.outbound.read_index(), 0);
    assert_eq!(fixture.outbound.write_index(), 1);
    assert_eq!(fixture.outbound_entries[0].payload()?, b"frame");
    assert_eq!(fixture.outbound_entries[1].payload()?, b"");
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 1);

    let consumed = fixture.outbound.dequeue(&fixture.outbound_entries)?;
    assert!(consumed.is_some());

    assert_eq!(state.on_vcpu_resume(0, 21), rejection);
    assert_eq!(state.require_consumed_network_output_stop(), rejection);
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 1);
    assert_eq!(fixture.slot.snapshot().current_icount, 1_000);
    Ok(())
}

#[test]
fn observed_sim_clock_progress_refuses_without_recalibrating_the_original_offset()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = OutputFixture::new()?;
    let mut state = fixture.state()?;
    state.on_vcpu_init(0)?;
    state.on_network_tx(20, b"frame")?;
    state.sim_tick_observed = Some(test_sim_tick_observed);
    TEST_SIM_TICK.set(1_050);
    let original = fixture.slot.snapshot();
    let offset = state.logical_icount_offset.load(Ordering::Acquire);

    let expected = Err(LiveVcpuTimeCallbackError::NetworkOutputStopProgressed {
        logical_icount: 1_000,
        raw_icount: 20,
        observed_logical_icount: 1_050,
        observed_raw_icount: 20,
    });
    assert_eq!(state.publish_current_icount(20), expected);
    assert_eq!(state.on_network_tx(20, b"later-clock"), expected);
    assert_eq!(fixture.slot.snapshot(), original);
    assert_eq!(state.logical_icount_offset.load(Ordering::Acquire), offset);
    assert_eq!(fixture.outbound.read_index(), 0);
    assert_eq!(fixture.outbound.write_index(), 1);
    assert_eq!(fixture.outbound_entries[0].payload()?, b"frame");
    assert_eq!(fixture.outbound_entries[1].payload()?, b"");
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 1);
    Ok(())
}

#[test]
fn concurrent_callback_borrow_refuses_before_publication_or_native_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = OutputFixture::new()?;
    let state = fixture.state()?;
    state.on_vcpu_init(0)?;
    state.on_network_tx(20, b"frame")?;
    let original = fixture.slot.snapshot();
    let network = state.network.as_ref().ok_or("missing original network")?;
    let owner = network
        .output_stop
        .lock()
        .map_err(|_| "poisoned test owner")?;

    assert_eq!(
        state.on_network_tx(20, b"reentered"),
        Err(LiveVcpuTimeCallbackError::NetworkOutputStopBorrowed)
    );
    assert_eq!(
        state.on_vcpu_resume(0, 20),
        Err(LiveVcpuTimeCallbackError::NetworkOutputStopBorrowed)
    );
    assert_eq!(fixture.slot.snapshot(), original);
    assert_eq!(fixture.outbound.read_index(), 0);
    assert_eq!(fixture.outbound.write_index(), 1);
    assert_eq!(fixture.outbound_entries[0].payload()?, b"frame");
    assert_eq!(fixture.outbound_entries[1].payload()?, b"");
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 1);

    // A native refusal has priority even while a different callback owns the
    // intent. The atomic cache never waits for or replaces that original cause.
    state.retain_network_output_stop_refusal(-libc::EPERM);
    state.retain_network_output_stop_refusal(-libc::EBUSY);
    assert_eq!(
        state.on_vcpu_resume(0, 20),
        Err(LiveVcpuTimeCallbackError::CheckpointVmStopRejected {
            boundary: "network-output",
            status: -libc::EPERM,
        })
    );
    drop(owner);
    Ok(())
}

#[test]
fn foreign_frontier_cannot_retire_or_replace_the_original_output_stop()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = OutputFixture::new()?;
    let state = fixture.state()?;
    state.on_vcpu_init(0)?;
    state.on_network_tx(20, b"original")?;
    let consumed = fixture.outbound.dequeue(&fixture.outbound_entries)?;
    assert!(consumed.is_some());

    // Model an invalid producer outside the retained original transaction.
    // Even consumption of its earlier tail must not authorize this new tail.
    let foreign = FrameEntry::new(1_000, 0, 1, b"foreign")?;
    fixture
        .outbound
        .enqueue(&mut fixture.outbound_entries, &foreign)?;
    let original = fixture.slot.snapshot();
    let expected = Err(
        LiveVcpuTimeCallbackError::NetworkOutputStopFrontierChanged {
            write_index: 1,
            observed_write_index: 2,
        },
    );

    assert_eq!(state.on_vcpu_resume(0, 20), expected);
    assert_eq!(state.on_network_tx(20, b"replacement"), expected);
    assert_eq!(state.require_consumed_network_output_stop(), expected);
    assert_eq!(fixture.slot.snapshot(), original);
    assert_eq!(fixture.outbound.read_index(), 1);
    assert_eq!(fixture.outbound.write_index(), 2);
    assert_eq!(fixture.outbound_entries[1].payload()?, b"foreign");
    assert_eq!(fixture.outbound_entries[2].payload()?, b"");
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 1);
    Ok(())
}

#[test]
fn ring_backpressure_cannot_retire_or_extend_original_output_stop()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = OutputFixture::new()?;
    let state = fixture.state()?;
    state.on_vcpu_init(0)?;
    for _ in 0..4 {
        state.on_network_tx(20, b"frame")?;
    }

    let exhausted = state.on_network_tx(20, b"overflow");
    assert!(matches!(
        exhausted,
        Err(LiveVcpuTimeCallbackError::NetworkTx { .. })
    ));
    state.on_vcpu_resume(0, 20)?;

    assert_eq!(fixture.slot.snapshot().status, STATUS_IDLE);
    assert_eq!(fixture.slot.snapshot().current_icount, 1_000);
    assert_eq!(fixture.outbound.read_index(), 0);
    assert_eq!(fixture.outbound.write_index(), 4);
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 4);
    Ok(())
}

#[test]
fn child_and_logical_restore_require_original_output_consumption()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = OutputFixture::new()?;
    let mut state = fixture.state()?;
    state.on_network_tx(20, b"frame")?;
    let expected = Err(LiveVcpuTimeCallbackError::NetworkOutputStopUnconsumed {
        write_index: 1,
        read_index: 0,
    });
    let generation = fixture.slot.arm_logical_time_restore(1_000)?;

    // These are the actual Rust reset entry points. The SDK/mapping admission
    // is modeled; this does not certify a physical child adoption or VMState.
    assert_eq!(
        state.reinitialize_hot_fork_child_workers(LiveWorkerQuiescence::new(WORKER_REQUIRED)),
        expected
    );
    assert_eq!(state.restore_logical_time_if_requested(20, false), expected);
    assert_ne!(fixture.slot.snapshot().logical_time_restore_ack, generation);
    let consumed = fixture.outbound.dequeue(&fixture.outbound_entries)?;
    assert!(consumed.is_some());

    state.reinitialize_hot_fork_child_workers(LiveWorkerQuiescence::new(WORKER_REQUIRED))?;
    state.restore_logical_time_if_requested(20, true)?;

    assert_eq!(fixture.slot.snapshot().logical_time_restore_ack, generation);
    assert_eq!(fixture.slot.snapshot().current_icount, 1_000);
    Ok(())
}

#[test]
fn explicit_pause_shutdown_and_their_control_ack_keep_priority()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = OutputFixture::new()?;
    let state = fixture.state()?;
    state.on_vcpu_init(0)?;
    state.on_network_tx(20, b"frame")?;
    state.header.get().request_pause([&fixture.slot])?;
    let request = fixture.slot.request_control_boundary(0, None)?;

    state.on_vcpu_resume(0, 20)?;
    assert_eq!(fixture.slot.snapshot().control_boundary_ack, request);
    state.on_control_boundary(20)?;
    assert_eq!(
        fixture.slot.snapshot().control_boundary_ack,
        request.wrapping_add(1)
    );
    assert_eq!(TEST_REQUEST_VMSTOP_CALLS.get(), 2);
    state.header.get().request_shutdown([&fixture.slot])?;
    state.on_vcpu_resume(0, 20)?;

    assert!(state.shared_shutdown_signaled.load(Ordering::Acquire));
    assert_eq!(fixture.outbound.read_index(), 0);
    assert_eq!(fixture.outbound_entries[0].delivery_icount, 1_000);
    Ok(())
}
