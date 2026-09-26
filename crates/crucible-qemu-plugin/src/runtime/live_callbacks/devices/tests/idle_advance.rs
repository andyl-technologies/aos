//! Idle-advance and burst-release tests for live device callbacks.

use super::*;

#[test]
fn live_ninep_burst_release_is_legal_while_idle_advance_retires() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 20, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let layout = RegionLayout::for_config(RegionConfig::new(1, 4))
        .unwrap_or_else(|error| panic!("test region layout should validate: {error}"));
    let header = RegionHeader::new(layout);
    let deadline = crate::ExactDeadlineReader::require(Some(test_deadline))
        .unwrap_or_else(|error| panic!("test deadline should bind: {error}"));
    let advance = crate::QueuedIdleAdvance::require(Some(test_advance))
        .unwrap_or_else(|error| panic!("test advance should bind: {error}"));
    let mut storage = DeviceRingStorage::new();
    let block = storage.block_pair();
    let ninep = storage.ninep_pair();
    let (teardown_sender, teardown_receiver) = std::sync::mpsc::channel();
    std::mem::forget(teardown_receiver);
    let state = LiveVcpuTimeCallbackState::new(
        test_icount_raw,
        crate::runtime::live_callbacks::test_support::test_force_vcpu_exit,
        crate::runtime::live_callbacks::test_support::test_idle_wake_wait(),
        crate::runtime::live_callbacks::test_support::test_request_vmstop,
        crate::runtime::live_callbacks::test_support::test_preemption_injector(),
        1,
        0,
        deadline,
        advance,
        crate::runtime::live_callbacks::test_support::test_virtual_timer_witness(),
        Box::new(crate::runtime::live_callbacks::TestFaultCommandBridge::empty()),
        &header,
        &slot,
        Arc::new(LiveCallbackQuiescence::new()),
        LiveRuntimeTeardownRouter::new(teardown_sender),
    )
    .and_then(|state| state.attach_devices(0, block, ninep, 1, storage.accelerator_rings()))
    .unwrap_or_else(|error| panic!("test live state should attach devices: {error}"));

    state
        .ninep_burst_start()
        .unwrap_or_else(|error| panic!("9p burst should start: {error}"));
    let pending = advance
        .enqueue(10)
        .unwrap_or_else(|error| panic!("idle advance should queue: {error}"));
    state
        .arm_idle_advance(0, 10, pending, None)
        .unwrap_or_else(|error| panic!("pending idle advance should arm: {error}"));
    state
        .ninep_burst_done()
        .unwrap_or_else(|error| panic!("burst release should not observe guest time: {error}"));

    assert_eq!(slot.snapshot().device_io_active, 0);
    assert!(
        state
            .pending_idle_advance
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some()
    );
}

#[test]
fn live_block_event_poll_consumes_the_wake_during_idle_advance() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 20, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let layout = RegionLayout::for_config(RegionConfig::new(1, 4))
        .unwrap_or_else(|error| panic!("test region layout should validate: {error}"));
    let header = RegionHeader::new(layout);
    let deadline = crate::ExactDeadlineReader::require(Some(test_deadline))
        .unwrap_or_else(|error| panic!("test deadline should bind: {error}"));
    let advance = crate::QueuedIdleAdvance::require(Some(test_advance))
        .unwrap_or_else(|error| panic!("test advance should bind: {error}"));
    let mut storage = DeviceRingStorage::new();
    let block = storage.block_pair();
    let ninep = storage.ninep_pair();
    let (teardown_sender, teardown_receiver) = std::sync::mpsc::channel();
    std::mem::forget(teardown_receiver);
    let state = LiveVcpuTimeCallbackState::new(
        test_icount_raw,
        crate::runtime::live_callbacks::test_support::test_force_vcpu_exit,
        crate::runtime::live_callbacks::test_support::test_idle_wake_wait(),
        crate::runtime::live_callbacks::test_support::test_request_vmstop,
        crate::runtime::live_callbacks::test_support::test_preemption_injector(),
        1,
        0,
        deadline,
        advance,
        crate::runtime::live_callbacks::test_support::test_virtual_timer_witness(),
        Box::new(crate::runtime::live_callbacks::TestFaultCommandBridge::empty()),
        &header,
        &slot,
        Arc::new(LiveCallbackQuiescence::new()),
        LiveRuntimeTeardownRouter::new(teardown_sender),
    )
    .and_then(|state| state.attach_devices(0, block, ninep, 1, storage.accelerator_rings()))
    .unwrap_or_else(|error| panic!("test live state should attach devices: {error}"));

    state
        .block_submit(0, 0, 0, 0, None, 0)
        .unwrap_or_else(|error| panic!("primary request should submit: {error}"));
    let userdata = std::ptr::from_ref(&state).cast_mut().cast::<c_void>();
    assert_eq!(
        crucible_qemu_plugin_live_block_transport_save_cb(std::ptr::null_mut(), 0, userdata,),
        QEMU_PLUGIN_BLOCK_TRANSPORT_SAVE_BUSY,
        "a busy migration must reject save without aborting the source process"
    );
    let completed = BlockResponse::new(BlockResponseStatus::Ok, 0, Vec::new())
        .encode()
        .unwrap_or_else(|error| panic!("primary response should encode: {error}"));
    enqueue_response(
        &storage.block_in_header,
        &mut storage.block_in_entries,
        10,
        SLOT_BLK_IO as u32,
        0,
        &completed,
    );
    let reset = crate::BlockTransportReset {
        next_epoch: 1,
        recovery_nanos: 1,
        request_ids: crate::BlockTransportRequestIds::NewEpochFromZero,
        reenumerate_declared: true,
        preserve_duplicate_history: true,
        failure_result: BlockResponseErrorCode::IoError,
        unadmitted: crate::BlockTransportUnadmitted::Reject,
        queued: crate::BlockTransportPending::Fail,
        executing: crate::BlockTransportPending::Fail,
        resolved: crate::BlockTransportResolved::Fail,
        completed_undelivered: crate::BlockTransportUndelivered::Fail,
        preserve_controller_buffer: true,
        preserve_volatile_cache: true,
    };
    let event = BlockResponse::reset_event(crate::BlockRequestIdentity::new(0, 0), reset)
        .encode()
        .unwrap_or_else(|error| panic!("reset event should encode: {error}"));
    enqueue_response(
        &storage.block_in_header,
        &mut storage.block_in_entries,
        10,
        SLOT_BLK_IO as u32,
        1,
        &event,
    );
    let pending = advance
        .enqueue(10)
        .unwrap_or_else(|error| panic!("idle advance should queue: {error}"));
    state
        .arm_idle_advance(0, 10, pending, None)
        .unwrap_or_else(|error| panic!("pending idle advance should arm: {error}"));
    state
        .complete_idle_advance(crate::TimeAdvanceCompletion::from_qemu(0, 10))
        .unwrap_or_else(|error| panic!("idle advance should commit: {error}"));

    assert_eq!(
        state
            .block_poll(0, 0, &mut [])
            .unwrap_or_else(|error| panic!("primary request should complete: {error}")),
        0
    );

    let mut output = [0_u8; QEMU_PLUGIN_BLOCK_EVENT_CAPACITY];
    assert_eq!(
        state
            .block_event_poll(&mut output)
            .unwrap_or_else(|error| panic!("the one-shot wake should expose the event: {error}")),
        i64::try_from(QEMU_PLUGIN_BLOCK_EVENT_CAPACITY)
            .unwrap_or_else(|error| panic!("event capacity should fit: {error}"))
    );
    assert_eq!(
        BlockResponse::decode(&output)
            .unwrap_or_else(|error| panic!("returned event should decode: {error}"))
            .transport_reset(),
        Ok(reset)
    );
}

#[test]
fn live_device_submits_during_idle_completion_use_the_advance_target() {
    FORCE_VCPU_EXIT_CALLS.store(0, Ordering::SeqCst);
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 20, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let layout = RegionLayout::for_config(RegionConfig::new(1, 4))
        .unwrap_or_else(|error| panic!("test region layout should validate: {error}"));
    let header = RegionHeader::new(layout);
    let deadline = crate::ExactDeadlineReader::require(Some(test_deadline))
        .unwrap_or_else(|error| panic!("test deadline should bind: {error}"));
    let advance = crate::QueuedIdleAdvance::require(Some(test_advance))
        .unwrap_or_else(|error| panic!("test advance should bind: {error}"));
    let mut storage = DeviceRingStorage::new();
    let block = storage.block_pair();
    let ninep = storage.ninep_pair();
    let (teardown_sender, teardown_receiver) = std::sync::mpsc::channel();
    std::mem::forget(teardown_receiver);
    let state = LiveVcpuTimeCallbackState::new(
        test_icount_raw,
        capture_force_vcpu_exit,
        crate::runtime::live_callbacks::test_support::test_idle_wake_wait(),
        crate::runtime::live_callbacks::test_support::test_request_vmstop,
        crate::runtime::live_callbacks::test_support::test_preemption_injector(),
        1,
        0,
        deadline,
        advance,
        crate::runtime::live_callbacks::test_support::test_virtual_timer_witness(),
        Box::new(crate::runtime::live_callbacks::TestFaultCommandBridge::empty()),
        &header,
        &slot,
        Arc::new(LiveCallbackQuiescence::new()),
        LiveRuntimeTeardownRouter::new(teardown_sender),
    )
    .and_then(|state| state.attach_devices(0, block, ninep, 1, storage.accelerator_rings()))
    .unwrap_or_else(|error| panic!("test live state should attach devices: {error}"));
    let pending = advance
        .enqueue(10)
        .unwrap_or_else(|error| panic!("idle advance should queue: {error}"));
    state
        .arm_idle_advance(0, 10, pending, None)
        .unwrap_or_else(|error| panic!("pending idle advance should arm: {error}"));

    state
        .block_submit(0, 0, 0, 0, None, 1)
        .unwrap_or_else(|error| panic!("timer-boundary block submit should succeed: {error}"));
    assert_eq!(FORCE_VCPU_EXIT_CALLS.load(Ordering::SeqCst), 1);
    state
        .ninep_burst_start()
        .unwrap_or_else(|error| panic!("timer-boundary 9p burst should start: {error}"));
    state
        .ninep_submit(0, b"request", 8)
        .unwrap_or_else(|error| panic!("timer-boundary 9p submit should succeed: {error}"));
    assert_eq!(FORCE_VCPU_EXIT_CALLS.load(Ordering::SeqCst), 2);

    assert_eq!(storage.block_out_entries[0].delivery_icount, 10);
    assert_eq!(storage.ninep_out_entries[0].delivery_icount, 10);
    assert_eq!(slot.snapshot().device_io_active, 1);
}
