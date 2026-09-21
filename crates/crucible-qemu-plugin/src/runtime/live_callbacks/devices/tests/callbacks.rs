//! Live device callback ownership and completion tests.

use super::*;

#[test]
fn live_device_adapters_retain_tokens_and_complete_block_and_ninep() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 20, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let mut storage = DeviceRingStorage::new();
    let block = storage.block_pair();
    let ninep = storage.ninep_pair();
    let accelerator = storage.accelerator_rings();
    let mut devices = LiveDeviceCallbackState::new(0, block, ninep, 1, accelerator)
        .unwrap_or_else(|error| panic!("live devices should bind fixed rings: {error}"));

    devices
        .submit_block(&slot, 5, 0, 0, 0, 12, None, 4)
        .unwrap_or_else(|error| panic!("block read should submit: {error}"));
    assert_eq!(storage.block_out_header.write_index(), 1);
    assert_eq!(slot.snapshot().device_io_active, 1);
    let mut block_output = [0_u8; 4];
    assert_eq!(
        devices
            .poll_block(&slot, 5, 0, 0, &mut block_output)
            .unwrap_or_else(|error| panic!("empty block poll should stay pending: {error}")),
        QEMU_PLUGIN_BLOCK_POLL_PENDING
    );
    let block_response = BlockResponse::new(BlockResponseStatus::Ok, 0, b"data".to_vec())
        .encode()
        .unwrap_or_else(|error| panic!("block response should encode: {error}"));
    enqueue_response(
        &storage.block_in_header,
        &mut storage.block_in_entries,
        5,
        SLOT_BLK_IO as u32,
        0,
        &block_response,
    );
    assert_eq!(
        devices
            .poll_block(&slot, 5, 0, 0, &mut block_output)
            .unwrap_or_else(|error| panic!("due block response should complete: {error}")),
        4
    );
    assert_eq!(&block_output, b"data");
    assert_eq!(storage.block_in_header.read_index(), 1);
    assert_eq!(slot.snapshot().device_io_active, 0);

    devices
        .begin_ninep_burst(&slot)
        .unwrap_or_else(|error| panic!("9p burst should start: {error}"));
    devices
        .submit_ninep(&slot, 7, 0, b"request", 8)
        .unwrap_or_else(|error| panic!("9p request should submit: {error}"));
    assert_eq!(storage.ninep_out_header.write_index(), 1);
    enqueue_response(
        &storage.ninep_in_header,
        &mut storage.ninep_in_entries,
        7,
        SLOT_9P_IO as u32,
        0,
        b"response",
    );
    let mut ninep_output = [0_u8; 8];
    assert_eq!(
        devices
            .poll_ninep(&slot, 7, 0, &mut ninep_output)
            .unwrap_or_else(|error| panic!("due 9p response should complete: {error}")),
        8
    );
    assert_eq!(&ninep_output, b"response");
    devices
        .finish_ninep_burst(&slot)
        .unwrap_or_else(|error| panic!("answered 9p burst should finish: {error}"));
    assert_eq!(slot.snapshot().device_io_active, 0);
}

#[test]
fn live_block_event_poll_delivers_reset_without_losing_pre_reset_tokens() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 40, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let mut storage = DeviceRingStorage::new();
    let block = storage.block_pair();
    let ninep = storage.ninep_pair();
    let accelerator = storage.accelerator_rings();
    let mut devices = LiveDeviceCallbackState::new(0, block, ninep, 1, accelerator)
        .unwrap_or_else(|error| panic!("live devices should bind fixed rings: {error}"));

    devices
        .submit_block(&slot, 5, 0, 0, 0, 0, None, 4)
        .unwrap_or_else(|error| panic!("primary read should submit: {error}"));
    let primary = BlockResponse::new(BlockResponseStatus::Ok, 0, b"data".to_vec())
        .encode()
        .unwrap_or_else(|error| panic!("primary response should encode: {error}"));
    enqueue_response(
        &storage.block_in_header,
        &mut storage.block_in_entries,
        10,
        SLOT_BLK_IO as u32,
        0,
        &primary,
    );
    let mut primary_output = [0_u8; 4];
    assert_eq!(
        devices
            .poll_block(&slot, 10, 0, 0, &mut primary_output)
            .unwrap_or_else(|error| panic!("primary should complete: {error}")),
        4
    );

    devices
        .submit_block(&slot, 11, 0, 1, 0, 4, None, 4)
        .unwrap_or_else(|error| panic!("pre-reset request should submit: {error}"));
    assert_eq!(slot.snapshot().device_io_active, 1);
    let reset = crate::BlockTransportReset {
        next_epoch: 1,
        recovery_nanos: 50,
        request_ids: crate::BlockTransportRequestIds::NewEpochFromZero,
        reenumerate_declared: true,
        preserve_duplicate_history: false,
        failure_result: BlockResponseErrorCode::IoError,
        unadmitted: crate::BlockTransportUnadmitted::WaitForRecovery,
        queued: crate::BlockTransportPending::RetryNewId,
        executing: crate::BlockTransportPending::Fail,
        resolved: crate::BlockTransportResolved::RetryPreserveId,
        completed_undelivered: crate::BlockTransportUndelivered::DropCompletion,
        preserve_controller_buffer: false,
        preserve_volatile_cache: true,
    };
    let event = BlockResponse::reset_event(crate::BlockRequestIdentity::new(0, 0), reset)
        .encode()
        .unwrap_or_else(|error| panic!("reset event should encode: {error}"));
    enqueue_response(
        &storage.block_in_header,
        &mut storage.block_in_entries,
        12,
        SLOT_BLK_IO as u32,
        0,
        &event,
    );
    let mut event_output = [0_u8; QEMU_PLUGIN_BLOCK_EVENT_CAPACITY];
    assert_eq!(
        devices
            .poll_block_event(&slot, 12, &mut event_output)
            .unwrap_or_else(|error| panic!("reset event should deliver: {error}")),
        i64::try_from(QEMU_PLUGIN_BLOCK_EVENT_CAPACITY)
            .unwrap_or_else(|error| panic!("event length should fit: {error}"))
    );
    let decoded = BlockResponse::decode(&event_output)
        .unwrap_or_else(|error| panic!("returned reset event should decode: {error}"));
    assert_eq!(decoded.status(), BlockResponseStatus::TransportReset);
    assert_eq!(decoded.transport_reset(), Ok(reset));
    assert_eq!(devices.block.request_epoch(), 0);
    assert_eq!(storage.block_in_header.read_index(), 1);
    devices
        .commit_block_event()
        .unwrap_or_else(|error| panic!("accepted reset event should commit: {error}"));
    assert_eq!(devices.block.request_epoch(), 1);
    assert_eq!(storage.block_in_header.read_index(), 2);
    assert_eq!(devices.block_tokens.len(), 1);
    assert_eq!(slot.snapshot().device_io_active, 1);
    assert_eq!(
        devices
            .poll_block_event(&slot, 12, &mut event_output)
            .unwrap_or_else(|error| panic!("empty event poll should succeed: {error}")),
        0
    );
}

#[test]
fn preserved_retry_authorization_survives_outbound_ring_backpressure() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 40, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let mut storage = DeviceRingStorage::new();
    let block = storage.block_pair();
    let ninep = storage.ninep_pair();
    let accelerator = storage.accelerator_rings();
    let mut devices = LiveDeviceCallbackState::new(0, block, ninep, 1, accelerator)
        .unwrap_or_else(|error| panic!("live devices should bind fixed rings: {error}"));
    let identity = crate::BlockRequestIdentity::new(0, 0);

    devices
        .submit_block(
            &slot,
            5,
            identity.epoch(),
            identity.request_id(),
            0,
            0,
            None,
            4,
        )
        .unwrap_or_else(|error| panic!("original request should submit: {error}"));
    let _submitted = storage
        .block_out_header
        .dequeue(&storage.block_out_entries)
        .unwrap_or_else(|error| panic!("host should dequeue original request: {error}"))
        .unwrap_or_else(|| panic!("original request frame should exist"));
    let retry =
        BlockResponse::with_identity(BlockResponseStatus::RetryPreserveId, identity, Vec::new())
            .encode()
            .unwrap_or_else(|error| panic!("retry disposition should encode: {error}"));
    enqueue_response(
        &storage.block_in_header,
        &mut storage.block_in_entries,
        5,
        SLOT_BLK_IO as u32,
        0,
        &retry,
    );
    assert_eq!(
        devices
            .poll_block(&slot, 5, identity.epoch(), identity.request_id(), &mut [])
            .unwrap_or_else(|error| panic!("retry disposition should poll: {error}")),
        QEMU_PLUGIN_BLOCK_RETRY_PRESERVE_ID
    );
    assert!(devices.block_reissue_preserve.contains(&identity));
    assert!(!devices.block_tokens.contains_key(&identity));

    for sequence in 0..storage.block_out_entries.len() {
        let frame = FrameEntry::new(6, 0, sequence as u32, &[0])
            .unwrap_or_else(|error| panic!("filler frame should encode: {error}"));
        storage
            .block_out_header
            .enqueue(&mut storage.block_out_entries, &frame)
            .unwrap_or_else(|error| panic!("filler frame should enqueue: {error}"));
    }
    assert!(
        devices
            .submit_block(
                &slot,
                6,
                identity.epoch(),
                identity.request_id(),
                0,
                0,
                None,
                4
            )
            .is_err()
    );
    assert!(devices.block_reissue_preserve.contains(&identity));
    assert!(!devices.block_tokens.contains_key(&identity));
    assert_eq!(slot.snapshot().device_io_active, 0);

    let _freed = storage
        .block_out_header
        .dequeue(&storage.block_out_entries)
        .unwrap_or_else(|error| panic!("host should free one outbound slot: {error}"))
        .unwrap_or_else(|| panic!("one filler frame should exist"));
    devices
        .submit_block(
            &slot,
            7,
            identity.epoch(),
            identity.request_id(),
            0,
            0,
            None,
            4,
        )
        .unwrap_or_else(|error| panic!("preserved retry should survive backpressure: {error}"));
    assert!(!devices.block_reissue_preserve.contains(&identity));
    assert!(devices.block_tokens.contains_key(&identity));
    assert_eq!(slot.snapshot().device_io_active, 1);
}

#[test]
fn transport_continuation_rejects_every_live_callback_continuation() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 40, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let mut storage = DeviceRingStorage::new();
    let block = storage.block_pair();
    let ninep = storage.ninep_pair();
    let accelerator = storage.accelerator_rings();
    let mut devices = LiveDeviceCallbackState::new(0, block, ninep, 1, accelerator)
        .unwrap_or_else(|error| panic!("live devices should bind fixed rings: {error}"));

    let continuation_len = devices
        .save_block_transport(&mut [])
        .unwrap_or_else(|error| panic!("pristine continuation should size: {error}"));
    let mut continuation = vec![0; continuation_len];
    assert_eq!(
        devices
            .save_block_transport(&mut continuation)
            .unwrap_or_else(|error| panic!("pristine continuation should save: {error}")),
        continuation_len
    );

    devices
        .submit_block(&slot, 5, 0, 0, 0, 0, None, 4)
        .unwrap_or_else(|error| panic!("authenticated request should submit: {error}"));
    let completed = BlockResponse::new(BlockResponseStatus::Ok, 0, b"data".to_vec())
        .encode()
        .unwrap_or_else(|error| panic!("authenticated response should encode: {error}"));
    enqueue_response(
        &storage.block_in_header,
        &mut storage.block_in_entries,
        5,
        SLOT_BLK_IO as u32,
        0,
        &completed,
    );
    let mut output = [0; 4];
    assert_eq!(
        devices
            .poll_block(&slot, 5, 0, 0, &mut output)
            .unwrap_or_else(|error| panic!("authenticated request should complete: {error}")),
        4
    );
    devices
        .submit_block(&slot, 6, 0, 1, 0, 4, None, 4)
        .unwrap_or_else(|error| panic!("live continuation request should submit: {error}"));
    devices
        .block_reissue_preserve
        .insert(crate::BlockRequestIdentity::new(0, 7));
    let event = BlockResponse::reset_event(
        crate::BlockRequestIdentity::new(0, 0),
        crate::BlockTransportReset {
            next_epoch: 1,
            recovery_nanos: 1,
            request_ids: crate::BlockTransportRequestIds::NewEpochFromZero,
            reenumerate_declared: false,
            preserve_duplicate_history: true,
            failure_result: BlockResponseErrorCode::IoError,
            unadmitted: crate::BlockTransportUnadmitted::Reject,
            queued: crate::BlockTransportPending::Fail,
            executing: crate::BlockTransportPending::Fail,
            resolved: crate::BlockTransportResolved::Fail,
            completed_undelivered: crate::BlockTransportUndelivered::Fail,
            preserve_controller_buffer: true,
            preserve_volatile_cache: true,
        },
    )
    .encode()
    .unwrap_or_else(|error| panic!("reset event should encode: {error}"));
    enqueue_response(
        &storage.block_in_header,
        &mut storage.block_in_entries,
        6,
        SLOT_BLK_IO as u32,
        1,
        &event,
    );
    let mut event_output = [0; QEMU_PLUGIN_BLOCK_EVENT_CAPACITY];
    assert_eq!(
        devices
            .poll_block_event(&slot, 6, &mut event_output)
            .unwrap_or_else(|error| panic!("reset event should prepare: {error}")),
        i64::try_from(QEMU_PLUGIN_BLOCK_EVENT_CAPACITY)
            .unwrap_or_else(|error| panic!("event capacity should fit: {error}"))
    );

    let expected = LiveDeviceCallbackError::TransportContinuationBusy {
        block_tokens: 1,
        retry_authorizations: 1,
        prepared_event: true,
    };
    assert_eq!(devices.save_block_transport(&mut []), Err(expected.clone()));
    assert_eq!(
        devices.restore_block_transport(&continuation, 0, 0),
        Err(expected)
    );
}

#[test]
fn live_device_preflight_rejects_qemu_request_id_drift_without_mutation() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 20, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let mut storage = DeviceRingStorage::new();
    let block = storage.block_pair();
    let ninep = storage.ninep_pair();
    let accelerator = storage.accelerator_rings();
    let mut devices = LiveDeviceCallbackState::new(0, block, ninep, 1, accelerator)
        .unwrap_or_else(|error| panic!("live devices should bind fixed rings: {error}"));

    assert_eq!(
        devices.submit_block(&slot, 5, 0, 3, 0, 0, None, 1),
        Err(LiveDeviceCallbackError::RequestIdMismatch {
            family: "block",
            qemu_epoch: 0,
            qemu_request_id: 3,
            plugin_epoch: 0,
            plugin_request_id: 0,
        })
    );
    assert_eq!(storage.block_out_header.write_index(), 0);
    assert_eq!(slot.snapshot().device_io_active, 0);
}

#[test]
fn live_device_callback_reentry_is_rejected_before_ring_or_freeze_mutation() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 20, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let layout = RegionLayout::for_config(RegionConfig::new(1, 4, 0))
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
    let devices = state
        .devices
        .as_ref()
        .unwrap_or_else(|| panic!("test device state should exist"));
    let guard = devices
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    assert_eq!(
        state.block_submit(0, 0, 0, 0, None, 1),
        Err(LiveVcpuTimeCallbackError::live_device(
            LiveDeviceCallbackError::CallbackReentered,
        ))
    );
    drop(guard);
    assert_eq!(storage.block_out_header.write_index(), 0);
    assert_eq!(slot.snapshot().device_io_active, 0);
}
