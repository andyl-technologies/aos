//! Live block and 9p callback adapter tests.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::BlockOperation;
use crate::runtime::callback_quiescence::LiveCallbackQuiescence;

use super::*;

use crucible_shmem::{
    AcceleratorEntry, DirectedRing, KIND_VM, MappedDirectedRingMut, RegionConfig, RegionHeader,
    RegionLayout, SLOT_9P_IO, SLOT_BLK_IO, authorize_advance_ceiling,
};

static FORCE_VCPU_EXIT_CALLS: AtomicUsize = AtomicUsize::new(0);

#[test]
fn qemu_discard_callback_maps_to_payload_free_wire_request() {
    let request = block_request(3, 4096, None, 8192)
        .unwrap_or_else(|error| panic!("discard callback should validate: {error}"));
    assert_eq!(request.operation(), BlockOperation::Discard);
    assert_eq!(request.offset(), 4096);
    assert_eq!(request.count(), 8192);
    assert!(request.payload().is_empty());
    let encoded = request
        .encode(crate::BlockRequestIdentity::new(0, 7))
        .unwrap_or_else(|error| panic!("discard wire request should encode: {error}"));
    let (request_id, decoded) = BlockRequest::decode(&encoded)
        .unwrap_or_else(|error| panic!("discard wire request should decode: {error}"));
    assert_eq!(request_id, crate::BlockRequestIdentity::new(0, 7));
    assert_eq!(decoded, request);

    assert!(matches!(
        block_request(3, 4096, Some(&[0]), 1),
        Err(LiveDeviceCallbackError::UnexpectedPayloadPointer {
            family: "block discard",
            ..
        })
    ));
}

#[test]
fn typed_block_errors_map_to_stable_linux_errno_values() {
    let cases = [
        (BlockResponseErrorCode::Offline, 123),
        (BlockResponseErrorCode::ReadOnly, 30),
        (BlockResponseErrorCode::InvalidRange, 22),
        (BlockResponseErrorCode::Busy, 16),
        (BlockResponseErrorCode::Timeout, 110),
        (BlockResponseErrorCode::MediumError, 5),
        (BlockResponseErrorCode::IntegrityError, 84),
        (BlockResponseErrorCode::IoError, 5),
        (BlockResponseErrorCode::NoSpace, 28),
        (BlockResponseErrorCode::NotFound, 2),
        (BlockResponseErrorCode::Stale, 116),
    ];
    for (error, errno) in cases {
        assert_eq!(block_error_errno(error), errno);
        assert_ne!(-(QEMU_PLUGIN_BLOCK_ERROR_BASE + errno), -1);
        assert_ne!(-(QEMU_PLUGIN_BLOCK_ERROR_BASE + errno), -2);
    }
}

#[test]
fn accelerator_adapter_round_trips_a_real_shared_memory_request() {
    let slot = NodeSlot::new(KIND_VM);
    let mut storage = DeviceRingStorage::new();
    let block = storage.block_pair();
    let ninep = storage.ninep_pair();
    let accelerator = storage.accelerator_rings();
    let mut devices = LiveDeviceCallbackState::new(0, block, ninep, 9, accelerator)
        .unwrap_or_else(|error| panic!("live devices should bind: {error}"));
    let device_id = [7_u8; 32];

    devices
        .submit_accelerator(&slot, 11, 41, device_id, 1, 1, 2, 8, &[1, 2, 3], 4)
        .unwrap_or_else(|error| panic!("accelerator request should submit: {error}"));
    assert_eq!(slot.snapshot().device_io_active, 1);
    let request = storage
        .accelerator_request_header
        .dequeue_accelerator(&storage.accelerator_request_entries)
        .unwrap_or_else(|error| panic!("host should dequeue request: {error}"))
        .unwrap_or_else(|| panic!("request should be present"));
    assert_eq!(request.sequence(), 41);
    assert_eq!(request.data(), Ok(&[1, 2, 3][..]));
    let completion = AcceleratorEntry::new(
        41,
        9,
        device_id,
        AcceleratorClass::Gpu,
        1,
        2,
        0,
        true,
        8,
        4,
        &[5, 6, 7, 8],
    )
    .unwrap_or_else(|error| panic!("completion should build: {error}"));
    storage
        .accelerator_completion_header
        .enqueue_accelerator(&mut storage.accelerator_completion_entries, completion)
        .unwrap_or_else(|error| panic!("host should enqueue completion: {error}"));
    let mut output = [0_u8; 4];
    assert_eq!(
        devices
            .poll_accelerator(&slot, 41, &mut output)
            .unwrap_or_else(|error| panic!("completion should poll: {error}")),
        (0, 4)
    );
    assert_eq!(output, [5, 6, 7, 8]);
    assert_eq!(slot.snapshot().device_io_active, 0);
}

#[test]
fn accelerator_cancellation_is_published_and_acknowledged() {
    let slot = NodeSlot::new(KIND_VM);
    let mut storage = DeviceRingStorage::new();
    let block = storage.block_pair();
    let ninep = storage.ninep_pair();
    let accelerator = storage.accelerator_rings();
    let mut devices = LiveDeviceCallbackState::new(0, block, ninep, 9, accelerator)
        .unwrap_or_else(|error| panic!("live devices should bind: {error}"));
    let device_id = [7_u8; 32];
    devices
        .submit_accelerator(&slot, 11, 41, device_id, 1, 1, 0, 8, &[1], 4)
        .unwrap_or_else(|error| panic!("request should submit: {error}"));
    storage
        .accelerator_request_header
        .dequeue_accelerator(&storage.accelerator_request_entries)
        .unwrap_or_else(|error| panic!("host dequeue should work: {error}"));
    devices
        .cancel_accelerator(&slot, 41)
        .unwrap_or_else(|error| panic!("request should cancel: {error}"));
    let cancellation = storage
        .accelerator_request_header
        .dequeue_accelerator(&storage.accelerator_request_entries)
        .unwrap_or_else(|error| panic!("host dequeue should work: {error}"))
        .unwrap_or_else(|| panic!("cancellation should be published"));
    assert!(cancellation.is_cancellation());
    assert_eq!(slot.snapshot().device_io_active, 0);
    let acknowledgement = AcceleratorEntry::new(
        41,
        9,
        device_id,
        AcceleratorClass::Gpu,
        1,
        0,
        crucible_shmem::ACCELERATOR_STATUS_CANCELLED,
        true,
        8,
        4,
        &[],
    )
    .unwrap_or_else(|error| panic!("acknowledgement should build: {error}"));
    storage
        .accelerator_completion_header
        .enqueue_accelerator(&mut storage.accelerator_completion_entries, acknowledgement)
        .unwrap_or_else(|error| panic!("host should acknowledge: {error}"));
    assert_eq!(
        devices
            .poll_accelerator(&slot, 0, &mut [])
            .unwrap_or_else(|error| panic!("drain should work: {error}")),
        (0, QEMU_PLUGIN_ACCELERATOR_POLL_PENDING)
    );
    assert!(devices.accelerator_cancelled.is_empty());
}

#[test]
fn accelerator_restore_stages_then_commits_as_one_batch() {
    let slot = NodeSlot::new(KIND_VM);
    let mut storage = DeviceRingStorage::new();
    let mut devices = LiveDeviceCallbackState::new(
        0,
        storage.block_pair(),
        storage.ninep_pair(),
        9,
        storage.accelerator_rings(),
    )
    .unwrap_or_else(|error| panic!("live devices should bind: {error}"));
    devices
        .begin_accelerator_restore(2)
        .unwrap_or_else(|error| panic!("restore should begin: {error}"));
    for sequence in [41, 42] {
        devices
            .stage_accelerator_restore(sequence, [7; 32], 1, 1, 0, 8, 4)
            .unwrap_or_else(|error| panic!("entry should stage: {error}"));
    }
    assert!(devices.accelerator_pending.is_empty());
    assert_eq!(slot.snapshot().device_io_active, 0);
    devices
        .commit_accelerator_restore(&slot, 11)
        .unwrap_or_else(|error| panic!("restore should commit: {error}"));
    assert_eq!(devices.accelerator_pending.len(), 2);
    assert_eq!(slot.snapshot().device_io_active, 1);
}

#[test]
fn live_device_adapters_retain_tokens_and_complete_block_and_ninep() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 20, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
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
    slot.publish_scheduler_ceiling(ceiling)
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
    slot.publish_scheduler_ceiling(ceiling)
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
    slot.publish_scheduler_ceiling(ceiling)
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
    slot.publish_scheduler_ceiling(ceiling)
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
    slot.publish_scheduler_ceiling(ceiling)
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
        61,
        test_icount_raw,
        super::super::test_support::test_force_vcpu_exit,
        super::super::test_support::test_request_vmstop,
        super::super::test_support::test_preemption_injector(),
        1,
        0,
        0,
        deadline,
        advance,
        None,
        &header,
        &slot,
        Arc::new(LiveCallbackQuiescence::new()),
        teardown_sender,
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

#[test]
fn live_ninep_burst_release_is_legal_while_idle_advance_retires() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 20, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
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
        62,
        test_icount_raw,
        super::super::test_support::test_force_vcpu_exit,
        super::super::test_support::test_request_vmstop,
        super::super::test_support::test_preemption_injector(),
        1,
        0,
        0,
        deadline,
        advance,
        None,
        &header,
        &slot,
        Arc::new(LiveCallbackQuiescence::new()),
        teardown_sender,
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
        .arm_idle_advance(0, 10, pending)
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
    slot.publish_scheduler_ceiling(ceiling)
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
        64,
        test_icount_raw,
        super::super::test_support::test_force_vcpu_exit,
        super::super::test_support::test_request_vmstop,
        super::super::test_support::test_preemption_injector(),
        1,
        0,
        0,
        deadline,
        advance,
        None,
        &header,
        &slot,
        Arc::new(LiveCallbackQuiescence::new()),
        teardown_sender,
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
        .arm_idle_advance(0, 10, pending)
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
    slot.publish_scheduler_ceiling(ceiling)
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
        63,
        test_icount_raw,
        capture_force_vcpu_exit,
        super::super::test_support::test_request_vmstop,
        super::super::test_support::test_preemption_injector(),
        1,
        0,
        0,
        deadline,
        advance,
        None,
        &header,
        &slot,
        Arc::new(LiveCallbackQuiescence::new()),
        teardown_sender,
    )
    .and_then(|state| state.attach_devices(0, block, ninep, 1, storage.accelerator_rings()))
    .unwrap_or_else(|error| panic!("test live state should attach devices: {error}"));
    let pending = advance
        .enqueue(10)
        .unwrap_or_else(|error| panic!("idle advance should queue: {error}"));
    state
        .arm_idle_advance(0, 10, pending)
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

extern "C" fn test_deadline() -> i64 {
    -1
}

extern "C" fn test_advance(_target: i64) -> c_int {
    0
}

extern "C" fn test_icount_raw() -> u64 {
    0
}

extern "C" fn capture_force_vcpu_exit() {
    FORCE_VCPU_EXIT_CALLS.fetch_add(1, Ordering::SeqCst);
}

struct DeviceRingStorage {
    block_out_header: RingHeader,
    block_out_entries: Vec<FrameEntry>,
    block_in_header: RingHeader,
    block_in_entries: Vec<FrameEntry>,
    ninep_out_header: RingHeader,
    ninep_out_entries: Vec<FrameEntry>,
    ninep_in_header: RingHeader,
    ninep_in_entries: Vec<FrameEntry>,
    accelerator_request_header: RingHeader,
    accelerator_request_entries: Vec<AcceleratorEntry>,
    accelerator_completion_header: RingHeader,
    accelerator_completion_entries: Vec<AcceleratorEntry>,
}

impl DeviceRingStorage {
    fn new() -> Self {
        Self {
            block_out_header: RingHeader::new(),
            block_out_entries: vec![FrameEntry::default(); 4],
            block_in_header: RingHeader::new(),
            block_in_entries: vec![FrameEntry::default(); 4],
            ninep_out_header: RingHeader::new(),
            ninep_out_entries: vec![FrameEntry::default(); 4],
            ninep_in_header: RingHeader::new(),
            ninep_in_entries: vec![FrameEntry::default(); 4],
            accelerator_request_header: RingHeader::new(),
            accelerator_request_entries: vec![AcceleratorEntry::default(); 4],
            accelerator_completion_header: RingHeader::new(),
            accelerator_completion_entries: vec![AcceleratorEntry::default(); 4],
        }
    }

    fn block_pair(&mut self) -> LiveDirectedRingPair {
        ring_pair(
            0,
            SLOT_BLK_IO as u32,
            2,
            3,
            &self.block_out_header,
            &mut self.block_out_entries,
            &self.block_in_header,
            &mut self.block_in_entries,
        )
    }

    fn ninep_pair(&mut self) -> LiveDirectedRingPair {
        ring_pair(
            0,
            SLOT_9P_IO as u32,
            4,
            5,
            &self.ninep_out_header,
            &mut self.ninep_out_entries,
            &self.ninep_in_header,
            &mut self.ninep_in_entries,
        )
    }

    fn accelerator_rings(&mut self) -> DetachedPluginAcceleratorRings {
        // SAFETY: this fixture retains the four allocations for the complete
        // handle lifetime and creates only one plugin role per test.
        unsafe {
            DetachedPluginAcceleratorRings::from_raw_parts(
                &self.accelerator_request_header,
                self.accelerator_request_entries.as_mut_ptr(),
                self.accelerator_request_entries.len(),
                &self.accelerator_completion_header,
                self.accelerator_completion_entries.as_mut_ptr(),
                self.accelerator_completion_entries.len(),
            )
        }
        .unwrap_or_else(|| panic!("accelerator test rings should be nonempty"))
    }
}

// crucible-lint: allow rust-allow -- the fixture spells both directed endpoints and their distinct backing stores.
#[allow(
    clippy::too_many_arguments,
    reason = "the test helper spells both directed ring endpoints and backing stores"
)]
fn ring_pair(
    vm_slot: u32,
    executor_slot: u32,
    outbound_index: u32,
    inbound_index: u32,
    outbound_header: &RingHeader,
    outbound_entries: &mut [FrameEntry],
    inbound_header: &RingHeader,
    inbound_entries: &mut [FrameEntry],
) -> LiveDirectedRingPair {
    LiveDirectedRingPair::new(
        MappedDirectedRingMut {
            descriptor: DirectedRing {
                index: outbound_index,
                src_slot: vm_slot,
                dst_slot: executor_slot,
            },
            header: outbound_header,
            entries: outbound_entries,
        },
        MappedDirectedRingMut {
            descriptor: DirectedRing {
                index: inbound_index,
                src_slot: executor_slot,
                dst_slot: vm_slot,
            },
            header: inbound_header,
            entries: inbound_entries,
        },
    )
    .unwrap_or_else(|error| panic!("test ring handles should build: {error}"))
}

fn enqueue_response(
    header: &RingHeader,
    entries: &mut [FrameEntry],
    delivery_icount: u64,
    source: u32,
    sequence: u32,
    payload: &[u8],
) {
    let frame = FrameEntry::new(delivery_icount, source, sequence, payload)
        .unwrap_or_else(|error| panic!("test response frame should build: {error}"));
    header
        .enqueue(entries, &frame)
        .unwrap_or_else(|error| panic!("test response should enqueue: {error}"));
}
