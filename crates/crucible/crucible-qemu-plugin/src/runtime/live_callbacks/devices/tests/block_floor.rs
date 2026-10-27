//! The live adapter's oldest-live-epoch stamp across a transport reset ([IO-35]).

use super::*;

/// Dequeues the next submitted request and returns its stamped floor.
fn next_stamped_floor(storage: &DeviceRingStorage) -> u64 {
    let frame = storage
        .block_out_header
        .dequeue(&storage.block_out_entries)
        .unwrap_or_else(|error| panic!("host should dequeue a request: {error}"))
        .unwrap_or_else(|| panic!("a submitted request frame should exist"));
    let payload = frame
        .payload()
        .unwrap_or_else(|error| panic!("request frame has a payload: {error}"));
    let (stamp, _request) = crate::BlockRequest::decode(payload)
        .unwrap_or_else(|error| panic!("submitted request decodes: {error}"));
    stamp.oldest_live_epoch()
}

fn respond(storage: &mut DeviceRingStorage, delivery_icount: u64, response: BlockResponse) {
    let encoded = response
        .encode()
        .unwrap_or_else(|error| panic!("response should encode: {error}"));
    enqueue_response(
        &storage.block_in_header,
        &mut storage.block_in_entries,
        delivery_icount,
        SLOT_BLK_IO as u32,
        0,
        &encoded,
    );
}

fn new_epoch_reset() -> crate::BlockTransportReset {
    crate::BlockTransportReset {
        next_epoch: 1,
        recovery_nanos: 50,
        request_ids: crate::BlockTransportRequestIds::NewEpochFromZero,
        reenumerate_declared: false,
        preserve_duplicate_history: true,
        failure_result: BlockResponseErrorCode::IoError,
        unadmitted: crate::BlockTransportUnadmitted::WaitForRecovery,
        queued: crate::BlockTransportPending::RetryPreserveId,
        executing: crate::BlockTransportPending::Fail,
        resolved: crate::BlockTransportResolved::Complete,
        completed_undelivered: crate::BlockTransportUndelivered::Complete,
        preserve_controller_buffer: true,
        preserve_volatile_cache: true,
    }
}

/// New-epoch requests name epoch 0 while a pre-reset identity is in flight or
/// awaiting its preserved retry, and name epoch 1 once it has completed.
#[test]
fn live_submit_stamps_the_oldest_epoch_qemu_can_still_submit() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 100, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_advance(ceiling, crucible_qemu_shmem::AdvanceStopCondition::Ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let mut storage = DeviceRingStorage::new();
    let block = storage.block_pair();
    let ninep = storage.ninep_pair();
    let accelerator = storage.accelerator_rings();
    let mut devices = LiveDeviceCallbackState::new(0, block, ninep, 1, accelerator)
        .unwrap_or_else(|error| panic!("live devices should bind fixed rings: {error}"));
    let completed = crate::BlockRequestIdentity::new(0, 0);
    let pre_reset = crate::BlockRequestIdentity::new(0, 1);
    let mut output = [0_u8; 4];

    // (0, 0) completes, so the reset event can name it; (0, 1) stays in flight.
    devices
        .submit_block(&slot, 5, 0, 0, 0, 0, None, 4)
        .unwrap_or_else(|error| panic!("first request should submit: {error}"));
    assert_eq!(next_stamped_floor(&storage), 0);
    respond(
        &mut storage,
        6,
        BlockResponse::with_identity(BlockResponseStatus::Ok, completed, b"data".to_vec()),
    );
    devices
        .poll_block(&slot, 6, 0, 0, &mut output)
        .unwrap_or_else(|error| panic!("first request should complete: {error}"));
    devices
        .submit_block(&slot, 7, 0, 1, 0, 0, None, 4)
        .unwrap_or_else(|error| panic!("pre-reset request should submit: {error}"));
    assert_eq!(next_stamped_floor(&storage), 0);

    respond(
        &mut storage,
        8,
        BlockResponse::reset_event(completed, new_epoch_reset()),
    );
    let mut event = [0_u8; QEMU_PLUGIN_BLOCK_EVENT_CAPACITY];
    devices
        .poll_block_event(&slot, 8, &mut event)
        .unwrap_or_else(|error| panic!("reset event should deliver: {error}"));
    devices
        .commit_block_event()
        .unwrap_or_else(|error| panic!("reset event should commit: {error}"));
    assert_eq!(devices.block.request_epoch(), 1);

    // In flight: the new-epoch request still names epoch 0.
    devices
        .submit_block(&slot, 9, 1, 0, 0, 0, None, 4)
        .unwrap_or_else(|error| panic!("new-epoch request should submit: {error}"));
    assert_eq!(next_stamped_floor(&storage), 0);

    // Awaiting a preserved retry: still epoch 0, and the retry names it too.
    respond(
        &mut storage,
        10,
        BlockResponse::with_identity(BlockResponseStatus::RetryPreserveId, pre_reset, Vec::new()),
    );
    assert_eq!(
        devices
            .poll_block(&slot, 10, 0, 1, &mut output)
            .unwrap_or_else(|error| panic!("retry disposition should poll: {error}")),
        QEMU_PLUGIN_BLOCK_RETRY_PRESERVE_ID
    );
    devices
        .submit_block(&slot, 11, 1, 1, 0, 0, None, 4)
        .unwrap_or_else(|error| panic!("second new-epoch request should submit: {error}"));
    assert_eq!(next_stamped_floor(&storage), 0);
    devices
        .submit_block(&slot, 12, 0, 1, 0, 0, None, 4)
        .unwrap_or_else(|error| panic!("preserved retry should submit: {error}"));
    assert_eq!(next_stamped_floor(&storage), 0);

    // Once the pre-reset identity completes, only epoch-1 identities remain.
    respond(
        &mut storage,
        13,
        BlockResponse::with_identity(BlockResponseStatus::Ok, pre_reset, b"data".to_vec()),
    );
    devices
        .poll_block(&slot, 13, 0, 1, &mut output)
        .unwrap_or_else(|error| panic!("preserved retry should complete: {error}"));
    devices
        .submit_block(&slot, 14, 1, 2, 0, 0, None, 4)
        .unwrap_or_else(|error| panic!("later request should submit: {error}"));
    assert_eq!(next_stamped_floor(&storage), 1);
}
