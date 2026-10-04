//! Wire-adapter callback tests for live block and 9p requests.

use super::*;

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
