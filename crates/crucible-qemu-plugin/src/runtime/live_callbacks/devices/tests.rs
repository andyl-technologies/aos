//! Live block and 9p callback adapter tests.

use std::sync::Arc;

use crate::runtime::callback_quiescence::LiveCallbackQuiescence;

use super::*;

use crucible_shmem::{
    DirectedRing, KIND_VM, MappedDirectedRingMut, RegionConfig, RegionHeader, RegionLayout,
    SLOT_9P_IO, SLOT_BLK_IO, authorize_advance_ceiling,
};

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
    let mut devices = LiveDeviceCallbackState::new(0, block, ninep)
        .unwrap_or_else(|error| panic!("live devices should bind fixed rings: {error}"));

    devices
        .submit_block(&slot, 5, 0, 0, 12, None, 4)
        .unwrap_or_else(|error| panic!("block read should submit: {error}"));
    assert_eq!(storage.block_out_header.write_index(), 1);
    assert_eq!(slot.snapshot().device_io_active, 1);
    let mut block_output = [0_u8; 4];
    assert_eq!(
        devices
            .poll_block(&slot, 5, 0, &mut block_output)
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
            .poll_block(&slot, 5, 0, &mut block_output)
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
fn live_device_preflight_rejects_qemu_request_id_drift_without_mutation() {
    let slot = NodeSlot::new(KIND_VM);
    let ceiling = authorize_advance_ceiling(0, 20, None)
        .unwrap_or_else(|error| panic!("test ceiling should authorize: {error}"));
    slot.publish_scheduler_ceiling(ceiling)
        .unwrap_or_else(|error| panic!("test ceiling should publish: {error}"));
    let mut storage = DeviceRingStorage::new();
    let block = storage.block_pair();
    let ninep = storage.ninep_pair();
    let mut devices = LiveDeviceCallbackState::new(0, block, ninep)
        .unwrap_or_else(|error| panic!("live devices should bind fixed rings: {error}"));

    assert_eq!(
        devices.submit_block(&slot, 5, 3, 0, 0, None, 1),
        Err(LiveDeviceCallbackError::RequestIdMismatch {
            family: "block",
            qemu_request_id: 3,
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
        1,
        0,
        0,
        deadline,
        advance,
        &header,
        &slot,
        Arc::new(LiveCallbackQuiescence::new()),
        teardown_sender,
    )
    .and_then(|state| state.attach_devices(0, block, ninep))
    .unwrap_or_else(|error| panic!("test live state should attach devices: {error}"));
    let devices = state
        .devices
        .as_ref()
        .unwrap_or_else(|| panic!("test device state should exist"));
    let guard = devices
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    assert_eq!(
        state.block_submit(0, 0, 0, None, 1),
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
        1,
        0,
        0,
        deadline,
        advance,
        &header,
        &slot,
        Arc::new(LiveCallbackQuiescence::new()),
        teardown_sender,
    )
    .and_then(|state| state.attach_devices(0, block, ninep))
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

extern "C" fn test_deadline() -> i64 {
    -1
}

extern "C" fn test_advance(_target: i64) -> c_int {
    0
}

extern "C" fn test_icount_raw() -> u64 {
    0
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
