//! Tests for plugin-side block request and completion transport.

use super::*;

use crucible_shmem::{KIND_VM, RegionConfig, RegionLayout, ReservedExecutorSlot};

#[test]
fn completed_identity_history_compacts_contiguous_ids_and_retains_gaps() {
    let mut history = CompletedIdentityHistory::default();
    let third = BlockRequestIdentity::new(7, 2);
    history
        .ensure_record_capacity(third)
        .unwrap_or_else(|error| panic!("history should admit a gap: {error}"));
    history.record(third);
    assert!(history.contains(third));
    assert_eq!(history.gaps, 1);

    for request_id in [0, 1] {
        let identity = BlockRequestIdentity::new(7, request_id);
        history
            .ensure_record_capacity(identity)
            .unwrap_or_else(|error| panic!("history should admit prefix: {error}"));
        history.record(identity);
    }

    assert_eq!(history.gaps, 0);
    assert_eq!(history.epochs[&7].contiguous_exclusive, 3);
    assert!(
        (0..=2).all(|request_id| { history.contains(BlockRequestIdentity::new(7, request_id)) })
    );
    assert!(!history.contains(BlockRequestIdentity::new(7, 3)));

    history.clear();
    assert!(!history.contains(third));
    assert_eq!(history.gaps, 0);
}

#[test]
fn transport_continuation_round_trips_allocator_and_exact_history() {
    let source = PluginBlockIo::new(2, 8, 9);
    source.request_epoch.set(7);
    source.next_request_id.set(19);
    {
        let mut history = source.completed_identities.borrow_mut();
        for identity in [
            BlockRequestIdentity::new(3, 0),
            BlockRequestIdentity::new(3, 2),
            BlockRequestIdentity::new(7, 0),
        ] {
            history
                .ensure_record_capacity(identity)
                .unwrap_or_else(|error| panic!("history should admit identity: {error}"));
            history.record(identity);
        }
    }
    let encoded = source
        .encode_transport_continuation()
        .unwrap_or_else(|error| panic!("continuation should encode: {error}"));
    let restored = PluginBlockIo::new(2, 8, 9);
    restored
        .restore_transport_continuation(&encoded, 7, 19)
        .unwrap_or_else(|error| panic!("continuation should restore: {error}"));
    assert_eq!(restored.request_epoch(), 7);
    assert_eq!(restored.next_request_id(), 19);
    assert_eq!(
        *restored.completed_identities.borrow(),
        *source.completed_identities.borrow()
    );

    assert!(matches!(
        restored.restore_transport_continuation(&encoded, 6, 19),
        Err(BlockIoError::InvalidTransportContinuation { .. })
    ));
    assert_eq!(restored.request_epoch(), 7);
    assert_eq!(restored.next_request_id(), 19);
    assert_eq!(
        *restored.completed_identities.borrow(),
        *source.completed_identities.borrow()
    );
    let mut trailing = encoded;
    trailing.push(0);
    assert!(matches!(
        restored.restore_transport_continuation(&trailing, 7, 19),
        Err(BlockIoError::InvalidTransportContinuation { .. })
    ));
    assert_eq!(restored.request_epoch(), 7);
    assert_eq!(restored.next_request_id(), 19);
    assert_eq!(
        *restored.completed_identities.borrow(),
        *source.completed_identities.borrow()
    );
}

#[test]
fn block_io_state_binds_reserved_block_rings() {
    let layout = layout();
    let (outbound, inbound) = block_rings(layout, 1);
    let block = match PluginBlockIo::from_directed_rings(1, outbound, inbound) {
        Ok(block) => block,
        Err(error) => panic!("block rings should bind: {error}"),
    };

    assert_eq!(block.vm_slot(), 1);
    assert_eq!(block.block_slot(), BLOCK_IO_SLOT_U32);
    assert_eq!(block.outbound_ring_index(), outbound.index);
    assert_eq!(block.inbound_ring_index(), inbound.index);

    let wrong = DirectedRing {
        index: outbound.index,
        src_slot: 1,
        dst_slot: ReservedExecutorSlot::NetRouter.slot() as u32,
    };
    assert_eq!(
        match PluginBlockIo::from_directed_rings(1, wrong, inbound) {
            Ok(_) => panic!("wrong block outbound ring should be rejected"),
            Err(error) => error,
        },
        BlockIoError::WrongOutboundRing {
            expected_src_slot: 1,
            expected_dst_slot: BLOCK_IO_SLOT_U32,
            expected_ring_index: None,
            actual_src_slot: 1,
            actual_dst_slot: ReservedExecutorSlot::NetRouter.slot() as u32,
            actual_ring_index: outbound.index,
        }
    );
}

#[test]
fn block_submit_encodes_request_stamps_icount_and_freezes_time() {
    let slot = NodeSlot::new(KIND_VM);
    let mut freeze = PluginDeviceIoFreeze::new();
    let block = PluginBlockIo::new(2, 8, 9);
    let header = RingHeader::new();
    let mut entries = empty_entries(4);
    let mut ring = outbound_ring(8, 2, &header, &mut entries);
    let request = match BlockRequest::write(4096, b"data".to_vec()) {
        Ok(request) => request,
        Err(error) => panic!("write request should build: {error}"),
    };

    let submit =
        match handle_block_submit_callback(&block, &mut freeze, &slot, &mut ring, 77, &request) {
            Ok(submit) => submit,
            Err(error) => panic!("block submit should enqueue: {error}"),
        };

    assert_eq!(submit.ring_index(), 8);
    assert_eq!(submit.submit_icount(), 77);
    assert_eq!(submit.request_id(), 0);
    assert_eq!(submit.payload_len(), BLOCK_REQUEST_HEADER_LEN + 4);
    assert_eq!(block.next_request_id(), 1);
    assert_eq!(freeze.pending_requests(), 1);
    assert_eq!(slot.snapshot().device_io_active, 1);
    assert_eq!(header.write_index(), 1);
    assert_frame(&ring.entries[0], 77, 2, 0);
    assert_eq!(
        ring.entries[0].payload(),
        Ok(&[
            1, 4, 0, 0, // type/version/reserved
            0, 0, 0, 0, 0, 0, 0, 0, // epoch
            0, 0, 0, 0, // request_id
            0, 0x10, 0, 0, 0, 0, 0, 0, // offset
            4, 0, 0, 0, // count
            b'd', b'a', b't', b'a',
        ][..])
    );
}

#[test]
fn block_submit_wrong_ring_does_not_freeze_or_enqueue() {
    let slot = NodeSlot::new(KIND_VM);
    let mut freeze = PluginDeviceIoFreeze::new();
    let block = PluginBlockIo::new(2, 8, 9);
    let header = RingHeader::new();
    let mut entries = empty_entries(4);
    let mut ring = BlockOutboundRing::new(10, 2, BLOCK_IO_SLOT_U32, &header, &mut entries);

    assert_eq!(
        block.submit_request(
            &mut freeze,
            &slot,
            &mut ring,
            77,
            &BlockRequest::read(0, 512)
        ),
        Err(BlockIoError::WrongOutboundRing {
            expected_src_slot: 2,
            expected_dst_slot: BLOCK_IO_SLOT_U32,
            expected_ring_index: Some(8),
            actual_src_slot: 2,
            actual_dst_slot: BLOCK_IO_SLOT_U32,
            actual_ring_index: 10,
        })
    );
    assert_eq!(freeze.pending_requests(), 0);
    assert_eq!(slot.snapshot().device_io_active, 0);
    assert_eq!(header.write_index(), 0);
}

#[test]
fn block_submit_rejects_oversized_write_before_copying_payload() {
    let slot = NodeSlot::new(KIND_VM);
    let mut freeze = PluginDeviceIoFreeze::new();
    let block = PluginBlockIo::new(2, 8, 9);
    let header = RingHeader::new();
    let mut entries = empty_entries(4);
    let mut ring = outbound_ring(8, 2, &header, &mut entries);
    let request = match BlockRequest::write(4096, vec![0xa5; MAX_FRAME_DATA]) {
        Ok(request) => request,
        Err(error) => {
            panic!("write request should build before frame-size validation: {error}")
        }
    };

    assert_eq!(
        block.submit_request(&mut freeze, &slot, &mut ring, 77, &request),
        Err(BlockIoError::Wire {
            source: BlockWireError::FramePayload {
                source: FrameEntryError::PayloadLengthExceedsCapacity {
                    len: BLOCK_REQUEST_HEADER_LEN + MAX_FRAME_DATA,
                    capacity: MAX_FRAME_DATA,
                },
            },
        })
    );
    assert_eq!(freeze.pending_requests(), 0);
    assert_eq!(slot.snapshot().device_io_active, 0);
    assert_eq!(block.next_request_id(), 0);
    assert_eq!(header.write_index(), 0);
}

#[test]
fn block_submit_full_ring_releases_freeze_token_loudly() {
    let slot = NodeSlot::new(KIND_VM);
    let mut freeze = PluginDeviceIoFreeze::new();
    let block = PluginBlockIo::new(2, 8, 9);
    let header = RingHeader::new();
    let mut entries = empty_entries(1);
    enqueue(&header, &mut entries, frame(70, 2, 99, b"occupied"));
    let mut ring = outbound_ring(8, 2, &header, &mut entries);

    let error = match block.submit_request(
        &mut freeze,
        &slot,
        &mut ring,
        77,
        &BlockRequest::read(0, 512),
    ) {
        Ok(_) => panic!("full block ring should fail"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        BlockIoError::RingEnqueueFailed {
            source: SpscRingError::QueueFull { capacity: 1 },
            ..
        }
    ));
    assert_eq!(freeze.pending_requests(), 0);
    assert_eq!(slot.snapshot().device_io_active, 0);
    assert_eq!(block.next_request_id(), 0);
}

#[test]
fn block_poll_returns_not_ready_until_delivery_icount_is_reached() {
    let slot = NodeSlot::new(KIND_VM);
    let mut freeze = PluginDeviceIoFreeze::new();
    let block = PluginBlockIo::new(2, 8, 9);
    let outbound_header = RingHeader::new();
    let mut outbound_entries = empty_entries(4);
    let mut outbound = outbound_ring(8, 2, &outbound_header, &mut outbound_entries);
    let submit = submit_read(&block, &mut freeze, &slot, &mut outbound, 77);
    let token = submit.into_token();
    let inbound_header = RingHeader::new();
    let mut inbound_entries = empty_entries(4);
    enqueue(
        &inbound_header,
        &mut inbound_entries,
        response_frame(90, 0, b"abcd"),
    );
    let inbound = inbound_ring(9, 2, &inbound_header, &inbound_entries);
    let mut completion = RecordingCompletion::default();

    let token = match block.poll_response(&mut freeze, &slot, &inbound, &mut completion, 89, token)
    {
        Ok(BlockPoll::NotReady { token }) => token,
        other => panic!("future response should not be ready: {other:?}"),
    };

    assert_eq!(inbound_header.read_index(), 0);
    assert_eq!(freeze.pending_requests(), 1);
    assert!(completion.responses.is_empty());

    let poll = match block.poll_response(&mut freeze, &slot, &inbound, &mut completion, 90, token) {
        Ok(poll) => poll,
        Err(error) => panic!("due block response should complete: {error}"),
    };

    let BlockPoll::Completed { response, release } = poll else {
        panic!("due response should complete");
    };
    assert_eq!(response.payload(), b"abcd");
    assert_eq!(release.pending_requests(), 0);
    assert!(!release.device_io_active());
    assert_eq!(inbound_header.read_index(), 1);
    assert_eq!(completion.responses, vec![response]);
    assert_eq!(slot.snapshot().device_io_active, 0);
}

#[test]
fn transport_reset_advances_epoch_only_after_a_completed_identity() {
    let slot = NodeSlot::new(KIND_VM);
    let mut freeze = PluginDeviceIoFreeze::new();
    let block = PluginBlockIo::new(2, 8, 9);
    let outbound_header = RingHeader::new();
    let mut outbound_entries = empty_entries(4);
    let mut outbound = outbound_ring(8, 2, &outbound_header, &mut outbound_entries);
    let token = submit_read(&block, &mut freeze, &slot, &mut outbound, 10).into_token();
    let inbound_header = RingHeader::new();
    let mut inbound_entries = empty_entries(4);
    enqueue(
        &inbound_header,
        &mut inbound_entries,
        response_frame(20, 0, b"done"),
    );
    let mut completion = RecordingCompletion::default();
    assert!(matches!(
        block.poll_response(
            &mut freeze,
            &slot,
            &inbound_ring(9, 2, &inbound_header, &inbound_entries),
            &mut completion,
            20,
            token
        ),
        Ok(BlockPoll::Completed { .. })
    ));

    let reset = test_transport_reset(1);
    let encoded = BlockResponse::reset_event(BlockRequestIdentity::new(0, 0), reset)
        .encode()
        .unwrap_or_else(|error| panic!("reset response should encode: {error}"));
    enqueue(
        &inbound_header,
        &mut inbound_entries,
        frame(21, BLOCK_IO_SLOT_U32, 0, &encoded),
    );
    let inbound = inbound_ring(9, 2, &inbound_header, &inbound_entries);
    let pending = block
        .peek_transport_event(&inbound, 21)
        .unwrap_or_else(|error| panic!("reset event should prepare: {error}"))
        .unwrap_or_else(|| panic!("reset event should be ready"));
    assert_eq!(
        pending.event(),
        BlockTransportEvent::Reset {
            identity: BlockRequestIdentity::new(0, 0),
            reset,
        }
    );
    assert_eq!(block.request_epoch(), 0);
    assert_eq!(block.next_request_id(), 1);
    assert_eq!(inbound_header.read_index(), 1);
    assert_eq!(
        block
            .commit_transport_event(&inbound, pending)
            .unwrap_or_else(|error| panic!("reset event should commit: {error}")),
        pending.event()
    );
    assert_eq!(block.request_epoch(), 1);
    assert_eq!(block.next_request_id(), 0);
    assert_eq!(inbound_header.read_index(), 2);

    let next = submit_read(&block, &mut freeze, &slot, &mut outbound, 22).into_token();
    assert_eq!(next.identity(), BlockRequestIdentity::new(1, 0));
    block
        .fail_polled_request(&mut freeze, &slot, next)
        .unwrap_or_else(|error| panic!("test request should release: {error}"));
}

#[test]
fn invalid_transport_reset_epoch_preserves_the_ring_and_plugin_state() {
    let slot = NodeSlot::new(KIND_VM);
    let mut freeze = PluginDeviceIoFreeze::new();
    let block = PluginBlockIo::new(2, 8, 9);
    let outbound_header = RingHeader::new();
    let mut outbound_entries = empty_entries(4);
    let mut outbound = outbound_ring(8, 2, &outbound_header, &mut outbound_entries);
    let token = submit_read(&block, &mut freeze, &slot, &mut outbound, 10).into_token();
    let inbound_header = RingHeader::new();
    let mut inbound_entries = empty_entries(4);
    enqueue(
        &inbound_header,
        &mut inbound_entries,
        response_frame(20, 0, b"done"),
    );
    let mut completion = RecordingCompletion::default();
    assert!(matches!(
        block.poll_response(
            &mut freeze,
            &slot,
            &inbound_ring(9, 2, &inbound_header, &inbound_entries),
            &mut completion,
            20,
            token
        ),
        Ok(BlockPoll::Completed { .. })
    ));

    let encoded =
        BlockResponse::reset_event(BlockRequestIdentity::new(0, 0), test_transport_reset(2))
            .encode()
            .unwrap_or_else(|error| panic!("reset response should encode: {error}"));
    enqueue(
        &inbound_header,
        &mut inbound_entries,
        frame(21, BLOCK_IO_SLOT_U32, 0, &encoded),
    );
    assert_eq!(
        block.peek_transport_event(&inbound_ring(9, 2, &inbound_header, &inbound_entries), 21,),
        Err(BlockIoError::InvalidTransportResetEpoch {
            current_epoch: 0,
            next_epoch: 2,
            request_ids: BlockTransportRequestIds::NewEpochFromZero,
        })
    );
    assert_eq!(block.request_epoch(), 0);
    assert_eq!(block.next_request_id(), 1);
    assert_eq!(inbound_header.read_index(), 1);
}

#[test]
fn block_poll_rejects_wrong_request_id_and_releases_freeze_token() {
    let slot = NodeSlot::new(KIND_VM);
    let mut freeze = PluginDeviceIoFreeze::new();
    let block = PluginBlockIo::new(2, 8, 9);
    let outbound_header = RingHeader::new();
    let mut outbound_entries = empty_entries(4);
    let mut outbound = outbound_ring(8, 2, &outbound_header, &mut outbound_entries);
    let token = submit_read(&block, &mut freeze, &slot, &mut outbound, 77).into_token();
    let inbound_header = RingHeader::new();
    let mut inbound_entries = empty_entries(4);
    enqueue(
        &inbound_header,
        &mut inbound_entries,
        response_frame(90, 1, b"wrong"),
    );
    let inbound = inbound_ring(9, 2, &inbound_header, &inbound_entries);
    let mut completion = RecordingCompletion::default();

    let error = match block.poll_response(&mut freeze, &slot, &inbound, &mut completion, 90, token)
    {
        Ok(_) => panic!("wrong request id should fail"),
        Err(error) => error,
    };
    match error {
        BlockIoError::UnexpectedResponse {
            expected_request_id: 0,
            actual_request_id: 1,
            frame,
            release,
        } => {
            assert_eq!(frame, response_frame(90, 1, b"wrong").delivery_key());
            assert_eq!(release.pending_requests(), 0);
            assert_eq!(release.outcome(), crate::DeviceIoRequestOutcome::Failed);
        }
        other => panic!("wrong request id should be unexpected response: {other:?}"),
    }
    assert_eq!(inbound_header.read_index(), 0);
    assert_eq!(freeze.pending_requests(), 0);
    assert_eq!(slot.snapshot().device_io_active, 0);
    assert!(completion.responses.is_empty());
}

#[test]
fn block_poll_rejects_wrong_response_source_and_releases_freeze_token() {
    let slot = NodeSlot::new(KIND_VM);
    let mut freeze = PluginDeviceIoFreeze::new();
    let block = PluginBlockIo::new(2, 8, 9);
    let outbound_header = RingHeader::new();
    let mut outbound_entries = empty_entries(4);
    let mut outbound = outbound_ring(8, 2, &outbound_header, &mut outbound_entries);
    let token = submit_read(&block, &mut freeze, &slot, &mut outbound, 77).into_token();
    let inbound_header = RingHeader::new();
    let mut inbound_entries = empty_entries(4);
    let malformed_source = frame(90, 99, 0, &encoded_response(0, b"bad-source"));
    enqueue(
        &inbound_header,
        &mut inbound_entries,
        malformed_source.clone(),
    );
    let inbound = inbound_ring(9, 2, &inbound_header, &inbound_entries);
    let mut completion = RecordingCompletion::default();

    let error = match block.poll_response(&mut freeze, &slot, &inbound, &mut completion, 90, token)
    {
        Ok(_) => panic!("wrong response source should fail"),
        Err(error) => error,
    };
    match error {
        BlockIoError::UnexpectedSource {
            expected_src_node: BLOCK_IO_SLOT_U32,
            actual_src_node: 99,
            frame,
            release,
        } => {
            assert_eq!(frame, malformed_source.delivery_key());
            assert_eq!(release.pending_requests(), 0);
            assert_eq!(release.outcome(), crate::DeviceIoRequestOutcome::Failed);
        }
        other => panic!("wrong response source should be unexpected source: {other:?}"),
    }
    assert_eq!(inbound_header.read_index(), 0);
    assert_eq!(freeze.pending_requests(), 0);
    assert_eq!(slot.snapshot().device_io_active, 0);
    assert!(completion.responses.is_empty());
}

#[test]
fn block_poll_guest_completion_failure_still_releases_freeze_token() {
    let slot = NodeSlot::new(KIND_VM);
    let mut freeze = PluginDeviceIoFreeze::new();
    let block = PluginBlockIo::new(2, 8, 9);
    let outbound_header = RingHeader::new();
    let mut outbound_entries = empty_entries(4);
    let mut outbound = outbound_ring(8, 2, &outbound_header, &mut outbound_entries);
    let token = submit_read(&block, &mut freeze, &slot, &mut outbound, 77).into_token();
    let inbound_header = RingHeader::new();
    let mut inbound_entries = empty_entries(4);
    enqueue(
        &inbound_header,
        &mut inbound_entries,
        response_frame(90, 0, b"abcd"),
    );
    let inbound = inbound_ring(9, 2, &inbound_header, &inbound_entries);
    let mut completion = RecordingCompletion {
        fail_message: Some("guest completion failure"),
        ..RecordingCompletion::default()
    };

    let error = match block.poll_response(&mut freeze, &slot, &inbound, &mut completion, 90, token)
    {
        Ok(_) => panic!("guest completion failure should be returned"),
        Err(error) => error,
    };
    match error {
        BlockIoError::GuestCompletion {
            request_id: 0,
            release,
            source,
        } => {
            assert_eq!(release.pending_requests(), 0);
            assert_eq!(release.outcome(), crate::DeviceIoRequestOutcome::Completed);
            assert_eq!(
                source,
                BlockGuestCompletionError::new("guest completion failure")
            );
        }
        other => panic!("guest failure should be guest completion error: {other:?}"),
    }
    assert_eq!(inbound_header.read_index(), 1);
    assert_eq!(freeze.pending_requests(), 0);
    assert_eq!(slot.snapshot().device_io_active, 0);
    assert!(completion.responses.is_empty());
}

#[test]
fn block_response_decode_rejects_nonzero_reserved_and_trailing_payload() {
    let mut reserved = encoded_response(7, b"ok");
    reserved[2] = 1;
    assert_eq!(
        BlockResponse::decode(&reserved),
        Err(BlockWireError::NonZeroReserved { reserved: 1 })
    );

    let mut trailing = encoded_response(7, b"ok");
    trailing.push(b'!');
    assert_eq!(
        BlockResponse::decode(&trailing),
        Err(BlockWireError::ResponseCountPayloadMismatch {
            count: 2,
            payload_len: 3,
        })
    );
}

#[test]
fn block_request_decode_rejects_nonzero_reserved_and_trailing_payload() {
    let Ok(mut reserved) = BlockRequest::read(4096, 512).encode(BlockRequestIdentity::new(0, 7))
    else {
        panic!("read request should encode");
    };
    reserved[2] = 1;
    assert_eq!(
        BlockRequest::decode(&reserved),
        Err(BlockWireError::NonZeroReserved { reserved: 1 })
    );

    let Ok(mut trailing) = BlockRequest::read(4096, 512).encode(BlockRequestIdentity::new(0, 7))
    else {
        panic!("read request should encode");
    };
    trailing.push(b'!');
    assert_eq!(
        BlockRequest::decode(&trailing),
        Err(BlockWireError::UnexpectedPayload {
            operation: BlockOperation::Read,
            payload_len: 1,
        })
    );
}

#[test]
fn block_response_frames_are_stamped_by_reserved_block_slot_and_delivery_icount() {
    let frame = response_frame(123, 9, b"block");

    assert_frame(&frame, 123, BLOCK_IO_SLOT_U32, 9);
    assert!(frame.is_deliverable_at(123));
    assert!(!frame.is_deliverable_at(122));
    assert_eq!(
        frame.payload(),
        Ok(&[
            0, 4, 0, 0, // status/version/reserved
            0, 0, 0, 0, 0, 0, 0, 0, // epoch
            9, 0, 0, 0, // request_id
            5, 0, 0, 0, // count
            b'b', b'l', b'o', b'c', b'k',
        ][..])
    );
}

#[test]
fn block_response_typed_errors_are_closed_and_exact() {
    let cases = [
        (1, BlockResponseErrorCode::Offline),
        (2, BlockResponseErrorCode::ReadOnly),
        (3, BlockResponseErrorCode::InvalidRange),
        (4, BlockResponseErrorCode::Busy),
        (5, BlockResponseErrorCode::Timeout),
        (6, BlockResponseErrorCode::MediumError),
        (7, BlockResponseErrorCode::IntegrityError),
        (8, BlockResponseErrorCode::IoError),
        (9, BlockResponseErrorCode::NoSpace),
        (10, BlockResponseErrorCode::NotFound),
        (11, BlockResponseErrorCode::Stale),
    ];
    for (wire, expected) in cases {
        let response = BlockResponse::new(BlockResponseStatus::Error, 7, vec![wire]);
        let decoded = BlockResponse::decode(
            &response
                .encode()
                .unwrap_or_else(|error| panic!("typed error should encode: {error}")),
        )
        .unwrap_or_else(|error| panic!("typed error should decode: {error}"));
        assert_eq!(
            decoded
                .error_code()
                .unwrap_or_else(|error| panic!("typed error should validate: {error}")),
            expected
        );
    }

    for payload in [Vec::new(), vec![0], vec![1, 2]] {
        let response = BlockResponse::new(BlockResponseStatus::Error, 7, payload);
        assert!(
            BlockResponse::decode(
                &response
                    .encode()
                    .unwrap_or_else(|error| panic!("malformed response should encode: {error}"))
            )
            .is_err()
        );
    }
}

#[derive(Default)]
struct RecordingCompletion {
    responses: Vec<BlockResponse>,
    fail_message: Option<&'static str>,
}

impl BlockGuestCompletion for RecordingCompletion {
    fn complete_block_response(
        &mut self,
        response: &BlockResponse,
    ) -> Result<(), BlockGuestCompletionError> {
        if let Some(message) = self.fail_message {
            return Err(BlockGuestCompletionError::new(message));
        }
        self.responses.push(response.clone());
        Ok(())
    }
}

fn layout() -> RegionLayout {
    match RegionLayout::for_config(RegionConfig::new(2, 4, 0)) {
        Ok(layout) => layout,
        Err(error) => panic!("layout should be valid: {error}"),
    }
}

fn block_rings(layout: RegionLayout, vm_slot: u32) -> (DirectedRing, DirectedRing) {
    let rings_per_vm = ReservedExecutorSlot::all().len() as u32 * 2;
    let index = vm_slot * rings_per_vm + 2;
    assert!(index + 1 < layout.ring_count);
    (
        DirectedRing {
            index,
            src_slot: vm_slot,
            dst_slot: BLOCK_IO_SLOT_U32,
        },
        DirectedRing {
            index: index + 1,
            src_slot: BLOCK_IO_SLOT_U32,
            dst_slot: vm_slot,
        },
    )
}

fn empty_entries(capacity: usize) -> Vec<FrameEntry> {
    vec![FrameEntry::default(); capacity]
}

fn outbound_ring<'a>(
    ring_index: u32,
    vm_slot: u32,
    header: &'a RingHeader,
    entries: &'a mut [FrameEntry],
) -> BlockOutboundRing<'a> {
    BlockOutboundRing::new(ring_index, vm_slot, BLOCK_IO_SLOT_U32, header, entries)
}

fn inbound_ring<'a>(
    ring_index: u32,
    vm_slot: u32,
    header: &'a RingHeader,
    entries: &'a [FrameEntry],
) -> BlockInboundRing<'a> {
    BlockInboundRing::new(ring_index, BLOCK_IO_SLOT_U32, vm_slot, header, entries)
}

fn submit_read(
    block: &PluginBlockIo,
    freeze: &mut PluginDeviceIoFreeze,
    slot: &NodeSlot,
    outbound: &mut BlockOutboundRing<'_>,
    submit_icount: u64,
) -> BlockSubmit {
    match block.submit_request(
        freeze,
        slot,
        outbound,
        submit_icount,
        &BlockRequest::read(0, 4),
    ) {
        Ok(submit) => submit,
        Err(error) => panic!("read submit should succeed: {error}"),
    }
}

fn response_frame(delivery_icount: u64, request_id: u32, payload: &[u8]) -> FrameEntry {
    let encoded = encoded_response(request_id, payload);
    frame(delivery_icount, BLOCK_IO_SLOT_U32, request_id, &encoded)
}

fn encoded_response(request_id: u32, payload: &[u8]) -> Vec<u8> {
    let response = BlockResponse::new(BlockResponseStatus::Ok, request_id, payload.to_vec());
    match response.encode() {
        Ok(encoded) => encoded,
        Err(error) => panic!("response should encode: {error}"),
    }
}

fn test_transport_reset(next_epoch: u64) -> BlockTransportReset {
    BlockTransportReset {
        next_epoch,
        recovery_nanos: 50,
        request_ids: BlockTransportRequestIds::NewEpochFromZero,
        reenumerate_declared: true,
        preserve_duplicate_history: false,
        failure_result: BlockResponseErrorCode::IoError,
        unadmitted: BlockTransportUnadmitted::WaitForRecovery,
        queued: BlockTransportPending::RetryNewId,
        executing: BlockTransportPending::Fail,
        resolved: BlockTransportResolved::RetryPreserveId,
        completed_undelivered: BlockTransportUndelivered::DropCompletion,
        preserve_controller_buffer: false,
        preserve_volatile_cache: true,
    }
}

fn frame(delivery_icount: u64, src_node: u32, seq: u32, payload: &[u8]) -> FrameEntry {
    match FrameEntry::new(delivery_icount, src_node, seq, payload) {
        Ok(frame) => frame,
        Err(error) => panic!("test frame should construct: {error}"),
    }
}

fn enqueue(header: &RingHeader, entries: &mut [FrameEntry], frame: FrameEntry) {
    if let Err(error) = PluginShmemOrdering::enqueue_outbound_frame(header, entries, &frame) {
        panic!("test frame should enqueue: {error}");
    }
}

fn assert_frame(frame: &FrameEntry, delivery_icount: u64, src_node: u32, seq: u32) {
    assert_eq!(frame.delivery_icount, delivery_icount);
    assert_eq!(frame.src_node, src_node);
    assert_eq!(frame.seq, seq);
    assert!(usize::from(frame.len) <= MAX_FRAME_DATA);
}
