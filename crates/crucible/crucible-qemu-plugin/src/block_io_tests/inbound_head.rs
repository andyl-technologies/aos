//! Original block-head ownership and stale-observation regressions.

#![cfg(test)]

use super::*;

struct BlockHeadFixture {
    slot: NodeSlot,
    freeze: PluginDeviceIoFreeze,
    block: PluginBlockIo,
    outbound_header: RingHeader,
    outbound_entries: Vec<FrameEntry>,
    inbound_header: RingHeader,
    inbound_entries: Vec<FrameEntry>,
}

impl BlockHeadFixture {
    fn new(epoch: u64) -> Self {
        let block = PluginBlockIo::new(2, 8, 9);
        block.request_epoch.set(epoch);
        Self {
            slot: NodeSlot::new(KIND_VM),
            freeze: PluginDeviceIoFreeze::new(),
            block,
            outbound_header: RingHeader::new(),
            outbound_entries: empty_entries(4),
            inbound_header: RingHeader::new(),
            inbound_entries: empty_entries(4),
        }
    }

    fn submit(&mut self) -> BlockRequestToken {
        let mut outbound = outbound_ring(8, 2, &self.outbound_header, &mut self.outbound_entries);
        submit_read(&self.block, &mut self.freeze, &self.slot, &mut outbound, 70).into_token()
    }

    fn enqueue(&mut self, identity: BlockRequestIdentity, payload: &[u8]) {
        enqueue(
            &self.inbound_header,
            &mut self.inbound_entries,
            identified_response(identity, payload),
        );
    }

    fn inbound(&self, generation: u64) -> BlockInboundRing<'_> {
        BlockInboundRing::registered(
            9,
            generation,
            BLOCK_IO_SLOT_U32,
            2,
            &self.inbound_header,
            &self.inbound_entries,
        )
    }
}

fn identified_response(identity: BlockRequestIdentity, payload: &[u8]) -> FrameEntry {
    let encoded = BlockResponse::with_identity(BlockResponseStatus::Ok, identity, payload.to_vec())
        .encode()
        .unwrap_or_else(|error| panic!("response should encode: {error}"));
    frame(90, BLOCK_IO_SLOT_U32, identity.request_id(), &encoded)
}

#[test]
fn foreign_block_owner_cannot_finalize_the_original_request() {
    let mut fixture = BlockHeadFixture::new(7);
    let token = fixture.submit();
    fixture.enqueue(token.identity(), b"original");
    let foreign_block = PluginBlockIo::new(2, 8, 9);
    foreign_block.request_epoch.set(7);
    let inbound = BlockInboundRing::registered(
        9,
        1,
        BLOCK_IO_SLOT_U32,
        2,
        &fixture.inbound_header,
        &fixture.inbound_entries,
    );
    let mut completion = RecordingCompletion {
        responses: Vec::new(),
        fail_message: None,
    };

    let token = match foreign_block.poll_response(
        &mut fixture.freeze,
        &fixture.slot,
        &inbound,
        &mut completion,
        90,
        token,
    ) {
        Ok(BlockPoll::Retry {
            token,
            source: BlockIoError::RequestForDifferentBlockOwner { identity, .. },
        }) => {
            assert_eq!(identity, token.identity());
            token
        }
        other => panic!("foreign owner must retain the original token: {other:?}"),
    };

    assert_eq!(fixture.inbound_header.read_index(), 0);
    assert_eq!(fixture.freeze.pending_requests(), 1);
    assert_eq!(fixture.slot.snapshot().device_io_active, 1);
    assert!(completion.responses.is_empty());
    assert!(
        foreign_block
            .completed_identities
            .borrow()
            .epochs
            .is_empty()
    );
    assert!(
        fixture
            .block
            .completed_identities
            .borrow()
            .epochs
            .is_empty()
    );
    assert!(
        fixture
            .block
            .observe_inbound_head(&fixture.freeze, &inbound, &token)
            .unwrap_or_else(|error| panic!("block head observation should succeed: {error}"))
            .is_some()
    );

    assert!(matches!(
        fixture.block.poll_response(
            &mut fixture.freeze,
            &fixture.slot,
            &inbound,
            &mut completion,
            90,
            token,
        ),
        Ok(BlockPoll::Completed { .. })
    ));

    assert_eq!(fixture.inbound_header.read_index(), 1);
    assert_eq!(fixture.freeze.pending_requests(), 0);
    assert_eq!(fixture.slot.snapshot().device_io_active, 0);
    assert_eq!(completion.responses.len(), 1);
    assert!(
        foreign_block
            .completed_identities
            .borrow()
            .epochs
            .is_empty()
    );
    assert!(
        fixture
            .block
            .completed_identities
            .borrow()
            .contains(BlockRequestIdentity::new(7, 0))
    );
}

#[test]
fn original_block_head_binds_owner_epoch_request_and_consumer_frontier() {
    let mut fixture = BlockHeadFixture::new(7);
    let first = fixture.submit();
    let second = fixture.submit();
    let foreign_block = PluginBlockIo::new(2, 8, 9);
    foreign_block.request_epoch.set(7);
    let mut outbound = outbound_ring(
        8,
        2,
        &fixture.outbound_header,
        &mut fixture.outbound_entries,
    );
    let copied_identity = submit_read(
        &foreign_block,
        &mut fixture.freeze,
        &fixture.slot,
        &mut outbound,
        70,
    )
    .into_token();
    assert_eq!(copied_identity.identity(), first.identity());
    fixture.enqueue(first.identity(), b"first");
    fixture.enqueue(second.identity(), b"second");
    let inbound = fixture.inbound(1);

    let observed = fixture
        .block
        .observe_inbound_head(&fixture.freeze, &inbound, &first)
        .unwrap_or_else(|error| panic!("original head should be readable: {error}"))
        .unwrap_or_else(|| panic!("first original request should own the head"));

    assert_eq!(observed.identity(), BlockRequestIdentity::new(7, 0));
    assert_eq!(observed.ring_index(), 9);
    assert_eq!(observed.ring_generation(), 1);
    assert_eq!(observed.read_index(), 0);
    assert_eq!(observed.delivery_key().seq, first.request_id());
    assert!(
        fixture
            .block
            .inbound_head_current(&fixture.freeze, &inbound, &first, &observed)
            .unwrap_or_else(|error| panic!("block head observation should succeed: {error}"))
    );
    assert!(
        fixture
            .block
            .observe_inbound_head(&fixture.freeze, &inbound, &second)
            .unwrap_or_else(|error| panic!("block head observation should succeed: {error}"))
            .is_none()
    );
    assert!(
        fixture
            .block
            .observe_inbound_head(&fixture.freeze, &inbound, &copied_identity)
            .unwrap_or_else(|error| panic!("block head observation should succeed: {error}"))
            .is_none()
    );
    assert!(
        !foreign_block
            .inbound_head_current(&fixture.freeze, &inbound, &copied_identity, &observed)
            .unwrap_or_else(|error| panic!("block head observation should succeed: {error}"))
    );
    assert_eq!(fixture.inbound_header.read_index(), 0);
    assert_eq!(fixture.freeze.pending_requests(), 3);

    PluginShmemOrdering::dequeue_inbound_frame(&fixture.inbound_header, &fixture.inbound_entries)
        .unwrap_or_else(|error| panic!("physical dequeue should succeed: {error}"))
        .unwrap_or_else(|| panic!("first response should be present"));

    assert!(
        !fixture
            .block
            .inbound_head_current(&fixture.freeze, &inbound, &first, &observed)
            .unwrap_or_else(|error| panic!("block head observation should succeed: {error}"))
    );
    assert!(
        fixture
            .block
            .observe_inbound_head(&fixture.freeze, &inbound, &second)
            .unwrap_or_else(|error| panic!("block head observation should succeed: {error}"))
            .is_some()
    );
}

#[test]
fn block_head_refuses_unregistered_remapped_and_changed_response_bytes() {
    let mut fixture = BlockHeadFixture::new(7);
    let token = fixture.submit();
    fixture.enqueue(token.identity(), b"original");
    let observed = fixture
        .block
        .observe_inbound_head(&fixture.freeze, &fixture.inbound(1), &token)
        .unwrap_or_else(|error| panic!("block head observation should succeed: {error}"))
        .unwrap_or_else(|| panic!("original inbound head should be present"));
    let unregistered = inbound_ring(9, 2, &fixture.inbound_header, &fixture.inbound_entries);

    assert!(
        fixture
            .block
            .observe_inbound_head(&fixture.freeze, &unregistered, &token)
            .unwrap_or_else(|error| panic!("block head observation should succeed: {error}"))
            .is_none()
    );
    assert!(
        !fixture
            .block
            .inbound_head_current(&fixture.freeze, &unregistered, &token, &observed)
            .unwrap_or_else(|error| panic!("block head observation should succeed: {error}"))
    );
    assert!(
        !fixture
            .block
            .inbound_head_current(&fixture.freeze, &fixture.inbound(2), &token, &observed)
            .unwrap_or_else(|error| panic!("block head observation should succeed: {error}"))
    );

    fixture.inbound_entries[0] = identified_response(token.identity(), b"replaced");
    assert!(
        !fixture
            .block
            .inbound_head_current(&fixture.freeze, &fixture.inbound(1), &token, &observed)
            .unwrap_or_else(|error| panic!("block head observation should succeed: {error}"))
    );

    fixture.inbound_entries[0] = identified_response(
        BlockRequestIdentity::new(6, token.request_id()),
        b"original",
    );
    assert!(
        fixture
            .block
            .observe_inbound_head(&fixture.freeze, &fixture.inbound(1), &token)
            .unwrap_or_else(|error| panic!("block head observation should succeed: {error}"))
            .is_none()
    );
    assert_eq!(fixture.inbound_header.read_index(), 0);
    assert_eq!(fixture.freeze.pending_requests(), 1);
}

#[test]
fn block_head_current_refuses_a_replacement_token_with_the_same_transport_identity() {
    let mut fixture = BlockHeadFixture::new(7);
    let token = fixture.submit();
    fixture.enqueue(token.identity(), b"original");
    let observed = fixture
        .block
        .observe_inbound_head(&fixture.freeze, &fixture.inbound(1), &token)
        .unwrap_or_else(|error| panic!("block head observation should succeed: {error}"))
        .unwrap_or_else(|| panic!("original inbound head should be present"));
    let mut outbound = outbound_ring(
        8,
        2,
        &fixture.outbound_header,
        &mut fixture.outbound_entries,
    );
    let replacement = fixture
        .block
        .submit_retry_request(
            &mut fixture.freeze,
            &fixture.slot,
            &mut outbound,
            70,
            &BlockRequest::read(0, 4),
            token.identity(),
        )
        .unwrap_or_else(|error| panic!("retry fixture should publish: {error}"))
        .into_token();

    assert_eq!(replacement.identity(), token.identity());
    // A fresh factual observation cannot resurrect the original token's head.
    assert!(
        fixture
            .block
            .observe_inbound_head(&fixture.freeze, &fixture.inbound(1), &replacement)
            .unwrap_or_else(|error| panic!("block head observation should succeed: {error}"))
            .is_some()
    );
    assert!(
        !fixture
            .block
            .inbound_head_current(
                &fixture.freeze,
                &fixture.inbound(1),
                &replacement,
                &observed
            )
            .unwrap_or_else(|error| panic!("block head observation should succeed: {error}"))
    );
    assert!(
        fixture
            .block
            .inbound_head_current(&fixture.freeze, &fixture.inbound(1), &token, &observed)
            .unwrap_or_else(|error| panic!("block head observation should succeed: {error}"))
    );
}

#[test]
fn block_head_validation_errors_preserve_the_request_and_physical_head() {
    let mut fixture = BlockHeadFixture::new(7);
    let token = fixture.submit();
    assert!(
        fixture
            .block
            .observe_inbound_head(&fixture.freeze, &fixture.inbound(1), &token)
            .unwrap_or_else(|error| panic!("block head observation should succeed: {error}"))
            .is_none()
    );
    fixture.enqueue(token.identity(), b"original");
    let foreign_freeze = PluginDeviceIoFreeze::new();

    assert!(matches!(
        fixture
            .block
            .observe_inbound_head(&foreign_freeze, &fixture.inbound(1), &token),
        Err(BlockIoError::DeviceIoFreeze { .. })
    ));
    let wrong_ring = BlockInboundRing::registered(
        10,
        1,
        BLOCK_IO_SLOT_U32,
        2,
        &fixture.inbound_header,
        &fixture.inbound_entries,
    );
    assert!(matches!(
        fixture
            .block
            .observe_inbound_head(&fixture.freeze, &wrong_ring, &token),
        Err(BlockIoError::WrongInboundRing { .. })
    ));
    fixture.inbound_entries[0] = frame(90, BLOCK_IO_SLOT_U32, token.request_id(), b"bad response");
    assert!(matches!(
        fixture
            .block
            .observe_inbound_head(&fixture.freeze, &fixture.inbound(1), &token),
        Err(BlockIoError::Wire { .. })
    ));

    assert_eq!(fixture.inbound_header.read_index(), 0);
    assert_eq!(fixture.freeze.pending_requests(), 1);
    assert_eq!(fixture.slot.snapshot().device_io_active, 1);
}

#[test]
fn block_head_refuses_staged_guest_delivery_and_asynchronous_transport_events() {
    let mut fixture = BlockHeadFixture::new(7);
    let token = fixture.submit();
    fixture.enqueue(token.identity(), b"original");
    let observed = fixture
        .block
        .observe_inbound_head(&fixture.freeze, &fixture.inbound(1), &token)
        .unwrap_or_else(|error| panic!("block head observation should succeed: {error}"))
        .unwrap_or_else(|| panic!("original inbound head should be present"));
    let response = BlockResponse::with_identity(
        BlockResponseStatus::DuplicateIgnored,
        token.identity(),
        Vec::new(),
    )
    .encode()
    .unwrap_or_else(|error| panic!("block head observation should succeed: {error}"));
    fixture.inbound_entries[0] = frame(90, BLOCK_IO_SLOT_U32, token.request_id(), &response);
    assert!(
        fixture
            .block
            .observe_inbound_head(&fixture.freeze, &fixture.inbound(1), &token)
            .unwrap_or_else(|error| panic!("block head observation should succeed: {error}"))
            .is_none()
    );

    fixture.inbound_entries[0] = identified_response(token.identity(), b"original");
    let mut completion = RecordingCompletion {
        responses: Vec::new(),
        fail_message: Some("guest delivery deferred"),
    };
    let inbound = BlockInboundRing::registered(
        9,
        1,
        BLOCK_IO_SLOT_U32,
        2,
        &fixture.inbound_header,
        &fixture.inbound_entries,
    );
    let token = match fixture.block.poll_response(
        &mut fixture.freeze,
        &fixture.slot,
        &inbound,
        &mut completion,
        90,
        token,
    ) {
        Ok(BlockPoll::Retry { token, .. }) => token,
        other => panic!("delivery failure should retain the token: {other:?}"),
    };

    assert!(
        fixture
            .block
            .observe_inbound_head(&fixture.freeze, &fixture.inbound(1), &token)
            .unwrap_or_else(|error| panic!("block head observation should succeed: {error}"))
            .is_none()
    );
    assert!(
        !fixture
            .block
            .inbound_head_current(&fixture.freeze, &fixture.inbound(1), &token, &observed)
            .unwrap_or_else(|error| panic!("block head observation should succeed: {error}"))
    );
    assert_eq!(fixture.inbound_header.read_index(), 0);
    assert_eq!(fixture.freeze.pending_requests(), 1);
}
