//! Block lifecycle, reset, latency, and delivery tests.

use super::test_support::*;
use super::*;
use crucible_shmem::{FrameEntry, KIND_VM, NodeSlot, RingHeader};

#[test]
fn device_read_then_write_then_read_through_lifecycle() {
    let mut dev = device(PAGE_SIZE * 2);
    let want0 = ok(dev.overlay().read(&ramp_base(PAGE_SIZE * 2), 0, 8));

    // Read at icount 0.
    ok(dev.submit(0, &BlockRequest::read(1, 0, 8)));
    let next = dev.core().next_exact_local_event();
    assert!(next.is_some());
    let limit = next.unwrap_or(0);
    assert_eq!(ok(dev.advance_to(limit)), 1);
    let r = ok(dev.next_response()).unwrap_or_else(|| panic!("expected response"));
    assert_eq!(r.status, BlockStatus::Ok);
    assert_eq!(r.data, want0);

    // Write, then a later read sees the overlay.
    ok(dev.submit(limit, &BlockRequest::write(2, 0, vec![0x77; 8])));
    let lim2 = dev.core().next_exact_local_event().unwrap_or(limit);
    ok(dev.advance_to(lim2));
    let _ = ok(dev.next_response());

    ok(dev.submit(lim2, &BlockRequest::read(3, 0, 8)));
    let lim3 = dev.core().next_exact_local_event().unwrap_or(lim2);
    ok(dev.advance_to(lim3));
    let r = ok(dev.next_response()).unwrap_or_else(|| panic!("expected response"));
    assert_eq!(r.data, vec![0x77; 8]);
}

#[test]
fn delivered_transport_reset_rewrites_later_completion_without_aliasing_identity() {
    let latency = BlockLatency::new(100, 100, 0, 0, 0);
    let mut dev = device_with_latency(PAGE_SIZE, latency);
    let trigger = BlockRequest::get_length(41).with_identity(BlockRequestIdentity::new(7, 41));
    let victim = BlockRequest::read(42, 0, 8).with_identity(BlockRequestIdentity::new(7, 42));
    let transition = ResolvedBlockControllerTransition {
        failure_result: BlockFaultResult::IoError,
        unadmitted: BlockTransitionUnadmitted::WaitForRecovery,
        queued: BlockTransitionPending::Fail,
        executing: BlockTransitionPending::RetryPreserveId,
        resolved: BlockTransitionResolved::Complete,
        completed_undelivered: BlockTransitionUndelivered::RetryNewId,
        controller_buffer: BlockTransitionState::Preserve,
        volatile_cache: BlockTransitionState::Preserve,
        request_ids: BlockTransportRequestIds::NewEpochFromZero,
        duplicate_history: BlockTransitionState::Lose,
        topology: BlockTransitionTopology::Preserve,
        recovery_nanos: 25,
    };
    let mut directive = ResolvedBlockFaultDirective::fault_free(&trigger, PAGE_SIZE as u64);
    directive.duplicate_completions = vec![ResolvedBlockDuplicateCompletion::Reset {
        gap_nanos: 10,
        transition,
    }];
    ok(dev.install_storage_fault_directive(trigger.identity(), directive));

    ok(dev.submit(0, &trigger));
    ok(dev.submit(0, &victim));
    assert_eq!(ok(dev.advance_to(100)), 3);

    let primary = ok(dev.next_response()).unwrap_or_else(|| panic!("trigger primary"));
    let reset = ok(dev.next_response()).unwrap_or_else(|| panic!("reset event"));
    let retried = ok(dev.next_response()).unwrap_or_else(|| panic!("victim disposition"));
    assert_eq!(primary.identity(), trigger.identity());
    assert_eq!(reset.status, BlockStatus::TransportReset);
    assert_eq!(reset.identity(), trigger.identity());
    assert_eq!(retried.status, BlockStatus::RetryNewId);
    assert_eq!(retried.identity(), victim.identity());
}

#[test]
fn transport_reset_commits_only_after_bounded_shmem_delivery() {
    let latency = BlockLatency::new(100, 100, 0, 0, 0);
    let mut dev = device_with_latency(PAGE_SIZE, latency);
    let trigger = BlockRequest::get_length(41).with_identity(BlockRequestIdentity::new(7, 41));
    let transition = ResolvedBlockControllerTransition {
        failure_result: BlockFaultResult::IoError,
        unadmitted: BlockTransitionUnadmitted::WaitForRecovery,
        queued: BlockTransitionPending::Fail,
        executing: BlockTransitionPending::RetryPreserveId,
        resolved: BlockTransitionResolved::Complete,
        completed_undelivered: BlockTransitionUndelivered::RetryNewId,
        controller_buffer: BlockTransitionState::Preserve,
        volatile_cache: BlockTransitionState::Preserve,
        request_ids: BlockTransportRequestIds::NewEpochFromZero,
        duplicate_history: BlockTransitionState::Lose,
        topology: BlockTransitionTopology::Preserve,
        recovery_nanos: 25,
    };
    let mut directive = ResolvedBlockFaultDirective::fault_free(&trigger, PAGE_SIZE as u64);
    directive.duplicate_completions = vec![ResolvedBlockDuplicateCompletion::Reset {
        gap_nanos: 10,
        transition,
    }];
    ok(dev.install_storage_fault_directive(trigger.identity(), directive));
    ok(dev.submit(0, &trigger));

    let outbox = RingHeader::new();
    let mut entries = vec![FrameEntry::default(); 1];
    let consumer = NodeSlot::new(KIND_VM);
    assert_eq!(
        ok(dev.advance_to_shmem(100, &outbox, &mut entries, &consumer)).delivered,
        1
    );
    assert_eq!(dev.storage_fault_state().transport_epoch(), Some(7));
    assert_eq!(dev.storage_fault_state().recovery_until_nanos(), None);

    let primary = ok(outbox.dequeue(&entries)).unwrap_or_else(|| panic!("primary response"));
    assert_eq!(
        ok(BlockResponse::decode(ok(primary.payload()))).status,
        BlockStatus::Ok
    );
    assert_eq!(
        ok(dev.advance_to_shmem(100, &outbox, &mut entries, &consumer)).delivered,
        1
    );
    assert_eq!(dev.storage_fault_state().transport_epoch(), Some(8));
    assert_eq!(
        dev.storage_fault_state().recovery_until_nanos(),
        Some((100_u64 << 8) + 25)
    );
    let reset = ok(outbox.dequeue(&entries)).unwrap_or_else(|| panic!("reset response"));
    assert_eq!(
        ok(BlockResponse::decode(ok(reset.payload()))).status,
        BlockStatus::TransportReset
    );
}

#[test]
fn asynchronous_controller_transition_advances_pristine_epoch_and_recovers() {
    let mut dev = device(PAGE_SIZE);
    let transition = ResolvedBlockControllerTransition {
        failure_result: BlockFaultResult::Offline,
        unadmitted: BlockTransitionUnadmitted::Reject,
        queued: BlockTransitionPending::Fail,
        executing: BlockTransitionPending::Fail,
        resolved: BlockTransitionResolved::Fail,
        completed_undelivered: BlockTransitionUndelivered::Fail,
        controller_buffer: BlockTransitionState::Lose,
        volatile_cache: BlockTransitionState::Lose,
        request_ids: BlockTransportRequestIds::NewEpochFromZero,
        duplicate_history: BlockTransitionState::Lose,
        topology: BlockTransitionTopology::ReenumerateDeclared,
        recovery_nanos: 25,
    };

    ok(dev.apply_storage_controller_transition(&transition, 100));
    assert_eq!(dev.storage_fault_state().transport_epoch(), Some(1));
    assert_eq!(dev.storage_fault_state().recovery_until_nanos(), Some(125));

    let request = BlockRequest::get_length(9).with_identity(BlockRequestIdentity::new(1, 9));
    let directive = ResolvedBlockFaultDirective::fault_free(&request, PAGE_SIZE as u64);
    ok(dev.install_storage_fault_directive(request.identity(), directive));
    ok(dev.submit(1, &request));
    let deadline = dev.core().next_exact_local_event().unwrap_or(1);
    ok(dev.advance_to(deadline));
    let response = ok(dev.next_response()).unwrap_or_else(|| panic!("post-reset response"));
    assert_eq!(response.status, BlockStatus::Ok);
    assert_eq!(dev.storage_fault_state().recovery_until_nanos(), None);
}

#[test]
fn queued_old_epoch_frames_receive_every_reset_disposition_after_backpressure() {
    let cases = [
        (BlockTransitionPending::Fail, BlockStatus::Error),
        (BlockTransitionPending::RetryNewId, BlockStatus::RetryNewId),
        (
            BlockTransitionPending::RetryPreserveId,
            BlockStatus::RetryPreserveId,
        ),
    ];

    for (queued, expected_status) in cases {
        let latency = BlockLatency::new(100, 100, 0, 0, 0);
        let mut dev = device_with_latency(PAGE_SIZE, latency);
        let trigger = BlockRequest::get_length(41).with_identity(BlockRequestIdentity::new(7, 41));
        let victim = BlockRequest::read(42, 0, 8).with_identity(BlockRequestIdentity::new(7, 42));
        let transition = ResolvedBlockControllerTransition {
            failure_result: BlockFaultResult::IoError,
            unadmitted: BlockTransitionUnadmitted::WaitForRecovery,
            queued,
            executing: BlockTransitionPending::Fail,
            resolved: BlockTransitionResolved::Complete,
            completed_undelivered: BlockTransitionUndelivered::Complete,
            controller_buffer: BlockTransitionState::Preserve,
            volatile_cache: BlockTransitionState::Preserve,
            request_ids: BlockTransportRequestIds::NewEpochFromZero,
            duplicate_history: BlockTransitionState::Preserve,
            topology: BlockTransitionTopology::Preserve,
            recovery_nanos: 25,
        };
        let mut directive = ResolvedBlockFaultDirective::fault_free(&trigger, PAGE_SIZE as u64);
        directive.duplicate_completions = vec![ResolvedBlockDuplicateCompletion::Reset {
            gap_nanos: 10,
            transition,
        }];
        ok(dev.install_storage_fault_directive(trigger.identity(), directive));
        ok(dev.submit(0, &trigger));

        let inbox = RingHeader::new();
        let mut inbox_entries = vec![FrameEntry::default(); 2];
        let victim_frame = ok(FrameEntry::new(
            0,
            0,
            victim.request_id,
            &ok(victim.encode()),
        ));
        ok(inbox.enqueue(&mut inbox_entries, &victim_frame));
        let producer = NodeSlot::new(KIND_VM);
        let outbox = RingHeader::new();
        let mut outbox_entries = vec![FrameEntry::default(); 1];
        let consumer = NodeSlot::new(KIND_VM);

        assert_eq!(
            ok(dev.advance_to_shmem(100, &outbox, &mut outbox_entries, &consumer)).delivered,
            1
        );
        assert_eq!(dev.storage_fault_state().transport_epoch(), Some(7));
        assert_eq!(ok(inbox.live_len(&inbox_entries)), 1);
        let primary = ok(outbox.dequeue(&outbox_entries))
            .unwrap_or_else(|| panic!("trigger primary response"));
        assert_eq!(
            ok(BlockResponse::decode(ok(primary.payload()))).status,
            BlockStatus::Ok
        );

        assert_eq!(
            ok(dev.advance_to_shmem(100, &outbox, &mut outbox_entries, &consumer)).delivered,
            1
        );
        assert_eq!(dev.storage_fault_state().transport_epoch(), Some(8));
        assert_eq!(ok(inbox.live_len(&inbox_entries)), 1);
        let reset = ok(outbox.dequeue(&outbox_entries))
            .unwrap_or_else(|| panic!("transport reset response"));
        assert_eq!(
            ok(BlockResponse::decode(ok(reset.payload()))).status,
            BlockStatus::TransportReset
        );

        let victim_directive = ResolvedBlockFaultDirective::fault_free(&victim, PAGE_SIZE as u64);
        ok(dev.install_storage_fault_directive(victim.identity(), victim_directive));
        assert_eq!(
            ok(dev.process_one_shmem_request(&inbox, &inbox_entries, &producer)).processed,
            1
        );
        assert_eq!(
            ok(dev.advance_to_shmem(100, &outbox, &mut outbox_entries, &consumer)).delivered,
            1
        );
        let disposition = ok(outbox.dequeue(&outbox_entries))
            .unwrap_or_else(|| panic!("queued request disposition"));
        let disposition = ok(BlockResponse::decode(ok(disposition.payload())));
        assert_eq!(disposition.identity(), victim.identity());
        assert_eq!(disposition.status, expected_status);

        if queued == BlockTransitionPending::RetryPreserveId {
            let retry_frame = ok(FrameEntry::new(
                101,
                0,
                victim.request_id,
                &ok(victim.encode()),
            ));
            ok(inbox.enqueue(&mut inbox_entries, &retry_frame));
            let retry_directive =
                ResolvedBlockFaultDirective::fault_free(&victim, PAGE_SIZE as u64);
            ok(dev.install_storage_fault_directive(victim.identity(), retry_directive));
            assert_eq!(
                ok(dev.process_one_shmem_request(&inbox, &inbox_entries, &producer)).processed,
                1
            );
            assert_eq!(
                ok(dev.advance_to_shmem(102, &outbox, &mut outbox_entries, &consumer)).delivered,
                1
            );
            let completion = ok(outbox.dequeue(&outbox_entries))
                .unwrap_or_else(|| panic!("preserved retry completion"));
            let completion = ok(BlockResponse::decode(ok(completion.payload())));
            assert_eq!(completion.identity(), victim.identity());
            assert_eq!(completion.status, BlockStatus::Ok);
        }
    }
}

#[test]
fn device_get_length_returns_base_size() {
    let mut dev = device(12345);
    ok(dev.submit(0, &BlockRequest::get_length(1)));
    let lim = dev.core().next_exact_local_event().unwrap_or(0);
    ok(dev.advance_to(lim));
    let r = ok(dev.next_response()).unwrap_or_else(|| panic!("expected response"));
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&r.data[..8]);
    assert_eq!(u64::from_le_bytes(bytes), 12345);
}

#[test]
fn device_out_of_range_read_returns_error_status() {
    let mut dev = device(PAGE_SIZE);
    ok(dev.submit(0, &BlockRequest::read(1, PAGE_SIZE as u64, 1)));
    let lim = dev.core().next_exact_local_event().unwrap_or(0);
    ok(dev.advance_to(lim));
    let r = ok(dev.next_response()).unwrap_or_else(|| panic!("expected response"));
    assert_eq!(r.status, BlockStatus::Error);
}

// ---- completion model: host-timing independence (IO-10,22) ----

#[test]
fn latency_depends_only_on_op_and_count() {
    let lat = BlockLatency::new(1000, 1500, 500, 100, 2);
    assert_eq!(lat.latency_for(BlockOp::Read, 0), 1000);
    assert_eq!(lat.latency_for(BlockOp::Read, 10), 1020);
    assert_eq!(lat.latency_for(BlockOp::Write, 10), 1520);
    assert_eq!(lat.latency_for(BlockOp::Flush, 999), 500);
    assert_eq!(lat.latency_for(BlockOp::GetLength, 999), 100);
    // Ordinary large count stays exact (no overflow at these magnitudes).
    assert_eq!(
        lat.latency_for(BlockOp::Read, u32::MAX),
        1000 + 2 * u64::from(u32::MAX)
    );
    // Saturating: a hostile per-byte parameter cannot overflow.
    let huge = BlockLatency::new(1000, 1500, 500, 100, u64::MAX);
    assert_eq!(huge.latency_for(BlockOp::Read, u32::MAX), u64::MAX);
}
