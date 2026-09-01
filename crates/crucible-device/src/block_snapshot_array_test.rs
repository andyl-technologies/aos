//! Block snapshot, restore, and storage-array tests.

use super::test_support::*;
use super::*;
#[test]
fn completion_is_host_timing_independent() {
    let a = run_sequence(0);
    let b = run_sequence(500_000);
    assert_eq!(a, b, "host COMPUTE skew leaked into delivery/payload");
}

// ---- coincident completion ordering (IO-10) ----

#[test]
fn coincident_completions_deliver_in_total_order() {
    // Two reads submitted at the same icount with identical latency land on
    // the same delivery_icount; they must deliver in (icount, src, seq) order.
    let mut dev = device(PAGE_SIZE);
    ok(dev.submit(0, &BlockRequest::read(10, 0, 8)));
    ok(dev.submit(0, &BlockRequest::read(11, 8, 8)));
    let lim = dev.core().next_exact_local_event().unwrap_or(0);
    ok(dev.advance_to(lim));
    let first = ok(dev.next_response()).unwrap_or_else(|| panic!("resp"));
    let second = ok(dev.next_response()).unwrap_or_else(|| panic!("resp"));
    // seq increases with submit order, so request_id 10 delivers before 11.
    assert_eq!(first.request_id, 10);
    assert_eq!(second.request_id, 11);
}

// ---- snapshot / restore round-trip (IO-11,23) ----

#[test]
fn snapshot_excludes_base_and_restore_round_trips() {
    let mut dev = device(PAGE_SIZE * 3);
    ok(dev.submit(0, &BlockRequest::write(1, 50, vec![0x42; 20])));
    let lim = dev.core().next_exact_local_event().unwrap_or(0);
    ok(dev.advance_to(lim));
    let _ = ok(dev.next_response());

    let snap = dev.snapshot();
    assert_eq!(snap.delta_page_count(), 1);
    assert_eq!(snap.base_hash, dev.base_hash());

    // Restore from the self-contained snapshot (no parent chain).
    let base = ramp_base(PAGE_SIZE * 3);
    let restored = ok(BlockDevice::restore(&snap, base, None));
    // Identical subsequent behavior: read the written range back.
    let got = ok(restored.overlay().read(restored.base(), 50, 20));
    assert_eq!(got, vec![0x42; 20]);
}

#[test]
fn snapshot_mutate_restore_yields_identical_behavior() {
    let base_len = PAGE_SIZE * 3;
    let mut dev = device(base_len);
    ok(dev.submit(0, &BlockRequest::write(1, 50, vec![0x42; 20])));
    let lim = dev.core().next_exact_local_event().unwrap_or(0);
    ok(dev.advance_to(lim));
    let _ = ok(dev.next_response());

    let snap = dev.snapshot();
    let baseline_image = dev.materialize();

    // Mutate after snapshot.
    ok(dev.submit(lim, &BlockRequest::write(2, 50, vec![0x99; 20])));
    let lim2 = dev.core().next_exact_local_event().unwrap_or(lim);
    ok(dev.advance_to(lim2));
    let _ = ok(dev.next_response());
    assert_ne!(
        dev.materialize(),
        baseline_image,
        "mutation must take effect"
    );

    // Restore: behavior returns to the snapshot point.
    let restored = ok(BlockDevice::restore(&snap, ramp_base(base_len), None));
    assert_eq!(restored.materialize(), baseline_image);
}

#[test]
fn restore_rejects_mismatched_base() {
    let mut dev = device(PAGE_SIZE);
    ok(dev.submit(0, &BlockRequest::write(1, 0, vec![1; 4])));
    let lim = dev.core().next_exact_local_event().unwrap_or(0);
    ok(dev.advance_to(lim));
    let _ = ok(dev.next_response());
    let snap = dev.snapshot();
    // A different base has a different hash.
    let wrong = BaseImage::new(vec![0xFF; PAGE_SIZE]);
    assert!(matches!(
        BlockDevice::restore(&snap, wrong, None),
        Err(crate::error::DeviceError::BaseMismatch { .. })
    ));
}

#[test]
fn snapshot_restore_preserves_inflight_responses() {
    let mut dev = device(PAGE_SIZE);
    // Submit but do not advance: the response stays in flight.
    ok(dev.submit(0, &BlockRequest::read(1, 0, 16)));
    assert_eq!(dev.core().inflight_len(), 1);
    let snap = dev.snapshot();
    assert_eq!(snap.inflight().len(), 1);

    let restored = ok(BlockDevice::restore(&snap, ramp_base(PAGE_SIZE), None));
    assert_eq!(restored.core().inflight_len(), 1);
    assert_eq!(
        restored.core().next_exact_local_event(),
        dev.core().next_exact_local_event()
    );
}

// ---- run-twice determinism (IO-22) ----

#[test]
fn run_twice_is_byte_identical() {
    let first = run_sequence(0);
    let second = run_sequence(0);
    assert_eq!(first, second);
}

#[test]
fn delta_pages_are_blake3_keyed() {
    let base = ramp_base(PAGE_SIZE * 2);
    let mut overlay = CowOverlay::new();
    ok(overlay.write(&base, 0, &[0xAB; 16]));
    let delta = overlay.dirty_delta();
    let hashes = delta.page_hashes();
    assert_eq!(hashes.len(), 1);
    // Hash is content-derived: same page bytes => same hash.
    let again = delta.page_hashes();
    assert_eq!(hashes, again);
}

// ---- regression: MAJOR #1 -- snapshot/restore preserves dirty set ----

#[test]
fn regression_restore_preserves_mid_epoch_dirty_set() {
    // Write a page WITHOUT crossing a checkpoint boundary: it stays dirty,
    // so a mid-epoch snapshot must capture and a restore must reinstate the
    // dirty bookkeeping ([IO-7], [IO-11]). Before the fix, restore reset the
    // dirty set empty and the next snapshot's delta was incomplete.
    let mut dev = device(PAGE_SIZE * 2);
    ok(dev.submit(0, &BlockRequest::write(1, 0, vec![0xCD; 16])));
    let lim = dev.core().next_exact_local_event().unwrap_or(0);
    ok(dev.advance_to(lim));
    let _ = ok(dev.next_response());

    let snap = dev.snapshot();
    assert_eq!(snap.delta_page_count(), 1, "page dirtied since boundary");

    // Restore (self-contained), then snapshot again: the delta must STILL be
    // 1 -- the dirty page survived the round-trip.
    let restored = ok(BlockDevice::restore(&snap, ramp_base(PAGE_SIZE * 2), None));
    let resnap = restored.snapshot();
    assert_eq!(
        resnap.delta_page_count(),
        1,
        "restore must preserve the mid-epoch dirty set"
    );
    assert_eq!(resnap.dirty, snap.dirty);

    // And the parent-chain restore path preserves it too.
    let parent = CowOverlay::new();
    let restored_p = ok(BlockDevice::restore(
        &snap,
        ramp_base(PAGE_SIZE * 2),
        Some(&parent),
    ));
    assert_eq!(restored_p.snapshot().delta_page_count(), 1);
}

// ---- regression: MAJOR #2 -- restore preserves the latency model ----

#[test]
fn regression_restore_preserves_latency_so_delivery_icount_matches() {
    // A device with a non-default latency base must, after plain restore,
    // schedule the next completion at the SAME delivery_icount as the
    // original. Before the fix, restore substituted BlockLatency::default(),
    // changing every post-restore completion icount.
    let latency = BlockLatency::new(9000, 9000, 9000, 9000, 0);
    let mut dev = device_with_latency(PAGE_SIZE, latency);
    // Take a clean snapshot before any request.
    let snap = dev.snapshot();

    // Original: submit a read, observe the next exact local event.
    ok(dev.submit(0, &BlockRequest::read(1, 0, 16)));
    let original_event = dev.core().next_exact_local_event();

    // Restored: same request, must yield the same delivery_icount.
    let mut restored = ok(BlockDevice::restore(&snap, ramp_base(PAGE_SIZE), None));
    ok(restored.submit(0, &BlockRequest::read(1, 0, 16)));
    let restored_event = restored.core().next_exact_local_event();

    assert_eq!(
        original_event, restored_event,
        "restore must not change the completion model"
    );
    // Sanity: with base 9000 at shift 8 the event is ceil(9000/256) = 36, not
    // the default model's value.
    assert_eq!(restored_event, Some(36));
}

// ---- regression: MAJOR #3 -- oversized read rejected, not un-transportable ----

#[test]
fn regression_read_over_frame_cap_returns_error_status() {
    use crate::block::device::MAX_READ_BYTES;
    // A base large enough to satisfy the in-range check at the cap.
    let big = MAX_READ_BYTES + PAGE_SIZE;
    let mut dev = device(big);

    // Exactly at the cap: served OK (payload + header fits one frame).
    ok(dev.submit(0, &BlockRequest::read(1, 0, MAX_READ_BYTES as u32)));
    let lim = dev.core().next_exact_local_event().unwrap_or(0);
    ok(dev.advance_to(lim));
    let r = ok(dev.next_response()).unwrap_or_else(|| panic!("resp"));
    assert_eq!(r.status, BlockStatus::Ok);
    assert_eq!(r.data.len(), MAX_READ_BYTES);
    // The encoded response fits one frame.
    assert!(ok(r.encode()).len() <= crucible_shmem::MAX_FRAME_DATA);

    // One byte over the cap: rejected with an error status, never emitting an
    // un-transportable frame ([IO-8]).
    ok(dev.submit(lim, &BlockRequest::read(2, 0, MAX_READ_BYTES as u32 + 1)));
    let lim2 = dev.core().next_exact_local_event().unwrap_or(lim);
    ok(dev.advance_to(lim2));
    let r2 = ok(dev.next_response()).unwrap_or_else(|| panic!("resp"));
    assert_eq!(r2.status, BlockStatus::Error);
}

#[test]
fn array_dirty_ranges_coalesce_and_survive_checkpoint_restore() {
    let mut dev = device(PAGE_SIZE * 2);
    ok(dev.record_storage_array_dirty_range(1, 512, vec![0; 512], 20));
    ok(dev.record_storage_array_dirty_range(1, 1024, vec![0; 512], 30));
    ok(dev.record_storage_array_dirty_range(2, 0, vec![0; 512], 40));
    assert_eq!(
        dev.storage_fault_state().array_dirty_ranges(),
        vec![
            BlockArrayDirtyRange {
                member_ordinal: 1,
                start_byte: 512,
                bytes: vec![0; 1024],
                generation: 1,
                dirty_nanos: 20,
            },
            BlockArrayDirtyRange {
                member_ordinal: 2,
                start_byte: 0,
                bytes: vec![0; 512],
                generation: 2,
                dirty_nanos: 40,
            },
        ]
    );
    assert_eq!(
        dev.storage_fault_state()
            .array_rebuild_cursor()
            .next_sequence,
        3
    );

    let snapshot = dev.snapshot();
    let restored = ok(BlockDevice::restore(
        &snapshot,
        ramp_base(PAGE_SIZE * 2),
        None,
    ));
    assert_eq!(
        restored.storage_fault_state().array_dirty_ranges(),
        dev.storage_fault_state().array_dirty_ranges()
    );
    assert_eq!(
        restored.storage_fault_state().array_rebuild_cursor(),
        dev.storage_fault_state().array_rebuild_cursor()
    );
}

#[test]
fn array_rebuild_is_rate_scheduled_authenticated_and_retryable() {
    let mut dev = device(PAGE_SIZE * 2);
    ok(dev.record_storage_array_dirty_range(1, 512, vec![7; 1024], 20));

    assert_eq!(
        ok(dev.next_storage_array_rebuild_opportunity(100, 512, 512, None)),
        None
    );
    assert_eq!(
        dev.storage_fault_state()
            .array_rebuild_cursor()
            .next_ready_nanos,
        Some(1_000_000_100)
    );
    let opportunity = ok(dev.next_storage_array_rebuild_opportunity(1_000_000_100, 512, 512, None))
        .unwrap_or_else(|| panic!("scheduled rebuild must be ready at its deadline"));
    assert_eq!(opportunity.start_byte, 512);
    assert_eq!(opportunity.bytes, vec![7; 512]);

    ok(dev.defer_storage_array_rebuild(&opportunity));
    assert_eq!(dev.next_exact_local_event(), None);
    assert_eq!(
        ok(dev.next_storage_array_rebuild_opportunity(1_000_000_100, 512, 512, None,)),
        None
    );
    let retry = ok(dev.next_storage_array_rebuild_opportunity(2_000_000_100, 512, 512, None))
        .unwrap_or_else(|| panic!("failed rebuild must become retryable after another service"));
    assert_ne!(retry.sequence, opportunity.sequence);
    ok(dev.complete_storage_array_rebuild(&retry));
    assert_eq!(
        dev.storage_fault_state().array_dirty_ranges(),
        vec![BlockArrayDirtyRange {
            member_ordinal: 1,
            start_byte: 1024,
            bytes: vec![7; 512],
            generation: 0,
            dirty_nanos: 20,
        }]
    );

    let snapshot = dev.snapshot();
    let restored = ok(BlockDevice::restore(
        &snapshot,
        ramp_base(PAGE_SIZE * 2),
        None,
    ));
    assert_eq!(
        restored.storage_fault_state().array_dirty_ranges(),
        dev.storage_fault_state().array_dirty_ranges()
    );
    assert_eq!(
        restored.storage_fault_state().array_rebuild_cursor(),
        dev.storage_fault_state().array_rebuild_cursor()
    );
}

#[test]
fn external_array_discard_and_flush_mutate_real_member_state() {
    let mut dev = device(PAGE_SIZE);
    let mut config = BlockDurabilityConfig::write_through(PAGE_SIZE as u64);
    config.discard_granularity_bytes = 512;
    ok(dev.configure_storage_faults(config, false));
    let discard = BlockRequest::discard(7, 0, 512);
    let replacement = ok(dev.storage_array_discard_replacement(&discard))
        .unwrap_or_else(|| panic!("zeroing discard must return replacement bytes"));
    assert_eq!(replacement, vec![0; 512]);
    ok(dev.apply_storage_external_mutation(1, 10, discard));
    assert_eq!(ok(dev.inspect_storage_visible(0, 512)), vec![0; 512]);

    let before = dev.storage_fault_state().actual_durable_frontier();
    let (durability, frontier) =
        ok(dev.apply_storage_external_mutation(2, 20, BlockRequest::flush(8)));
    assert_eq!(durability, BlockCompletionDurability::Durable);
    assert!(frontier >= before);
    assert!(dev.storage_fault_state().actual_durable_frontier() >= frontier);
}
