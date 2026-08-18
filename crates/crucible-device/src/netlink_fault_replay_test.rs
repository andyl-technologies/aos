//! Network-link corruption, replay, and checkpoint tests.

use super::test_support::*;
use super::*;
use crate::DeviceError;

#[test]
fn corrupt_flips_exactly_the_seeded_bits() {
    let mut faults = LinkFaults::none();
    faults.corrupt = Probability::ALWAYS;
    faults.corruption_strategies = vec![LinkCorruptionStrategy::BitFlip { max_bits: 2 }];
    let mut l = link(faults);
    let draws = FrameDraws {
        corrupt_bits: vec![0, 8], // bit 0 of byte 0, bit 0 of byte 1
        ..FrameDraws::default()
    };
    let out = ok(l.emit(
        &frame(vec![0, 0, 0, 0]),
        &draws,
        PastDeliveryPolicy::FailLoud,
    ));
    assert_eq!(out.deliveries[0].payload, vec![0b1, 0b1, 0, 0]);
    // Not-firing corrupt leaves the payload intact.
    let mut faults2 = LinkFaults::none();
    faults2.corrupt = Probability::new(1, 100);
    faults2.corruption_strategies = vec![LinkCorruptionStrategy::BitFlip { max_bits: 2 }];
    let mut l2 = link(faults2);
    let out2 = ok(l2.emit(
        &frame(vec![0; 4]),
        &FrameDraws {
            corrupt: 50,
            corrupt_bits: vec![0, 8],
            ..FrameDraws::default()
        },
        PastDeliveryPolicy::FailLoud,
    ));
    assert_eq!(out2.deliveries[0].payload, vec![0; 4]);
}

#[test]
fn corruption_strategies_use_seeded_selectors() {
    let mut faults = LinkFaults::none();
    faults.corrupt = Probability::ALWAYS;
    faults.corruption_strategies = vec![
        LinkCorruptionStrategy::FieldMutation,
        LinkCorruptionStrategy::Truncation { max_bytes: 3 },
    ];

    let mut first = link(faults.clone());
    let first_out = ok(first.emit(
        &frame(vec![0, 0, 0, 0, 0]),
        &FrameDraws {
            corrupt_bits: vec![1, 0],
            ..FrameDraws::default()
        },
        PastDeliveryPolicy::FailLoud,
    ));
    assert_eq!(first_out.deliveries[0].payload, vec![0, 0x80, 0, 0]);

    let mut second = link(faults);
    let second_out = ok(second.emit(
        &frame(vec![0, 0, 0, 0, 0]),
        &FrameDraws {
            corrupt_bits: vec![3, 2],
            ..FrameDraws::default()
        },
        PastDeliveryPolicy::FailLoud,
    ));
    assert_eq!(
        second_out.deliveries[0].payload,
        vec![0, 0],
        "different selectors mutate a different byte and choose a different truncation length"
    );
}

// ---- into-the-past: fail-loud (IO-34) ----

#[test]
fn reorder_into_consumer_past_fails_loud() {
    // Advance the consumer frontier past where a small-latency frame would land.
    let mut faults = LinkFaults::none();
    faults.reorder_window_ns = 0;
    let mut l = link(faults);
    // Move the frontier to icount 50.
    let _ = ok(l.advance_to(50));
    // A frame emitted at icount 0 with base 10 icounts would deliver at 10 --
    // already in the past relative to frontier 50. Fail loud, do not deliver.
    let res = l.emit(
        &frame(vec![0; 4]),
        &FrameDraws::default(),
        PastDeliveryPolicy::FailLoud,
    );
    assert!(matches!(
        res,
        Err(DeviceError::DeliveryReorderedIntoPast { .. })
    ));
    assert_eq!(
        l.inflight_len(),
        0,
        "no delivery may be enqueued on fail-loud"
    );
}

// ---- into-the-past: clamp policy (IO-34) ----

#[test]
fn reorder_into_consumer_past_clamps_to_future() {
    let mut l = link(LinkFaults::none());
    let _ = ok(l.advance_to(50));
    let out = ok(l.emit(
        &frame(vec![0; 4]),
        &FrameDraws::default(),
        PastDeliveryPolicy::ClampToFuture,
    ));
    // Clamped to frontier + 1 = 51 (a deliverable future), never delivered late.
    assert_eq!(out.deliveries.len(), 1);
    assert_eq!(out.deliveries[0].delivery_icount(), 51);
    assert!(out.deliveries[0].delivery_icount() > l.current_icount());
}

#[test]
fn clamp_preserves_duplicate_gap_when_both_land_in_past() {
    // MINOR fix: under ClampToFuture, if both the primary and the duplicate
    // land in the consumer's past, the duplicate must keep its gap rather than
    // collapsing onto frontier+1 with the primary.
    let mut faults = LinkFaults::none();
    faults.duplicate = Probability::ALWAYS;
    faults.duplicate_gap_ns = 2_560; // +10 icounts at shift 8
    let mut l = link(faults);
    let _ = ok(l.advance_to(50));
    let out = ok(l.emit(
        &frame(vec![0; 4]),
        &FrameDraws::default(),
        PastDeliveryPolicy::ClampToFuture,
    ));
    assert_eq!(out.deliveries.len(), 2);
    let primary = out.deliveries[0].delivery_icount();
    let dup = out.deliveries[1].delivery_icount();
    // Primary clamps to frontier+1 = 51; the duplicate keeps the 10-icount gap.
    assert_eq!(primary, 51);
    assert_eq!(dup, 61, "duplicate gap collapsed under clamp");
    assert!(
        dup > primary,
        "duplicate must stay strictly after the primary"
    );
    // Both are strictly in the consumer's future.
    assert!(primary > l.current_icount() && dup > l.current_icount());
}

// ---- effective-latency-change raises the recompute signal (IO-33) ----

#[test]
fn effective_latency_change_raises_recompute_signal() {
    let mut l = link(LinkFaults::none());
    assert!(!l.lookahead_recompute_pending());
    // Raise the latency: signal must be set.
    let mut raised = LinkFaults::none();
    raised.added_latency_ns = 5_000;
    l.set_faults(raised.clone());
    assert!(l.lookahead_recompute_pending());
    // take_* returns it once then clears.
    assert!(l.take_lookahead_recompute());
    assert!(!l.take_lookahead_recompute());

    // A loss-only change does NOT affect latency and raises no signal.
    let mut loss_only = raised;
    loss_only.loss = Probability::ALWAYS;
    l.set_faults(loss_only);
    assert!(
        !l.lookahead_recompute_pending(),
        "loss change must not request recompute"
    );
}

// ---- REGRESSION: recompute tracks the conservative lookahead bound ----

#[test]
fn regression_recompute_tracks_minimum_latency_not_delivery_profile() {
    // The scheduler consumes NetLink::effective_latency_ns(), the conservative
    // minimum edge latency. Jitter/reorder/bandwidth can push individual
    // frames later, but their minimum additional delay is zero, so they do not
    // change the scalar lookahead edge and must not raise this signal.

    // A named mutation of one fault-table field, for the table-driven cases.
    type FieldMutation = (&'static str, fn(&mut LinkFaults));

    let mut l = link(LinkFaults::none());
    let mut faults = LinkFaults::none();
    faults.added_latency_ns = 5_000;
    l.set_faults(faults.clone());
    assert!(
        l.take_lookahead_recompute(),
        "added_latency_ns changes the conservative lookahead bound"
    );
    // Re-setting the SAME table is a no-op: no spurious recompute.
    l.set_faults(faults);
    assert!(
        !l.take_lookahead_recompute(),
        "unchanged added latency must not raise the signal"
    );

    // A change to each non-bound field, in isolation, does NOT raise it.
    let non_bound_changes: [FieldMutation; 8] = [
        ("partitioned", |f| f.partitioned = true),
        ("jitter_window_ns", |f| f.jitter_window_ns = 100_000),
        ("reorder_window_ns", |f| f.reorder_window_ns = 100_000),
        ("bandwidth_bits_per_sec", |f| {
            f.bandwidth_bits_per_sec = vec![8_000]
        }),
        ("loss", |f| f.loss = Probability::ALWAYS),
        ("duplicate", |f| f.duplicate = Probability::ALWAYS),
        ("duplicate_gap_ns", |f| f.duplicate_gap_ns = 9_999),
        ("corrupt", |f| {
            f.corrupt = Probability::ALWAYS;
            f.corruption_strategies = vec![LinkCorruptionStrategy::BitFlip { max_bits: 3 }];
        }),
    ];
    for (name, mutate) in non_bound_changes {
        let mut l = link(LinkFaults::none());
        let mut faults = LinkFaults::none();
        mutate(&mut faults);
        l.set_faults(faults);
        assert!(
            !l.take_lookahead_recompute(),
            "{name} change must NOT raise the lookahead-recompute signal"
        );
    }
}

// ---- snapshot / restore round-trip (IO-23) ----

#[test]
fn snapshot_restore_round_trips() {
    let mut faults = LinkFaults::none();
    faults.added_latency_ns = 1_000;
    faults.duplicate = Probability::ALWAYS;
    faults.duplicate_gap_ns = 256;
    let mut l = link(faults);
    // Leave a frame in flight (do not advance to delivery).
    ok(l.emit(
        &frame(vec![9; 4]),
        &FrameDraws::default(),
        PastDeliveryPolicy::FailLoud,
    ));
    assert!(l.inflight_len() >= 1);

    let snap = l.snapshot();
    let restored = ok(NetLink::restore(&snap));
    assert_eq!(restored, l, "restore must be byte-identical");
    assert_eq!(restored.inflight_len(), l.inflight_len());
    assert_eq!(
        restored.next_exact_local_event(),
        l.next_exact_local_event()
    );
    assert_eq!(restored.rng_position(), l.rng_position());
}

#[test]
fn restore_rejects_corrupt_subfloor_snapshot() {
    let l = link(LinkFaults::none());
    let mut snap = l.snapshot();
    snap.floor_ns = BASE_NS + 1; // base now below floor
    assert!(matches!(
        NetLink::restore(&snap),
        Err(DeviceError::LinkLatencyBelowFloor { .. })
    ));
}

// ---- run-twice determinism, byte-identical (IO-22) ----

/// Drives a fixed frame+draw sequence through a fresh link and returns the
/// (delivery_icount, frame_id, payload) of every delivery in order.
fn run_sequence() -> Vec<(u64, u32, Vec<u8>)> {
    let mut faults = LinkFaults::none();
    faults.jitter_window_ns = 1_024;
    faults.reorder_window_ns = 2_048;
    faults.duplicate = Probability::new(1, 2);
    faults.duplicate_gap_ns = 512;
    faults.corrupt = Probability::new(1, 2);
    faults.corruption_strategies = vec![LinkCorruptionStrategy::BitFlip { max_bits: 1 }];
    let mut l = link(faults);

    let frames = [
        (
            Frame::new(0, 10, vec![1, 2, 3, 4]),
            FrameDraws {
                jitter: 300,
                reorder: 700,
                loss: 5,
                additional_loss: Vec::new(),
                duplicate: 0,
                corrupt: 0,
                corrupt_bits: vec![3],
            },
        ),
        (
            Frame::new(0, 11, vec![5, 6, 7, 8]),
            FrameDraws {
                jitter: 100,
                reorder: 50,
                loss: 9,
                additional_loss: Vec::new(),
                duplicate: 1,
                corrupt: 1,
                corrupt_bits: vec![17],
            },
        ),
        (
            Frame::new(1, 12, vec![9, 9, 9, 9]),
            FrameDraws {
                jitter: 1000,
                reorder: 0,
                loss: 1,
                additional_loss: Vec::new(),
                duplicate: 1,
                corrupt: 0,
                corrupt_bits: vec![0],
            },
        ),
    ];
    for (f, d) in &frames {
        ok(l.emit(f, d, PastDeliveryPolicy::ClampToFuture));
    }
    let due = ok(l.advance_to(100_000));
    due.into_iter()
        .map(|d| (d.delivery_icount(), d.frame_id, d.payload))
        .collect()
}

#[test]
fn run_twice_with_same_draws_is_byte_identical() {
    let a = run_sequence();
    let b = run_sequence();
    assert_eq!(
        a, b,
        "same draws + same frames must yield identical deliveries"
    );
    // The sequence is non-trivial: it produced deliveries.
    assert!(!a.is_empty());
}

// ---- streaming next_delivery one-at-a-time ----

#[test]
fn next_delivery_yields_one_coincident_frame_per_call() {
    let mut l = link(LinkFaults::none());
    // Two frames at the same emit icount with no faults => same delivery icount.
    ok(l.emit(
        &Frame::new(0, 1, vec![0; 4]),
        &FrameDraws::default(),
        PastDeliveryPolicy::FailLoud,
    ));
    ok(l.emit(
        &Frame::new(0, 2, vec![0; 4]),
        &FrameDraws::default(),
        PastDeliveryPolicy::FailLoud,
    ));
    let first = l
        .next_delivery(10)
        .unwrap_or_else(|| panic!("expected a delivery"));
    let second = l
        .next_delivery(10)
        .unwrap_or_else(|| panic!("expected a delivery"));
    // Tie-break by seq: frame 1 before frame 2.
    assert_eq!(first.frame_id, 1);
    assert_eq!(second.frame_id, 2);
    assert!(l.next_delivery(10).is_none());
}

#[test]
fn drop_inflight_returns_complete_delivery_evidence() {
    let mut l = link(LinkFaults::none());
    ok(l.emit(
        &Frame::new(0, 11, vec![1, 2, 3]),
        &FrameDraws::default(),
        PastDeliveryPolicy::FailLoud,
    ));
    ok(l.emit(
        &Frame::new(1, 12, vec![4, 5]),
        &FrameDraws::default(),
        PastDeliveryPolicy::FailLoud,
    ));

    let dropped = l.drop_inflight();

    assert_eq!(
        dropped
            .iter()
            .map(|delivery| delivery.frame_id)
            .collect::<Vec<_>>(),
        vec![11, 12]
    );
    assert_eq!(dropped[0].payload, vec![1, 2, 3]);
    assert_eq!(dropped[1].payload, vec![4, 5]);
    assert_eq!(l.inflight_len(), 0);
    assert!(l.next_exact_local_event().is_none());
    assert!(l.drop_inflight().is_empty());
}

#[test]
fn link_slot_references_router_constant() {
    assert_eq!(LINK_SLOT, crucible_shmem::SLOT_NET_ROUTER);
}

// ---- seeded per-device RNG drives the link draws (IO-21, IO-23) -------

#[test]
fn emit_from_rng_is_reproducible_and_advances_the_cursor() {
    use crate::fault::DeviceRng;

    let faults = LinkFaults {
        jitter_window_ns: 4_096,
        reorder_window_ns: 4_096,
        loss: Probability::new(1, 4),
        duplicate: Probability::new(1, 3),
        duplicate_gap_ns: 1_024,
        corrupt: Probability::new(1, 2),
        corruption_strategies: vec![LinkCorruptionStrategy::BitFlip { max_bits: 2 }],
        ..LinkFaults::none()
    };
    let root = 0x0117_5eed_u64;
    let domain = "crucible.test.link-stream";
    let name = "a->b";
    let mut a = link(faults.clone());
    let mut b = link(faults);
    let mut rng_a = DeviceRng::fork(root, domain, name);
    let mut rng_b = DeviceRng::fork(root, domain, name);

    let out_a = ok(a.emit_from_rng(
        &frame(vec![1, 2, 3, 4]),
        &mut rng_a,
        PastDeliveryPolicy::ClampToFuture,
    ));
    let out_b = ok(b.emit_from_rng(
        &frame(vec![1, 2, 3, 4]),
        &mut rng_b,
        PastDeliveryPolicy::ClampToFuture,
    ));

    assert_eq!(
        out_a, out_b,
        "same seed + same frame => identical deliveries"
    );
    assert!(
        a.rng_position() > 0,
        "emit_from_rng advanced the RNG cursor"
    );
    assert_eq!(a.rng_position(), b.rng_position());
    assert_eq!(a.rng_position(), rng_a.position());

    // The snapshot captures the cursor; a restored link resumes the same
    // stream via `rng`, so its next emit matches the uninterrupted run.
    let snap = a.snapshot();
    assert_eq!(snap.rng_position, a.rng_position());
    let mut restored = ok(NetLink::restore(&snap));
    let mut resumed_rng = restored.rng(root, domain, name);
    let mut continued_rng = DeviceRng::restore(root, domain, name, a.rng_position());
    let resumed = ok(restored.emit_from_rng(
        &frame(vec![5, 6, 7, 8]),
        &mut resumed_rng,
        PastDeliveryPolicy::ClampToFuture,
    ));
    let continued = ok(a.emit_from_rng(
        &frame(vec![5, 6, 7, 8]),
        &mut continued_rng,
        PastDeliveryPolicy::ClampToFuture,
    ));
    assert_eq!(
        resumed, continued,
        "restored link resumes the draw stream byte-identically"
    );
}
