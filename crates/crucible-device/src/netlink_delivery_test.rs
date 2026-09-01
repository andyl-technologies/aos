//! Network-link delivery, timing, and loss tests.

use super::test_support::*;
use super::*;
use crate::{DeviceError, PendingResponse, Response, ResponseStatus};

#[test]
fn link_snapshot_codec_round_trips_complete_state() {
    let mut faults = LinkFaults {
        partitioned: true,
        added_latency_ns: 11,
        jitter_window_ns: 12,
        reorder_window_ns: 13,
        bandwidth_bits_per_sec: vec![1_000, 2_000],
        loss: Probability::new(1, 7),
        additional_loss: vec![Probability::new(2, 9)],
        duplicate: Probability::new(3, 11),
        duplicate_gap_ns: 14,
        corrupt: Probability::new(4, 13),
        corruption_strategies: vec![
            LinkCorruptionStrategy::BitFlip { max_bits: 3 },
            LinkCorruptionStrategy::FieldMutation,
            LinkCorruptionStrategy::Truncation { max_bytes: 5 },
        ],
    };
    faults.partitioned = false;
    let mut snapshot = link(faults).snapshot();
    snapshot.current_icount = 20;
    snapshot.next_seq = 7;
    snapshot.lookahead_recompute_pending = true;
    snapshot.rng_position = 19;
    snapshot.inflight.push(PendingResponse::from_parts(
        21,
        snapshot.src_node,
        6,
        Response::new(44, ResponseStatus::Ok, vec![1, 2, 3]),
    ));

    let bytes = ok(snapshot.canonical_bytes());
    let restored = ok(LinkSnapshot::from_canonical_bytes(&bytes));
    assert_eq!(restored, snapshot);
    assert_eq!(ok(restored.canonical_bytes()), bytes);

    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(
        LinkSnapshot::from_canonical_bytes(&trailing),
        Err(LinkSnapshotCodecError::Noncanonical)
    );
}

#[test]
fn link_snapshot_codec_enforces_authored_aggregate_limit() {
    let snapshot = link(LinkFaults::none()).snapshot();
    let bytes = ok(snapshot.canonical_bytes());
    let maximum = u64::try_from(bytes.len() - 1).unwrap_or(u64::MAX);

    assert!(matches!(
        snapshot.canonical_bytes_with_limit(maximum),
        Err(LinkSnapshotCodecError::ResourceLimit {
            field: "link snapshot bytes",
            current,
            requested,
            configured,
            hard: 1_073_741_824,
        }) if current.saturating_add(requested) > maximum && configured == maximum
    ));
    assert!(matches!(
        LinkSnapshot::from_canonical_bytes_with_limit(&bytes, maximum),
        Err(LinkSnapshotCodecError::ResourceLimit {
            field: "link snapshot bytes",
            current: 0,
            requested,
            configured,
            hard: 1_073_741_824,
        }) if requested == u64::try_from(bytes.len()).unwrap_or(u64::MAX)
            && configured == maximum
    ));

    assert_eq!(
        ok(snapshot.canonical_length_with_limit(u64::try_from(bytes.len()).unwrap_or(u64::MAX))),
        bytes.len()
    );
    assert_eq!(
        ok(snapshot.canonical_bytes_with_limit(u64::try_from(bytes.len()).unwrap_or(u64::MAX))),
        bytes
    );
}

// ---- construction: latency floor (IO-33) ----

#[test]
fn zero_floor_or_subfloor_base_is_rejected() {
    let src = 0;
    // Zero floor is rejected (floor must be strictly positive).
    assert!(matches!(
        NetLink::new(SHIFT, src, 1000, 0, LinkFaults::none()),
        Err(DeviceError::LinkLatencyBelowFloor { .. })
    ));
    // Base below the floor is rejected.
    assert!(matches!(
        NetLink::new(SHIFT, src, 500, 1000, LinkFaults::none()),
        Err(DeviceError::LinkLatencyBelowFloor { .. })
    ));
    // Base == floor is accepted.
    assert!(NetLink::new(SHIFT, src, 1000, 1000, LinkFaults::none()).is_ok());
}

// ---- fault-free delivery at base latency (IO-20) ----

#[test]
fn fault_free_delivers_at_base_latency() {
    let mut l = link(LinkFaults::none());
    let out = ok(l.emit(
        &frame(vec![1, 2, 3, 4]),
        &FrameDraws::default(),
        PastDeliveryPolicy::FailLoud,
    ));
    assert_eq!(out.deliveries.len(), 1);
    // emit at icount 0, base 2560 ns => ceil(2560/256) = 10.
    assert_eq!(out.deliveries[0].delivery_icount(), 10);
    assert_eq!(l.next_exact_local_event(), Some(10));
    // Nothing delivered before icount 10.
    assert!(ok(l.advance_to(9)).is_empty());
    let due = ok(l.advance_to(10));
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].payload, vec![1, 2, 3, 4]);
    assert_eq!(due[0].frame_id, 1);
}

#[test]
fn resolved_signal_outcomes_apply_without_link_rng_interpretation() {
    let mut l = link(LinkFaults::none());
    let mut effects = ResolvedNetworkFrameEffects::default();
    ok(effects.add_latency_delta(-1_280));
    ok(effects.add_delay(256));
    ok(effects.constrain_rate(32_000_000));
    ok(effects.add_duplicate_gap(512));
    ok(effects.add_duplicate_gap(256));
    let resolved = frame(vec![1, 2, 3, 4]).with_resolved_effects(effects);
    let out = ok(l.emit(
        &resolved,
        &FrameDraws::default(),
        PastDeliveryPolicy::FailLoud,
    ));

    // 1,280 ns adjusted latency + 1,000 ns serialization + 256 ns delay
    // rounds to icount 10; the two exact copy gaps round to 11 and 12.
    assert_eq!(
        out.deliveries
            .iter()
            .map(Delivery::delivery_icount)
            .collect::<Vec<_>>(),
        vec![10, 11, 12]
    );
}

#[test]
fn resolved_signal_drop_and_latency_floor_are_exact() {
    let mut dropped = link(LinkFaults::none());
    let mut dropped_effects = ResolvedNetworkFrameEffects::default();
    ok(dropped_effects.add_latency_delta(i64::MIN));
    dropped_effects.mark_drop();
    let dropped_frame = frame(vec![0; 4]).with_resolved_effects(dropped_effects);
    let out = ok(dropped.emit(
        &dropped_frame,
        &FrameDraws::default(),
        PastDeliveryPolicy::FailLoud,
    ));
    assert!(out.deliveries.is_empty());

    let mut clamped = link(LinkFaults::none());
    let mut clamped_effects = ResolvedNetworkFrameEffects::default();
    ok(clamped_effects.add_latency_delta(-10_000));
    let clamped_frame = frame(vec![0; 4]).with_resolved_effects(clamped_effects);
    let out = ok(clamped.emit(
        &clamped_frame,
        &FrameDraws::default(),
        PastDeliveryPolicy::FailLoud,
    ));
    assert_eq!(out.deliveries[0].delivery_icount(), 4);
}

#[test]
fn resolved_duplicate_failure_enqueues_nothing() {
    let mut l = link(LinkFaults::none());
    let mut effects = ResolvedNetworkFrameEffects::default();
    ok(effects.add_delay(u64::MAX - BASE_NS - 100));
    ok(effects.add_duplicate_gap(200));
    let overflowing = frame(vec![0; 4]).with_resolved_effects(effects);

    assert!(
        l.emit(
            &overflowing,
            &FrameDraws::default(),
            PastDeliveryPolicy::FailLoud,
        )
        .is_err()
    );
    assert_eq!(l.inflight_len(), 0);

    let out = ok(l.emit(
        &frame(vec![0; 4]),
        &FrameDraws::default(),
        PastDeliveryPolicy::FailLoud,
    ));
    assert_eq!(out.deliveries[0].key.seq, 0);
}

// ---- latency fault shifts delivery later (IO-20) ----

#[test]
fn added_latency_shifts_delivery_later() {
    let mut faults = LinkFaults::none();
    faults.added_latency_ns = 2_560; // +10 icounts
    let mut l = link(faults.clone());
    let out = ok(l.emit(
        &frame(vec![0; 4]),
        &FrameDraws::default(),
        PastDeliveryPolicy::FailLoud,
    ));
    assert_eq!(out.deliveries[0].delivery_icount(), 20);
}

// ---- sub-floor latency fault clamped to floor (IO-33) ----

#[test]
fn subfloor_latency_is_clamped_to_floor() {
    // A link at base == floor; the effective latency can never drop below the
    // floor regardless of the fault table (added_latency only raises).
    let l = link(LinkFaults::none());
    assert_eq!(l.effective_latency_ns(), BASE_NS.max(FLOOR_NS));

    // Construct a link whose base equals the floor; effective latency stays
    // pinned at the floor -- never below.
    let at_floor = ok(NetLink::new(
        SHIFT,
        0,
        FLOOR_NS,
        FLOOR_NS,
        LinkFaults::none(),
    ));
    assert_eq!(at_floor.effective_latency_ns(), FLOOR_NS);
    assert!(at_floor.effective_latency_ns() >= at_floor.floor_ns());
}

// ---- jitter shifts later, deterministic given draw (IO-20) ----

#[test]
fn jitter_shifts_later_and_is_deterministic() {
    let mut faults = LinkFaults::none();
    faults.jitter_window_ns = 2_560; // up to +10 icounts
    let mut a = link(faults.clone());
    let mut b = link(faults.clone());
    let draws = FrameDraws {
        jitter: 1_280, // 1280 ns extra => +5 icounts
        ..FrameDraws::default()
    };
    let oa = ok(a.emit(&frame(vec![0; 4]), &draws, PastDeliveryPolicy::FailLoud));
    let ob = ok(b.emit(&frame(vec![0; 4]), &draws, PastDeliveryPolicy::FailLoud));
    // base 10 + jitter 5 = 15.
    assert_eq!(oa.deliveries[0].delivery_icount(), 15);
    assert_eq!(
        oa.deliveries[0].delivery_icount(),
        ob.deliveries[0].delivery_icount()
    );
    // A larger draw shifts strictly later (it never moves earlier).
    let mut c = link(faults);
    let bigger = FrameDraws {
        jitter: 2_560,
        ..FrameDraws::default()
    };
    let oc = ok(c.emit(&frame(vec![0; 4]), &bigger, PastDeliveryPolicy::FailLoud));
    assert!(oc.deliveries[0].delivery_icount() >= oa.deliveries[0].delivery_icount());
}

// ---- reorder shifts a frame past a sibling (IO-20) ----

#[test]
fn reorder_moves_a_frame_past_its_sibling() {
    let mut faults = LinkFaults::none();
    faults.reorder_window_ns = 5_120; // up to +20 icounts
    let mut l = link(faults.clone());
    // Frame 1 emitted first at icount 0; frame 2 emitted later at icount 1.
    // Without reorder frame 1 would deliver first. Give frame 1 a big reorder
    // shift and frame 2 none, so frame 2 overtakes frame 1.
    let f1 = Frame::new(0, 1, vec![0xA; 4]);
    let f2 = Frame::new(1, 2, vec![0xB; 4]);
    ok(l.emit(
        &f1,
        &FrameDraws {
            reorder: 5_120,
            ..FrameDraws::default()
        },
        PastDeliveryPolicy::FailLoud,
    ));
    ok(l.emit(
        &f2,
        &FrameDraws {
            reorder: 0,
            ..FrameDraws::default()
        },
        PastDeliveryPolicy::FailLoud,
    ));
    // Drain everything; frame 2 must come out first (it overtook frame 1).
    let due = ok(l.advance_to(1_000));
    let ids: Vec<u32> = due.iter().map(|d| d.frame_id).collect();
    assert_eq!(ids, vec![2, 1], "reorder did not move frame 1 past frame 2");
}

// ---- bandwidth adds serialization delay proportional to size (IO-20) ----

#[test]
fn bandwidth_adds_size_proportional_delay() {
    let mut faults = LinkFaults::none();
    // 256 bytes per icount-ns scale: pick a rate so a 256-byte frame adds a
    // round delay. 256 bytes at 1e9 B/s => 256 ns => +1 icount.
    faults.bandwidth_bits_per_sec = vec![8_000_000_000];
    let mut l = link(faults.clone());
    let small = ok(l.emit(
        &Frame::new(0, 1, vec![0; 256]),
        &FrameDraws::default(),
        PastDeliveryPolicy::FailLoud,
    ));
    // base 10 icounts + 256 ns serialization (1 icount) = 11.
    assert_eq!(small.deliveries[0].delivery_icount(), 11);
    // A larger frame is delayed strictly more.
    let mut l2 = link(faults);
    let big = ok(l2.emit(
        &Frame::new(0, 2, vec![0; 2560]),
        &FrameDraws::default(),
        PastDeliveryPolicy::FailLoud,
    ));
    assert!(big.deliveries[0].delivery_icount() > small.deliveries[0].delivery_icount());
}

// ---- loss drops the frame (IO-20) ----

#[test]
fn loss_drops_the_frame() {
    let mut faults = LinkFaults::none();
    faults.loss = Probability::ALWAYS;
    let mut l = link(faults);
    let out = ok(l.emit(
        &frame(vec![0; 4]),
        &FrameDraws::default(),
        PastDeliveryPolicy::FailLoud,
    ));
    assert_eq!(out.deliveries.len(), 0, "loss must produce no delivery");
    assert_eq!(l.inflight_len(), 0);
    // A non-firing draw delivers normally.
    let mut faults2 = LinkFaults::none();
    faults2.loss = Probability::new(1, 100); // 1%
    let mut l2 = link(faults2);
    let out2 = ok(l2.emit(
        &frame(vec![0; 4]),
        &FrameDraws {
            loss: 50,
            ..FrameDraws::default()
        },
        PastDeliveryPolicy::FailLoud,
    ));
    assert_eq!(out2.deliveries.len(), 1);
}

#[test]
fn partition_drops_the_frame() {
    let mut faults = LinkFaults::none();
    faults.partitioned = true;
    let mut l = link(faults);
    let out = ok(l.emit(
        &frame(vec![1, 2, 3, 4]),
        &FrameDraws::default(),
        PastDeliveryPolicy::FailLoud,
    ));

    assert_eq!(
        out.deliveries.len(),
        0,
        "partition must produce no delivery"
    );
    assert_eq!(l.inflight_len(), 0);

    ok(l.advance_to(100));
    let late = ok(l.emit(
        &frame(vec![1, 2, 3, 4]),
        &FrameDraws::default(),
        PastDeliveryPolicy::FailLoud,
    ));
    assert_eq!(
        late.deliveries.len(),
        0,
        "partition drops before past-delivery guards can reject a frame"
    );
}

// ---- duplicate emits exactly two deliveries (IO-20) ----

#[test]
fn duplicate_emits_exactly_two_deliveries_at_distinct_icounts() {
    let mut faults = LinkFaults::none();
    faults.duplicate = Probability::ALWAYS;
    faults.duplicate_gap_ns = 2_560; // +10 icounts later
    let mut l = link(faults);
    let out = ok(l.emit(
        &frame(vec![7; 4]),
        &FrameDraws::default(),
        PastDeliveryPolicy::FailLoud,
    ));
    assert_eq!(out.deliveries.len(), 2, "duplicate must emit exactly two");
    assert_eq!(out.deliveries[0].delivery_icount(), 10);
    assert_eq!(out.deliveries[1].delivery_icount(), 20);
    // Both carry the same id and payload but distinct delivery keys.
    assert_eq!(out.deliveries[0].frame_id, out.deliveries[1].frame_id);
    assert_eq!(out.deliveries[0].payload, out.deliveries[1].payload);
    assert_ne!(out.deliveries[0].key, out.deliveries[1].key);
    assert_eq!(l.inflight_len(), 2);
}

// ---- corrupt flips exactly the seeded bits (IO-20) ----
