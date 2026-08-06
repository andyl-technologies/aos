//! The network-link sub-node: inter-VM frame delivery with deterministic faults.
//!
//! This module assembles the network-link sub-node of RFC-0010 §15.4 from two
//! focused submodules and re-exports their public surface:
//!
//! - [`fault`]: the effective fault table ([`LinkFaults`]) and the pure,
//!   integer-only fault transforms — bandwidth serialization, jitter/reorder
//!   shifts, Bernoulli [`Probability`], and payload corruption ([IO-20]).
//! - [`ipv4`]: the bounded Ethernet/IPv4 parser and exact fragmentation and
//!   later-hop re-fragmentation encoder.
//! - [`response`]: portable ICMPv4, ICMPv6, TCP-reset, and exact opaque
//!   Ethernet response generation with protocol suppression rules and checksums.
//! - [`link`]: the [`NetLink`] sub-node — the directed `A -> B` edge that
//!   schedules each [`Frame`] over the
//!   [`SLOT_NET_ROUTER`](crucible_shmem::SLOT_NET_ROUTER) slot, enforces the
//!   strictly-positive latency floor, clamps sub-floor latency faults, raises the
//!   scheduler lookahead-recompute signal when the conservative minimum latency
//!   bound changes ([IO-33]), and clamps-or-fails-loud on a reorder/jitter shift
//!   into the consumer's past ([IO-34]).
//!
//! # Why the link is special among sub-nodes
//!
//! The block and 9p sub-nodes produce *exact* local events; the network link is
//! the **one source of conservative uncertainty** (§15.4.2). Its base latency
//! `L(A->B)` is what *sets* the scheduler's lookahead bound, so the floor lives
//! at the link: a zero-latency link would give a peer zero lookahead and collapse
//! the system to single-instruction lockstep. A fixed latency fault that raises
//! the conservative minimum effective latency only widens lookahead (safe); a
//! fault that would lower it below the floor is clamped; and any change to that
//! scalar bound triggers a lookahead recompute at the next quantum boundary,
//! never mid-RUN. Jitter, reorder, and bandwidth can delay individual frames, but
//! their minimum additional delay is zero and therefore does not change the
//! scheduler's scalar lookahead edge.
//!
//! # Determinism and the RNG seam
//!
//! Every probabilistic transform (jitter magnitude, reorder shift, loss
//! decisions, duplicate timing, corruption decision, and corruption selectors)
//! is a pure function of draw values carried in [`FrameDraws`]. The seeded
//! per-device RNG ([`crate::fault::DeviceRng`]) forked by name-hash produces
//! those draws in their fixed consumption order via
//! [`FrameDraws::from_rng_for_faults`] and [`NetLink::emit_from_rng`] ([IO-21]);
//! the snapshot captures the RNG cursor so a fork resumes the same sequence
//! ([IO-23]). The same frame and the same draws always yield byte-identical
//! deliveries ([IO-4], [IO-22]). No floating point, no host clock, and no
//! default-hasher iteration appears on any delivery path ([IO-24]).

pub mod fault;
pub mod ipv4;
pub mod link;
pub mod response;

pub use fault::{
    LinkCorruptionStrategy, LinkFaults, Probability, corrupt_payload, jitter_shift_ns,
    reorder_shift_ns, serialization_delay_ns,
};
pub use ipv4::{Ipv4FragmentationError, Ipv4FragmentationOutcome, fragment_ethernet_ipv4};
pub use link::{
    Delivery, Frame, FrameDraws, LINK_SLOT, LinkSnapshot, NetLink, PastDeliveryPolicy,
    ResolveOutcome, ResolvedNetworkFrameEffects, ResolvedNetworkFrameEffectsError,
};
pub use response::{
    NetworkResponseError, NetworkResponseHeaders, NetworkResponseKind, NetworkResponseOutcome,
    NetworkResponseSpecification, generate_network_response,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DeviceError;

    /// Unwraps a result in tests, panicking with the error on failure.
    fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| panic!("expected Ok, got {error:?}"))
    }

    const SHIFT: u8 = 8; // 256 ns per icount
    const FLOOR_NS: u64 = 1_000;
    const BASE_NS: u64 = 2_560; // exactly 10 icounts at shift 8

    /// Builds a fault-free link whose source id is the router slot.
    fn link(faults: LinkFaults) -> NetLink {
        let src = crucible_shmem::SLOT_NET_ROUTER as u32;
        ok(NetLink::new(SHIFT, src, BASE_NS, FLOOR_NS, faults))
    }

    /// A frame at emit icount 0 with a fixed 4-byte payload.
    fn frame(payload: Vec<u8>) -> Frame {
        Frame::new(0, 1, payload)
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
        // pinned at the floor — never below.
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

    // ---- bandwidth adds serialization delay ∝ size (IO-20) ----

    #[test]
    fn bandwidth_adds_size_proportional_delay() {
        let mut faults = LinkFaults::none();
        // 256 bytes per icount-ns scale: pick a rate so a 256-byte frame adds a
        // round delay. 256 bytes at 1e9 B/s => 256 ns => +1 icount.
        faults.bandwidth_bytes_per_sec = 1_000_000_000;
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

    #[test]
    fn corrupt_flips_exactly_the_seeded_bits() {
        let mut faults = LinkFaults::none();
        faults.corrupt = Probability::ALWAYS;
        faults.corrupt_bit_flips = 2;
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
        faults2.corrupt_bit_flips = 2;
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
        // A frame emitted at icount 0 with base 10 icounts would deliver at 10 —
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
            ("bandwidth_bytes_per_sec", |f| {
                f.bandwidth_bytes_per_sec = 1_000
            }),
            ("loss", |f| f.loss = Probability::ALWAYS),
            ("duplicate", |f| f.duplicate = Probability::ALWAYS),
            ("duplicate_gap_ns", |f| f.duplicate_gap_ns = 9_999),
            ("corrupt", |f| {
                f.corrupt = Probability::ALWAYS;
                f.corrupt_bit_flips = 3;
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
        faults.corrupt_bit_flips = 1;
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
            corrupt_bit_flips: 2,
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
}
