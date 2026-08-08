//! The engine-side bridge to the `crucible-device` I/O sub-nodes.
//!
//! `crucible-device` (L1) models block, 9p, and network sub-nodes whose
//! probabilistic effects are pure functions of an injected RNG draw. This module
//! is the L3 seam that supplies those draws from the scenario's determinism RNG
//! and records each one in the [`Schedule`](crate::Schedule) ([IO-21],
//! [SCHED-30]). Signal-driven block and 9p effects are owned by their production
//! adapters and do not pass through this network-link bridge.
//!
//! # Per-device RNG forked by name-hash
//!
//! Each device owns a seeded RNG forked by name-hash from the scenario seed
//! ([DET-25]): [`device_rng`] computes the device's stream seed as
//! `seed XOR stable_hash(device-domain, name)` (via
//! [`Seed::stream_seed`](crate::Seed::stream_seed) over an
//! [`RngStreamId::for_device`] id) and hands it to a
//! [`crucible_device::DeviceRng`]. Because the fork is by name-hash, adding or
//! renaming an unrelated device never perturbs another device's draw sequence.
//! The device RNG and the engine's own decision streams share the same
//! SplitMix64 algorithm and cursor convention, so a device draw is a real
//! [`Decision::RngDraw`] in the schedule.
//!
//! # `MaterializedState` wiring
//!
//! - [`device_overlay`] builds a [`DeviceOverlayDelta`] that carries the device's
//!   RNG cursor in its [`DeviceRngState`] ([IO-23]).
//! The cursor feeds the canonical materialized-state hash.

use std::collections::{BTreeMap, BTreeSet};

use crucible_device::{
    DeviceError, DeviceRng, Frame, FrameDraws, LinkCorruptionStrategy, LinkFaults, NetLink,
    PastDeliveryPolicy, Probability, ResolveOutcome,
};

use crate::decision::DecisionRecorder;
use crate::{
    CombinedNetworkFaults, CombinedPartitionFault, Decision, DeviceId, DeviceOverlayDelta,
    DeviceRngState, EffectOutcomeDecision, FaultId, FaultRateBasisPoints, FaultState,
    NetworkCorruptionFault, RngDecision, RngStreamId, RngStreamPosition, SchedulerError,
    SchedulerLookaheadEdge, SchedulerLookaheadEdgeEndpoint, SchedulerNodeId,
    SchedulerTopologyChange, Seed, SingleScheduler, VirtualTime,
};

/// Builds a device's seeded RNG, forked by name-hash from the scenario seed.
///
/// The fork is computed inside `crucible-device` by delegating to the L0
/// [`crucible_sim::DecisionRng`] (the single source of the SplitMix64 stream and
/// the `seed XOR stable_hash(device-domain, name)` formula, [DET-25]): this
/// passes the scenario's decision-RNG root seed plus the device stream domain and
/// name, so a [`crucible_device::DeviceRng`] and an engine
/// [`crucible_sim::DecisionRng::fork_in_domain`] / [`Seed::stream_seed`] over the
/// same [`RngStreamId::for_device`] produce identical sequences — no second PRNG
/// to drift. The returned RNG resumes at `position` draws, so a snapshot's
/// captured cursor restores the exact continuation of the draw sequence
/// ([IO-23]). Pass `position = 0` for a fresh device.
#[must_use]
pub fn device_rng(seed: crate::Seed, device: &DeviceId, position: u64) -> DeviceRng {
    let stream = device_stream_id(device);
    DeviceRng::restore(
        seed.decision_rng().root_seed(),
        &stream.domain,
        &stream.name,
        position,
    )
}

/// Returns the canonical decision-stream id for a device ([IO-21]).
#[must_use]
pub fn device_stream_id(device: &DeviceId) -> RngStreamId {
    RngStreamId::for_device(device.name.clone())
}

/// Resolves a probabilistic device fault, recording the draw and outcome ([SCHED-30]).
///
/// Draws one raw `u64` from the device's decision stream — recorded as a
/// [`Decision::RngDraw`] — and resolves the fault from
/// it through the same exact-fraction test [`crucible_device::Probability`] uses,
/// then records the derived [`Decision::EffectOutcome`]
/// outcome. The recording is total-ordered in the schedule, so a device's
/// probabilistic choices are reproducible from the seed ([IO-21], [IO-24]).
///
/// The fault fires when `(draw % denominator) < numerator`; a zero `denominator`
/// never fires.
pub fn record_device_fault(
    recorder: &mut DecisionRecorder,
    at: VirtualTime,
    device: &DeviceId,
    fault: FaultId,
    numerator: u64,
    denominator: u64,
) -> bool {
    let stream = device_stream_id(device);
    let value = recorder.draw_u64(stream);
    let fired = denominator != 0 && (value % denominator) < numerator;
    recorder.record_effect_outcome(EffectOutcomeDecision { at, fault, fired });
    fired
}

/// The recorded result of emitting one network-link frame from the device RNG.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkEmitDecisionRecord {
    /// The deliveries produced by the link after applying its effective fault table.
    pub outcome: ResolveOutcome,
    /// The exact fixed-order draw vector consumed by this frame.
    pub draws: FrameDraws,
    /// The raw RNG draws and derived effect outcomes recorded for the schedule.
    pub decisions: Vec<Decision>,
}

/// The engine-side result of applying a combined network fault set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkFaultApplication {
    /// The concrete fault table installed on the directed link.
    pub link_faults: LinkFaults,
    /// The scheduler topology mutations produced by partition activation or heal.
    pub topology_changes: Vec<SchedulerTopologyChange>,
}

/// The orientation of one directed [`NetLink`] relative to a declared logical link.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetworkLinkDirection {
    /// The directed link carries frames from endpoint A to endpoint B.
    EndpointAToEndpointB,
    /// The directed link carries frames from endpoint B to endpoint A.
    EndpointBToEndpointA,
}

impl NetworkLinkDirection {
    fn is_partitioned_by(self, partition: &CombinedPartitionFault) -> bool {
        match self {
            Self::EndpointAToEndpointB => partition.endpoint_a_to_endpoint_b,
            Self::EndpointBToEndpointA => partition.endpoint_b_to_endpoint_a,
        }
    }
}

/// Emits one network-link frame and records the link's RNG choices ([IO-21]).
///
/// The frame is already emitted by a modeled guest/device endpoint before this
/// helper applies link behavior. This helper is not a host-side workload
/// generator and MUST NOT be used to originate application traffic for a
/// scenario.
///
/// The link's [`NetLink::rng_position`] selects the starting cursor of the
/// canonical device stream for `link_id`. This helper draws the frame's
/// [`FrameDraws`] through [`NetLink::emit_with_rng_draws`], so the deliveries are
/// produced by the real link implementation and the returned schedule decisions
/// record the exact same raw draw values in fixed model order: jitter, reorder,
/// loss rates, duplicate, corrupt, and corruption selectors. The derived
/// loss/duplicate/corrupt outcomes are appended as [`Decision::EffectOutcome`] using
/// the same device-scoped [`FaultId`] namespace as block and 9p faults.
///
/// # Errors
///
/// Returns [`DeviceError`] when the link cannot emit the frame, including clock
/// overflow or fail-loud past-delivery guards.
pub fn emit_link_frame_with_recorded_faults(
    seed: Seed,
    link_id: &DeviceId,
    link: &mut NetLink,
    frame: &Frame,
    policy: PastDeliveryPolicy,
) -> Result<LinkEmitDecisionRecord, DeviceError> {
    emit_link_frame_with_recorded_stream(
        seed,
        &device_stream_id(link_id),
        link_id,
        link,
        frame,
        policy,
    )
}

/// Emits one network-link frame from an explicit canonical RNG stream.
///
/// World-backed schedulers use this entry point so adapters cannot substitute
/// an identity-external device label for the link stream declared by the World.
/// `fault_id` names the recorded derived effect outcomes; `stream` alone selects
/// the raw draw sequence.
///
/// # Errors
///
/// Returns [`DeviceError`] when the link cannot emit the frame, including clock
/// overflow or fail-loud past-delivery guards.
pub fn emit_link_frame_with_recorded_stream(
    seed: Seed,
    stream: &RngStreamId,
    fault_id: &DeviceId,
    link: &mut NetLink,
    frame: &Frame,
    policy: PastDeliveryPolicy,
) -> Result<LinkEmitDecisionRecord, DeviceError> {
    emit_link_frame_with_recorded_stream_at_position(
        seed,
        stream,
        fault_id,
        link.rng_position(),
        link,
        frame,
        policy,
    )
}

/// Converts link fault draws into schedule decisions in consumption order.
fn link_rng_draw_decisions(stream: &RngStreamId, draws: &FrameDraws) -> Vec<Decision> {
    [draws.jitter, draws.reorder, draws.loss]
        .into_iter()
        .chain(draws.additional_loss.iter().copied())
        .chain([draws.duplicate, draws.corrupt])
        .chain(draws.corrupt_bits.iter().copied())
        .map(|value| {
            Decision::RngDraw(RngDecision {
                stream: stream.clone(),
                value,
            })
        })
        .collect()
}

/// Pushes a link effect outcome into a decision list.
fn push_link_effect_outcome(
    decisions: &mut Vec<Decision>,
    at: VirtualTime,
    link: &DeviceId,
    kind: &str,
    fired: bool,
) {
    decisions.push(Decision::EffectOutcome(EffectOutcomeDecision {
        at,
        fault: io_fault_id(link, kind),
        fired,
    }));
}

/// Applies combined RFC network faults to a live network link fault table.
///
/// The model layer reduces active faults into [`CombinedNetworkFaults`]; this
/// helper lowers that target-local table to the concrete [`LinkFaults`] consumed
/// by [`NetLink`] at RESOLVE, including directed partition drops. This legacy
/// helper applies only the link half; use [`apply_combined_network_faults`] when
/// the scheduler topology mutation must be queued with the link update.
pub fn apply_combined_network_faults_to_link(
    link: &mut NetLink,
    faults: &CombinedNetworkFaults,
    direction: NetworkLinkDirection,
) {
    link.set_faults(link_faults_from_combined_network(faults, direction));
}

/// Applies combined RFC network faults to a link and builds the topology effect.
///
/// This is the one-call bridge for activation: it installs the concrete
/// [`LinkFaults`] on the directed [`NetLink`] and, when the same combined set
/// contains a partition, returns the scheduler effective-topology removal that
/// must be queued at the same boundary.
#[must_use]
pub fn apply_combined_network_faults(
    sequence: u64,
    endpoint_a: SchedulerNodeId,
    endpoint_b: SchedulerNodeId,
    link: &mut NetLink,
    faults: &CombinedNetworkFaults,
    direction: NetworkLinkDirection,
) -> NetworkFaultApplication {
    let link_faults = link_faults_from_combined_network(faults, direction);
    link.set_faults(link_faults.clone());
    let topology_changes = network_partition_change(sequence, endpoint_a, endpoint_b, faults)
        .into_iter()
        .collect();
    NetworkFaultApplication {
        link_faults,
        topology_changes,
    }
}

/// Applies combined network faults and queues their scheduler topology effect.
///
/// This activation bridge installs the concrete directed-link table and, when
/// the combined fault set contains a partition, schedules the matching
/// effective-edge removal on `scheduler` for the next quantum boundary.
///
/// # Errors
///
/// Returns [`SchedulerError`] when the scheduler rejects the topology change,
/// for example because an activation-timed change is already in the past.
pub fn apply_combined_network_faults_to_scheduler(
    sequence: u64,
    endpoint_a: SchedulerNodeId,
    endpoint_b: SchedulerNodeId,
    link: &mut NetLink,
    faults: &CombinedNetworkFaults,
    direction: NetworkLinkDirection,
    scheduler: &mut SingleScheduler,
) -> Result<NetworkFaultApplication, SchedulerError> {
    let application =
        apply_combined_network_faults(sequence, endpoint_a, endpoint_b, link, faults, direction);
    for change in application.topology_changes.clone() {
        scheduler.schedule_topology_change(change)?;
    }
    Ok(application)
}

/// Re-applies remaining network faults after a heal and queues topology restore.
///
/// `remaining_faults` is the combined fault table after the healed tag has been
/// removed. The link receives that remaining table. If another partition still
/// covers the directed link, the helper queues the remaining partition removal;
/// otherwise it queues a heal restoration for `restored_edges`.
///
/// # Errors
///
/// Returns [`SchedulerError`] when the scheduler rejects the topology change,
/// for example because an activation-timed change is already in the past.
// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::too_many_arguments)]
pub fn heal_combined_network_faults_to_scheduler(
    sequence: u64,
    endpoint_a: SchedulerNodeId,
    endpoint_b: SchedulerNodeId,
    link: &mut NetLink,
    remaining_faults: &CombinedNetworkFaults,
    direction: NetworkLinkDirection,
    restored_edges: Vec<SchedulerLookaheadEdge>,
    scheduler: &mut SingleScheduler,
) -> Result<NetworkFaultApplication, SchedulerError> {
    let link_faults = link_faults_from_combined_network(remaining_faults, direction);
    link.set_faults(link_faults.clone());

    let remaining_removed_edges = remaining_faults
        .partition
        .as_ref()
        .map(|partition| {
            network_partition_removed_edges(endpoint_a.clone(), endpoint_b.clone(), partition)
        })
        .unwrap_or_default();
    let remaining_removed_endpoints = remaining_removed_edges
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let restored_edges = restored_edges
        .into_iter()
        .filter(|edge| !remaining_removed_endpoints.contains(&edge.endpoint()))
        .collect::<Vec<_>>();

    let mut topology_changes = Vec::new();
    if !remaining_removed_edges.is_empty() {
        topology_changes.push(SchedulerTopologyChange::partition(
            sequence,
            remaining_removed_edges,
        ));
    }
    if !restored_edges.is_empty() {
        topology_changes.push(SchedulerTopologyChange::heal(sequence, restored_edges));
    }

    for change in topology_changes.clone() {
        scheduler.schedule_topology_change(change)?;
    }
    Ok(NetworkFaultApplication {
        link_faults,
        topology_changes,
    })
}

/// Lowers combined RFC network faults into a concrete link fault table.
///
/// Loss rates remain highest-first and use the any-fires rule, latency bumps are
/// summed in the model before becoming the link's conservative latency raise,
/// duplicate/corruption are already highest-rate choices, and every active
/// bandwidth limit contributes exact bit-rate serialization delay.
#[must_use]
pub fn link_faults_from_combined_network(
    faults: &CombinedNetworkFaults,
    direction: NetworkLinkDirection,
) -> LinkFaults {
    let mut link = LinkFaults::none();
    if let Some(partition) = &faults.partition {
        link.partitioned = direction.is_partitioned_by(partition);
    }
    link.added_latency_ns = faults.latency.nanos();
    if let Some(window) = faults.reorder_window {
        link.reorder_window_ns = window.nanos();
    }

    let mut loss_rates = faults.loss_rates.iter().copied();
    if let Some(rate) = loss_rates.next() {
        link.loss = probability_from_basis_points(rate);
        link.additional_loss = loss_rates.map(probability_from_basis_points).collect();
    }

    if let Some(duplicate) = faults.duplicate {
        link.duplicate = probability_from_basis_points(duplicate.rate);
        link.duplicate_gap_ns = duplicate.gap.nanos();
    }

    if let Some(corruption) = &faults.corruption {
        link.corrupt = probability_from_basis_points(corruption.rate);
        link.corruption_strategies = corruption
            .strategies
            .iter()
            .map(link_corruption_strategy)
            .collect();
    }

    link.bandwidth_bits_per_sec = faults
        .bandwidth_limits
        .iter()
        .map(|limit| limit.bits_per_second())
        .collect();
    link
}

/// Builds the scheduler partition change for combined network partition faults.
///
/// Endpoint A/B are the declared logical link endpoints. A directed partition
/// removes only its covered scheduler edge, while a bidirectional partition
/// removes both edges.
#[must_use]
pub fn network_partition_change(
    sequence: u64,
    endpoint_a: SchedulerNodeId,
    endpoint_b: SchedulerNodeId,
    faults: &CombinedNetworkFaults,
) -> Option<SchedulerTopologyChange> {
    let partition = faults.partition.as_ref()?;
    let removed_edges = network_partition_removed_edges(endpoint_a, endpoint_b, partition);
    if removed_edges.is_empty() {
        return None;
    }
    Some(SchedulerTopologyChange::partition(sequence, removed_edges))
}

/// Returns the directed scheduler edges removed by one combined partition fault.
#[must_use]
pub fn network_partition_removed_edges(
    endpoint_a: SchedulerNodeId,
    endpoint_b: SchedulerNodeId,
    partition: &CombinedPartitionFault,
) -> Vec<SchedulerLookaheadEdgeEndpoint> {
    let mut removed = Vec::new();
    if partition.endpoint_a_to_endpoint_b {
        removed.push(SchedulerLookaheadEdgeEndpoint::new(
            endpoint_a.clone(),
            endpoint_b.clone(),
        ));
    }
    if partition.endpoint_b_to_endpoint_a {
        removed.push(SchedulerLookaheadEdgeEndpoint::new(endpoint_b, endpoint_a));
    }
    removed
}

fn probability_from_basis_points(rate: FaultRateBasisPoints) -> Probability {
    Probability::new(
        u64::from(rate.basis_points()),
        u64::from(FaultRateBasisPoints::DENOMINATOR),
    )
}

fn link_corruption_strategy(fault: &NetworkCorruptionFault) -> LinkCorruptionStrategy {
    match fault {
        NetworkCorruptionFault::BitFlip { max_bits, .. } => LinkCorruptionStrategy::BitFlip {
            max_bits: *max_bits,
        },
        NetworkCorruptionFault::FieldMutation { .. } => LinkCorruptionStrategy::FieldMutation,
        NetworkCorruptionFault::Truncation { max_bytes, .. } => {
            LinkCorruptionStrategy::Truncation {
                max_bytes: *max_bytes,
            }
        }
    }
}

/// Builds a device overlay delta that captures the device's RNG cursor ([IO-23]).
///
/// The returned [`DeviceOverlayDelta`] carries the content-addressed overlay
/// pieces plus a [`DeviceRngState`] recording the device stream's cursor, so the
/// device's RNG position is part of its `MaterializedState` contribution. A
/// checkpoint that drops this cursor hashes to a different materialized-state id
/// and is rejected by the replay oracle.
#[must_use]
pub fn device_overlay(
    device: &DeviceId,
    parent: crate::ContentHash,
    delta: crate::ContentHash,
    resolved: crate::ContentHash,
    rng_position: u64,
) -> DeviceOverlayDelta {
    let mut streams = BTreeMap::new();
    streams.insert(
        device_stream_id(device),
        RngStreamPosition::new(rng_position),
    );
    DeviceOverlayDelta::new(parent, delta, resolved, DeviceRngState { streams })
}

/// Returns the device-fault tag the scheduler keys an active I/O fault by ([IO-26]).
///
/// I/O faults share the network-fault activation mechanism: a fault targets a
/// device by identity and is healed by its tag. This derives the stable tag for
/// a `(device, kind)` pair so block, 9p, and link faults live in one namespace.
#[must_use]
pub fn io_fault_id(device: &DeviceId, kind: &str) -> FaultId {
    FaultId {
        name: format!("io/{}/{kind}", device.name),
    }
}

/// Builds the scheduler [`FaultState`] for an active I/O fault ([IO-26]).
#[must_use]
pub fn io_fault_state(active_since: VirtualTime, heal_at: Option<VirtualTime>) -> FaultState {
    FaultState {
        active_since,
        heal_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Configuration, ScenarioDef, Seed};
    use crucible_device::{Frame, LinkFaults, NetLink, PastDeliveryPolicy, Probability};

    fn scenario(seed: u64) -> ScenarioDef {
        ScenarioDef::from_canonical_material_with_seed(
            "crucible.test.device",
            "scenario=device",
            Seed::from_u64(seed),
        )
    }

    fn device(name: &str) -> DeviceId {
        DeviceId {
            name: name.to_owned(),
        }
    }

    #[test]
    fn device_rng_is_forked_by_name_hash_and_topology_stable() {
        // A device's draw sequence is reproducible from the seed and is
        // unaffected by an unrelated device's existence ([IO-21], [DET-25]).
        let seed = Seed::from_u64(0xd0c5);
        let disk = device("disk");
        let cache = device("cache");

        let mut a = device_rng(seed, &disk, 0);
        let mut b = device_rng(seed, &disk, 0);
        let mut unrelated = device_rng(seed, &cache, 0);

        let disk_first = a.next_u64();
        let _ = unrelated.next_u64();
        assert_eq!(disk_first, b.next_u64(), "reproducible from seed");

        // A same-named node stream draws from a different domain, so it differs.
        let node_stream = RngStreamId::for_node("disk");
        let device_stream = device_stream_id(&disk);
        assert_ne!(node_stream.domain, device_stream.domain);
        assert_eq!(
            device_rng(seed, &disk, 1).position(),
            1,
            "restore positions the cursor"
        );
    }

    #[test]
    fn device_rng_sequence_matches_engine_fork_over_many_draws() {
        // Cross-crate drift guard ([IO-21], [DET-25]): the L1 `DeviceRng` and the
        // L0 engine fork for the SAME `(seed, device stream)` MUST draw identical
        // sequences. `DeviceRng` delegates to `crucible_sim` so this holds by
        // construction; this test fails loudly if either side ever forks
        // differently (a different domain, formula, or PRNG), which would split a
        // device's recorded draws from an engine replay.
        let seed = Seed::from_u64(0x5151_a5a5_1234_abcd);
        for name in ["disk", "fs", "a->b", ""] {
            let dev = device(name);
            let mut device_side = device_rng(seed, &dev, 0);
            // The engine's own fork of the device stream id.
            let mut engine_side = seed.fork_stream(&device_stream_id(&dev));
            assert_eq!(
                device_side.seed(),
                engine_side.seed(),
                "device {name}: forked stream seed must match the engine fork"
            );
            for draw_index in 0..1_000 {
                assert_eq!(
                    device_side.next_u64(),
                    engine_side.next_u64(),
                    "device {name}: draw {draw_index} diverged from the engine fork"
                );
            }
        }
    }

    #[test]
    fn record_device_fault_records_draw_and_outcome_in_order() {
        let config = Configuration::genesis(scenario(7));
        let mut recorder = DecisionRecorder::new(config);
        let disk = device("disk");

        let fired = record_device_fault(
            &mut recorder,
            VirtualTime { ticks: 3 },
            &disk,
            io_fault_id(&disk, "loss"),
            1,
            1, // always fires
        );

        assert!(fired);
        let decisions = recorder.schedule().decisions();
        assert_eq!(decisions.len(), 2);
        assert!(matches!(
            &decisions[0],
            crate::Decision::RngDraw(draw) if draw.stream == device_stream_id(&disk)
        ));
        assert!(matches!(
            &decisions[1],
            crate::Decision::EffectOutcome(outcome)
                if outcome.fault == io_fault_id(&disk, "loss") && outcome.fired
        ));
    }

    #[test]
    fn link_emit_records_seeded_rng_draws_effect_outcomes_and_cursor() {
        let seed = Seed::from_u64(0x10_21_22_23);
        let link_id = device("link-a-b");
        let mut faults = LinkFaults::none();
        faults.jitter_window_ns = 7;
        faults.reorder_window_ns = 3;
        faults.duplicate = Probability::ALWAYS;
        faults.duplicate_gap_ns = 1;
        faults.corrupt = Probability::ALWAYS;
        faults.corrupt_bit_flips = 1;
        let mut link = match NetLink::new(0, 99, 10, 1, faults) {
            Ok(link) => link,
            Err(error) => panic!("valid link should construct: {error}"),
        };

        let first = Frame::new(7, 11, vec![0]);
        let record = match emit_link_frame_with_recorded_faults(
            seed,
            &link_id,
            &mut link,
            &first,
            PastDeliveryPolicy::FailLoud,
        ) {
            Ok(record) => record,
            Err(error) => panic!("valid frame should emit: {error}"),
        };

        assert_eq!(
            record.outcome.deliveries.len(),
            2,
            "duplicate fault should emit a second delivery"
        );
        assert!(
            record
                .outcome
                .deliveries
                .iter()
                .all(|delivery| delivery.payload != first.payload),
            "corrupt fault should flip the delivered payload"
        );
        assert_eq!(
            link.rng_position(),
            6,
            "jitter, reorder, loss, duplicate, corrupt, and one bit draw"
        );
        assert_eq!(
            record.decisions,
            expected_link_decisions(seed, &link_id, 0, first.emit_icount)
        );

        let second = Frame::new(8, 12, vec![0]);
        let resumed = match emit_link_frame_with_recorded_faults(
            seed,
            &link_id,
            &mut link,
            &second,
            PastDeliveryPolicy::FailLoud,
        ) {
            Ok(record) => record,
            Err(error) => panic!("second frame should resume the device RNG: {error}"),
        };

        assert_eq!(
            link.rng_position(),
            12,
            "the second frame should advance from the restored cursor"
        );
        assert_eq!(
            resumed.decisions,
            expected_link_decisions(seed, &link_id, 6, second.emit_icount)
        );
    }

    fn expected_link_decisions(
        seed: Seed,
        link_id: &DeviceId,
        start_position: u64,
        emit_icount: u64,
    ) -> Vec<Decision> {
        let stream = device_stream_id(link_id);
        let mut rng = device_rng(seed, link_id, start_position);
        let mut decisions = Vec::new();
        for _ in 0..6 {
            decisions.push(Decision::RngDraw(RngDecision {
                stream: stream.clone(),
                value: rng.next_u64(),
            }));
        }
        for (kind, fired) in [("loss", false), ("duplicate", true), ("corrupt", true)] {
            decisions.push(Decision::EffectOutcome(EffectOutcomeDecision {
                at: VirtualTime { ticks: emit_icount },
                fault: io_fault_id(link_id, kind),
                fired,
            }));
        }
        decisions
    }
}
mod link_emission;

pub use link_emission::*;
