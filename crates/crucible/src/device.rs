//! The engine-side bridge to the `crucible-device` I/O sub-nodes.
//!
//! `crucible-device` (L1) models block, 9p, and network sub-nodes whose
//! probabilistic faults are pure functions of an injected RNG draw. This module
//! is the L3 seam that supplies those draws from the scenario's determinism RNG
//! and records each one in the [`Schedule`](crate::Schedule) ([IO-21],
//! [SCHED-30]), and that folds each device's RNG cursor and active I/O faults
//! into the device half of a [`MaterializedState`](crate::MaterializedState) so
//! omitting either fails the replay oracle ([IO-23], [IO-26]).
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
//! - [`io_fault_state`] / [`with_active_io_faults`] fold active I/O faults into
//!   the scheduler state's `active_faults` map ([IO-26]).
//!
//! Both pieces feed the canonical materialized-state hash, so a checkpoint that
//! drops a device's RNG cursor or its active faults computes a different
//! materialized-state id and is rejected by the replay oracle. The
//! `device_rng_cursor_or_active_fault_omission_fails_replay_oracle` test proves
//! this end to end.

use std::collections::{BTreeMap, BTreeSet};

use crucible_device::{
    DeviceError, DeviceRng, Frame, FrameDraws, IoFaults, LinkCorruptionStrategy, LinkFaults,
    NetLink, PastDeliveryPolicy, Probability, ResolveOutcome,
};

use crate::decision::DecisionRecorder;
use crate::{
    CombinedBlockFaults, CombinedNetworkFaults, CombinedNinePFaults, CombinedPartitionFault,
    Decision, DeviceId, DeviceOverlayDelta, DeviceRngState, FaultDecision, FaultId,
    FaultRateBasisPoints, FaultState, IoFailureMode, NetworkCorruptionFault, RngDecision,
    RngStreamId, RngStreamPosition, SchedulerError, SchedulerLookaheadEdge,
    SchedulerLookaheadEdgeEndpoint, SchedulerNodeId, SchedulerState, SchedulerTopologyChange, Seed,
    SingleScheduler, VirtualTime,
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
/// then records the derived [`Decision::FaultFires`]
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
    recorder.record_fault_outcome(FaultDecision { at, fault, fired });
    fired
}

/// The recorded result of emitting one network-link frame from the device RNG.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkEmitDecisionRecord {
    /// The deliveries produced by the link after applying its effective fault table.
    pub outcome: ResolveOutcome,
    /// The raw RNG draws and derived fault outcomes recorded for the schedule.
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
/// loss/duplicate/corrupt outcomes are appended as [`Decision::FaultFires`] using
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
/// `fault_id` names the recorded derived fault outcomes; `stream` alone selects
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

/// Emits one network-link frame from an explicit canonical RNG stream cursor.
///
/// A logical World link uses one stream across both directed runtime edges.
/// The scheduler therefore owns the shared cursor and supplies it here rather
/// than allowing either concrete [`NetLink`] to restart from its local cursor.
///
/// # Errors
///
/// Returns [`DeviceError`] when the link cannot emit the frame, including clock
/// overflow or fail-loud past-delivery guards.
pub fn emit_link_frame_with_recorded_stream_at_position(
    seed: Seed,
    stream: &RngStreamId,
    fault_id: &DeviceId,
    rng_position: u64,
    link: &mut NetLink,
    frame: &Frame,
    policy: PastDeliveryPolicy,
) -> Result<LinkEmitDecisionRecord, DeviceError> {
    let fault_table = link.faults().clone();
    let mut rng = DeviceRng::restore(
        seed.decision_rng().root_seed(),
        &stream.domain,
        &stream.name,
        rng_position,
    );
    let (outcome, draws) = link.emit_with_rng_draws(frame, &mut rng, policy)?;
    let at = VirtualTime {
        ticks: frame.emit_icount,
    };
    let mut decisions = link_rng_draw_decisions(stream, &draws);
    let partitioned = fault_table.partitioned;
    let loss_fired = !partitioned && fault_table.loss_fires(draws.loss, &draws.additional_loss);
    let duplicate_fired =
        !partitioned && !loss_fired && fault_table.duplicate.fires(draws.duplicate);
    let corrupt_fired = !partitioned && !loss_fired && fault_table.corrupt.fires(draws.corrupt);
    push_link_fault_outcome(&mut decisions, at, fault_id, "loss", loss_fired);
    push_link_fault_outcome(&mut decisions, at, fault_id, "duplicate", duplicate_fired);
    push_link_fault_outcome(&mut decisions, at, fault_id, "corrupt", corrupt_fired);
    Ok(LinkEmitDecisionRecord { outcome, decisions })
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

/// Pushes a link fault outcome into a decision list.
fn push_link_fault_outcome(
    decisions: &mut Vec<Decision>,
    at: VirtualTime,
    link: &DeviceId,
    kind: &str,
    fired: bool,
) {
    decisions.push(Decision::FaultFires(FaultDecision {
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

/// Applies combined block faults to a live block scheduling sub-node.
///
/// The model layer reduces active faults into [`CombinedBlockFaults`]; this
/// helper lowers that table into concrete [`IoFaults`] and installs it on the
/// sub-node so pending and future completions resolve through the active set.
#[must_use]
pub fn apply_combined_block_faults_to_subnode(
    sub_node: &mut crate::DeviceSchedulingSubNode,
    faults: &CombinedBlockFaults,
) -> IoFaults {
    let table = block_faults_from_combined_block(faults);
    sub_node.set_io_faults(table.clone());
    table
}

/// Applies combined block faults and materializes the active I/O fault set.
///
/// This is the one-call bridge for checkpointable activation: it installs the
/// concrete table on the live block sub-node and folds the active I/O fault kinds
/// into `scheduler.active_faults` for `MaterializedState` hashing.
#[must_use]
pub fn apply_combined_block_faults_to_subnode_and_state(
    scheduler: SchedulerState,
    sub_node: &mut crate::DeviceSchedulingSubNode,
    faults: &CombinedBlockFaults,
    active_since: VirtualTime,
) -> (IoFaults, SchedulerState) {
    let table = apply_combined_block_faults_to_subnode(sub_node, faults);
    let scheduler = with_active_io_faults(scheduler, sub_node.device_id(), &table, active_since);
    (table, scheduler)
}

/// Applies combined 9p faults to a live 9p scheduling sub-node.
///
/// The lowering is uniform with block and network faults: latency/jitter,
/// reorder, failure, duplicate, corruption, and bandwidth all become one active
/// completion-fault table driven by the device RNG.
#[must_use]
pub fn apply_combined_ninep_faults_to_subnode(
    sub_node: &mut crate::DeviceSchedulingSubNode,
    faults: &CombinedNinePFaults,
) -> IoFaults {
    let table = ninep_faults_from_combined_ninep(faults);
    sub_node.set_io_faults(table.clone());
    table
}

/// Applies combined 9p faults and materializes the active I/O fault set.
///
/// This is the filesystem twin of
/// [`apply_combined_block_faults_to_subnode_and_state`]: activation mutates the
/// live sub-node and returns a scheduler state that carries the active fault set.
#[must_use]
pub fn apply_combined_ninep_faults_to_subnode_and_state(
    scheduler: SchedulerState,
    sub_node: &mut crate::DeviceSchedulingSubNode,
    faults: &CombinedNinePFaults,
    active_since: VirtualTime,
) -> (IoFaults, SchedulerState) {
    let table = apply_combined_ninep_faults_to_subnode(sub_node, faults);
    let scheduler = with_active_io_faults(scheduler, sub_node.device_id(), &table, active_since);
    (table, scheduler)
}

/// Lowers combined RFC block faults into the concrete block/9p fault table.
///
/// Failure rates remain highest-first and use the any-fires rule. Drop-mode
/// failures suppress completion emission; error-status failures re-encode the
/// block payload as a normal block error response.
#[must_use]
pub fn block_faults_from_combined_block(faults: &CombinedBlockFaults) -> IoFaults {
    let mut table = IoFaults::none();
    table.added_latency_ns = faults.latency_extra.nanos();
    table.jitter_window_ns = faults.latency_jitter.nanos();
    if let Some(window) = faults.reorder_window {
        table.reorder_window_ns = window.nanos();
    }
    lower_io_failure_rates(&mut table, faults.failure_rates.iter().copied());
    table.drop_on_loss = matches!(faults.failure_mode, Some(IoFailureMode::Drop));
    lower_io_duplicate(&mut table, faults.duplicate);
    lower_io_corruption(
        &mut table,
        faults
            .corruption
            .map(|corruption| (corruption.rate, corruption.bit_flips)),
    );
    table.bandwidth_bits_per_sec = faults
        .bandwidth_limits
        .iter()
        .map(|limit| limit.bits_per_second())
        .collect();
    table
}

/// Lowers combined RFC 9p faults into the concrete block/9p fault table.
///
/// 9p failure faults keep their selected errno payloads so the sub-node can
/// synthesize an `Rlerror` reply with the original request tag when a failure
/// fires.
#[must_use]
pub fn ninep_faults_from_combined_ninep(faults: &CombinedNinePFaults) -> IoFaults {
    let mut table = IoFaults::none();
    table.added_latency_ns = faults.latency_extra.nanos();
    table.jitter_window_ns = faults.latency_jitter.nanos();
    if let Some(window) = faults.reorder_window {
        table.reorder_window_ns = window.nanos();
    }
    let mut failures = faults.failures.iter();
    if let Some(failure) = failures.next() {
        table.loss = probability_from_basis_points(failure.rate);
        table.failure_errno = Some(failure.errno.code() as u32);
        for failure in failures {
            table
                .additional_loss
                .push(probability_from_basis_points(failure.rate));
            table
                .additional_failure_errno
                .push(failure.errno.code() as u32);
        }
    }
    lower_io_duplicate(&mut table, faults.duplicate);
    lower_io_corruption(
        &mut table,
        faults
            .corruption
            .map(|corruption| (corruption.rate, corruption.bit_flips)),
    );
    table.bandwidth_bits_per_sec = faults
        .bandwidth_limits
        .iter()
        .map(|limit| limit.bits_per_second())
        .collect();
    table
}

fn lower_io_failure_rates(
    table: &mut IoFaults,
    rates: impl IntoIterator<Item = FaultRateBasisPoints>,
) {
    let mut rates = rates.into_iter();
    if let Some(rate) = rates.next() {
        table.loss = probability_from_basis_points(rate);
        table.additional_loss = rates.map(probability_from_basis_points).collect();
    }
}

fn lower_io_duplicate(table: &mut IoFaults, duplicate: Option<crate::CombinedDuplicateFault>) {
    if let Some(duplicate) = duplicate {
        table.duplicate = probability_from_basis_points(duplicate.rate);
        table.duplicate_gap_ns = duplicate.gap.nanos();
    }
}

fn lower_io_corruption(table: &mut IoFaults, corruption: Option<(FaultRateBasisPoints, u32)>) {
    if let Some((rate, bit_flips)) = corruption {
        table.corrupt = probability_from_basis_points(rate);
        table.corrupt_bit_flips = bit_flips;
    }
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

/// Folds the device's active I/O faults into a scheduler state ([IO-26]).
///
/// For each latency/jitter/reorder/bandwidth/loss/duplicate/corrupt fault active
/// in `faults`, inserts a scheduler `active_faults` entry keyed by
/// [`io_fault_id`], all marked active since `active_since`. The active I/O fault
/// set therefore becomes part of the scheduler state captured in
/// `MaterializedState`, so omitting it fails the replay oracle ([IO-26],
/// [TEMP-10]).
#[must_use]
pub fn with_active_io_faults(
    mut scheduler: SchedulerState,
    device: &DeviceId,
    faults: &IoFaults,
    active_since: VirtualTime,
) -> SchedulerState {
    for kind in active_io_fault_kinds(faults) {
        scheduler.active_faults.insert(
            io_fault_id(device, kind),
            io_fault_state(active_since, None),
        );
    }
    scheduler
}

/// Lists the active fault kinds in `faults`, in a fixed deterministic order.
///
/// Each kind that is not at its fault-free default contributes one stable label,
/// so two equal tables list the same kinds and the active-fault set is a pure
/// function of the table ([IO-24]).
fn active_io_fault_kinds(faults: &IoFaults) -> Vec<&'static str> {
    let mut kinds = Vec::new();
    if faults.added_latency_ns != 0 {
        kinds.push("latency");
    }
    if faults.jitter_window_ns != 0 {
        kinds.push("jitter");
    }
    if faults.reorder_window_ns != 0 {
        kinds.push("reorder");
    }
    if faults.bandwidth_bytes_per_sec != 0 || !faults.bandwidth_bits_per_sec.is_empty() {
        kinds.push("bandwidth");
    }
    if faults.loss.numerator != 0
        || faults
            .additional_loss
            .iter()
            .any(|loss| loss.numerator != 0)
    {
        kinds.push("loss");
    }
    if faults.duplicate.numerator != 0 {
        kinds.push("duplicate");
    }
    if faults.corrupt.numerator != 0 {
        kinds.push("corrupt");
    }
    kinds
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Checkpoint, CheckpointKind, Configuration, ContentHash, EngineError, EventLogOffset,
        GenesisCheckpoint, MaterializedState, ScenarioDef, Seed, TemporalGraph,
    };
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
            crate::Decision::FaultFires(outcome)
                if outcome.fault == io_fault_id(&disk, "loss") && outcome.fired
        ));
    }

    #[test]
    fn link_emit_records_seeded_rng_draws_fault_outcomes_and_cursor() {
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
            decisions.push(Decision::FaultFires(FaultDecision {
                at: VirtualTime { ticks: emit_icount },
                fault: io_fault_id(link_id, kind),
                fired,
            }));
        }
        decisions
    }

    #[test]
    fn active_io_fault_kinds_are_deterministic_and_uniform() {
        let faults = IoFaults {
            added_latency_ns: 1,
            jitter_window_ns: 1,
            reorder_window_ns: 1,
            bandwidth_bytes_per_sec: 1,
            bandwidth_bits_per_sec: vec![1],
            loss: Probability::ALWAYS,
            additional_loss: vec![Probability::ALWAYS],
            duplicate: Probability::ALWAYS,
            duplicate_gap_ns: 1,
            corrupt: Probability::ALWAYS,
            corrupt_bit_flips: 1,
            ..IoFaults::none()
        };
        assert_eq!(
            active_io_fault_kinds(&faults),
            vec![
                "latency",
                "jitter",
                "reorder",
                "bandwidth",
                "loss",
                "duplicate",
                "corrupt",
            ]
        );
        assert!(active_io_fault_kinds(&IoFaults::none()).is_empty());
    }

    /// Builds a fat checkpoint whose materialized state has an explicit device
    /// half: a device overlay carrying `rng_position` and the device's active
    /// I/O faults folded into the scheduler state.
    fn fat_checkpoint_with_device_state(
        configuration: &Configuration,
        device: &DeviceId,
        rng_position: u64,
        faults: &IoFaults,
    ) -> Checkpoint {
        let mut checkpoint = fat_checkpoint_for(configuration);
        let overlay = device_overlay(
            device,
            ContentHash::from_canonical_material("test.parent", &device.name),
            ContentHash::from_canonical_material("test.delta", &device.name),
            ContentHash::from_canonical_material("test.resolved", &device.name),
            rng_position,
        );
        let scheduler = with_active_io_faults(
            SchedulerState::empty(),
            device,
            faults,
            VirtualTime { ticks: 1 },
        );
        checkpoint.state = Some(MaterializedState::from_components(
            BTreeMap::new(),
            BTreeMap::from([(device.clone(), overlay)]),
            scheduler,
            crate::DecisionRngState::empty(),
            EventLogOffset::default(),
        ));
        checkpoint
    }

    fn fat_checkpoint_for(configuration: &Configuration) -> Checkpoint {
        let result = Checkpoint::from_recorded_configuration(
            configuration,
            None,
            VirtualTime::default(),
            BTreeMap::new(),
            CheckpointKind::Fat,
            BTreeMap::new(),
        );
        match result {
            Ok(checkpoint) => checkpoint,
            Err(error) => panic!("test checkpoint should be recorded-shaped: {error}"),
        }
    }

    #[test]
    fn device_rng_cursor_or_active_fault_omission_fails_replay_oracle() {
        // The determinism-completeness check ([IO-23], [IO-26], T-IO-11). The
        // reference (baked genesis) carries the FAITHFUL device half — RNG cursor
        // = 5 with jitter + loss active — so the replay oracle compares each
        // candidate against a non-trivial expected state. The faithful checkpoint
        // PASSES the oracle; a checkpoint that OMITS the RNG cursor or the active
        // faults FAILS it. This is the non-vacuous shape: an implementation that
        // dropped the cursor/faults from the hash would make `omits_rng` /
        // `omits_faults` wrongly pass, and `assert_faithful_then_omissions_fail`
        // (below) confirms the test goes red in that case.
        let disk = device("disk");
        let faults = IoFaults {
            jitter_window_ns: 4_096,
            loss: Probability::new(1, 4),
            ..IoFaults::none()
        };

        assert_faithful_then_omissions_fail(0xfa17, &disk, &faults, DeviceHashMode::Complete);
    }

    #[test]
    fn omission_test_would_go_red_if_cursor_and_faults_were_not_hashed() {
        // The required falsifiability proof: if the device RNG cursor and the
        // active I/O faults were NOT folded into the materialized-state id, the
        // `omits_rng` / `omits_faults` checkpoints would hash identically to the
        // faithful one and wrongly PASS the oracle. `DeviceHashMode::Stripped`
        // models exactly that defect by zeroing the device half in BOTH the
        // reference and the candidates; under it the omission assertions must
        // fail, so we assert the harness panics — proving the real test (above)
        // is capable of catching the regression rather than passing vacuously.
        let disk = device("disk");
        let faults = IoFaults {
            jitter_window_ns: 4_096,
            loss: Probability::new(1, 4),
            ..IoFaults::none()
        };

        let result = std::panic::catch_unwind(|| {
            assert_faithful_then_omissions_fail(0xfa17, &disk, &faults, DeviceHashMode::Stripped);
        });
        assert!(
            result.is_err(),
            "with the cursor/faults stripped from the hash, the omission checkpoints \
             would pass the oracle — the determinism-completeness test must detect this"
        );
    }

    /// Whether the device half (RNG cursor + active faults) feeds the state id.
    #[derive(Clone, Copy)]
    enum DeviceHashMode {
        /// The production behavior: the device half is part of the state id.
        Complete,
        /// A modeled defect: the device half is stripped, so it never affects the
        /// state id. Used only to prove the omission test can fail.
        Stripped,
    }

    /// Bakes the faithful device half into genesis, asserts it replays `Ok`, and
    /// asserts the cursor-omitting and fault-omitting checkpoints each fail the
    /// replay oracle. Under [`DeviceHashMode::Stripped`] the device half is zeroed
    /// everywhere, so the omission checkpoints become equal to the faithful one
    /// and the failure assertions panic (the falsifiability proof).
    fn assert_faithful_then_omissions_fail(
        seed: u64,
        disk: &DeviceId,
        faults: &IoFaults,
        mode: DeviceHashMode,
    ) {
        let scenario = scenario(seed);
        let genesis = Configuration::genesis(scenario.clone());

        // The reference: genesis baked WITH the faithful device half.
        let faithful = device_state_checkpoint(&genesis, disk, 5, faults, mode);
        let baked = GenesisCheckpoint {
            checkpoint: faithful.clone(),
        };
        let graph = match TemporalGraph::empty().with_baked_genesis(&scenario, baked) {
            Ok(graph) => graph,
            Err(error) => panic!("valid baked genesis should register: {error}"),
        };

        // (a) The faithful checkpoint PASSES the replay oracle.
        match graph.replay_checkpoint(&genesis, &faithful) {
            Ok(_) => {}
            Err(error) => panic!("the faithful device-half checkpoint must replay Ok: {error}"),
        }

        // (b) Omitting the device RNG cursor (position 0 instead of 5) FAILS.
        let omits_rng = device_state_checkpoint(&genesis, disk, 0, faults, mode);
        assert_replay_oracle_rejects(
            &graph,
            &genesis,
            &omits_rng,
            "dropping the device RNG cursor must fail the replay oracle",
        );

        // (c) Omitting the active I/O faults (fault-free table) FAILS.
        let omits_faults = device_state_checkpoint(&genesis, disk, 5, &IoFaults::none(), mode);
        assert_replay_oracle_rejects(
            &graph,
            &genesis,
            &omits_faults,
            "dropping the active I/O faults must fail the replay oracle",
        );
    }

    /// Asserts `candidate` is rejected by the replay oracle with a state mismatch.
    fn assert_replay_oracle_rejects(
        graph: &TemporalGraph,
        genesis: &Configuration,
        candidate: &Checkpoint,
        context: &str,
    ) {
        match graph.replay_checkpoint(genesis, candidate) {
            Ok(_) => panic!("{context}"),
            Err(EngineError::ReplayOracleMismatch { actual, .. }) => {
                assert_eq!(actual, state_id(candidate), "{context}");
            }
            Err(other) => panic!("{context}: expected a replay-oracle mismatch, got {other}"),
        }
    }

    /// Builds a fat genesis checkpoint whose device half carries `rng_position`
    /// and the device's active I/O faults. Under [`DeviceHashMode::Stripped`] the
    /// device half is replaced by the empty one, modeling a defect where the
    /// cursor and faults are not hashed.
    fn device_state_checkpoint(
        configuration: &Configuration,
        device: &DeviceId,
        rng_position: u64,
        faults: &IoFaults,
        mode: DeviceHashMode,
    ) -> Checkpoint {
        match mode {
            DeviceHashMode::Complete => {
                fat_checkpoint_with_device_state(configuration, device, rng_position, faults)
            }
            DeviceHashMode::Stripped => fat_checkpoint_for(configuration),
        }
    }

    fn state_id(checkpoint: &Checkpoint) -> ContentHash {
        checkpoint
            .state
            .as_ref()
            .map(|state| state.id)
            .unwrap_or_else(|| panic!("fat checkpoint should carry materialized state"))
    }
}
