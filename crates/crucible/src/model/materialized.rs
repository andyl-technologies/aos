//! RNG, materialized scheduler state, checkpoints, and checkpoint policy.

use super::*;
mod seed;
pub use seed::{Seed, SeededRngStream};

/// A deterministic decision-stream identifier.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RngStreamId {
    /// The stable stream domain.
    pub domain: String,
    /// The canonical stream name.
    pub name: String,
}

impl RngStreamId {
    /// Builds a stream id in the default decision-RNG name-hash domain.
    #[must_use]
    pub fn from_name(name: impl Into<String>) -> Self {
        Self::new(DECISION_RNG_NAME_HASH_DOMAIN, name)
    }

    /// Builds a node-scoped stream id.
    #[must_use]
    pub fn for_node(name: impl Into<String>) -> Self {
        Self::new(DECISION_RNG_NODE_STREAM_DOMAIN, name)
    }

    /// Builds a link-scoped stream id.
    #[must_use]
    pub fn for_link(name: impl Into<String>) -> Self {
        Self::new(DECISION_RNG_LINK_STREAM_DOMAIN, name)
    }

    /// Builds a device-scoped stream id ([IO-21]).
    ///
    /// Devices (block / 9p / network sub-nodes) fork their probabilistic-fault
    /// RNG from this domain by name-hash, keeping device streams independent of
    /// same-named node and link streams ([DET-25]).
    #[must_use]
    pub fn for_device(name: impl Into<String>) -> Self {
        Self::new(DECISION_RNG_DEVICE_STREAM_DOMAIN, name)
    }

    /// Builds a stream id in a caller-supplied stable domain.
    #[must_use]
    pub fn new(domain: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            name: name.into(),
        }
    }
}

/// A scheduling point identifier used by override decisions.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchedulingPoint {
    /// The canonical scheduling-point key.
    pub key: String,
}

/// An override choice identifier used by exploration.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChoiceTag {
    /// The canonical choice name.
    pub name: String,
}

/// A delivery-order decision payload.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DeliveryOrderDecision {
    /// The virtual time at which the ordering was resolved.
    pub at: VirtualTime,
    /// The ordered event keys.
    pub order: Vec<EventKey>,
}

/// A decision-stream draw payload.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RngDecision {
    /// The stream that produced the value.
    pub stream: RngStreamId,
    /// The drawn value.
    pub value: u64,
}

/// A search or fuzzing override payload.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OverrideDecision {
    /// The scheduling point being overridden.
    pub point: SchedulingPoint,
    /// The selected override choice.
    pub choice: ChoiceTag,
}

/// A vCPU-switch or interrupt-preemption payload.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PreemptionDecision {
    /// The node whose execution is preempted.
    pub node: NodeId,
    /// The instruction count where the preemption occurs.
    pub at: Icount,
    /// The kind of preemption.
    pub kind: PreemptionKind,
}

/// The kind of a preemption decision.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PreemptionKind {
    /// A multi-vCPU round-robin switch.
    VcpuSwitch {
        /// The previously running vCPU.
        from_vcpu: VcpuId,
        /// The newly selected vCPU.
        to_vcpu: VcpuId,
    },
    /// A timer or external interrupt at a chosen instruction count.
    InterruptAt {
        /// The vCPU receiving the interrupt.
        target_vcpu: VcpuId,
        /// The interrupt vector delivered.
        irq: IrqVector,
    },
}

/// An application-requested random draw payload.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AppRandomDecision {
    /// The requesting node.
    pub node: NodeId,
    /// The decision stream used to serve the request.
    pub stream: RngStreamId,
    /// The per-stream request identifier.
    pub request_id: u64,
    /// The requested bit width.
    pub width: u8,
    /// The served random value.
    pub value: u64,
}

/// A per-VM snapshot reference captured by a fat checkpoint.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VmSnapshotRef {
    /// The content-addressed VM-state blob or CoW delta.
    pub blob: NodeBlobRef,
    /// The retired-instruction count at which the snapshot was taken.
    pub icount: Icount,
}

impl VmSnapshotRef {
    /// Builds a VM snapshot reference from a blob ref and snapshot icount.
    #[must_use]
    pub fn new(blob: NodeBlobRef, icount: Icount) -> Self {
        Self { blob, icount }
    }
}

/// A device or I/O sub-node identifier.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId {
    /// The canonical device name.
    pub name: String,
}

impl DeviceId {
    /// Builds a device identifier from its stable world-wide name.
    #[must_use]
    pub fn from_name(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

/// A deterministic RNG stream cursor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct RngStreamPosition {
    /// Number of draws already consumed from the stream.
    pub draws: u64,
}

impl RngStreamPosition {
    /// Builds a deterministic RNG stream cursor.
    #[must_use]
    pub fn new(draws: u64) -> Self {
        Self { draws }
    }
}

/// The deterministic RNG state owned by one device overlay.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct DeviceRngState {
    /// Per-stream cursor positions for device-local randomness.
    pub streams: BTreeMap<RngStreamId, RngStreamPosition>,
}

impl DeviceRngState {
    /// Builds an empty device RNG state.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            streams: BTreeMap::new(),
        }
    }
}

/// A per-device copy-on-write overlay delta captured by a checkpoint.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DeviceOverlayDelta {
    /// Parent overlay or read-only base content address.
    pub parent: ContentHash,
    /// Dirty-page delta content address.
    pub delta: ContentHash,
    /// Resolved overlay content address after applying `delta`.
    pub resolved: ContentHash,
    /// Device-local deterministic RNG state at this checkpoint.
    pub rng: DeviceRngState,
}

impl DeviceOverlayDelta {
    /// Builds a device overlay delta from content-addressed pieces.
    #[must_use]
    pub fn new(
        parent: ContentHash,
        delta: ContentHash,
        resolved: ContentHash,
        rng: DeviceRngState,
    ) -> Self {
        Self {
            parent,
            delta,
            resolved,
            rng,
        }
    }

    /// Returns the stored CoW object for this device overlay delta.
    #[must_use]
    pub fn cow_delta_ref(&self) -> CowDeltaRef {
        CowDeltaRef::new(CowDeltaKind::DeviceOverlay, self.delta)
    }
}

/// A pending cross-node frame captured in scheduler state.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PendingFrame {
    /// The source node that produced the frame.
    pub source: NodeId,
    /// Stable source-local frame sequence.
    pub sequence: u64,
    /// Delivery instruction count selected by the scheduler.
    pub delivery_icount: Icount,
    /// Content-addressed payload reference.
    pub payload: ContentHash,
}

/// One exact in-flight delivery owned by a directed World network link.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NetworkLinkPendingFrame {
    /// Stable source-local delivery sequence.
    pub sequence: u32,
    /// Exact consumer instruction count at which the frame becomes visible.
    pub delivery_icount: Icount,
    /// Correlation identifier carried by the modeled link frame.
    pub frame_id: u32,
    /// Content-addressed payload reference.
    pub payload: ContentHash,
}

/// Checkpoint cursor for one concrete directed World network link.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct NetworkLinkRuntimeCursor {
    /// Destination-side link clock at the checkpoint boundary.
    pub current_icount: u64,
    /// Next deterministic delivery-key sequence assigned by the link.
    pub next_sequence: u32,
    /// Number of canonical link-stream RNG draws already consumed.
    pub rng_position: u64,
    /// Computed-but-not-yet-delivered frames in canonical delivery order.
    pub inflight: Vec<NetworkLinkPendingFrame>,
}

/// Runtime-derived search choices available at one frontier.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct SearchFrontierChoices {
    pub(super) choices: Vec<SearchFrontierChoice>,
    pub(super) decisions: Vec<Decision>,
}

impl SearchFrontierChoices {
    /// Builds an empty frontier-choice set.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            choices: Vec::new(),
            decisions: Vec::new(),
        }
    }

    /// Builds a frontier-choice set from scheduler-derived candidate decisions.
    ///
    /// The retained decisions are limited to the closed search taxonomy:
    /// decision-RNG draws and search overrides. Delivery order is excluded here
    /// because RESOLVE already imposes a total order over scheduled events.
    #[must_use]
    pub fn from_decisions<I>(decisions: I) -> Self
    where
        I: IntoIterator<Item = Decision>,
    {
        Self::from_choices(decisions.into_iter().filter_map(|decision| {
            if is_genuine_search_frontier_decision(&decision) {
                Some(SearchFrontierChoice::single(decision))
            } else {
                None
            }
        }))
    }

    /// Builds a frontier-choice set from candidate decision sequences.
    #[must_use]
    pub fn from_decision_sequences<I, J>(choices: I) -> Self
    where
        I: IntoIterator<Item = J>,
        J: IntoIterator<Item = Decision>,
    {
        Self::from_choices(
            choices
                .into_iter()
                .filter_map(SearchFrontierChoice::from_decisions),
        )
    }

    /// Returns the retained search frontier decisions.
    #[must_use]
    pub fn decisions(&self) -> &[Decision] {
        &self.decisions
    }

    /// Returns the retained search frontier choices.
    #[must_use]
    pub fn choices(&self) -> &[SearchFrontierChoice] {
        &self.choices
    }

    /// Returns whether this frontier has no retained search choices.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.decisions.is_empty()
    }

    fn from_choices<I>(choices: I) -> Self
    where
        I: IntoIterator<Item = SearchFrontierChoice>,
    {
        let choices = choices.into_iter().collect::<Vec<_>>();
        let decisions = choices
            .iter()
            .map(|choice| choice.decision.clone())
            .collect();
        Self { choices, decisions }
    }
}

/// One search choice and the causal decision sequence that realizes it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SearchFrontierChoice {
    pub(super) decision: Decision,
    pub(super) decisions: Vec<Decision>,
}

impl SearchFrontierChoice {
    fn single(decision: Decision) -> Self {
        Self {
            decision: decision.clone(),
            decisions: vec![decision],
        }
    }

    fn from_decisions<I>(decisions: I) -> Option<Self>
    where
        I: IntoIterator<Item = Decision>,
    {
        let decisions = decisions.into_iter().collect::<Vec<_>>();
        let decision = match decisions.as_slice() {
            [decision] if is_genuine_search_frontier_decision(decision) => decision.clone(),
            [
                decision @ Decision::Override(override_decision),
                causal @ ..,
            ] if override_decision
                .point
                .key
                .starts_with("live-world-network/")
                && causal
                    .iter()
                    .all(|decision| matches!(decision, Decision::RngDraw(_)))
                && !causal.is_empty() =>
            {
                decision.clone()
            }
            _ => return None,
        };
        Some(Self {
            decision,
            decisions,
        })
    }

    /// Returns the primary decision reported for this search choice.
    #[must_use]
    pub fn decision(&self) -> &Decision {
        &self.decision
    }

    /// Returns the causal decision sequence applied for this search choice.
    #[must_use]
    pub fn decisions(&self) -> &[Decision] {
        &self.decisions
    }
}

/// The saved sequence-counter key for one event producer/consumer pair.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventSequenceKey {
    /// The scheduler node that emits the event.
    pub producer: SchedulerNodeId,
    /// The scheduler node that consumes the event.
    pub consumer: SchedulerNodeId,
}

impl EventSequenceKey {
    /// Builds a producer/consumer sequence-counter key.
    #[must_use]
    pub fn new(producer: SchedulerNodeId, consumer: SchedulerNodeId) -> Self {
        Self { producer, consumer }
    }
}

/// Saved per-`(producer, consumer)` event sequence counters.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct EventSequenceState {
    /// The next sequence number to assign for each producer/consumer pair.
    pub next: BTreeMap<EventSequenceKey, u64>,
}

impl EventSequenceState {
    /// Builds an empty event sequence state.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            next: BTreeMap::new(),
        }
    }

    /// Returns the next sequence number for `producer` and `consumer`.
    #[must_use]
    pub fn next_sequence(&self, producer: &SchedulerNodeId, consumer: &SchedulerNodeId) -> u64 {
        self.next
            .get(&EventSequenceKey::new(producer.clone(), consumer.clone()))
            .copied()
            .unwrap_or(0)
    }

    /// Records the next sequence number for `producer` and `consumer`.
    pub fn set_next_sequence(
        &mut self,
        producer: SchedulerNodeId,
        consumer: SchedulerNodeId,
        next: u64,
    ) {
        self.next
            .insert(EventSequenceKey::new(producer, consumer), next);
    }
}

/// A timer identifier inside the scheduler state.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimerId {
    /// The canonical timer name.
    pub name: String,
}

/// An armed timer captured by the scheduler state.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TimerState {
    /// The node that owns the timer.
    pub owner: NodeId,
    /// Virtual time when the timer was armed.
    pub armed_at: VirtualTime,
    /// Virtual time when the timer should fire.
    pub fire_at: VirtualTime,
    /// Instruction count corresponding to the fire point.
    pub fire_icount: Icount,
}

/// The set of armed timers captured by a materialized checkpoint.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct TimerRegistry {
    /// Timers keyed by stable timer id.
    pub timers: BTreeMap<TimerId, TimerState>,
}

impl TimerRegistry {
    /// Builds an empty timer registry.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            timers: BTreeMap::new(),
        }
    }
}

/// Authoritative scheduler state needed to resume a fat checkpoint.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct SchedulerState {
    /// Per-node scheduler horizons.
    pub horizons: BTreeMap<NodeId, VirtualTime>,
    /// Pending frame queues with deterministic delivery counts.
    pub pending_frames: BTreeMap<NodeId, Vec<PendingFrame>>,
    /// Per-directed-link clocks, delivery sequences, and RNG cursors.
    pub network_link_cursors: BTreeMap<DeviceId, NetworkLinkRuntimeCursor>,
    /// Per-`(producer, consumer)` sequence counters for future emitted events.
    pub event_sequences: EventSequenceState,
    /// Monotone generation of the effective scheduler topology.
    pub topology_epoch: u64,
    /// Exact directed edge set currently used for send authorization and lookahead.
    pub effective_topology_edges: Vec<crate::scheduler::SchedulerLookaheadEdge>,
    /// Boundary topology transitions that have been admitted but not yet applied.
    pub pending_topology_changes: Vec<crate::scheduler::SchedulerTopologyChange>,
    /// Armed timer registry.
    pub timers: TimerRegistry,
    /// Device decisions already drawn but not yet emitted at a scheduler boundary.
    pub pending_device_decisions: Vec<Decision>,
    /// Search choices captured from the runtime frontier.
    pub search_frontier: SearchFrontierChoices,
}

impl SchedulerState {
    /// Builds an empty scheduler state.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            horizons: BTreeMap::new(),
            pending_frames: BTreeMap::new(),
            network_link_cursors: BTreeMap::new(),
            event_sequences: EventSequenceState::empty(),
            topology_epoch: 0,
            effective_topology_edges: Vec::new(),
            pending_topology_changes: Vec::new(),
            timers: TimerRegistry::empty(),
            pending_device_decisions: Vec::new(),
            search_frontier: SearchFrontierChoices::empty(),
        }
    }

    /// Reconstructs scheduler state from the causal decisions in `schedule`.
    #[must_use]
    pub fn from_schedule(schedule: &Schedule) -> Self {
        let mut state = Self::empty();
        state.apply_decisions(schedule.decisions());
        state
    }

    /// Applies causal decisions that mutate materialized scheduler state.
    pub fn apply_decisions(&mut self, decisions: &[Decision]) {
        for decision in decisions {
            self.apply_decision(decision);
        }
    }

    /// Applies one causal decision that mutates materialized scheduler state.
    pub fn apply_decision(&mut self, decision: &Decision) {
        let _ = decision;
    }

    /// Serializes this materialized scheduler continuation canonically.
    #[must_use]
    pub fn to_compact_binary(&self) -> Vec<u8> {
        let mut writer = ScenarioBinaryWriter::new(SCHEDULER_STATE_BINARY_MAGIC);
        write_scheduler_state_binary(self, &mut writer);
        writer.finish()
    }

    /// Parses one complete materialized scheduler continuation.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] for an unsupported
    /// version, malformed or over-limit collections, invalid nested values, or
    /// trailing bytes.
    pub fn from_compact_binary(bytes: &[u8]) -> Result<Self, EngineError> {
        let mut reader = ScenarioBinaryReader::new(bytes, SCHEDULER_STATE_BINARY_MAGIC)?;
        let state = read_scheduler_state_binary(&mut reader)?;
        reader.finish()?;
        Ok(state)
    }
}

/// Harness decision-RNG cursor state captured at a checkpoint.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct DecisionRngState {
    /// Per-stream cursor positions.
    pub positions: BTreeMap<RngStreamId, RngStreamPosition>,
}

impl DecisionRngState {
    /// Builds an empty decision-RNG state.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            positions: BTreeMap::new(),
        }
    }
}

/// The shared event-log prefix position for a checkpoint.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct EventLogOffset {
    /// Content address of the shared event-log prefix.
    pub prefix: ContentHash,
    /// Content address of the segment appended after the parent checkpoint.
    pub appended_segment: Option<ContentHash>,
    /// Byte offset at which resume continues appending.
    pub bytes: u64,
    /// Event count at which resume continues appending.
    pub events: u64,
}

impl EventLogOffset {
    /// Builds an event-log offset from prefix, byte offset, and event count.
    #[must_use]
    pub fn new(prefix: ContentHash, bytes: u64, events: u64) -> Self {
        Self {
            prefix,
            appended_segment: None,
            bytes,
            events,
        }
    }

    /// Builds an event-log offset with an appended segment delta.
    #[must_use]
    pub fn with_appended_segment(
        prefix: ContentHash,
        bytes: u64,
        events: u64,
        appended_segment: ContentHash,
    ) -> Self {
        Self {
            prefix,
            appended_segment: Some(appended_segment),
            bytes,
            events,
        }
    }

    /// Returns the stored event-log segment delta, when one was appended.
    #[must_use]
    pub fn cow_delta_ref(self) -> Option<CowDeltaRef> {
        self.appended_segment
            .map(|segment| CowDeltaRef::new(CowDeltaKind::EventLogSegment, segment))
    }
}

/// The CoW namespace for a content-addressed delta object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CowDeltaKind {
    /// Dirty VM memory or device-state pages for one node.
    VmMemory,
    /// Dirty block/9p overlay pages for one device.
    DeviceOverlay,
    /// Decisions appended after a checkpoint parent.
    ScheduleDelta,
    /// Event-log bytes appended after a checkpoint parent.
    EventLogSegment,
}

/// A typed content-addressed CoW delta object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CowDeltaRef {
    /// The delta namespace.
    pub kind: CowDeltaKind,
    /// The canonical content hash of the stored delta bytes.
    pub content: ContentHash,
}

impl CowDeltaRef {
    /// Builds a typed CoW delta reference.
    #[must_use]
    pub fn new(kind: CowDeltaKind, content: ContentHash) -> Self {
        Self { kind, content }
    }
}

/// CoW sharing accounting for a checkpoint set.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct CowSharingStats {
    /// Total logical references to CoW objects before content-address dedup.
    pub logical_references: usize,
    /// Unique typed content hashes that must be stored.
    pub unique_objects: usize,
}

impl CowSharingStats {
    /// Computes sharing stats from logical CoW references.
    #[must_use]
    pub fn from_refs<I>(refs: I) -> Self
    where
        I: IntoIterator<Item = CowDeltaRef>,
    {
        let mut logical_references = 0;
        let mut unique_refs = BTreeSet::new();
        for cow_ref in refs {
            logical_references += 1;
            unique_refs.insert(cow_ref);
        }
        Self {
            logical_references,
            unique_objects: unique_refs.len(),
        }
    }

    /// Returns references eliminated by content-addressed sharing.
    #[must_use]
    pub fn deduped_references(&self) -> usize {
        self.logical_references.saturating_sub(self.unique_objects)
    }
}

/// The cached realization carried by a fat checkpoint.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MaterializedState {
    /// Content address of the materialized runtime/cache payload.
    pub id: ContentHash,
    /// Per-VM snapshot refs and the icount at which each was taken.
    pub vm_snapshots: BTreeMap<NodeId, VmSnapshotRef>,
    /// Per-device CoW overlay deltas and device RNG state.
    pub device_overlays: BTreeMap<DeviceId, DeviceOverlayDelta>,
    /// Scheduler state required to resume cross-node ordering.
    pub scheduler: SchedulerState,
    /// Harness decision-RNG cursor positions.
    pub decision_rng: DecisionRngState,
    /// Event-log prefix position at this checkpoint.
    pub event_log: EventLogOffset,
    /// Event-log segment keys retained for shared-store debugging/fork fetches.
    pub event_log_segments: Vec<ContentHash>,
}

impl MaterializedState {
    /// Builds a legacy materialized-state handle from an existing content address.
    ///
    /// The resulting value is not sufficient for a loadable fat checkpoint
    /// unless `id` is the canonical hash of the empty component set. Use
    /// [`Self::from_components`] for loadable checkpoint state.
    #[must_use]
    pub fn from_content_hash(id: ContentHash) -> Self {
        Self {
            id,
            vm_snapshots: BTreeMap::new(),
            device_overlays: BTreeMap::new(),
            scheduler: SchedulerState::empty(),
            decision_rng: DecisionRngState::empty(),
            event_log: EventLogOffset::default(),
            event_log_segments: Vec::new(),
        }
    }

    /// Builds a materialized state from content-addressed components.
    #[must_use]
    pub fn from_components(
        vm_snapshots: BTreeMap<NodeId, VmSnapshotRef>,
        device_overlays: BTreeMap<DeviceId, DeviceOverlayDelta>,
        scheduler: SchedulerState,
        decision_rng: DecisionRngState,
        event_log: EventLogOffset,
    ) -> Self {
        Self::from_components_with_event_log_segments(
            vm_snapshots,
            device_overlays,
            scheduler,
            decision_rng,
            event_log,
            event_log.appended_segment,
        )
    }

    /// Builds a materialized state with explicit retained event-log segment keys.
    #[must_use]
    pub fn from_components_with_event_log_segments<I>(
        vm_snapshots: BTreeMap<NodeId, VmSnapshotRef>,
        device_overlays: BTreeMap<DeviceId, DeviceOverlayDelta>,
        scheduler: SchedulerState,
        decision_rng: DecisionRngState,
        event_log: EventLogOffset,
        event_log_segments: I,
    ) -> Self
    where
        I: IntoIterator<Item = ContentHash>,
    {
        let id = canonical::materialized_state_hash(
            &vm_snapshots,
            &device_overlays,
            &scheduler,
            &decision_rng,
            event_log,
        );
        let mut event_log_segments = event_log_segments.into_iter().collect::<Vec<_>>();
        if let Some(segment) = event_log.appended_segment {
            event_log_segments.push(segment);
        }
        Self {
            id,
            vm_snapshots,
            device_overlays,
            scheduler,
            decision_rng,
            event_log,
            event_log_segments: sorted_unique_hashes(event_log_segments),
        }
    }

    /// Builds an empty structured materialized state.
    #[must_use]
    pub fn empty() -> Self {
        Self::from_components(
            BTreeMap::new(),
            BTreeMap::new(),
            SchedulerState::empty(),
            DecisionRngState::empty(),
            EventLogOffset::default(),
        )
    }

    /// Builds a materialized state from checkpoint VM refs.
    #[must_use]
    pub fn from_checkpoint_parts(
        node_icounts: &BTreeMap<NodeId, Icount>,
        node_blobs: &BTreeMap<NodeId, NodeBlobRef>,
    ) -> Self {
        Self::from_components(
            materialized_vm_snapshots(node_icounts, node_blobs),
            BTreeMap::new(),
            SchedulerState::empty(),
            DecisionRngState::empty(),
            EventLogOffset::default(),
        )
    }

    /// Enumerates logical CoW delta refs stored by this materialized state.
    #[must_use]
    pub fn cow_delta_refs(&self) -> Vec<CowDeltaRef> {
        let mut refs = Vec::new();
        refs.extend(
            self.vm_snapshots
                .values()
                .filter_map(|snapshot| snapshot.blob.cow_delta_ref()),
        );
        refs.extend(
            self.device_overlays
                .values()
                .map(DeviceOverlayDelta::cow_delta_ref),
        );
        if self.event_log_segments.is_empty() {
            if let Some(event_log) = self.event_log.cow_delta_ref() {
                refs.push(event_log);
            }
        } else {
            refs.extend(
                self.event_log_segments
                    .iter()
                    .copied()
                    .map(|segment| CowDeltaRef::new(CowDeltaKind::EventLogSegment, segment)),
            );
        }
        refs
    }
}

/// Identity-irrelevant checkpoint metadata.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct CheckpointMeta {
    /// Human/debug annotations that must not affect [`Checkpoint::id`].
    pub labels: BTreeMap<String, String>,
}

impl CheckpointMeta {
    /// Builds empty checkpoint metadata.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            labels: BTreeMap::new(),
        }
    }

    /// Builds checkpoint metadata from key/value annotations.
    #[must_use]
    pub fn from_labels(labels: BTreeMap<String, String>) -> Self {
        Self { labels }
    }
}

/// A checkpoint handle in the temporal graph.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Checkpoint {
    /// The checkpoint content address.
    pub id: ContentHash,
    /// The configuration this checkpoint materializes.
    pub configuration: ContentHash,
    /// The scenario definition this checkpoint belongs to.
    pub scenario_ref: ContentHash,
    /// The parent checkpoint id, or `None` for genesis.
    pub parent: Option<ContentHash>,
    /// The decisions appended after `parent` to reach this checkpoint.
    pub schedule_delta: Schedule,
    /// The shared virtual-time coordinate at this checkpoint.
    pub virtual_time: VirtualTime,
    /// Per-node instruction counters at this checkpoint.
    pub node_icounts: BTreeMap<NodeId, Icount>,
    /// The materialized state, when this is a fat checkpoint.
    pub state: Option<MaterializedState>,
    /// Observation-only coverage fingerprint for this checkpoint.
    pub coverage_fingerprint: ContentHash,
    /// Observation-only assertion-proximity fingerprint for guided search.
    pub assertion_proximity_fingerprint: ContentHash,
    /// Identity-irrelevant metadata for humans and cache policy.
    pub metadata: CheckpointMeta,
    /// Per-node VM-state blob references.
    pub node_blobs: BTreeMap<NodeId, NodeBlobRef>,
    /// Content address of the concrete production continuation closure.
    ///
    /// This is distinct from [`Self::id`], which names model configuration.
    /// Production resume requires this reference for the VMState, host-I/O,
    /// scheduler, trigger, fault-runtime, and lifecycle-state closure. Pure
    /// model checkpoints leave it absent.
    pub execution_closure: Option<ContentHash>,
    /// Whether this is a fat or thin checkpoint.
    pub kind: CheckpointKind,
}

impl Checkpoint {
    /// Builds a checkpoint handle with no recorded VM blob references.
    #[must_use]
    pub fn new(id: ContentHash, configuration: ContentHash, kind: CheckpointKind) -> Self {
        Self::with_node_blobs(id, configuration, kind, BTreeMap::new())
    }

    /// Builds the recorded checkpoint node for `configuration`.
    ///
    /// The checkpoint node identity is the recorded [`Configuration::id`].
    /// `parent` and `schedule_delta` are derived from the supplied parent
    /// configuration and must reconstruct the same configuration identity.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::CheckpointTopologyMismatch`] when a non-genesis
    /// checkpoint has no parent, a genesis checkpoint has a parent, the parent
    /// belongs to another scenario, or the parent schedule is not a prefix of
    /// the checkpoint schedule. Returns [`EngineError::SchedulePrefix`] when
    /// the schedule prefix/suffix cannot be constructed.
    pub fn from_recorded_configuration(
        configuration: &Configuration,
        parent: Option<&Configuration>,
        virtual_time: VirtualTime,
        node_icounts: BTreeMap<NodeId, Icount>,
        kind: CheckpointKind,
        node_blobs: BTreeMap<NodeId, NodeBlobRef>,
    ) -> Result<Self, EngineError> {
        let (parent, schedule_delta) = checkpoint_edge(configuration, parent)?;
        let state = materialized_state_for_kind_with_scheduler(
            kind,
            &node_icounts,
            &node_blobs,
            scheduler_state_for_configuration(configuration),
        );
        Ok(Self {
            id: configuration.id(),
            configuration: configuration.id(),
            scenario_ref: configuration.def.id,
            parent,
            schedule_delta,
            virtual_time,
            state,
            node_icounts,
            coverage_fingerprint: ContentHash::default(),
            assertion_proximity_fingerprint: ContentHash::default(),
            metadata: CheckpointMeta::empty(),
            node_blobs,
            execution_closure: None,
            kind,
        })
    }

    /// Builds a checkpoint handle with explicit per-node VM blob references.
    #[must_use]
    pub fn with_node_blobs(
        id: ContentHash,
        configuration: ContentHash,
        kind: CheckpointKind,
        node_blobs: BTreeMap<NodeId, NodeBlobRef>,
    ) -> Self {
        Self {
            id,
            configuration,
            scenario_ref: ContentHash::default(),
            parent: None,
            schedule_delta: Schedule::empty(),
            virtual_time: VirtualTime::default(),
            node_icounts: BTreeMap::new(),
            state: materialized_state_for_kind(kind, &BTreeMap::new(), &node_blobs),
            coverage_fingerprint: ContentHash::default(),
            assertion_proximity_fingerprint: ContentHash::default(),
            metadata: CheckpointMeta::empty(),
            node_blobs,
            execution_closure: None,
            kind,
        }
    }

    /// Replaces the optional materialized state without changing identity.
    #[must_use]
    pub fn with_materialized_state(mut self, state: Option<MaterializedState>) -> Self {
        self.kind = if state.is_some() {
            CheckpointKind::Fat
        } else {
            CheckpointKind::Thin
        };
        self.state = state;
        self
    }

    /// Attaches the concrete production continuation closure to this checkpoint.
    #[must_use]
    pub fn with_execution_closure(mut self, closure: ContentHash) -> Self {
        self.execution_closure = Some(closure);
        self
    }

    /// Replaces the observation-only coverage fingerprint without changing identity.
    #[must_use]
    pub fn with_coverage_fingerprint(mut self, coverage_fingerprint: ContentHash) -> Self {
        self.coverage_fingerprint = coverage_fingerprint;
        self
    }

    /// Derives and replaces the observation-only coverage fingerprint from the event log.
    ///
    /// The checkpoint identity is unchanged: coverage is search/fuzzing feedback,
    /// not execution state. The fingerprint is derived from the scheduler event-log
    /// coverage projection, so callers with retained log entries do not maintain a
    /// parallel coverage record.
    #[must_use]
    pub fn with_coverage_from_event_log(
        mut self,
        entries: &[crate::scheduler::SchedulerEventLogEntry],
    ) -> Self {
        self.coverage_fingerprint = crate::scheduler::coverage_fingerprint_from_event_log(entries);
        self
    }

    /// Derives assertion-proximity feedback from the event log without changing identity.
    ///
    /// The checkpoint stores only the deterministic minimum-distance projection
    /// digest. The proximity records themselves remain unified event-log entries,
    /// avoiding a second steering record parallel to the log.
    #[must_use]
    pub fn with_assertion_proximity_from_event_log(
        mut self,
        entries: &[crate::scheduler::SchedulerEventLogEntry],
    ) -> Self {
        self.assertion_proximity_fingerprint =
            crate::scheduler::assertion_proximity_fingerprint_from_event_log(entries);
        self
    }

    /// Replaces identity-irrelevant metadata without changing identity.
    #[must_use]
    pub fn with_metadata(mut self, metadata: CheckpointMeta) -> Self {
        self.metadata = metadata;
        self
    }

    /// Returns the VM-state blob reference for `node`, when one is recorded.
    #[must_use]
    pub fn node_blob(&self, node: &NodeId) -> Option<&NodeBlobRef> {
        self.node_blobs.get(node)
    }

    /// Returns the canonical-relabeling fingerprint used by symmetry reduction.
    ///
    /// Checkpoints with no observed coverage fingerprint, no loadable
    /// materialized state, no explicit symmetry classes, or ambiguous canonical
    /// relabeling return `None`, forcing search to explore rather than assume
    /// equivalence.
    #[must_use]
    pub fn symmetry_reduction_key(
        &self,
        classes: &SymmetryReductionClasses,
    ) -> Option<SymmetryReductionKey> {
        checkpoint_symmetry_reduction_key(self, classes)
    }

    /// Enumerates logical CoW delta refs stored by this checkpoint.
    #[must_use]
    pub fn cow_delta_refs(&self) -> Vec<CowDeltaRef> {
        let mut refs = Vec::new();
        if !self.schedule_delta.is_empty() {
            refs.push(CowDeltaRef::new(
                CowDeltaKind::ScheduleDelta,
                self.schedule_delta.content_hash(),
            ));
        }
        if let Some(state) = &self.state {
            refs.extend(state.cow_delta_refs());
        }
        refs
    }

    /// Serializes this checkpoint as compact canonical bytes.
    #[must_use]
    pub fn to_compact_binary(&self) -> Vec<u8> {
        let mut writer = ScenarioBinaryWriter::new(CHECKPOINT_BINARY_MAGIC);
        write_checkpoint_binary(self, &mut writer);
        writer.finish()
    }

    /// Parses and validates a compact checkpoint payload.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] when the payload is
    /// malformed, when embedded materialized-state identity fields do not
    /// match their decoded components, or when the outer checkpoint shape is
    /// internally inconsistent.
    pub fn from_compact_binary(bytes: &[u8]) -> Result<Self, EngineError> {
        let mut reader = ScenarioBinaryReader::new(bytes, CHECKPOINT_BINARY_MAGIC)?;
        let checkpoint = read_checkpoint_binary(&mut reader)?;
        validate_checkpoint_binary_shape(&checkpoint)?;
        reader.finish()?;
        Ok(checkpoint)
    }
}

/// The storage shape of a checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CheckpointKind {
    /// A self-contained materialized checkpoint.
    Fat,
    /// A checkpoint represented by ancestor plus schedule delta.
    Thin,
}

/// Why a checkpoint is being considered for materialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MaterializationTrigger {
    /// The checkpoint is repeatedly used as a fork source.
    RepeatedForkSource,
    /// The checkpoint is on a replay path shared by many descendants.
    SharedReplayPath,
    /// The checkpoint is the target of an interactive session.
    InteractiveTarget,
    /// The checkpoint is cold and should remain thin unless explicitly saved.
    Cold,
}

impl MaterializationTrigger {
    /// Returns whether this trigger identifies a hot node.
    #[must_use]
    pub const fn is_hot(self) -> bool {
        matches!(
            self,
            Self::RepeatedForkSource | Self::SharedReplayPath | Self::InteractiveTarget
        )
    }
}

/// Advisory budget for turning thin checkpoints into fat cache entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MaterializationPolicy {
    /// Maximum number of non-genesis fat checkpoint cache entries to keep.
    pub max_fat_checkpoints: usize,
}

impl MaterializationPolicy {
    /// Builds a policy that permits at most `max_fat_checkpoints` fat caches.
    #[must_use]
    pub const fn with_budget(max_fat_checkpoints: usize) -> Self {
        Self {
            max_fat_checkpoints,
        }
    }

    /// Builds a policy that keeps every ordinary checkpoint thin.
    #[must_use]
    pub const fn thin_only() -> Self {
        Self::with_budget(0)
    }

    /// Returns whether a new fat cache entry should be created.
    #[must_use]
    pub const fn should_materialize(
        self,
        current_fat_checkpoints: usize,
        trigger: MaterializationTrigger,
    ) -> bool {
        trigger.is_hot() && current_fat_checkpoints < self.max_fat_checkpoints
    }
}

/// Deterministic replay-oracle sampling policy for active graph search.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SearchReplayOracleSamplingConfig {
    pub(super) numerator: u64,
    pub(super) denominator: u64,
    pub(super) seed_tag: String,
}

impl SearchReplayOracleSamplingConfig {
    /// Builds a deterministic sampling-rate configuration.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::InvalidSearchReplayOracleSamplingConfig`] when the
    /// denominator is zero, numerator is zero, numerator exceeds denominator, or
    /// the seed tag is empty.
    pub fn new(
        numerator: u64,
        denominator: u64,
        seed_tag: impl Into<String>,
    ) -> Result<Self, EngineError> {
        if denominator == 0 {
            return Err(EngineError::InvalidSearchReplayOracleSamplingConfig {
                reason: "sampling denominator must be non-zero",
            });
        }
        if numerator == 0 {
            return Err(EngineError::InvalidSearchReplayOracleSamplingConfig {
                reason: "sampling numerator must be non-zero",
            });
        }
        if numerator > denominator {
            return Err(EngineError::InvalidSearchReplayOracleSamplingConfig {
                reason: "sampling numerator cannot exceed denominator",
            });
        }
        let seed_tag = seed_tag.into();
        if seed_tag.is_empty() {
            return Err(EngineError::InvalidSearchReplayOracleSamplingConfig {
                reason: "sampling seed tag must be non-empty",
            });
        }

        Ok(Self {
            numerator,
            denominator,
            seed_tag,
        })
    }

    /// Returns the sampling-rate numerator.
    #[must_use]
    pub const fn numerator(&self) -> u64 {
        self.numerator
    }

    /// Returns the sampling-rate denominator.
    #[must_use]
    pub const fn denominator(&self) -> u64 {
        self.denominator
    }

    /// Returns the deterministic sampling seed tag.
    #[must_use]
    pub fn seed_tag(&self) -> &str {
        &self.seed_tag
    }

    pub(super) fn samples(&self, sequence: u64, checkpoint: ContentHash) -> bool {
        search_replay_oracle_sampling_score(&self.seed_tag, sequence, checkpoint) % self.denominator
            < self.numerator
    }
}
