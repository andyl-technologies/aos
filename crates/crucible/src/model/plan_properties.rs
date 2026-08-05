//! Declarative plans, assertions, predicates, and properties.

use super::*;

/// One entry in the declarative membership-fault plan.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PlanEntry {
    /// Activate a membership fault at an exact virtual time.
    Activate {
        /// Virtual time when the fault activates.
        at: VirtualTime,
        /// Stable tag used by a later heal.
        tag: FaultTag,
        /// Membership fault to layer over the static world.
        fault: MembershipFault,
    },
    /// Heal, restart, or rejoin a previously activated fault tag at an exact virtual time.
    Heal {
        /// Virtual time when the fault heals.
        at: VirtualTime,
        /// Stable tag naming the fault to heal.
        tag: FaultTag,
    },
}

/// One entry in the full-taxonomy declarative [`FaultPlan`] body.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FaultPlanEntry {
    /// Activate a fault at `at` and automatically heal it after `duration`.
    At {
        /// Virtual time when the fault activates.
        at: VirtualTime,
        /// Finite virtual-time duration before the automatic heal event.
        duration: FaultDuration,
        /// Stable tag shared by the injected fault and automatic heal.
        tag: FaultTag,
        /// Full taxonomy fault to activate.
        fault: Fault,
    },
    /// Activate a fault at `at` until an explicit [`Self::Heal`] entry fires.
    PermanentAt {
        /// Virtual time when the fault activates.
        at: VirtualTime,
        /// Stable tag used by a later explicit heal.
        tag: FaultTag,
        /// Full taxonomy fault to activate.
        fault: Fault,
    },
    /// Heal a previously injected tag at an exact virtual time.
    Heal {
        /// Virtual time when the fault heals.
        at: VirtualTime,
        /// Stable tag naming the fault to heal.
        tag: FaultTag,
    },
}

/// A declarative full-taxonomy fault plan layered over a static [`World`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct FaultPlan {
    pub(super) entries: Vec<FaultPlanEntry>,
}

impl FaultPlan {
    /// Builds an empty full-taxonomy fault plan.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Builds a fault plan in canonical entry order without world validation.
    #[must_use]
    pub fn from_entries(entries: Vec<FaultPlanEntry>) -> Self {
        Self {
            entries: canonical_fault_plan_entries(&entries),
        }
    }

    /// Builds a fault plan after validating every entry against `world`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::PlanFaultUnknownNode`],
    /// [`EngineError::PlanFaultUnknownLinkId`],
    /// [`EngineError::PlanFaultUnknownDevice`],
    /// [`EngineError::PlanFaultDeviceKindMismatch`],
    /// [`EngineError::PlanHealUnknownTag`],
    /// [`EngineError::PlanHealBeforeActivate`], or
    /// [`EngineError::PlanFaultDurationOverflow`] when an entry cannot be
    /// reduced to exact virtual-time fault actions for the supplied world.
    pub fn from_entries_for_world(
        world: &World,
        entries: Vec<FaultPlanEntry>,
    ) -> Result<Self, EngineError> {
        validate_fault_plan_entries_for_world(world, &entries)?;
        Ok(Self::from_entries(entries))
    }

    /// Returns fault-plan entries in canonical order.
    #[must_use]
    pub fn entries(&self) -> &[FaultPlanEntry] {
        &self.entries
    }
}

/// Configuration for deterministic random [`FaultPlan`] generation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RandomFaultConfig {
    /// Number of fault-generation slots to draw before deterministic pruning.
    pub fault_slots: u32,
    /// Total virtual-time span that generated finite faults must fit inside.
    pub duration: FaultDuration,
    /// Integer relative weights used for weighted fault-kind selection.
    pub weights: FaultWeights,
    /// Inclusive severity bounds used when drawing kind-specific parameters.
    pub bounds: SeverityBounds,
    /// Integer caps enforced by deterministic generation-order pruning.
    pub caps: FaultCaps,
    /// Root seed for the generator's single deterministic RNG stream.
    pub seed: Seed,
}

impl RandomFaultConfig {
    /// Generates a validated, canonically ordered fault plan for `world`.
    ///
    /// The same configuration and world always produce a byte-identical
    /// [`FaultPlan`]. Generated entries are finite [`FaultPlanEntry::At`] faults
    /// and are validated through [`FaultPlan::from_entries_for_world`] before
    /// returning, so unsupported targets cannot escape this API.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::RandomFaultConfigInvalid`] when the configuration
    /// has no legal target/kind space or its bounds are inconsistent, or any
    /// [`FaultPlan`] validation error if the generated entries do not layer over
    /// `world`.
    pub fn generate_for_world(&self, world: &World) -> Result<FaultPlan, EngineError> {
        validate_random_fault_config(self)?;
        if self.fault_slots == 0 || self.caps.max_concurrent_faults == 0 {
            return Ok(FaultPlan::empty());
        }

        let nodes = random_fault_nodes(world);
        let links = random_fault_links(world);
        let block_devices = random_fault_devices(world, WorldDeviceKind::Block);
        let ninep_devices = random_fault_devices(world, WorldDeviceKind::NineP);
        let kinds = eligible_random_fault_kinds(
            &self.weights,
            !nodes.is_empty(),
            !links.is_empty(),
            !block_devices.is_empty(),
            !ninep_devices.is_empty(),
        );
        if kinds.is_empty() {
            return Err(EngineError::RandomFaultConfigInvalid {
                reason: "no weighted random fault kind has a valid target in the world",
            });
        }

        let mut stream = self.seed.decision_rng().fork_in_domain(
            RANDOM_FAULT_CONFIG_RNG_DOMAIN,
            &random_fault_config_material(self, world),
        );
        let mut generated = Vec::with_capacity(self.fault_slots as usize);
        for slot in 0..self.fault_slots {
            let start = draw_random_fault_start(&mut stream, self)?;
            let active_duration = draw_random_fault_duration(&mut stream, self, start)?;
            let kind = draw_random_fault_kind(&mut stream, &kinds)?;
            let fault = draw_random_fault(
                &mut stream,
                self,
                kind,
                &nodes,
                &links,
                &block_devices,
                &ninep_devices,
            )?;
            generated.push(RandomFaultCandidate {
                order: slot,
                start,
                end: start.saturating_add(active_duration.nanos()),
                kind,
                entry: FaultPlanEntry::At {
                    at: VirtualTime { ticks: start },
                    duration: active_duration,
                    tag: FaultTag::from_name(format!("random-fault-{slot:016}")),
                    fault,
                },
            });
        }

        let entries = prune_random_fault_candidates(generated, self.caps)
            .into_iter()
            .map(|candidate| candidate.entry)
            .collect();
        FaultPlan::from_entries_for_world(world, entries)
    }
}

/// Integer relative weights for each generated fault kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FaultWeights {
    /// Weight for network partition faults.
    pub partition: u32,
    /// Weight for network message-loss faults.
    pub message_loss: u32,
    /// Weight for network reorder-window faults.
    pub reorder: u32,
    /// Weight for network duplicate-delivery faults.
    pub duplicate: u32,
    /// Weight for network corruption faults.
    pub corruption: u32,
    /// Weight for network bandwidth-limit faults.
    pub bandwidth_limit: u32,
    /// Weight for network latency-bump faults.
    pub latency_bump: u32,
    /// Weight for node crash faults.
    pub crash: u32,
    /// Weight for node slowdown faults.
    pub slow: u32,
    /// Weight for node clock-skew faults.
    pub clock_skew: u32,
    /// Weight for block-device latency faults.
    pub block_latency: u32,
    /// Weight for block-device failure faults.
    pub block_failure: u32,
    /// Weight for block-device completion-reorder faults.
    pub block_reorder: u32,
    /// Weight for 9p-device latency faults.
    pub ninep_latency: u32,
    /// Weight for 9p-device failure faults.
    pub ninep_failure: u32,
}

impl Default for FaultWeights {
    fn default() -> Self {
        Self {
            partition: 1,
            message_loss: 1,
            reorder: 1,
            duplicate: 1,
            corruption: 1,
            bandwidth_limit: 1,
            latency_bump: 1,
            crash: 1,
            slow: 1,
            clock_skew: 1,
            block_latency: 0,
            block_failure: 0,
            block_reorder: 0,
            ninep_latency: 0,
            ninep_failure: 0,
        }
    }
}

/// Inclusive severity bounds for generated fault parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SeverityBounds {
    /// Minimum finite active duration for generated faults.
    pub min_duration: FaultDuration,
    /// Maximum finite active duration for generated faults.
    pub max_duration: FaultDuration,
    /// Minimum basis-point rate for probabilistic generated faults.
    pub min_rate: FaultRateBasisPoints,
    /// Maximum basis-point rate for probabilistic generated faults.
    pub max_rate: FaultRateBasisPoints,
    /// Minimum latency-like duration for generated latency faults.
    pub min_latency: FaultDuration,
    /// Maximum latency-like duration for generated latency faults.
    pub max_latency: FaultDuration,
    /// Minimum reorder window for generated reorder faults.
    pub min_reorder_window: FaultDuration,
    /// Maximum reorder window for generated reorder faults.
    pub max_reorder_window: FaultDuration,
    /// Minimum duplicate gap for generated duplicate faults.
    pub min_duplicate_gap: FaultDuration,
    /// Maximum duplicate gap for generated duplicate faults.
    pub max_duplicate_gap: FaultDuration,
    /// Minimum generated bandwidth limit.
    pub min_bandwidth: FaultBandwidthBitsPerSecond,
    /// Maximum generated bandwidth limit.
    pub max_bandwidth: FaultBandwidthBitsPerSecond,
    /// Minimum generated slowdown factor.
    pub min_slowdown: FaultSlowdownFactorBasisPoints,
    /// Maximum generated slowdown factor.
    pub max_slowdown: FaultSlowdownFactorBasisPoints,
    /// Minimum generated guest-visible clock skew.
    pub min_clock_skew: SimOffset,
    /// Maximum generated guest-visible clock skew.
    pub max_clock_skew: SimOffset,
    /// Minimum generated bit-flip count.
    pub min_corruption_bits: u32,
    /// Maximum generated bit-flip count.
    pub max_corruption_bits: u32,
    /// Minimum generated truncation byte count.
    pub min_truncation_bytes: u64,
    /// Maximum generated truncation byte count.
    pub max_truncation_bytes: u64,
}

impl Default for SeverityBounds {
    fn default() -> Self {
        Self {
            min_duration: FaultDuration::from_nanos(1),
            max_duration: FaultDuration::from_nanos(100),
            min_rate: FaultRateBasisPoints { basis_points: 1 },
            max_rate: FaultRateBasisPoints {
                basis_points: MAX_FAULT_RATE_BASIS_POINTS as u16,
            },
            min_latency: FaultDuration::from_nanos(1),
            max_latency: FaultDuration::from_nanos(100),
            min_reorder_window: FaultDuration::from_nanos(1),
            max_reorder_window: FaultDuration::from_nanos(100),
            min_duplicate_gap: FaultDuration::from_nanos(1),
            max_duplicate_gap: FaultDuration::from_nanos(100),
            min_bandwidth: FaultBandwidthBitsPerSecond { bits_per_second: 1 },
            max_bandwidth: FaultBandwidthBitsPerSecond {
                bits_per_second: 1_000_000,
            },
            min_slowdown: FaultSlowdownFactorBasisPoints::ONE,
            max_slowdown: FaultSlowdownFactorBasisPoints {
                basis_points: 20_000,
            },
            min_clock_skew: SimOffset { nanos: -100 },
            max_clock_skew: SimOffset { nanos: 100 },
            min_corruption_bits: 1,
            max_corruption_bits: 16,
            min_truncation_bytes: 1,
            max_truncation_bytes: 4096,
        }
    }
}

/// Integer caps applied to generated fault campaigns.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FaultCaps {
    /// Maximum simultaneously active generated faults retained after pruning.
    pub max_concurrent_faults: u32,
    /// Maximum retained network partition faults.
    pub max_partitions: u32,
    /// Maximum retained node crash faults.
    pub max_crashes: u32,
}

impl Default for FaultCaps {
    fn default() -> Self {
        Self {
            max_concurrent_faults: u32::MAX,
            max_partitions: u32::MAX,
            max_crashes: u32::MAX,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RandomFaultCandidate {
    pub(super) order: u32,
    pub(super) start: u64,
    pub(super) end: u64,
    pub(super) kind: RandomFaultKind,
    pub(super) entry: FaultPlanEntry,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RandomFaultKind {
    Partition,
    MessageLoss,
    Reorder,
    Duplicate,
    Corruption,
    BandwidthLimit,
    LatencyBump,
    Crash,
    Slow,
    ClockSkew,
    BlockLatency,
    BlockFailure,
    BlockReorder,
    NinePLatency,
    NinePFailure,
}

/// A declarative fault plan layered over a static [`World`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Plan {
    /// The independently content-addressed plan identity.
    pub(super) id: ContentHash,
    pub(super) kind: PlanKind,
    pub(super) fault_signals: FaultSignalPlan,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) enum PlanKind {
    ScheduledEntries { entries: Vec<PlanEntry> },
    EventGraph { graph: EventGraph },
}

impl Default for Plan {
    fn default() -> Self {
        Self::empty()
    }
}

impl Plan {
    /// Builds an empty plan.
    #[must_use]
    pub fn empty() -> Self {
        let entries = Vec::new();
        Self::from_canonical_entries(entries)
    }

    /// Builds a plan after validating every entry against `world`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::PlanFaultUnknownNode`] when a membership fault
    /// names a node that is not declared by `world`,
    /// [`EngineError::PlanFaultUnknownLink`] when a partition names no declared
    /// link, [`EngineError::PlanHealUnknownTag`] when a heal names no activated
    /// fault tag in the plan, [`EngineError::PlanHealBeforeActivate`] when a
    /// heal is not after its activation, or
    /// [`EngineError::PlanNotYetJoinedAfterStart`] when an initial join hold is
    /// scheduled after `t = 0`.
    pub fn from_entries_for_world(
        world: &World,
        entries: Vec<PlanEntry>,
    ) -> Result<Self, EngineError> {
        validate_plan_entries_for_world(world, &entries)?;
        Ok(Self::from_canonical_entries(canonical_plan_entries(
            &entries,
        )))
    }

    /// Returns plan entries in their canonical order.
    ///
    /// Event-graph plans return an empty slice; use [`Self::event_graph`] to
    /// inspect graph-native plans.
    #[must_use]
    pub fn entries(&self) -> &[PlanEntry] {
        match &self.kind {
            PlanKind::ScheduledEntries { entries } => entries,
            PlanKind::EventGraph { .. } => &[],
        }
    }

    /// Returns the graph carried by this plan when it is graph-native.
    #[must_use]
    pub fn event_graph(&self) -> Option<&EventGraph> {
        match &self.kind {
            PlanKind::ScheduledEntries { .. } => None,
            PlanKind::EventGraph { graph } => Some(graph),
        }
    }

    /// Returns the scenario's signal-driven fault programs and bindings.
    #[must_use]
    pub const fn fault_signals(&self) -> &FaultSignalPlan {
        &self.fault_signals
    }

    /// Replaces the signal-driven fault layer and recomputes plan identity.
    #[must_use]
    pub fn with_fault_signals(self, fault_signals: FaultSignalPlan) -> Self {
        Self::from_canonical_parts(self.kind, fault_signals)
    }

    /// Builds a graph-native plan after validating it against `world`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] when event-graph
    /// validation rejects the graph for the supplied world namespace.
    pub fn from_event_graph_for_world(
        world: &World,
        graph: EventGraph,
    ) -> Result<Self, EngineError> {
        Self::from_event_graph_with_assertions_for_world(world, [], graph)
    }

    /// Builds a graph-native plan with assertion ids available to triggers.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] when event-graph
    /// validation rejects the graph for the supplied world and assertion
    /// namespaces.
    pub fn from_event_graph_with_assertions_for_world(
        world: &World,
        assertions: impl IntoIterator<Item = AssertionId>,
        graph: EventGraph,
    ) -> Result<Self, EngineError> {
        let assertions = assertions.into_iter().collect::<Vec<_>>();
        let graph = resolve_event_graph_dsl_for_world(world, &graph);
        let graph =
            validate_event_graph_plan(world, assertions, graph).map_err(event_graph_plan_error)?;
        Ok(Self::from_canonical_event_graph(graph))
    }

    /// Computes the canonical identity of this plan.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        self.id
    }

    /// Serializes this plan component as deterministic TOML.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] if the TOML renderer rejects
    /// the internal DTO shape.
    pub fn to_canonical_toml(&self) -> Result<String, EngineError> {
        toml::to_string(&plan_to_toml(self)?).map_err(|source| {
            scenario_serialization_error(format!("serialize plan TOML: {source}"))
        })
    }

    /// Parses and validates a deterministic TOML plan component for `world`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] for malformed TOML or an id
    /// mismatch, [`EngineError::PlanNegativeTime`],
    /// [`EngineError::PlanFaultUnknownDirection`], or
    /// [`EngineError::PlanFaultUnsupportedParam`] for localized serialized plan
    /// validation failures, or a plan validation error when the parsed entries do
    /// not layer over `world`.
    pub fn from_canonical_toml_for_world(world: &World, input: &str) -> Result<Self, EngineError> {
        validate_scenario_toml_size(input)?;
        validate_plan_entries_in_toml(input)?;
        let toml = toml::from_str::<PlanToml>(input)
            .map_err(|source| scenario_serialization_error(format!("parse plan TOML: {source}")))?;
        plan_from_toml(world, toml)
    }

    /// Parses and validates a deterministic TOML plan component with assertion ids.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::from_canonical_toml_for_world`], and
    /// also rejects assertion-state triggers that reference ids outside
    /// `assertions`.
    pub fn from_canonical_toml_with_assertions_for_world(
        world: &World,
        assertions: impl IntoIterator<Item = AssertionId>,
        input: &str,
    ) -> Result<Self, EngineError> {
        validate_scenario_toml_size(input)?;
        validate_plan_entries_in_toml(input)?;
        let toml = toml::from_str::<PlanToml>(input)
            .map_err(|source| scenario_serialization_error(format!("parse plan TOML: {source}")))?;
        plan_from_toml_with_assertions(world, assertions, toml)
    }

    /// Serializes this plan component as compact binary.
    #[must_use]
    pub fn to_compact_binary(&self) -> Vec<u8> {
        let mut writer = ScenarioBinaryWriter::new(PLAN_BINARY_MAGIC);
        write_plan_binary(self, &mut writer);
        writer.finish()
    }

    /// Parses and validates a compact binary plan component for `world`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] for malformed binary input
    /// or an id mismatch, or a plan validation error when the parsed entries do
    /// not layer over `world`.
    pub fn from_compact_binary_for_world(world: &World, bytes: &[u8]) -> Result<Self, EngineError> {
        let mut reader = ScenarioBinaryReader::new(bytes, PLAN_BINARY_MAGIC)?;
        let plan = read_plan_binary(world, [], &mut reader)?;
        reader.finish()?;
        Ok(plan)
    }

    /// Parses and validates a compact binary plan component with assertion ids.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::from_compact_binary_for_world`], and
    /// also rejects assertion-state triggers that reference ids outside
    /// `assertions`.
    pub fn from_compact_binary_with_assertions_for_world(
        world: &World,
        assertions: impl IntoIterator<Item = AssertionId>,
        bytes: &[u8],
    ) -> Result<Self, EngineError> {
        let mut reader = ScenarioBinaryReader::new(bytes, PLAN_BINARY_MAGIC)?;
        let plan = read_plan_binary(world, assertions, &mut reader)?;
        reader.finish()?;
        Ok(plan)
    }

    /// Returns the canonical bytes used to compute this plan's content address.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        plan_material(self).into_bytes()
    }

    /// Validates this plan against `world`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::PlanFaultUnknownNode`],
    /// [`EngineError::PlanFaultUnknownLink`],
    /// [`EngineError::PlanFaultUnknownLinkId`],
    /// [`EngineError::PlanFaultUnknownDevice`],
    /// [`EngineError::PlanFaultDeviceKindMismatch`],
    /// [`EngineError::PlanHealUnknownTag`],
    /// [`EngineError::PlanHealBeforeActivate`],
    /// [`EngineError::PlanFaultDurationOverflow`], or
    /// [`EngineError::PlanNotYetJoinedAfterStart`] when an entry cannot be
    /// layered over the static world topology.
    pub fn validate_for_world(&self, world: &World) -> Result<(), EngineError> {
        self.validate_for_world_with_assertions(world, [])
    }

    pub(super) fn validate_for_world_with_properties(
        &self,
        world: &World,
        properties: &Properties,
    ) -> Result<(), EngineError> {
        self.validate_for_world_with_assertions(
            world,
            properties
                .assertions()
                .iter()
                .map(|assertion| assertion.id.clone()),
        )
    }

    fn validate_for_world_with_assertions(
        &self,
        world: &World,
        assertions: impl IntoIterator<Item = AssertionId>,
    ) -> Result<(), EngineError> {
        match &self.kind {
            PlanKind::ScheduledEntries { entries } => {
                validate_plan_entries_for_world(world, entries)
            }
            PlanKind::EventGraph { graph } => {
                validate_event_graph_plan(world, assertions, graph.clone())
                    .map(|_| ())
                    .map_err(event_graph_plan_error)
            }
        }
    }

    fn from_canonical_entries(entries: Vec<PlanEntry>) -> Self {
        let kind = PlanKind::ScheduledEntries { entries };
        Self::from_canonical_kind(kind)
    }

    fn from_canonical_event_graph(graph: EventGraph) -> Self {
        Self::from_canonical_kind(PlanKind::EventGraph { graph })
    }

    fn from_canonical_kind(kind: PlanKind) -> Self {
        Self::from_canonical_parts(kind, FaultSignalPlan::empty())
    }

    fn from_canonical_parts(kind: PlanKind, fault_signals: FaultSignalPlan) -> Self {
        let material = plan_parts_material(&kind, &fault_signals);
        Self {
            id: ContentHash::from_canonical_material("crucible.model.plan.v3", &material),
            kind,
            fault_signals,
        }
    }
}

/// A stable assertion identifier inside a [`Properties`] bundle.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AssertionId {
    /// The canonical assertion name.
    pub name: String,
}

impl AssertionId {
    /// Builds an assertion id from a canonical name.
    #[must_use]
    pub fn from_name(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

/// A stable white-box marker identifier.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MarkerId {
    /// The canonical marker name.
    pub name: String,
}

impl MarkerId {
    /// Builds a marker id from a canonical name.
    #[must_use]
    pub fn from_name(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

/// Stable identity of an event inside an event graph.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventId {
    /// Canonical event name, unique within the graph.
    pub name: String,
}

impl EventId {
    /// Builds an event id from a canonical name.
    #[must_use]
    pub fn from_name(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

/// Stable identity of an observable network link.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LinkId {
    /// Canonical link name.
    pub name: String,
}

impl LinkId {
    /// Builds a link id from a canonical name.
    #[must_use]
    pub fn from_name(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

/// Host-side byte predicate for a delivered network frame.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum FramePredicate {
    /// Match any delivered frame.
    Any,
    /// Match a frame whose bytes exactly equal the declared bytes.
    Exact(Vec<u8>),
    /// Match a frame containing the declared byte sequence.
    Contains(Vec<u8>),
    /// Match a frame starting with the declared byte sequence.
    Prefix(Vec<u8>),
}

impl FramePredicate {
    /// Builds a predicate that matches any frame.
    #[must_use]
    pub const fn any() -> Self {
        Self::Any
    }

    /// Builds an exact frame-byte predicate.
    #[must_use]
    pub fn exact(bytes: impl Into<Vec<u8>>) -> Self {
        Self::Exact(bytes.into())
    }

    /// Builds a contained-byte-sequence frame predicate.
    #[must_use]
    pub fn contains(bytes: impl Into<Vec<u8>>) -> Self {
        Self::Contains(bytes.into())
    }

    /// Builds a prefix frame-byte predicate.
    #[must_use]
    pub fn prefix(bytes: impl Into<Vec<u8>>) -> Self {
        Self::Prefix(bytes.into())
    }
}

/// Bounded host-side regex program for console output.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RegexProgram {
    /// Regex pattern evaluated by the host over captured output bytes.
    pub pattern: String,
}

impl RegexProgram {
    /// Builds a regex program from a pattern string.
    #[must_use]
    pub fn from_pattern(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
        }
    }
}

/// Host-side reference to executable guest code.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CodePoint {
    /// Guest physical or virtual address resolved before evaluation.
    GuestAddress {
        /// Guest instruction address.
        address: u64,
    },
    /// Symbol resolved host-side against node-owned debug or symbol data.
    Symbol {
        /// Stable symbol name.
        name: String,
    },
}

impl CodePoint {
    /// Builds a raw guest-address code point.
    #[must_use]
    pub const fn guest_address(address: u64) -> Self {
        Self::GuestAddress { address }
    }

    /// Builds a host-resolved symbol code point.
    #[must_use]
    pub fn symbol(name: impl Into<String>) -> Self {
        Self::Symbol { name: name.into() }
    }
}

/// Width of a deterministic guest memory or register sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MemoryWidth {
    /// One byte.
    U8,
    /// Two bytes.
    U16,
    /// Four bytes.
    U32,
    /// Eight bytes.
    U64,
}

impl MemoryWidth {
    /// Returns the byte width of the sampled value.
    #[must_use]
    pub const fn bytes(self) -> u8 {
        match self {
            Self::U8 => 1,
            Self::U16 => 2,
            Self::U32 => 4,
            Self::U64 => 8,
        }
    }
}

/// Host-side reference to a deterministic guest memory or register sample.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MemPlace {
    /// Guest physical address sampled out of band.
    PhysicalAddress {
        /// Guest physical address.
        address: u64,
        /// Width to sample.
        width: MemoryWidth,
    },
    /// Guest virtual address sampled out of band.
    VirtualAddress {
        /// Guest virtual address.
        address: u64,
        /// Width to sample.
        width: MemoryWidth,
    },
    /// Host-resolved guest symbol.
    Symbol {
        /// Stable symbol name.
        name: String,
        /// Width to sample at the resolved symbol address.
        width: MemoryWidth,
    },
    /// Architectural register sampled out of band.
    Register {
        /// Stable register name.
        name: String,
        /// Width to sample.
        width: MemoryWidth,
    },
}

impl MemPlace {
    /// Builds a physical-address memory place.
    #[must_use]
    pub const fn physical_address(address: u64, width: MemoryWidth) -> Self {
        Self::PhysicalAddress { address, width }
    }

    /// Builds a virtual-address memory place.
    #[must_use]
    pub const fn virtual_address(address: u64, width: MemoryWidth) -> Self {
        Self::VirtualAddress { address, width }
    }

    /// Builds a symbol memory place resolved host-side.
    #[must_use]
    pub fn symbol(name: impl Into<String>, width: MemoryWidth) -> Self {
        Self::Symbol {
            name: name.into(),
            width,
        }
    }

    /// Builds a register memory place.
    #[must_use]
    pub fn register(name: impl Into<String>, width: MemoryWidth) -> Self {
        Self::Register {
            name: name.into(),
            width,
        }
    }
}

/// Unsigned comparison for deterministic memory samples.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MemoryCmp {
    /// Equal to the expected value.
    Eq,
    /// Not equal to the expected value.
    Ne,
    /// Less than the expected value.
    Lt,
    /// Less than or equal to the expected value.
    Le,
    /// Greater than the expected value.
    Gt,
    /// Greater than or equal to the expected value.
    Ge,
}

/// Observable I/O operation class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IoEventKind {
    /// Match any deterministic I/O completion.
    Any,
    /// A block-device read completed.
    BlockRead,
    /// A block-device write completed.
    BlockWrite,
    /// A durable flush completed.
    Fsync,
    /// A 9p filesystem operation completed.
    NineP,
    /// A network-device operation completed.
    Network,
}

/// Lifecycle state entered by a scenario node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NodeLifecycle {
    /// The node started or became runnable.
    Started,
    /// The node crashed.
    Crashed,
    /// The node stopped making forward progress within its deterministic window.
    Hung,
    /// The node exited or completed.
    Exited,
}

/// Terminal assertion state visible to trigger steering.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AssertionPhase {
    /// The assertion became satisfied.
    Satisfied,
    /// The assertion became violated.
    Violated,
}

/// Disposition for an ordinary reachable marker that is never reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReachableDisposition {
    /// Report a coverage warning when the marker is never reached.
    Warn,
    /// Treat the never-reached marker as a property failure.
    Fail,
}

/// Reachability expectation and never-reached policy for a coverage property.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReachabilityExpectation {
    /// The predicate is expected to become true at least once.
    Reachable {
        /// Disposition when the predicate is never reached.
        on_unreached: ReachableDisposition,
    },
    /// The predicate is expected to remain false throughout the run.
    Unreachable,
}

/// Schema version for the closed assertion property vocabulary.
///
/// The version covers the five temporal quantifiers, their binary tags, their
/// canonical material labels, and the TOML `kind` strings. Adding or removing a
/// quantifier is a schema change, not a runtime extension point.
pub const PROPERTY_SCHEMA_VERSION: u32 = 1;

/// Canonical material domain for [`Properties`] bundles.
///
/// The domain embeds [`PROPERTY_SCHEMA_VERSION`] through the `v1` suffix so a
/// quantifier schema change cannot collide with an older properties component.
pub const PROPERTY_SCHEMA_DOMAIN: &str = "crucible.model.properties.v1";

/// Number of temporal property quantifiers in the closed vocabulary.
pub const PROPERTY_QUANTIFIER_COUNT: usize = 5;

/// Closed set of temporal property quantifier kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PropertyKind {
    /// Invariant checked at every relevant evaluation point.
    Always,
    /// Liveness witness that must hold at least once.
    Sometimes,
    /// Bounded liveness property armed by a trigger predicate.
    Eventually,
    /// End-state property checked once at quiescence or run limit.
    AfterQuiescence,
    /// Coverage-style property, including the unreachable dual expectation.
    Reachable,
}

impl PropertyKind {
    /// Canonical closed-vocabulary order for the property schema.
    pub const ALL: [Self; PROPERTY_QUANTIFIER_COUNT] = [
        Self::Always,
        Self::Sometimes,
        Self::Eventually,
        Self::AfterQuiescence,
        Self::Reachable,
    ];

    /// Returns the compact-binary tag assigned to this property kind.
    #[must_use]
    pub const fn binary_tag(self) -> u8 {
        match self {
            Self::Always => 0,
            Self::Sometimes => 1,
            Self::Eventually => 2,
            Self::AfterQuiescence => 3,
            Self::Reachable => 4,
        }
    }

    /// Parses a compact-binary property kind tag.
    #[must_use]
    pub const fn from_binary_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Always),
            1 => Some(Self::Sometimes),
            2 => Some(Self::Eventually),
            3 => Some(Self::AfterQuiescence),
            4 => Some(Self::Reachable),
            _ => None,
        }
    }

    /// Returns the canonical material label for this property kind.
    #[must_use]
    pub const fn canonical_label(self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::Sometimes => "sometimes",
            Self::Eventually => "eventually",
            Self::AfterQuiescence => "after-quiescence",
            Self::Reachable => "reachable",
        }
    }

    /// Returns the deterministic TOML `kind` string for this property kind.
    #[must_use]
    pub const fn toml_kind(self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::Sometimes => "sometimes",
            Self::Eventually => "eventually",
            Self::AfterQuiescence => "after_quiescence",
            Self::Reachable => "reachable",
        }
    }

    /// Parses a deterministic TOML `kind` string.
    #[must_use]
    pub const fn from_toml_kind(kind: &str) -> Option<Self> {
        match kind.as_bytes() {
            b"always" => Some(Self::Always),
            b"sometimes" => Some(Self::Sometimes),
            b"eventually" => Some(Self::Eventually),
            b"after_quiescence" => Some(Self::AfterQuiescence),
            b"reachable" => Some(Self::Reachable),
            _ => None,
        }
    }
}

/// The shared declarative predicate vocabulary used by properties and triggers.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Predicate {
    /// True at one exact virtual time.
    At {
        /// Virtual time where the predicate becomes true.
        at: VirtualTime,
    },
    /// True after a duration from a referenced event's last firing.
    After {
        /// Virtual duration after the referenced event fires.
        duration: SimDuration,
        /// Event whose firing anchors the relative duration.
        of: EventId,
    },
    /// True when a named timer fires.
    Timer {
        /// Timer identity armed by an event action.
        name: TimerId,
    },
    /// True when a delivered network frame matches a host-side predicate.
    NetworkMatch {
        /// Optional link to constrain the delivered frame.
        link: Option<LinkId>,
        /// Host-side frame predicate.
        predicate: FramePredicate,
    },
    /// True when a node's captured console stream matches a regex.
    ConsoleMatch {
        /// Node whose console output is observed.
        node: NodeId,
        /// Host-side regex program matched against console bytes.
        regex: RegexProgram,
    },
    /// True when a node executes a host-resolved guest code point.
    CoveragePoint {
        /// Node whose execution is observed.
        node: NodeId,
        /// Guest code point observed by the TCG-exec hook.
        point: CodePoint,
    },
    /// True when a deterministic memory/register sample satisfies a comparison.
    MemoryPredicate {
        /// Node whose memory or register is sampled.
        node: NodeId,
        /// Host-side memory/register place.
        place: MemPlace,
        /// Unsigned comparison to apply to the sampled value.
        cmp: MemoryCmp,
        /// Expected comparison value.
        value: u64,
    },
    /// True when a node performs an I/O completion of the requested kind.
    IoPattern {
        /// Node whose deterministic I/O completion is observed.
        node: NodeId,
        /// I/O completion kind to match.
        kind: IoEventKind,
    },
    /// True when a node enters a lifecycle state.
    NodeState {
        /// Node whose lifecycle is observed.
        node: NodeId,
        /// Lifecycle state to match.
        state: NodeLifecycle,
    },
    /// True when a named assertion enters the requested terminal state.
    AssertionState {
        /// Assertion identity whose state transition is observed.
        name: AssertionId,
        /// Assertion state to match.
        state: AssertionPhase,
    },
    /// True when scheduler-owned quiescence evidence has no blockers.
    Quiescent,
    /// True when a declared fault tag is active at the evaluation point.
    FaultActive {
        /// Stable fault tag whose active state is matched.
        tag: FaultTag,
    },
    /// A named host-side predicate resolved by the harness and event log.
    Named {
        /// Stable predicate name.
        name: String,
        /// Declared nodes the predicate references.
        nodes: Vec<NodeId>,
    },
    /// A named white-box marker emitted by the optional guest-host channel.
    GuestMarker {
        /// Stable marker identity.
        marker: MarkerId,
    },
    /// Logical conjunction over sub-predicates.
    AllOf {
        /// Predicates that must all hold.
        predicates: Vec<Predicate>,
    },
    /// Logical disjunction over sub-predicates.
    AnyOf {
        /// Predicates where at least one must hold.
        predicates: Vec<Predicate>,
    },
    /// Latching predicate that remains true once its inner predicate holds.
    Once {
        /// Predicate being latched.
        predicate: Box<Predicate>,
    },
    /// Logical negation of an inner predicate.
    Not {
        /// Predicate being negated.
        predicate: Box<Predicate>,
    },
}

impl Predicate {
    /// Returns a stable canonical summary for event-log payload attributes.
    #[must_use]
    pub fn canonical_summary(&self) -> String {
        predicate_material(self)
    }

    /// Serializes this predicate as compact canonical bytes.
    #[must_use]
    pub fn to_compact_binary(&self) -> Vec<u8> {
        let mut writer = ScenarioBinaryWriter::new(PREDICATE_BINARY_MAGIC);
        write_predicate_binary(self, &mut writer);
        writer.finish()
    }

    /// Parses a compact predicate payload.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] when the payload has an
    /// unknown predicate tag, malformed embedded data, or trailing bytes.
    pub fn from_compact_binary(bytes: &[u8]) -> Result<Self, EngineError> {
        let mut reader = ScenarioBinaryReader::new(bytes, PREDICATE_BINARY_MAGIC)?;
        let predicate = read_predicate_binary(&mut reader)?;
        reader.finish()?;
        Ok(predicate)
    }

    /// Builds a named host-side predicate with no declared node references.
    #[must_use]
    pub fn named(name: impl Into<String>) -> Self {
        Self::Named {
            name: name.into(),
            nodes: Vec::new(),
        }
    }

    /// Builds a named host-side predicate with explicit declared node references.
    #[must_use]
    pub fn named_for_nodes(name: impl Into<String>, nodes: Vec<NodeId>) -> Self {
        Self::Named {
            name: name.into(),
            nodes,
        }
    }

    /// Builds an exact virtual-time predicate.
    #[must_use]
    pub fn at(at: VirtualTime) -> Self {
        Self::At { at }
    }

    /// Builds a relative event-firing predicate.
    #[must_use]
    pub fn after(duration: SimDuration, of: EventId) -> Self {
        Self::After { duration, of }
    }

    /// Builds a named timer predicate.
    #[must_use]
    pub fn timer(name: TimerId) -> Self {
        Self::Timer { name }
    }

    /// Builds a delivered-network-frame predicate.
    #[must_use]
    pub fn network_match(link: Option<LinkId>, predicate: FramePredicate) -> Self {
        Self::NetworkMatch { link, predicate }
    }

    /// Builds a console-output predicate.
    #[must_use]
    pub fn console_match(node: NodeId, regex: RegexProgram) -> Self {
        Self::ConsoleMatch { node, regex }
    }

    /// Builds a basic-block coverage predicate.
    #[must_use]
    pub fn coverage_point(node: NodeId, point: CodePoint) -> Self {
        Self::CoveragePoint { node, point }
    }

    /// Builds a deterministic memory/register sample predicate.
    #[must_use]
    pub fn memory_predicate(node: NodeId, place: MemPlace, cmp: MemoryCmp, value: u64) -> Self {
        Self::MemoryPredicate {
            node,
            place,
            cmp,
            value,
        }
    }

    /// Builds an I/O completion predicate.
    #[must_use]
    pub fn io_pattern(node: NodeId, kind: IoEventKind) -> Self {
        Self::IoPattern { node, kind }
    }

    /// Builds a node-lifecycle predicate.
    #[must_use]
    pub fn node_state(node: NodeId, state: NodeLifecycle) -> Self {
        Self::NodeState { node, state }
    }

    /// Builds an assertion-state predicate.
    #[must_use]
    pub fn assertion_state(name: AssertionId, state: AssertionPhase) -> Self {
        Self::AssertionState { name, state }
    }

    /// Builds a scheduler-quiescence predicate.
    #[must_use]
    pub const fn quiescent() -> Self {
        Self::Quiescent
    }

    /// Builds an active-fault-tag predicate.
    #[must_use]
    pub fn fault_active(tag: FaultTag) -> Self {
        Self::FaultActive { tag }
    }

    /// Builds a guest-marker predicate.
    #[must_use]
    pub fn guest_marker(marker: MarkerId) -> Self {
        Self::GuestMarker { marker }
    }

    /// Builds a conjunction predicate.
    #[must_use]
    pub fn all_of(predicates: Vec<Predicate>) -> Self {
        Self::AllOf { predicates }
    }

    /// Builds a disjunction predicate.
    #[must_use]
    pub fn any_of(predicates: Vec<Predicate>) -> Self {
        Self::AnyOf { predicates }
    }

    /// Builds a latching predicate.
    #[must_use]
    pub fn once(predicate: Predicate) -> Self {
        Self::Once {
            predicate: Box::new(predicate),
        }
    }

    /// Builds a negated predicate.
    #[must_use]
    // crucible-lint: allow rust-allow -- local exception is documented at the allow site.
    #[allow(clippy::should_implement_trait)]
    pub fn not(predicate: Predicate) -> Self {
        !predicate
    }
}
impl std::ops::Not for Predicate {
    type Output = Self;
    fn not(self) -> Self::Output {
        Self::Not {
            predicate: Box::new(self),
        }
    }
}

impl Action {
    /// Serializes this event action as compact canonical bytes.
    #[must_use]
    pub fn to_compact_binary(&self) -> Vec<u8> {
        let mut writer = ScenarioBinaryWriter::new(ACTION_BINARY_MAGIC);
        write_action_binary(self, &mut writer);
        writer.finish()
    }

    /// Parses a compact event action payload.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] when the payload has an
    /// unknown action tag, malformed embedded data, or trailing bytes.
    pub fn from_compact_binary(bytes: &[u8]) -> Result<Self, EngineError> {
        let mut reader = ScenarioBinaryReader::new(bytes, ACTION_BINARY_MAGIC)?;
        let action = read_action_binary(&mut reader)?;
        reader.finish()?;
        Ok(action)
    }
}

impl ControlOperationKind {
    /// Serializes this scheduler control kind as compact canonical bytes.
    #[must_use]
    pub fn to_compact_binary(&self) -> Vec<u8> {
        let mut writer = ScenarioBinaryWriter::new(CONTROL_OPERATION_KIND_BINARY_MAGIC);
        write_control_operation_kind_binary(self, &mut writer);
        writer.finish()
    }

    /// Parses a compact scheduler control kind payload.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] when the payload has an
    /// unknown control-operation tag, malformed embedded data, or trailing
    /// bytes.
    pub fn from_compact_binary(bytes: &[u8]) -> Result<Self, EngineError> {
        let mut reader = ScenarioBinaryReader::new(bytes, CONTROL_OPERATION_KIND_BINARY_MAGIC)?;
        let kind = read_control_operation_kind_binary(&mut reader)?;
        reader.finish()?;
        Ok(kind)
    }
}

/// A temporal property declaration.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Property {
    /// Invariant checked at every relevant evaluation point.
    Always {
        /// Predicate that must always hold.
        predicate: Predicate,
    },
    /// Liveness witness that must hold at least once.
    Sometimes {
        /// Predicate that must eventually be seen.
        predicate: Predicate,
    },
    /// Bounded liveness property armed by a trigger predicate.
    Eventually {
        /// Predicate that opens the bounded obligation.
        trigger: Predicate,
        /// Predicate that must hold within the deadline.
        property: Predicate,
        /// Virtual-time deadline measured from the trigger instant.
        deadline: VirtualTime,
    },
    /// End-state property checked once at quiescence or run limit.
    AfterQuiescence {
        /// Predicate that must hold at the terminal evaluation point.
        predicate: Predicate,
    },
    /// Coverage-style property over a predicate that may or may not be reached.
    Reachable {
        /// Predicate whose reachability is recorded.
        predicate: Predicate,
        /// Whether the predicate is expected to be reached, with never-reached
        /// disposition, or expected to remain unreachable.
        expectation: ReachabilityExpectation,
    },
}

impl Property {
    /// Returns this property's temporal quantifier kind.
    #[must_use]
    pub const fn kind(&self) -> PropertyKind {
        match self {
            Self::Always { .. } => PropertyKind::Always,
            Self::Sometimes { .. } => PropertyKind::Sometimes,
            Self::Eventually { .. } => PropertyKind::Eventually,
            Self::AfterQuiescence { .. } => PropertyKind::AfterQuiescence,
            Self::Reachable { .. } => PropertyKind::Reachable,
        }
    }
}

/// One named property assertion in a [`Properties`] bundle.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AssertionDef {
    /// Stable assertion id used for canonical ordering and reports.
    pub id: AssertionId,
    /// Human-readable failure or coverage message.
    pub message: String,
    /// Temporal property definition.
    pub property: Property,
}

/// A declarative assertion bundle layered over a static [`World`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Properties {
    /// The independently content-addressed properties identity.
    pub(super) id: ContentHash,
    pub(super) assertions: Vec<AssertionDef>,
}

impl Default for Properties {
    fn default() -> Self {
        Self::empty()
    }
}

impl Properties {
    /// Builds an empty properties bundle.
    #[must_use]
    pub fn empty() -> Self {
        let assertions = Vec::new();
        Self::from_canonical_assertions(assertions)
    }

    /// Builds a properties bundle after validating every predicate against `world`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::PropertyDuplicateAssertionId`] when two
    /// assertions share an id, [`EngineError::PropertyPredicateUnknownNode`]
    /// when a predicate names a node that is not declared by `world`,
    /// [`EngineError::PropertyPredicateUnknownAssertion`] when an
    /// `AssertionState` predicate names no declared assertion,
    /// [`EngineError::PropertyPredicateGuestMarkerRequiresWhiteBoxOptIn`] when a
    /// `GuestMarker` predicate is used but `world` has no white-box-enabled node,
    /// [`EngineError::PropertyPredicateEmptyCompound`] when an `AllOf` or
    /// `AnyOf` predicate has no children, or
    /// [`EngineError::PropertyPredicateTriggerOnly`] when a property uses an
    /// edge-shaped trigger-only predicate.
    pub fn from_assertions_for_world(
        world: &World,
        assertions: Vec<AssertionDef>,
    ) -> Result<Self, EngineError> {
        validate_properties_for_world(world, &assertions)?;
        Ok(Self::from_canonical_assertions(canonical_assertions(
            &assertions,
        )))
    }

    /// Builds a properties bundle after resolving DSL predicates against `world`
    /// and `plan`.
    ///
    /// Named DSL predicates such as `no_crashed_nodes`, `node_alive:<node>`, and
    /// `no_active_faults` are expanded to concrete predicates before validation
    /// and hashing. Unrecognized `Named` predicates remain available for linted
    /// host-side assertion oracles.
    ///
    /// # Errors
    ///
    /// Returns the same validation errors as [`Self::from_assertions_for_world`]
    /// after DSL expansion.
    pub fn from_assertions_for_world_and_plan(
        world: &World,
        plan: &Plan,
        assertions: Vec<AssertionDef>,
    ) -> Result<Self, EngineError> {
        let assertions = resolve_assertions_dsl_for_context(world, plan, &assertions);
        Self::from_assertions_for_world(world, assertions)
    }

    /// Returns property assertions in their canonical order.
    #[must_use]
    pub fn assertions(&self) -> &[AssertionDef] {
        &self.assertions
    }

    /// Computes the canonical identity of this properties bundle.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        self.id
    }

    /// Serializes this properties component as deterministic TOML.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] if the TOML renderer rejects
    /// the internal DTO shape.
    pub fn to_canonical_toml(&self) -> Result<String, EngineError> {
        toml::to_string(&properties_to_toml(self)).map_err(|source| {
            scenario_serialization_error(format!("serialize properties TOML: {source}"))
        })
    }

    /// Parses and validates a deterministic TOML properties component for `world`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] for malformed TOML or an id
    /// mismatch, or a property validation error when the parsed assertions do
    /// not layer over `world`.
    pub fn from_canonical_toml_for_world(world: &World, input: &str) -> Result<Self, EngineError> {
        let toml = toml::from_str::<PropertiesToml>(input).map_err(|source| {
            scenario_serialization_error(format!("parse properties TOML: {source}"))
        })?;
        properties_from_toml(world, toml)
    }

    /// Parses and validates deterministic TOML properties for `world` and `plan`.
    ///
    /// This parser resolves string-authored DSL predicates before checking the
    /// serialized properties id. Use [`Self::from_canonical_toml_for_world`] for
    /// component-only TOML that intentionally preserves opaque named host
    /// predicates without plan context.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] for malformed TOML or an id
    /// mismatch, or a property validation error after DSL expansion.
    pub fn from_canonical_toml_for_world_and_plan(
        world: &World,
        plan: &Plan,
        input: &str,
    ) -> Result<Self, EngineError> {
        let toml = toml::from_str::<PropertiesToml>(input).map_err(|source| {
            scenario_serialization_error(format!("parse properties TOML: {source}"))
        })?;
        properties_from_toml_with_plan(world, plan, toml)
    }

    /// Serializes this properties component as compact binary.
    #[must_use]
    pub fn to_compact_binary(&self) -> Vec<u8> {
        let mut writer = ScenarioBinaryWriter::new(PROPERTIES_BINARY_MAGIC);
        write_properties_binary(self, &mut writer);
        writer.finish()
    }

    /// Parses and validates a compact binary properties component for `world`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::ScenarioSerialization`] for malformed binary input
    /// or an id mismatch, or a property validation error when the parsed assertions
    /// do not layer over `world`.
    pub fn from_compact_binary_for_world(world: &World, bytes: &[u8]) -> Result<Self, EngineError> {
        let mut reader = ScenarioBinaryReader::new(bytes, PROPERTIES_BINARY_MAGIC)?;
        let properties = read_properties_binary(world, &mut reader)?;
        reader.finish()?;
        Ok(properties)
    }

    /// Returns the canonical bytes used to compute this properties bundle's content address.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        properties_material(&self.assertions).into_bytes()
    }

    /// Validates this properties bundle against `world`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::PropertyDuplicateAssertionId`],
    /// [`EngineError::PropertyPredicateUnknownNode`],
    /// [`EngineError::PropertyPredicateUnknownAssertion`], or
    /// [`EngineError::PropertyPredicateGuestMarkerRequiresWhiteBoxOptIn`], or
    /// [`EngineError::PropertyPredicateEmptyCompound`], or
    /// [`EngineError::PropertyPredicateTriggerOnly`] when an assertion cannot be
    /// layered over the static world topology.
    pub fn validate_for_world(&self, world: &World) -> Result<(), EngineError> {
        validate_properties_for_world(world, &self.assertions)
    }

    fn from_canonical_assertions(assertions: Vec<AssertionDef>) -> Self {
        Self {
            id: ContentHash::from_canonical_material(
                PROPERTY_SCHEMA_DOMAIN,
                &properties_material(&assertions),
            ),
            assertions,
        }
    }
}
