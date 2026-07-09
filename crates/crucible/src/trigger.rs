//! Event-graph control-flow spine.
//!
//! RFC-0010 file 17a defines scenario control flow as a graph of events. This
//! module owns the first, condition-agnostic layer of that model: an [`Event`]
//! binds an optional [`Condition`] to an [`Action`] and a [`FirePolicy`], while
//! [`EventGraphState`] is the only local producer of fired actions. The
//! code-first builder and graph-native plan serialization keep that control flow
//! as a content-addressed scenario component instead of a separate scenario poke
//! path.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::ops::Deref;

use crate::model::{
    AssertionDef, AssertionId, AssertionPhase, BlockFault, CodePoint, ContentHash,
    ControlFaultAction, Decision, DeviceId, EngineError, EventKey, EventLogOffset, Fault, FaultId,
    FaultPlanEntry, FaultTag, FramePredicate, Icount, IoEventKind, LinkDef, LinkId, MarkerId,
    MemPlace, MembershipFault, MemoryCmp, NetworkFault, NinePFault, NodeFault, NodeId,
    NodeLifecycle, PartitionDirection, Plan, PlanEntry, Predicate, PreemptionKind, Properties,
    Property, ReachabilityExpectation, ReachableDisposition, ReadyPoint, RegexProgram,
    ReproductionArtifact, ReproductionReplay, RestartPolicy, RngStreamId, Schedule,
    SchedulerNodeId, SchedulingNodeKind, Shift, SimDuration, TimeConversionError, TimerId,
    VirtualTime, WhiteBoxPolicy, World, WorldStaticTopology,
};
use crate::scheduler::{
    AssertionRunVerdict, AssertionVerdictFailure, ControlOperationKind, EventAttributeValue,
    EventLevel, EventLogCausalDivergencePoint, EventLogIcountStamp, ScheduledEvent,
    ScheduledEventKey, ScheduledEventPayload, ScheduledEventResolveClass,
    SchedulerEvaluationBoundaryKind, SchedulerEventLogClass, SchedulerEventLogEntry,
    SchedulerEventLogPayload, SchedulerQuiescence, TriggerActionApplication,
    compare_event_log_determinism, scheduled_event_resolve_class, scheduler_event_log_empty_prefix,
    scheduler_event_log_segment_bytes,
};

pub use crate::model::EventId;

/// Shared predicate vocabulary used by both assertions and event triggers.
///
/// This is a public alias rather than a second enum: a predicate usable by the
/// assertion [`crate::model::Property`] layer is the same value accepted by an
/// event trigger.
pub type Condition = Predicate;

/// Identity-preserving event-graph lowering of a time-scheduled [`Plan`].
///
/// This is the RFC-0010 §17a.7 bridge between the legacy declarative fault plan
/// and trigger events: every lowered event has a pure [`Condition::At`] trigger
/// and an [`Action::InjectFault`] or [`Action::HealFault`] action. The lowering
/// deliberately carries the source plan's canonical bytes and content hash so a
/// pure-`At` plan and the equivalent event graph remain one content-addressed
/// value. Graph-native plans return their already-authored event graph with the
/// same identity-preserving wrapper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoweredPlanEventGraph {
    graph: EventGraph,
    content_hash: ContentHash,
    canonical_bytes: Vec<u8>,
    evaluation_times: Vec<VirtualTime>,
}

impl LoweredPlanEventGraph {
    /// Returns the lowered trigger graph.
    #[must_use]
    pub fn event_graph(&self) -> &EventGraph {
        &self.graph
    }

    /// Consumes the lowering and returns the trigger graph.
    #[must_use]
    pub fn into_event_graph(self) -> EventGraph {
        self.graph
    }

    /// Returns the identity-preserving content hash inherited from the source plan.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        self.content_hash
    }

    /// Returns the canonical bytes used by the inherited content hash.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Returns the exact virtual-time points where the pure-`At` graph must run.
    #[must_use]
    pub fn evaluation_times(&self) -> &[VirtualTime] {
        &self.evaluation_times
    }
}

impl Plan {
    /// Lowers this plan into the event graph executed by the trigger layer.
    ///
    /// Each [`PlanEntry::Activate`] becomes one once-only event with an
    /// [`Condition::At`] trigger and [`Action::InjectFault`] action. Each
    /// [`PlanEntry::Heal`] becomes one once-only event with an [`Action::HealFault`]
    /// action. The returned lowering preserves this plan's canonical bytes and
    /// content hash as the graph identity.
    ///
    /// # Errors
    ///
    /// Returns [`EventGraphError`] when the lowered graph fails event-graph
    /// validation against `world`.
    pub fn lower_to_event_graph_for_world(
        &self,
        world: &World,
    ) -> Result<LoweredPlanEventGraph, EventGraphError> {
        if let Some(graph) = self.event_graph() {
            let graph = EventGraph::new_with_assertions_for_world(
                graph.events().to_vec(),
                event_graph_assertion_references(graph.events()),
                world,
            )?;
            let evaluation_times = graph_static_evaluation_times(graph.events());
            return Ok(LoweredPlanEventGraph {
                graph,
                content_hash: self.content_hash(),
                canonical_bytes: self.canonical_bytes(),
                evaluation_times,
            });
        }
        if let Some(plan) = self.fault_plan() {
            let actions = lower_fault_plan_actions(plan.entries());
            let events = actions
                .iter()
                .enumerate()
                .map(lower_fault_plan_action_to_event)
                .collect::<Vec<_>>();
            let evaluation_times = fault_plan_action_evaluation_times(&actions);
            let graph = EventGraph::new_for_world(events, world)?;
            return Ok(LoweredPlanEventGraph {
                graph,
                content_hash: self.content_hash(),
                canonical_bytes: self.canonical_bytes(),
                evaluation_times,
            });
        }
        let events = self
            .entries()
            .iter()
            .enumerate()
            .map(lower_plan_entry_to_event)
            .collect::<Vec<_>>();
        let evaluation_times = plan_evaluation_times(self.entries());
        let graph = EventGraph::new_for_world(events, world)?;
        Ok(LoweredPlanEventGraph {
            graph,
            content_hash: self.content_hash(),
            canonical_bytes: self.canonical_bytes(),
            evaluation_times,
        })
    }
}

fn graph_static_evaluation_times(events: &[Event]) -> Vec<VirtualTime> {
    events
        .iter()
        .filter_map(|event| match &event.trigger {
            None => Some(VirtualTime { ticks: 0 }),
            Some(Condition::At { at }) => Some(*at),
            Some(_) => None,
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn event_graph_assertion_references(events: &[Event]) -> Vec<AssertionId> {
    let mut assertions = BTreeSet::new();
    for event in events {
        if let Some(trigger) = &event.trigger {
            collect_condition_assertion_references(trigger, &mut assertions);
        }
    }
    assertions.into_iter().collect()
}

fn collect_condition_assertion_references(
    condition: &Condition,
    assertions: &mut BTreeSet<AssertionId>,
) {
    match condition {
        Condition::AssertionState { name, .. } => {
            assertions.insert(name.clone());
        }
        Condition::AllOf { predicates } | Condition::AnyOf { predicates } => {
            for condition in predicates {
                collect_condition_assertion_references(condition, assertions);
            }
        }
        Condition::Once { predicate } | Condition::Not { predicate } => {
            collect_condition_assertion_references(predicate, assertions);
        }
        Condition::At { .. }
        | Condition::After { .. }
        | Condition::Timer { .. }
        | Condition::NetworkMatch { .. }
        | Condition::ConsoleMatch { .. }
        | Condition::CoveragePoint { .. }
        | Condition::MemoryPredicate { .. }
        | Condition::IoPattern { .. }
        | Condition::NodeState { .. }
        | Condition::FaultActive { .. }
        | Condition::Quiescent
        | Condition::Named { .. }
        | Condition::GuestMarker { .. } => {}
    }
}

/// Host-resolved executable guest code coordinate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ResolvedCodePoint {
    address: u64,
}

impl ResolvedCodePoint {
    /// Builds a resolved guest-address code point.
    #[must_use]
    pub const fn guest_address(address: u64) -> Self {
        Self { address }
    }

    /// Returns the resolved guest instruction address.
    #[must_use]
    pub const fn address(self) -> u64 {
        self.address
    }
}

/// Host-resolved guest memory or register coordinate.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResolvedMemPlace {
    /// Guest physical address sampled out of band.
    PhysicalAddress {
        /// Guest physical address.
        address: u64,
        /// Sample width in bytes.
        bytes: u8,
    },
    /// Guest virtual address sampled out of band.
    VirtualAddress {
        /// Guest virtual address.
        address: u64,
        /// Sample width in bytes.
        bytes: u8,
    },
    /// Architectural register sampled out of band.
    Register {
        /// Stable register name.
        name: String,
        /// Sample width in bytes.
        bytes: u8,
    },
}

impl ResolvedMemPlace {
    /// Builds a resolved physical-address place.
    #[must_use]
    pub const fn physical_address(address: u64, bytes: u8) -> Self {
        Self::PhysicalAddress { address, bytes }
    }

    /// Builds a resolved virtual-address place.
    #[must_use]
    pub const fn virtual_address(address: u64, bytes: u8) -> Self {
        Self::VirtualAddress { address, bytes }
    }

    /// Builds a resolved register place.
    #[must_use]
    pub fn register(name: impl Into<String>, bytes: u8) -> Self {
        Self::Register {
            name: name.into(),
            bytes,
        }
    }
}

/// Required black-box observation surface categories.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BlackBoxObservationKind {
    /// Network frame traffic observed outside the guest.
    NetworkTraffic,
    /// Block-device or 9p request/response completion observed outside the guest.
    DiskOrNinePIo,
    /// Console or serial bytes captured as a pure output sink.
    ConsoleSerialOutput,
    /// QMP/plugin register or memory state sampled at a scheduler-defined point.
    ArchitecturalStateSample,
    /// Guest lifecycle outcome such as start or clean exit.
    RunOutcome,
    /// Crash or no-forward-progress detection.
    CrashOrHangDetection,
    /// TCG-exec basic-block coverage harvested without guest instrumentation.
    BasicBlockCoverage,
}

/// Number of required black-box observation surface categories.
pub const BLACK_BOX_OBSERVATION_KIND_COUNT: usize = 7;

/// Closed required black-box observation surface.
pub const BLACK_BOX_OBSERVATION_KINDS: [BlackBoxObservationKind; BLACK_BOX_OBSERVATION_KIND_COUNT] = [
    BlackBoxObservationKind::NetworkTraffic,
    BlackBoxObservationKind::DiskOrNinePIo,
    BlackBoxObservationKind::ConsoleSerialOutput,
    BlackBoxObservationKind::ArchitecturalStateSample,
    BlackBoxObservationKind::RunOutcome,
    BlackBoxObservationKind::CrashOrHangDetection,
    BlackBoxObservationKind::BasicBlockCoverage,
];

/// Host-side source used to acquire a black-box observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BlackBoxObservationSource {
    /// Frames captured by the host-owned network device path.
    ExternalNetworkTap,
    /// Block or 9p completion records captured by host-owned device sub-nodes.
    ExternalDeviceSubNode,
    /// Console or serial bytes captured as a host-side output sink.
    ExternalConsoleSerialSink,
    /// Architectural registers or memory read at a scheduler-defined point.
    ExternalArchitecturalSampler,
    /// Exit, crash, hang, start, or stop state observed by the host runtime.
    ExternalLifecycleMonitor,
    /// Basic-block execution trace collected by host/plugin execution hooks.
    ExternalExecutionTrace,
}

/// OS-agnostic contract for one black-box observation category.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BlackBoxObservationContract {
    kind: BlackBoxObservationKind,
    source: BlackBoxObservationSource,
}

impl BlackBoxObservationContract {
    /// Builds a contract for one black-box observation category.
    #[must_use]
    const fn new(kind: BlackBoxObservationKind, source: BlackBoxObservationSource) -> Self {
        Self { kind, source }
    }

    /// Returns the black-box observation category covered by this contract.
    #[must_use]
    pub const fn kind(self) -> BlackBoxObservationKind {
        self.kind
    }

    /// Returns the host-side source for this observation category.
    #[must_use]
    pub const fn source(self) -> BlackBoxObservationSource {
        self.source
    }

    /// Returns whether this observation requires a guest operating-system contract.
    #[must_use]
    pub const fn requires_guest_os_contract(self) -> bool {
        false
    }

    /// Returns whether this observation requires a guest init or service manager.
    #[must_use]
    pub const fn requires_guest_init_contract(self) -> bool {
        false
    }

    /// Returns whether this observation requires a guest filesystem layout.
    #[must_use]
    pub const fn requires_guest_filesystem_contract(self) -> bool {
        false
    }

    /// Returns whether this observation requires a guest ABI or in-guest agent.
    #[must_use]
    pub const fn requires_guest_abi_contract(self) -> bool {
        false
    }

    /// Returns whether this observation carries host-to-guest payload bytes.
    #[must_use]
    pub const fn carries_host_to_guest_payload(self) -> bool {
        false
    }
}

/// Default number of entries in the basic-block coverage feedback map.
pub const DEFAULT_BASIC_BLOCK_COVERAGE_MAP_ENTRIES: usize = 65_536;

/// Registration-time switch for plugin TCG-exec basic-block coverage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BasicBlockCoverageMode {
    /// Coverage is disabled and no TCG-exec callback is registered.
    Off,
    /// Coverage is enabled and the plugin registers the TCG-exec callback.
    On,
}

/// Engine-side policy for consuming plugin TCG-exec basic-block coverage.
///
/// This policy is intentionally not part of [`crate::model::World`] or
/// [`crate::model::ScenarioDef`]: it controls observational feedback collection
/// only, so toggling it cannot change scenario, configuration, or checkpoint
/// identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BasicBlockCoverageConfig {
    mode: BasicBlockCoverageMode,
    map_entries: usize,
}

impl BasicBlockCoverageConfig {
    /// Builds a coverage policy with an explicit registration-time mode.
    #[must_use]
    pub const fn new(mode: BasicBlockCoverageMode, map_entries: usize) -> Self {
        Self { mode, map_entries }
    }

    /// Builds the default off policy.
    #[must_use]
    pub const fn off() -> Self {
        Self::new(
            BasicBlockCoverageMode::Off,
            DEFAULT_BASIC_BLOCK_COVERAGE_MAP_ENTRIES,
        )
    }

    /// Builds the default on policy.
    #[must_use]
    pub const fn on() -> Self {
        Self::new(
            BasicBlockCoverageMode::On,
            DEFAULT_BASIC_BLOCK_COVERAGE_MAP_ENTRIES,
        )
    }

    /// Returns the registration-time coverage mode.
    #[must_use]
    pub const fn mode(self) -> BasicBlockCoverageMode {
        self.mode
    }

    /// Returns the fixed coverage-map entry count.
    #[must_use]
    pub const fn map_entries(self) -> usize {
        self.map_entries
    }

    /// Returns whether this policy can affect execution fingerprints.
    #[must_use]
    pub const fn affects_execution_fingerprint(self) -> bool {
        false
    }

    /// Returns whether this policy requires guest instrumentation or an agent.
    #[must_use]
    pub const fn requires_guest_instrumentation(self) -> bool {
        false
    }

    /// Builds the registration-time plan for this coverage policy.
    ///
    /// Disabled coverage returns [`BasicBlockCoverageRegistrationPlan::Disabled`]
    /// before validating coverage-only settings, so the engine creates no
    /// coverage consumer token. The plugin-side T-PLUG-15 registration plan owns
    /// the corresponding proof that QEMU receives no TCG-exec callback when the
    /// launch switch is off.
    ///
    /// # Errors
    ///
    /// Returns [`BasicBlockCoverageError::InvalidMapEntries`] when coverage is
    /// enabled with a zero or non-power-of-two map size.
    pub fn registration_plan(
        self,
    ) -> Result<BasicBlockCoverageRegistrationPlan, BasicBlockCoverageError> {
        if self.mode == BasicBlockCoverageMode::Off {
            return Ok(BasicBlockCoverageRegistrationPlan::Disabled);
        }
        validate_basic_block_coverage_map_entries(self.map_entries)?;
        Ok(BasicBlockCoverageRegistrationPlan::RegisterTcgExec {
            map_entries: self.map_entries,
        })
    }
}

/// Registration-time plan for TCG-exec basic-block coverage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BasicBlockCoverageRegistrationPlan {
    /// Coverage is disabled and no engine coverage consumer may be created.
    Disabled,
    /// Coverage is enabled and the QEMU launch layer should request TCG-exec coverage.
    RegisterTcgExec {
        /// Fixed coverage-map entry count.
        map_entries: usize,
    },
}

impl BasicBlockCoverageRegistrationPlan {
    /// Returns whether the plan requests TCG-exec coverage from the QEMU launch layer.
    #[must_use]
    pub const fn requests_tcg_exec_coverage(self) -> bool {
        matches!(self, Self::RegisterTcgExec { .. })
    }

    /// Returns whether the plan creates no engine-side hot-path coverage consumer.
    #[must_use]
    pub const fn has_no_engine_hot_path_consumer(self) -> bool {
        matches!(self, Self::Disabled)
    }

    /// Returns whether this plan can affect execution fingerprints.
    #[must_use]
    pub const fn affects_execution_fingerprint(self) -> bool {
        false
    }

    /// Returns a consumer token for one node when coverage is enabled.
    ///
    /// # Errors
    ///
    /// Returns [`BasicBlockCoverageError::CallbackWhileDisabled`] when this plan
    /// is disabled.
    pub fn require_consumer(
        self,
        node: NodeId,
    ) -> Result<BasicBlockCoverageConsumer, BasicBlockCoverageError> {
        match self {
            Self::Disabled => Err(BasicBlockCoverageError::CallbackWhileDisabled),
            Self::RegisterTcgExec { map_entries } => {
                Ok(BasicBlockCoverageConsumer { node, map_entries })
            }
        }
    }
}

/// One TCG-exec basic-block callback observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TcgExecBasicBlock {
    execution_icount: Icount,
    guest_pc: u64,
    block_len: u32,
}

impl TcgExecBasicBlock {
    /// Builds a basic-block observation from plugin callback metadata.
    #[must_use]
    pub const fn new(execution_icount: Icount, guest_pc: u64, block_len: u32) -> Self {
        Self {
            execution_icount,
            guest_pc,
            block_len,
        }
    }

    /// Returns the exact instruction count at which the block executed.
    #[must_use]
    pub const fn execution_icount(self) -> Icount {
        self.execution_icount
    }

    /// Returns the guest program counter for the translated block.
    #[must_use]
    pub const fn guest_pc(self) -> u64 {
        self.guest_pc
    }

    /// Returns the translated block length supplied by QEMU.
    #[must_use]
    pub const fn block_len(self) -> u32 {
        self.block_len
    }
}

/// Proof that coverage was enabled for one node at registration time.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BasicBlockCoverageConsumer {
    node: NodeId,
    map_entries: usize,
}

impl BasicBlockCoverageConsumer {
    /// Returns the node whose TCG-exec callback stream this consumer accepts.
    #[must_use]
    pub fn node(&self) -> &NodeId {
        &self.node
    }

    /// Returns the fixed coverage-map entry count.
    #[must_use]
    pub const fn map_entries(&self) -> usize {
        self.map_entries
    }

    /// Converts one TCG-exec basic-block callback into an observational event.
    ///
    /// The conversion depends only on callback metadata and the registration-time
    /// node binding. It does not require guest source, symbols, an in-guest
    /// agent, or a runtime coverage switch branch.
    ///
    /// # Errors
    ///
    /// Returns [`BasicBlockCoverageError::InvalidMapEntries`] when the consumer
    /// carries an invalid fixed map size, or
    /// [`BasicBlockCoverageError::InvalidBlockLength`] when QEMU reports a zero
    /// block length.
    pub fn consume_tcg_exec_block(
        &self,
        block: TcgExecBasicBlock,
    ) -> Result<ConsumedBasicBlockCoverage, BasicBlockCoverageError> {
        if block.block_len == 0 {
            return Err(BasicBlockCoverageError::InvalidBlockLength {
                block_len: block.block_len,
            });
        }
        let map_index = basic_block_coverage_map_index(block.guest_pc, self.map_entries)?;
        Ok(ConsumedBasicBlockCoverage {
            map_index,
            event: ObservableEvent::coverage_block(
                block.execution_icount,
                self.node.clone(),
                block.guest_pc,
                block.block_len,
            ),
        })
    }
}

/// One consumed basic-block coverage event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsumedBasicBlockCoverage {
    map_index: usize,
    event: ObservableEvent,
}

impl ConsumedBasicBlockCoverage {
    /// Returns the fixed-map index touched by this basic block.
    #[must_use]
    pub const fn map_index(&self) -> usize {
        self.map_index
    }

    /// Returns the observational event-log payload for this coverage block.
    #[must_use]
    pub const fn event(&self) -> &ObservableEvent {
        &self.event
    }

    /// Consumes this value and returns the observational event.
    #[must_use]
    pub fn into_event(self) -> ObservableEvent {
        self.event
    }
}

/// An error produced while registering or consuming basic-block coverage.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum BasicBlockCoverageError {
    /// The fixed coverage map size is invalid.
    InvalidMapEntries {
        /// Rejected entry count.
        entries: usize,
    },
    /// A coverage consumer was requested while coverage was disabled.
    CallbackWhileDisabled,
    /// QEMU reported an impossible basic-block length.
    InvalidBlockLength {
        /// Rejected block length.
        block_len: u32,
    },
}

impl fmt::Display for BasicBlockCoverageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMapEntries { entries } => {
                write!(
                    f,
                    "coverage map entries {entries} must be a nonzero power of two"
                )
            }
            Self::CallbackWhileDisabled => {
                f.write_str("basic-block coverage callback requested while disabled")
            }
            Self::InvalidBlockLength { block_len } => {
                write!(f, "coverage block length {block_len} is invalid")
            }
        }
    }
}

impl Error for BasicBlockCoverageError {}

/// Folds a guest basic-block PC into a fixed-size coverage map.
///
/// # Errors
///
/// Returns [`BasicBlockCoverageError::InvalidMapEntries`] when `map_entries` is
/// zero or not a power of two.
pub fn basic_block_coverage_map_index(
    guest_pc: u64,
    map_entries: usize,
) -> Result<usize, BasicBlockCoverageError> {
    validate_basic_block_coverage_map_entries(map_entries)?;
    let folded = guest_pc ^ guest_pc.rotate_right(17) ^ (guest_pc >> 32);
    Ok((folded as usize) & (map_entries - 1))
}

fn validate_basic_block_coverage_map_entries(
    entries: usize,
) -> Result<(), BasicBlockCoverageError> {
    if entries == 0 || !entries.is_power_of_two() {
        Err(BasicBlockCoverageError::InvalidMapEntries { entries })
    } else {
        Ok(())
    }
}

impl BlackBoxObservationKind {
    /// Returns the OS-agnostic contract for this black-box observation category.
    #[must_use]
    pub const fn contract(self) -> BlackBoxObservationContract {
        match self {
            Self::NetworkTraffic => BlackBoxObservationContract::new(
                self,
                BlackBoxObservationSource::ExternalNetworkTap,
            ),
            Self::DiskOrNinePIo => BlackBoxObservationContract::new(
                self,
                BlackBoxObservationSource::ExternalDeviceSubNode,
            ),
            Self::ConsoleSerialOutput => BlackBoxObservationContract::new(
                self,
                BlackBoxObservationSource::ExternalConsoleSerialSink,
            ),
            Self::ArchitecturalStateSample => BlackBoxObservationContract::new(
                self,
                BlackBoxObservationSource::ExternalArchitecturalSampler,
            ),
            Self::RunOutcome => BlackBoxObservationContract::new(
                self,
                BlackBoxObservationSource::ExternalLifecycleMonitor,
            ),
            Self::CrashOrHangDetection => BlackBoxObservationContract::new(
                self,
                BlackBoxObservationSource::ExternalLifecycleMonitor,
            ),
            Self::BasicBlockCoverage => BlackBoxObservationContract::new(
                self,
                BlackBoxObservationSource::ExternalExecutionTrace,
            ),
        }
    }
}

/// Closed OS-agnostic contract catalog for the required black-box surface.
pub const BLACK_BOX_OBSERVATION_CONTRACTS: [BlackBoxObservationContract;
    BLACK_BOX_OBSERVATION_KIND_COUNT] = [
    BlackBoxObservationKind::NetworkTraffic.contract(),
    BlackBoxObservationKind::DiskOrNinePIo.contract(),
    BlackBoxObservationKind::ConsoleSerialOutput.contract(),
    BlackBoxObservationKind::ArchitecturalStateSample.contract(),
    BlackBoxObservationKind::RunOutcome.contract(),
    BlackBoxObservationKind::CrashOrHangDetection.contract(),
    BlackBoxObservationKind::BasicBlockCoverage.contract(),
];

/// Black-box ready-point heuristic that produced a deterministic point.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReadyPointResolutionKind {
    /// The policy resolved directly from a fixed retired-instruction count.
    FixedIcount,
    /// The policy resolved from the first deterministic network-idle window.
    FirstNetworkIdle,
    /// The policy resolved from a host-side console/serial marker match.
    ConsoleMarker,
}

/// Deterministic point where a node reached its configured ready point.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReadyPointResolution {
    node: NodeId,
    kind: ReadyPointResolutionKind,
    icount: Icount,
    virtual_time: VirtualTime,
}

impl ReadyPointResolution {
    /// Returns the node whose ready point was resolved.
    #[must_use]
    pub fn node(&self) -> &NodeId {
        &self.node
    }

    /// Returns the black-box heuristic that resolved readiness.
    #[must_use]
    pub const fn kind(&self) -> ReadyPointResolutionKind {
        self.kind
    }

    /// Returns the deterministic retired-instruction coordinate.
    #[must_use]
    pub const fn icount(&self) -> Icount {
        self.icount
    }

    /// Returns the deterministic virtual-time coordinate.
    #[must_use]
    pub const fn virtual_time(&self) -> VirtualTime {
        self.virtual_time
    }
}

/// Failure to resolve a node's configured ready point from deterministic evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadyPointResolutionError {
    /// No declared world node matched the requested id.
    UnknownNode {
        /// Requested node id.
        node: NodeId,
    },
    /// The configured ready point uses the optional white-box channel.
    AgentSignalRequiresWhiteBoxChannel {
        /// Node whose ready point is not black-box resolvable.
        node: NodeId,
    },
    /// Network-idle readiness saw no activity on any link for the node.
    NetworkIdleRequiresObservedActivity {
        /// Node whose links never showed initial activity.
        node: NodeId,
    },
    /// Network-idle readiness has not yet observed a full idle window.
    NetworkIdleWindowNotReached {
        /// Node whose links have not been idle long enough.
        node: NodeId,
        /// Required idle window.
        window: SimDuration,
    },
    /// Network-idle readiness would overflow virtual time.
    NetworkIdleWindowOverflow {
        /// Node whose idle-window endpoint overflowed.
        node: NodeId,
        /// Activity time at the start of the idle window.
        last_activity: VirtualTime,
        /// Required idle window.
        window: SimDuration,
    },
    /// Console-marker readiness did not observe the marker.
    ConsoleMarkerNotObserved {
        /// Node whose console stream did not match.
        node: NodeId,
        /// Marker that was required.
        marker: String,
    },
    /// A virtual-time/icount conversion failed.
    TimeConversion {
        /// Node whose resolved point could not be converted.
        node: NodeId,
        /// Deterministic conversion failure.
        source: TimeConversionError,
    },
}

impl fmt::Display for ReadyPointResolutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownNode { .. } => f.write_str("ready-point node is not declared"),
            Self::AgentSignalRequiresWhiteBoxChannel { .. } => {
                f.write_str("agent-signal ready point is not black-box resolvable")
            }
            Self::NetworkIdleRequiresObservedActivity { .. } => {
                f.write_str("network-idle ready point requires observed link activity")
            }
            Self::NetworkIdleWindowNotReached { .. } => {
                f.write_str("network-idle ready point has not reached its idle window")
            }
            Self::NetworkIdleWindowOverflow { .. } => {
                f.write_str("network-idle ready point overflows virtual time")
            }
            Self::ConsoleMarkerNotObserved { .. } => {
                f.write_str("console-marker ready point was not observed")
            }
            Self::TimeConversion { source, .. } => {
                write!(f, "ready-point time conversion failed: {source}")
            }
        }
    }
}

impl Error for ReadyPointResolutionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::TimeConversion { source, .. } => Some(source),
            Self::UnknownNode { .. }
            | Self::AgentSignalRequiresWhiteBoxChannel { .. }
            | Self::NetworkIdleRequiresObservedActivity { .. }
            | Self::NetworkIdleWindowNotReached { .. }
            | Self::NetworkIdleWindowOverflow { .. }
            | Self::ConsoleMarkerNotObserved { .. } => None,
        }
    }
}

/// Resolves a node's black-box ready point from deterministic observations.
///
/// `observed_until` is the checked event-log frontier. Network-idle readiness
/// uses it to prove the idle window elapsed rather than relying on host wall
/// clock. Console-marker readiness scans the ordered console byte stream and
/// resolves at the event that completes the marker match.
///
/// # Errors
///
/// Returns [`ReadyPointResolutionError`] when `node` is undeclared, when the
/// node uses the white-box-only agent signal, when the provided observations do
/// not yet prove the configured heuristic, or when an icount/virtual-time
/// conversion fails.
pub fn resolve_ready_point(
    world: &World,
    node: &NodeId,
    observed_until: VirtualTime,
    observations: &[ObservableEvent],
) -> Result<ReadyPointResolution, ReadyPointResolutionError> {
    let world_node = world
        .nodes()
        .iter()
        .find(|candidate| &candidate.id == node)
        .ok_or_else(|| ReadyPointResolutionError::UnknownNode { node: node.clone() })?;
    let shift = Shift {
        bits: world_node.icount_shift,
    };

    match &world_node.ready_point {
        ReadyPoint::FixedIcount { icount } => {
            resolution_from_icount(node, ReadyPointResolutionKind::FixedIcount, *icount, shift)
        }
        ReadyPoint::NetworkIdle { window } => {
            resolve_network_idle_ready_point(world, node, *window, observed_until, observations)
                .and_then(|at| {
                    resolution_from_virtual_time(
                        node,
                        ReadyPointResolutionKind::FirstNetworkIdle,
                        at,
                        shift,
                    )
                })
        }
        ReadyPoint::ConsoleMarker { marker } => resolve_console_marker_ready_point(
            node,
            marker,
            observed_until,
            observations,
        )
        .and_then(|at| {
            resolution_from_virtual_time(node, ReadyPointResolutionKind::ConsoleMarker, at, shift)
        }),
        ReadyPoint::AgentSignal => Err(
            ReadyPointResolutionError::AgentSignalRequiresWhiteBoxChannel { node: node.clone() },
        ),
    }
}

fn resolution_from_icount(
    node: &NodeId,
    kind: ReadyPointResolutionKind,
    icount: Icount,
    shift: Shift,
) -> Result<ReadyPointResolution, ReadyPointResolutionError> {
    let virtual_time =
        icount
            .to_virtual(shift)
            .map_err(|source| ReadyPointResolutionError::TimeConversion {
                node: node.clone(),
                source,
            })?;
    Ok(ReadyPointResolution {
        node: node.clone(),
        kind,
        icount,
        virtual_time: VirtualTime {
            ticks: virtual_time.nanos,
        },
    })
}

fn resolution_from_virtual_time(
    node: &NodeId,
    kind: ReadyPointResolutionKind,
    virtual_time: VirtualTime,
    shift: Shift,
) -> Result<ReadyPointResolution, ReadyPointResolutionError> {
    let icount = crate::model::VirtualInstant {
        nanos: virtual_time.ticks,
    }
    .to_icount_ceil(shift)
    .map_err(|source| ReadyPointResolutionError::TimeConversion {
        node: node.clone(),
        source,
    })?;
    let rounded_virtual_time =
        icount
            .to_virtual(shift)
            .map_err(|source| ReadyPointResolutionError::TimeConversion {
                node: node.clone(),
                source,
            })?;
    Ok(ReadyPointResolution {
        node: node.clone(),
        kind,
        icount,
        virtual_time: VirtualTime {
            ticks: rounded_virtual_time.nanos,
        },
    })
}

fn resolve_network_idle_ready_point(
    world: &World,
    node: &NodeId,
    window: SimDuration,
    observed_until: VirtualTime,
    observations: &[ObservableEvent],
) -> Result<VirtualTime, ReadyPointResolutionError> {
    let link_ids = incident_link_ids(world, node);
    let mut activity = observations
        .iter()
        .filter_map(|event| match event.payload() {
            ObservableEventPayload::NetworkDelivered {
                link: Some(link), ..
            } if link_ids.contains(link) => Some(event.at()),
            ObservableEventPayload::NetworkDelivered { .. }
            | ObservableEventPayload::ConsoleOutput { .. }
            | ObservableEventPayload::CoverageBlock { .. }
            | ObservableEventPayload::CoverageMarker { .. }
            | ObservableEventPayload::AssertionProximity { .. }
            | ObservableEventPayload::MemorySample { .. }
            | ObservableEventPayload::IoCompletion { .. }
            | ObservableEventPayload::NodeState { .. }
            | ObservableEventPayload::AssertionStateChanged { .. }
            | ObservableEventPayload::AssertionEvaluated { .. }
            | ObservableEventPayload::GuestMarker { .. }
            | ObservableEventPayload::GuestAssertionMarker { .. } => None,
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    activity.retain(|at| *at <= observed_until);
    if activity.is_empty() {
        return Err(
            ReadyPointResolutionError::NetworkIdleRequiresObservedActivity { node: node.clone() },
        );
    }

    for (index, last_activity) in activity.iter().copied().enumerate() {
        let ready_at = last_activity
            .ticks
            .checked_add(window.nanos)
            .map(|ticks| VirtualTime { ticks })
            .ok_or_else(|| ReadyPointResolutionError::NetworkIdleWindowOverflow {
                node: node.clone(),
                last_activity,
                window,
            })?;
        let next_activity = activity.get(index + 1).copied();
        let next_is_after_window = next_activity.is_none_or(|next| next > ready_at);
        if ready_at <= observed_until && next_is_after_window {
            return Ok(ready_at);
        }
    }

    Err(ReadyPointResolutionError::NetworkIdleWindowNotReached {
        node: node.clone(),
        window,
    })
}

fn resolve_console_marker_ready_point(
    node: &NodeId,
    marker: &str,
    observed_until: VirtualTime,
    observations: &[ObservableEvent],
) -> Result<VirtualTime, ReadyPointResolutionError> {
    let marker = marker.as_bytes();
    let mut console = Vec::new();
    let mut ordered = observations
        .iter()
        .filter_map(|event| {
            if event.at() > observed_until {
                return None;
            }
            match event.payload() {
                ObservableEventPayload::ConsoleOutput {
                    node: source,
                    bytes,
                } if source == node => Some((event.at(), bytes.as_slice())),
                ObservableEventPayload::ConsoleOutput { .. }
                | ObservableEventPayload::NetworkDelivered { .. }
                | ObservableEventPayload::CoverageBlock { .. }
                | ObservableEventPayload::CoverageMarker { .. }
                | ObservableEventPayload::AssertionProximity { .. }
                | ObservableEventPayload::MemorySample { .. }
                | ObservableEventPayload::IoCompletion { .. }
                | ObservableEventPayload::NodeState { .. }
                | ObservableEventPayload::AssertionStateChanged { .. }
                | ObservableEventPayload::AssertionEvaluated { .. }
                | ObservableEventPayload::GuestMarker { .. }
                | ObservableEventPayload::GuestAssertionMarker { .. } => None,
            }
        })
        .collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(right.1)));
    for (at, bytes) in ordered {
        console.extend_from_slice(bytes);
        if contains_subsequence(&console, marker) {
            return Ok(at);
        }
    }

    Err(ReadyPointResolutionError::ConsoleMarkerNotObserved {
        node: node.clone(),
        marker: String::from_utf8_lossy(marker).into_owned(),
    })
}

fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|candidate| candidate == needle)
}

fn incident_link_ids(world: &World, node: &NodeId) -> BTreeSet<LinkId> {
    let mut ids = BTreeSet::new();
    for link in world.links() {
        let (endpoint_a, endpoint_b) = link.endpoints();
        if endpoint_a == node || endpoint_b == node {
            ids.insert(LinkId::from_name(format!(
                "{}--{}",
                endpoint_a.name, endpoint_b.name
            )));
            ids.insert(LinkId::from_name(format!(
                "link_endpoint_a_len={}\nlink_endpoint_a={}\nlink_endpoint_b_len={}\nlink_endpoint_b={}",
                endpoint_a.name.len(),
                endpoint_a.name,
                endpoint_b.name.len(),
                endpoint_b.name
            )));
        }
    }
    ids
}

/// One observable event visible to condition evaluation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ObservableEvent {
    at: VirtualTime,
    payload: ObservableEventPayload,
}

impl ObservableEvent {
    /// Builds a delivered-network-frame observation.
    #[must_use]
    pub fn network_delivered(
        at: VirtualTime,
        link: Option<LinkId>,
        payload: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            at,
            payload: ObservableEventPayload::NetworkDelivered {
                link,
                payload: payload.into(),
            },
        }
    }

    /// Builds a console-output observation.
    #[must_use]
    pub fn console_output(at: VirtualTime, node: NodeId, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            at,
            payload: ObservableEventPayload::ConsoleOutput {
                node,
                bytes: bytes.into(),
            },
        }
    }

    /// Builds a TCG-exec basic-block coverage observation.
    #[must_use]
    pub fn coverage_block(
        execution_icount: Icount,
        node: NodeId,
        guest_pc: u64,
        block_len: u32,
    ) -> Self {
        Self {
            at: VirtualTime {
                ticks: execution_icount.retired,
            },
            payload: ObservableEventPayload::CoverageBlock {
                execution_icount,
                node,
                guest_pc,
                block_len,
            },
        }
    }

    /// Builds a white-box named coverage-marker observation.
    #[must_use]
    pub fn coverage_marker(retired_icount: Icount, node: NodeId, marker: MarkerId) -> Self {
        Self {
            at: VirtualTime {
                ticks: retired_icount.retired,
            },
            payload: ObservableEventPayload::CoverageMarker {
                retired_icount,
                node,
                marker,
            },
        }
    }

    /// Builds an assertion-proximity steering observation.
    #[must_use]
    pub fn assertion_proximity(
        at: VirtualTime,
        assertion: AssertionId,
        quantifier: AssertionQuantifierKind,
        distance: u128,
        node: Option<NodeId>,
    ) -> Self {
        Self {
            at,
            payload: ObservableEventPayload::AssertionProximity {
                assertion,
                quantifier,
                distance,
                node,
            },
        }
    }

    /// Builds a deterministic memory/register sample observation.
    #[must_use]
    pub fn memory_sample(
        at: VirtualTime,
        sample_icount: Icount,
        node: NodeId,
        place: ResolvedMemPlace,
        value: u64,
    ) -> Self {
        Self {
            at,
            payload: ObservableEventPayload::MemorySample {
                sample_icount,
                node,
                place,
                value,
            },
        }
    }

    /// Builds a deterministic I/O completion observation.
    #[must_use]
    pub fn io_completion(
        at: VirtualTime,
        node: NodeId,
        kind: IoEventKind,
        payload: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            at,
            payload: ObservableEventPayload::IoCompletion {
                node,
                kind,
                payload: payload.into(),
            },
        }
    }

    /// Builds a node-lifecycle observation.
    #[must_use]
    pub fn node_state(at: VirtualTime, node: NodeId, state: NodeLifecycle) -> Self {
        Self {
            at,
            payload: ObservableEventPayload::NodeState { node, state },
        }
    }

    /// Builds a causal assertion-state-change observation.
    #[must_use]
    pub fn assertion_state_changed(
        at: VirtualTime,
        name: AssertionId,
        state: AssertionPhase,
    ) -> Self {
        Self {
            at,
            payload: ObservableEventPayload::AssertionStateChanged { name, state },
        }
    }

    /// Builds a causal assertion-evaluation observation.
    #[must_use]
    pub fn assertion_evaluated(
        at: VirtualTime,
        name: AssertionId,
        flavor: AssertionQuantifierKind,
        condition: bool,
        message: impl Into<String>,
        details: Vec<GuestAssertionDetail>,
    ) -> Self {
        Self {
            at,
            payload: ObservableEventPayload::AssertionEvaluated {
                name,
                flavor,
                condition,
                message: message.into(),
                details,
            },
        }
    }

    /// Builds an optional white-box guest-marker observation.
    #[must_use]
    pub fn guest_marker(retired_icount: Icount, node: NodeId, marker: MarkerId) -> Self {
        Self {
            at: VirtualTime {
                ticks: retired_icount.retired,
            },
            payload: ObservableEventPayload::GuestMarker {
                retired_icount,
                node,
                marker,
            },
        }
    }

    /// Builds an optional white-box assertion-marker observation.
    #[must_use]
    pub fn guest_assertion_marker(
        retired_icount: Icount,
        node: NodeId,
        marker: GuestAssertionMarker,
    ) -> Self {
        Self {
            at: VirtualTime {
                ticks: retired_icount.retired,
            },
            payload: ObservableEventPayload::GuestAssertionMarker {
                retired_icount,
                node,
                marker,
            },
        }
    }

    /// Returns the deterministic virtual-time coordinate of the observation.
    #[must_use]
    pub fn at(&self) -> VirtualTime {
        self.at
    }

    /// Returns the typed observable payload.
    #[must_use]
    pub fn payload(&self) -> &ObservableEventPayload {
        &self.payload
    }

    /// Returns the required black-box surface category for this event, if any.
    #[must_use]
    pub fn black_box_observation_kind(&self) -> Option<BlackBoxObservationKind> {
        self.payload.black_box_observation_kind()
    }

    /// Returns the OS-agnostic black-box contract for this event, if any.
    #[must_use]
    pub fn black_box_observation_contract(&self) -> Option<BlackBoxObservationContract> {
        self.payload.black_box_observation_contract()
    }
}

/// Typed observable event payloads used by condition leaves.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ObservableEventPayload {
    /// A network frame was delivered at RESOLVE.
    NetworkDelivered {
        /// Link where the frame was delivered, when known.
        link: Option<LinkId>,
        /// Delivered frame payload bytes.
        payload: Vec<u8>,
    },
    /// Console or serial bytes were captured for a node.
    ConsoleOutput {
        /// Node whose console stream produced the bytes.
        node: NodeId,
        /// Captured console bytes.
        bytes: Vec<u8>,
    },
    /// A TCG-exec basic-block coverage observation became visible.
    CoverageBlock {
        /// Exact guest instruction count at which the block executed.
        execution_icount: Icount,
        /// Node that executed the block.
        node: NodeId,
        /// Guest program counter for the block.
        guest_pc: u64,
        /// Translated block length supplied by QEMU.
        block_len: u32,
    },
    /// A white-box named coverage marker became visible.
    CoverageMarker {
        /// Exact guest instruction count where the marker retired.
        retired_icount: Icount,
        /// Node that emitted the marker.
        node: NodeId,
        /// Stable marker identity carried by the doorbell payload.
        marker: MarkerId,
    },
    /// An assertion-proximity distance became visible as steering-only feedback.
    AssertionProximity {
        /// Assertion whose predicate produced this distance.
        assertion: AssertionId,
        /// Assertion quantifier that owns the steering obligation.
        quantifier: AssertionQuantifierKind,
        /// Non-negative structural distance; zero means satisfied.
        distance: u128,
        /// Optional node associated with the distance.
        node: Option<NodeId>,
    },
    /// A deterministic guest memory or register sample became visible.
    MemorySample {
        /// Exact guest instruction count at which the sample was taken.
        sample_icount: Icount,
        /// Node whose memory/register was sampled.
        node: NodeId,
        /// Host-resolved place that was sampled.
        place: ResolvedMemPlace,
        /// Unsigned sampled value.
        value: u64,
    },
    /// A deterministic device I/O completion became visible.
    IoCompletion {
        /// Node that observes the completion.
        node: NodeId,
        /// Completion class.
        kind: IoEventKind,
        /// Completion payload bytes.
        payload: Vec<u8>,
    },
    /// A node entered a lifecycle state.
    NodeState {
        /// Node whose lifecycle changed.
        node: NodeId,
        /// Lifecycle state entered by the node.
        state: NodeLifecycle,
    },
    /// A named assertion entered a terminal state.
    AssertionStateChanged {
        /// Assertion whose state changed.
        name: AssertionId,
        /// Terminal assertion state entered at this log point.
        state: AssertionPhase,
    },
    /// A named assertion was evaluated at this log point.
    AssertionEvaluated {
        /// Assertion whose predicate was evaluated.
        name: AssertionId,
        /// Assertion quantifier or marker flavor evaluated.
        flavor: AssertionQuantifierKind,
        /// Boolean condition value observed by the assertion fold.
        condition: bool,
        /// Human-readable assertion message.
        message: String,
        /// Structured assertion details retained for projections.
        details: Vec<GuestAssertionDetail>,
    },
    /// An optional white-box doorbell marker was observed.
    GuestMarker {
        /// Exact guest instruction count where the doorbell retired.
        retired_icount: Icount,
        /// Node that emitted the marker.
        node: NodeId,
        /// Stable marker identity carried by the doorbell payload.
        marker: MarkerId,
    },
    /// An optional white-box assertion marker was observed.
    GuestAssertionMarker {
        /// Exact guest instruction count where the doorbell retired.
        retired_icount: Icount,
        /// Node that emitted the marker.
        node: NodeId,
        /// Assertion marker payload carried by the doorbell.
        marker: GuestAssertionMarker,
    },
}

impl ObservableEventPayload {
    /// Returns the required black-box surface category for this payload, if any.
    #[must_use]
    pub fn black_box_observation_kind(&self) -> Option<BlackBoxObservationKind> {
        match self {
            Self::NetworkDelivered { .. } => Some(BlackBoxObservationKind::NetworkTraffic),
            Self::ConsoleOutput { .. } => Some(BlackBoxObservationKind::ConsoleSerialOutput),
            Self::CoverageBlock { .. } => Some(BlackBoxObservationKind::BasicBlockCoverage),
            Self::MemorySample { .. } => Some(BlackBoxObservationKind::ArchitecturalStateSample),
            Self::IoCompletion {
                kind:
                    IoEventKind::BlockRead
                    | IoEventKind::BlockWrite
                    | IoEventKind::Fsync
                    | IoEventKind::NineP,
                ..
            } => Some(BlackBoxObservationKind::DiskOrNinePIo),
            Self::IoCompletion {
                kind: IoEventKind::Network,
                ..
            } => Some(BlackBoxObservationKind::NetworkTraffic),
            Self::NodeState {
                state: NodeLifecycle::Started | NodeLifecycle::Exited,
                ..
            } => Some(BlackBoxObservationKind::RunOutcome),
            Self::NodeState {
                state: NodeLifecycle::Crashed | NodeLifecycle::Hung,
                ..
            } => Some(BlackBoxObservationKind::CrashOrHangDetection),
            Self::CoverageMarker { .. }
            | Self::AssertionProximity { .. }
            | Self::AssertionStateChanged { .. }
            | Self::AssertionEvaluated { .. }
            | Self::IoCompletion {
                kind: IoEventKind::Any,
                ..
            }
            | Self::GuestMarker { .. }
            | Self::GuestAssertionMarker { .. } => None,
        }
    }

    /// Returns the OS-agnostic black-box contract for this payload, if any.
    #[must_use]
    pub fn black_box_observation_contract(&self) -> Option<BlackBoxObservationContract> {
        self.black_box_observation_kind()
            .map(BlackBoxObservationKind::contract)
    }
}

/// Assertion flavor carried by a white-box doorbell assertion marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GuestAssertionKind {
    /// Invariant marker; any false observation violates the assertion.
    Always,
    /// Liveness marker; at least one true observation is required.
    Sometimes,
    /// Coverage marker; true observation satisfies reachability.
    Reachable,
    /// Unreachable dual; any true observation violates the assertion.
    Unreachable,
}

/// One structured key/value detail carried by a guest assertion marker.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GuestAssertionDetail {
    /// Stable detail key.
    pub key: String,
    /// Stable detail value.
    pub value: String,
}

impl GuestAssertionDetail {
    /// Builds one guest assertion detail field.
    #[must_use]
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

/// Assertion payload carried by a white-box doorbell marker.
///
/// The payload is observational: it is stored in the event log and can drive
/// assertion finalization, but it does not feed scheduler decisions or node
/// fingerprints.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GuestAssertionMarker {
    /// Stable assertion id in the marker/assertion namespace.
    pub id: AssertionId,
    /// Human-readable assertion message.
    pub message: String,
    /// Quantifier flavor declared by the marker payload.
    pub kind: GuestAssertionKind,
    /// Boolean truth value observed at the doorbell retirement point.
    pub condition: bool,
    /// Whether this marker is catalog-declared and must be hit to avoid failure.
    pub must_hit: bool,
    /// Structured marker details for later violation records.
    pub details: Vec<GuestAssertionDetail>,
    /// Source location supplied by the guest emitter.
    pub location: String,
}

impl GuestAssertionMarker {
    /// Builds a white-box assertion marker payload.
    #[must_use]
    pub fn new(
        id: AssertionId,
        message: impl Into<String>,
        kind: GuestAssertionKind,
        condition: bool,
        must_hit: bool,
        details: Vec<GuestAssertionDetail>,
        location: impl Into<String>,
    ) -> Self {
        Self {
            id,
            message: message.into(),
            kind,
            condition,
            must_hit,
            details,
            location: location.into(),
        }
    }
}

/// Converts a decoded white-box doorbell marker payload into engine event-log semantics.
///
/// Assertion payloads become [`ObservableEvent::guest_assertion_marker`] events,
/// so the existing host assertion finalizer consumes the shared marker fields.
/// Coverage payloads become named coverage-marker observations. Diagnostic
/// event and lifecycle payloads become observational guest-marker identities, so
/// they do not masquerade as black-box node lifecycle observations. The in-band
/// random-request kind returns [`None`] because it is handled by the app-random
/// decision path instead of the observational marker path.
#[cfg(feature = "test-double")]
#[must_use]
pub fn observable_event_from_whitebox_marker_payload(
    retired_icount: Icount,
    node: NodeId,
    payload: &crucible_protocol::WhiteboxMarkerPayload,
) -> Option<ObservableEvent> {
    match payload {
        crucible_protocol::WhiteboxMarkerPayload::Assertion(assertion) => {
            Some(ObservableEvent::guest_assertion_marker(
                retired_icount,
                node,
                guest_assertion_marker_from_whitebox_body(assertion),
            ))
        }
        crucible_protocol::WhiteboxMarkerPayload::Lifecycle(event) => {
            Some(ObservableEvent::guest_marker(
                retired_icount,
                node,
                MarkerId::from_name(format!("lifecycle.{}", event.semantic_label())),
            ))
        }
        crucible_protocol::WhiteboxMarkerPayload::Event(event) => {
            Some(ObservableEvent::guest_marker(
                retired_icount,
                node,
                MarkerId::from_name(event.name.clone()),
            ))
        }
        crucible_protocol::WhiteboxMarkerPayload::Coverage(coverage) => {
            Some(ObservableEvent::coverage_marker(
                retired_icount,
                node,
                MarkerId::from_name(coverage.point.clone()),
            ))
        }
        crucible_protocol::WhiteboxMarkerPayload::RandomRequest(_) => None,
    }
}

#[cfg(feature = "test-double")]
fn guest_assertion_marker_from_whitebox_body(
    body: &crucible_protocol::WhiteboxAssertionMarkerBody,
) -> GuestAssertionMarker {
    GuestAssertionMarker::new(
        AssertionId::from_name(body.id.clone()),
        body.message.clone(),
        guest_assertion_kind_from_whitebox_flavor(body.flavor),
        body.condition,
        body.must_hit,
        body.details
            .iter()
            .map(|detail| GuestAssertionDetail::new(detail.key.clone(), detail.value.clone()))
            .collect(),
        body.location.clone(),
    )
}

#[cfg(feature = "test-double")]
fn guest_assertion_kind_from_whitebox_flavor(
    flavor: crucible_protocol::WhiteboxAssertionMarkerFlavor,
) -> GuestAssertionKind {
    match flavor {
        crucible_protocol::WhiteboxAssertionMarkerFlavor::Always => GuestAssertionKind::Always,
        crucible_protocol::WhiteboxAssertionMarkerFlavor::Sometimes => {
            GuestAssertionKind::Sometimes
        }
        crucible_protocol::WhiteboxAssertionMarkerFlavor::Reachable => {
            GuestAssertionKind::Reachable
        }
        crucible_protocol::WhiteboxAssertionMarkerFlavor::Unreachable => {
            GuestAssertionKind::Unreachable
        }
    }
}

/// One leaf predicate request made by the shared condition evaluator.
///
/// The shared evaluator centralizes leaf dispatch so assertions and triggers
/// cannot use different boolean composition code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConditionLeaf<'a> {
    /// A named host-side predicate resolved over the current event-log point.
    Named {
        /// Stable predicate name.
        name: &'a str,
        /// Declared nodes referenced by the predicate.
        nodes: &'a [NodeId],
    },
    /// A named white-box marker resolved over the current event-log point.
    GuestMarker {
        /// Stable marker identity.
        marker: &'a MarkerId,
    },
}

/// Oracle for condition leaves at one deterministic evaluation point.
pub trait ConditionLeafOracle {
    /// Returns whether one leaf predicate is true.
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool;
}

impl<F> ConditionLeafOracle for F
where
    F: for<'leaf> FnMut(ConditionLeaf<'leaf>) -> bool,
{
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        self(leaf)
    }
}

/// Shared evaluator used by both assertion and trigger consumers.
pub trait ConditionEvaluator: condition_evaluator_sealed::Sealed {
    /// Returns the deterministic point where this evaluator observes the log.
    fn evaluation_point(&self) -> EventEvaluationPoint;

    /// Returns the event-log prefix identity observed by this evaluator.
    fn event_log_offset(&self) -> EventLogOffset;

    /// Resolves a leaf predicate at [`Self::evaluation_point`].
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool;

    /// Returns the most recent firing time for an event, when known.
    fn last_event_firing(&self, event: &EventId) -> Option<VirtualTime> {
        let _ = event;
        None
    }

    /// Returns the virtual time where a timer fires, when armed and known.
    fn timer_fire_time(&self, timer: &TimerId) -> Option<VirtualTime> {
        let _ = timer;
        None
    }

    /// Returns the complete timer-fire map visible to `Timer` leaves.
    fn timer_fires(&self) -> BTreeMap<TimerId, VirtualTime> {
        BTreeMap::new()
    }

    /// Returns observable event-log entries visible at the evaluation point.
    fn observable_events(&self) -> &[ObservableEvent] {
        &[]
    }

    /// Returns scheduler-owned quiescence evidence for the evaluation point.
    fn scheduler_quiescence(&self) -> Option<&SchedulerQuiescence> {
        None
    }

    /// Returns fault activation and heal facts visible at the evaluation point.
    fn fault_facts(&self) -> &[ObservedFaultFact] {
        &[]
    }

    /// Returns the authoritative white-box opt-in policy for a node.
    fn white_box_policy_for_node(&self, node: &NodeId) -> Option<WhiteBoxPolicy> {
        let _ = node;
        None
    }

    /// Returns whether a `Once` predicate has already latched true.
    fn once_condition_is_latched(&self, condition: &Condition) -> bool;

    /// Records that a `Once` predicate has latched true.
    fn latch_once_condition(&mut self, condition: &Condition);

    /// Resolves an authored code point using host-side symbol metadata.
    fn resolve_code_point(&self, _node: &NodeId, point: &CodePoint) -> Option<ResolvedCodePoint> {
        match point {
            CodePoint::GuestAddress { address } => Some(ResolvedCodePoint::guest_address(*address)),
            CodePoint::Symbol { .. } => None,
        }
    }

    /// Resolves an authored memory place using host-side symbol metadata.
    fn resolve_mem_place(&self, _node: &NodeId, place: &MemPlace) -> Option<ResolvedMemPlace> {
        match place {
            MemPlace::PhysicalAddress { address, width } => {
                Some(ResolvedMemPlace::physical_address(*address, width.bytes()))
            }
            MemPlace::Register { name, width } => {
                Some(ResolvedMemPlace::register(name.clone(), width.bytes()))
            }
            MemPlace::VirtualAddress { .. } | MemPlace::Symbol { .. } => None,
        }
    }
}

mod condition_evaluator_sealed {
    pub trait Sealed {}
}

/// Error returned when constructing a deterministic condition-evaluation prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConditionEvaluationError {
    /// A scheduler event-log prefix contained no entries.
    EmptyEventLogPrefix,
    /// A scheduler event-log entry does not continue the dense prefix sequence.
    NonPrefixEventLogSequence {
        /// Sequence number expected at this prefix offset.
        expected: u64,
        /// Sequence number carried by the entry.
        actual: u64,
    },
    /// A scheduler event-log entry's content hash does not match its material.
    InvalidEventLogEntryHash {
        /// Sequence number carried by the invalid entry.
        sequence: u64,
    },
    /// A required black-box observation regressed relative to the previous one.
    OutOfOrderEventLogEntry {
        /// Sequence number carried by the previous black-box observation entry.
        previous_sequence: u64,
        /// Time of the previous black-box observation entry.
        previous_at: VirtualTime,
        /// Sequence number carried by the out-of-order black-box observation.
        sequence: u64,
        /// Time of the out-of-order black-box observation.
        event_at: VirtualTime,
    },
    /// An event-log entry occurs after the derived evaluation point.
    FutureEventLogEntry {
        /// Deterministic evaluation point.
        point: VirtualTime,
        /// Sequence number carried by the future entry.
        sequence: u64,
        /// Time of the future event-log entry.
        event_at: VirtualTime,
    },
    /// A required black-box observation was not logged as observational.
    InvalidBlackBoxObservationClass {
        /// Sequence number carried by the invalid entry.
        sequence: u64,
        /// Required black-box surface kind reconstructed from the payload.
        kind: BlackBoxObservationKind,
        /// Class recorded by the event-log entry.
        class: SchedulerEventLogClass,
    },
    /// A required black-box observation's icount stamp does not match its payload.
    InvalidBlackBoxObservationStamp {
        /// Sequence number carried by the invalid entry.
        sequence: u64,
        /// Required black-box surface kind reconstructed from the payload.
        kind: BlackBoxObservationKind,
        /// Expected icount stamp for the payload at this event-log time.
        expected: EventLogIcountStamp,
        /// Icount stamp recorded by the event-log entry.
        actual: EventLogIcountStamp,
    },
}

impl fmt::Display for ConditionEvaluationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyEventLogPrefix => write!(
                formatter,
                "scheduler event-log prefix must contain at least one entry"
            ),
            Self::NonPrefixEventLogSequence { expected, actual } => write!(
                formatter,
                "scheduler event-log prefix expected sequence {expected}, found {actual}"
            ),
            Self::InvalidEventLogEntryHash { sequence } => write!(
                formatter,
                "scheduler event-log entry {sequence} has an invalid content hash"
            ),
            Self::OutOfOrderEventLogEntry {
                previous_sequence,
                previous_at,
                sequence,
                event_at,
            } => write!(
                formatter,
                "black-box observation entry {sequence} at {} is before entry {previous_sequence} at {}",
                event_at.ticks, previous_at.ticks
            ),
            Self::FutureEventLogEntry {
                point,
                sequence,
                event_at,
            } => write!(
                formatter,
                "event-log entry {sequence} at {} is after evaluation point {}",
                event_at.ticks, point.ticks
            ),
            Self::InvalidBlackBoxObservationClass {
                sequence,
                kind,
                class,
            } => write!(
                formatter,
                "black-box observation {kind:?} at event-log entry {sequence} has class {class:?}"
            ),
            Self::InvalidBlackBoxObservationStamp {
                sequence,
                kind,
                expected,
                actual,
            } => write!(
                formatter,
                "black-box observation {kind:?} at event-log entry {sequence} has icount stamp {actual:?}, expected {expected:?}"
            ),
        }
    }
}

impl Error for ConditionEvaluationError {}

/// Observable event-log prefix visible at one deterministic evaluation point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConditionEventLogPrefix {
    point: EventEvaluationPoint,
    base_sequence: u64,
    event_log_offset: EventLogOffset,
    prefix_offsets: BTreeMap<u64, EventLogOffset>,
    scheduler_entries: Vec<SchedulerEventLogEntry>,
    observable_events: Vec<ObservableEvent>,
    black_box_observation_kinds: BTreeSet<BlackBoxObservationKind>,
    event_firings: BTreeMap<EventId, VirtualTime>,
    timer_fires: BTreeMap<TimerId, VirtualTime>,
    ordering_facts: Vec<ObservedOrderingFact>,
    fault_facts: Vec<ObservedFaultFact>,
}

impl ConditionEventLogPrefix {
    /// Builds the run-start genesis prefix.
    #[must_use]
    pub fn genesis() -> Self {
        Self {
            point: EventEvaluationPoint::genesis(),
            base_sequence: 0,
            event_log_offset: EventLogOffset::default(),
            prefix_offsets: BTreeMap::new(),
            scheduler_entries: Vec::new(),
            observable_events: Vec::new(),
            black_box_observation_kinds: BTreeSet::new(),
            event_firings: BTreeMap::new(),
            timer_fires: BTreeMap::new(),
            ordering_facts: Vec::new(),
            fault_facts: Vec::new(),
        }
    }

    /// Builds a checked condition prefix from scheduler event-log entries.
    ///
    /// The evaluation point is derived from the final log entry: explicit
    /// scheduler evaluation-boundary payloads produce quantum or rendezvous
    /// points, while all other entries produce event-log-entry points. The
    /// observable prefix is likewise derived from `Observable` payloads rather
    /// than supplied by the caller.
    ///
    /// # Errors
    ///
    /// Returns [`ConditionEvaluationError::EmptyEventLogPrefix`] when no
    /// scheduler entries are supplied,
    /// [`ConditionEvaluationError::NonPrefixEventLogSequence`] when the entries
    /// are not a dense prefix starting at zero,
    /// [`ConditionEvaluationError::InvalidEventLogEntryHash`] when any entry's
    /// content hash does not match its canonical material,
    /// [`ConditionEvaluationError::OutOfOrderEventLogEntry`] when required
    /// black-box observations are not ordered by event-log time,
    /// [`ConditionEvaluationError::FutureEventLogEntry`] when an entry occurs
    /// after the derived evaluation point, or a black-box observation error
    /// when a required surface observation is not observational or carries an
    /// invalid icount stamp.
    pub fn from_scheduler_event_log_entries(
        entries: Vec<SchedulerEventLogEntry>,
    ) -> Result<Self, ConditionEvaluationError> {
        Self::from_scheduler_event_log_entries_with_base(entries, 0)
    }

    /// Builds a checked condition prefix from a scheduler event-log segment.
    ///
    /// This is the same validation path as
    /// [`Self::from_scheduler_event_log_entries`], but the dense sequence check
    /// starts at `base_sequence`. It is intended for live consumers that hold the
    /// prefix length separately and evaluate a newly emitted segment at its
    /// deterministic boundary.
    ///
    /// # Errors
    ///
    /// Returns the same validation errors as
    /// [`Self::from_scheduler_event_log_entries`], with sequence-prefix checks
    /// relative to `base_sequence`.
    pub fn from_scheduler_event_log_entries_with_base_sequence(
        entries: Vec<SchedulerEventLogEntry>,
        base_sequence: u64,
    ) -> Result<Self, ConditionEvaluationError> {
        Self::from_scheduler_event_log_entries_with_base(entries, base_sequence)
    }

    /// Builds a checked condition prefix with an in-memory evaluation boundary.
    ///
    /// The supplied entries are treated as the canonical event-log prefix and the
    /// synthesized boundary is appended only for this evaluation pass. This lets
    /// live consumers evaluate scheduler-owned evidence for no-entry boundaries
    /// without mutating the canonical log.
    ///
    /// # Errors
    ///
    /// Returns the same validation errors as
    /// [`Self::from_scheduler_event_log_entries`] after appending the synthesized
    /// boundary entry.
    pub fn from_scheduler_event_log_entries_with_evaluation_boundary(
        mut entries: Vec<SchedulerEventLogEntry>,
        sequence: u64,
        at: VirtualTime,
        kind: SchedulerEvaluationBoundaryKind,
    ) -> Result<Self, ConditionEvaluationError> {
        entries.push(SchedulerEventLogEntry::evaluation_boundary(
            sequence, at, kind,
        ));
        Self::from_scheduler_event_log_entries_with_base(entries, 0).map(|prefix| {
            prefix.with_event_log_offset(EventLogOffset::new(ContentHash::default(), 0, sequence))
        })
    }

    /// Builds an in-memory evaluation-boundary prefix.
    ///
    /// This creates a checked boundary point for consumers that need to evaluate
    /// scheduler-owned evidence, such as quiescence, even when the scheduler did
    /// not append a canonical event-log entry at that boundary.
    ///
    /// # Errors
    ///
    /// Returns [`ConditionEvaluationError`] if the synthesized boundary entry is
    /// not a valid dense prefix at `sequence`.
    pub fn from_evaluation_boundary(
        sequence: u64,
        at: VirtualTime,
        kind: SchedulerEvaluationBoundaryKind,
    ) -> Result<Self, ConditionEvaluationError> {
        Self::from_scheduler_event_log_entries_with_base(
            vec![SchedulerEventLogEntry::evaluation_boundary(
                sequence, at, kind,
            )],
            sequence,
        )
        .map(|prefix| {
            prefix.with_event_log_offset(EventLogOffset::new(ContentHash::default(), 0, sequence))
        })
    }

    pub(crate) fn from_scheduler_event_log_entries_with_base(
        entries: Vec<SchedulerEventLogEntry>,
        base_sequence: u64,
    ) -> Result<Self, ConditionEvaluationError> {
        let Some(last) = entries.last() else {
            return Err(ConditionEvaluationError::EmptyEventLogPrefix);
        };
        let point = EventEvaluationPoint::event_log_entry(last);
        let mut observable_events = Vec::new();
        let mut black_box_observation_kinds = BTreeSet::new();
        let mut event_firings = BTreeMap::new();
        let mut timer_fires = BTreeMap::new();
        let mut ordering_facts = Vec::new();
        let mut fault_facts = Vec::new();
        let mut previous_black_box_observation: Option<&SchedulerEventLogEntry> = None;
        for (offset, entry) in entries.iter().enumerate() {
            let offset = u64::try_from(offset).map_err(|_| {
                ConditionEvaluationError::NonPrefixEventLogSequence {
                    expected: u64::MAX,
                    actual: entry.sequence(),
                }
            })?;
            let expected = base_sequence.checked_add(offset).ok_or(
                ConditionEvaluationError::NonPrefixEventLogSequence {
                    expected: u64::MAX,
                    actual: entry.sequence(),
                },
            )?;
            if entry.sequence() != expected {
                return Err(ConditionEvaluationError::NonPrefixEventLogSequence {
                    expected,
                    actual: entry.sequence(),
                });
            }
            if !entry.has_valid_content_hash() {
                return Err(ConditionEvaluationError::InvalidEventLogEntryHash {
                    sequence: entry.sequence(),
                });
            }
            if scheduler_entry_black_box_observation_kind(entry).is_some() {
                if let Some(previous) = previous_black_box_observation
                    && entry.at().ticks < previous.at().ticks
                {
                    return Err(ConditionEvaluationError::OutOfOrderEventLogEntry {
                        previous_sequence: previous.sequence(),
                        previous_at: previous.at(),
                        sequence: entry.sequence(),
                        event_at: entry.at(),
                    });
                }
                previous_black_box_observation = Some(entry);
            }
            if entry.at().ticks > point.at().ticks {
                return Err(ConditionEvaluationError::FutureEventLogEntry {
                    point: point.at(),
                    sequence: entry.sequence(),
                    event_at: entry.at(),
                });
            }
            push_observed_state_facts(
                entry,
                &mut observable_events,
                &mut black_box_observation_kinds,
                &mut ordering_facts,
                &mut fault_facts,
            )?;
            push_condition_runtime_facts(entry, &mut event_firings, &mut timer_fires);
        }
        Ok(Self {
            point,
            base_sequence,
            event_log_offset: EventLogOffset::new(
                ContentHash::default(),
                0,
                base_sequence
                    .checked_add(u64::try_from(entries.len()).map_err(|_| {
                        ConditionEvaluationError::NonPrefixEventLogSequence {
                            expected: u64::MAX,
                            actual: u64::MAX,
                        }
                    })?)
                    .ok_or(ConditionEvaluationError::NonPrefixEventLogSequence {
                        expected: u64::MAX,
                        actual: u64::MAX,
                    })?,
            ),
            prefix_offsets: BTreeMap::new(),
            scheduler_entries: entries,
            observable_events,
            black_box_observation_kinds,
            event_firings,
            timer_fires,
            ordering_facts,
            fault_facts,
        })
    }

    pub(crate) fn with_event_log_offset(mut self, event_log_offset: EventLogOffset) -> Self {
        self.event_log_offset = event_log_offset;
        self
    }

    fn with_base_sequence(mut self, base_sequence: u64) -> Self {
        self.base_sequence = base_sequence;
        self
    }

    pub(crate) fn with_prefix_offsets(
        mut self,
        prefix_offsets: BTreeMap<u64, EventLogOffset>,
    ) -> Self {
        self.prefix_offsets = prefix_offsets;
        self
    }

    pub(crate) fn with_point(mut self, point: EventEvaluationPoint) -> Self {
        self.point = point;
        self
    }

    pub(crate) fn with_facts_through_point(&self, point: EventEvaluationPoint) -> Option<Self> {
        let through = point.at().ticks;
        let entries = self
            .scheduler_entries
            .iter()
            .take_while(|entry| entry.at().ticks <= through)
            .cloned()
            .collect::<Vec<_>>();
        let prefix_len = u64::try_from(entries.len()).ok()?;
        if entries.is_empty() {
            let mut prefix = Self::genesis();
            if !self.prefix_offsets.is_empty() {
                let prefix_events = self.base_sequence.checked_add(prefix_len)?;
                prefix = prefix.with_event_log_offset(*self.prefix_offsets.get(&prefix_events)?);
            }
            return Some(
                prefix
                    .with_base_sequence(self.base_sequence)
                    .with_prefix_offsets(self.prefix_offsets.clone())
                    .with_point(point),
            );
        }
        let prefix_events = self.base_sequence.checked_add(prefix_len)?;
        let mut prefix =
            Self::from_scheduler_event_log_entries_with_base(entries, self.base_sequence).ok()?;
        if !self.prefix_offsets.is_empty() {
            prefix = prefix.with_event_log_offset(*self.prefix_offsets.get(&prefix_events)?);
        }
        Some(
            prefix
                .with_prefix_offsets(self.prefix_offsets.clone())
                .with_point(point),
        )
    }

    /// Returns the deterministic evaluation point this prefix is visible at.
    #[must_use]
    pub fn point(&self) -> EventEvaluationPoint {
        self.point
    }

    /// Returns the event-log prefix identity this condition prefix was derived from.
    #[must_use]
    pub fn event_log_offset(&self) -> EventLogOffset {
        self.event_log_offset
    }

    /// Returns observable event-log entries visible at [`Self::point`].
    #[must_use]
    pub fn observable_events(&self) -> &[ObservableEvent] {
        &self.observable_events
    }

    /// Returns the required black-box observation categories present in this prefix.
    #[must_use]
    pub fn black_box_observation_kinds(&self) -> &BTreeSet<BlackBoxObservationKind> {
        &self.black_box_observation_kinds
    }

    /// Returns cross-node ordering facts visible at [`Self::point`].
    #[must_use]
    pub fn ordering_facts(&self) -> &[ObservedOrderingFact] {
        &self.ordering_facts
    }

    /// Returns fault activation, outcome, and heal facts visible at [`Self::point`].
    #[must_use]
    pub fn fault_facts(&self) -> &[ObservedFaultFact] {
        &self.fault_facts
    }

    /// Returns a read-only observed-state view materialized from this checked prefix.
    #[must_use]
    pub fn observed_state(&self) -> ObservedState<'_> {
        ObservedState {
            point: self.point,
            event_log_offset: self.event_log_offset,
            observable_events: &self.observable_events,
            ordering_facts: &self.ordering_facts,
            fault_facts: &self.fault_facts,
        }
    }
}

/// Read-only observable run state at one deterministic evaluation point.
///
/// The view is derived only from a checked scheduler event-log prefix. It
/// exposes black-box observable events plus explicit ordering and fault facts;
/// raw scheduler entries, RNG draws, app-random draws, host-worker state, and
/// wall-clock data are not part of this API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObservedState<'log> {
    point: EventEvaluationPoint,
    event_log_offset: EventLogOffset,
    observable_events: &'log [ObservableEvent],
    ordering_facts: &'log [ObservedOrderingFact],
    fault_facts: &'log [ObservedFaultFact],
}

impl<'log> ObservedState<'log> {
    /// Returns the deterministic evaluation point for this view.
    #[must_use]
    pub fn point(self) -> EventEvaluationPoint {
        self.point
    }

    /// Returns the virtual time where this view is evaluated.
    #[must_use]
    pub fn at(self) -> VirtualTime {
        self.point.at()
    }

    /// Returns the event-log prefix identity backing this view.
    #[must_use]
    pub fn event_log_offset(self) -> EventLogOffset {
        self.event_log_offset
    }

    /// Returns black-box observable events in deterministic log order.
    #[must_use]
    pub fn observable_events(self) -> &'log [ObservableEvent] {
        self.observable_events
    }

    /// Returns scheduler ordering facts in deterministic log order.
    #[must_use]
    pub fn ordering_facts(self) -> &'log [ObservedOrderingFact] {
        self.ordering_facts
    }

    /// Returns fault activation, outcome, and heal facts in deterministic log order.
    #[must_use]
    pub fn fault_facts(self) -> &'log [ObservedFaultFact] {
        self.fault_facts
    }
}

/// Cross-node ordering information exposed to property predicates.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ObservedOrderingFact {
    /// A scheduled event was resolved at this prefix position.
    ResolvedHappening {
        /// Dense event-log sequence where the fact was recorded.
        sequence: u64,
        /// Virtual time of the event-log entry.
        at: VirtualTime,
        /// Deterministic scheduler key for the resolved event.
        key: ScheduledEventKey,
        /// Resolve class without payload-specific data.
        class: ScheduledEventResolveClass,
    },
    /// A total delivery order was chosen for one virtual time.
    DeliveryOrder {
        /// Dense event-log sequence where the fact was recorded.
        sequence: u64,
        /// Virtual time of the event-log entry.
        at: VirtualTime,
        /// Ordered legacy event keys recorded by the delivery decision.
        order: Vec<EventKey>,
    },
}

/// Fault information exposed to property predicates.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ObservedFaultFact {
    /// A scheduled fault activation entered the event log.
    ScheduledActivation {
        /// Dense event-log sequence where the fact was recorded.
        sequence: u64,
        /// Virtual time of the event-log entry.
        at: VirtualTime,
        /// Fault whose activation was resolved.
        fault: FaultId,
    },
    /// A scheduled probabilistic fault choice entered the event log.
    ScheduledProbabilisticChoice {
        /// Dense event-log sequence where the fact was recorded.
        sequence: u64,
        /// Virtual time of the event-log entry.
        at: VirtualTime,
        /// Fault whose probabilistic choice was resolved.
        fault: FaultId,
    },
    /// A probabilistic fault outcome was decided.
    ProbabilisticOutcome {
        /// Dense event-log sequence where the fact was recorded.
        sequence: u64,
        /// Virtual time of the event-log entry.
        at: VirtualTime,
        /// Fault whose outcome was decided.
        fault: FaultId,
        /// Whether the probabilistic fault fired.
        fired: bool,
    },
    /// A control-plane full-taxonomy fault was injected.
    ControlInjected {
        /// Dense event-log sequence where the fact was recorded.
        sequence: u64,
        /// Virtual time of the event-log entry.
        at: VirtualTime,
        /// Monotone control operation sequence.
        control_sequence: u64,
        /// Stable fault tag.
        tag: FaultTag,
        /// Fault taxonomy value activated under `tag`.
        fault: Fault,
    },
    /// A control-plane full-taxonomy fault was healed.
    ControlHealed {
        /// Dense event-log sequence where the fact was recorded.
        sequence: u64,
        /// Virtual time of the event-log entry.
        at: VirtualTime,
        /// Monotone control operation sequence.
        control_sequence: u64,
        /// Stable fault tag.
        tag: FaultTag,
    },
    /// A trigger-owned membership fault was injected.
    TriggerInjected {
        /// Dense event-log sequence where the fact was recorded.
        sequence: u64,
        /// Virtual time of the event-log entry.
        at: VirtualTime,
        /// Monotone trigger action sequence.
        trigger_sequence: u64,
        /// Trigger event that produced the action.
        event: EventId,
        /// Stable fault tag.
        tag: FaultTag,
        /// Membership fault activated under `tag`.
        fault: MembershipFault,
    },
    /// A trigger-owned membership fault was healed.
    TriggerHealed {
        /// Dense event-log sequence where the fact was recorded.
        sequence: u64,
        /// Virtual time of the event-log entry.
        at: VirtualTime,
        /// Monotone trigger action sequence.
        trigger_sequence: u64,
        /// Trigger event that produced the action.
        event: EventId,
        /// Stable fault tag.
        tag: FaultTag,
    },
}

/// Host-authored resolver for assertion leaves over materialized observed state.
///
/// Implementations do not grade runs directly. Wrap them in
/// [`LintedHostAssertionOracle`] with a [`HostAssertionHarnessLint`] proof first,
/// so custom host predicate source cannot bypass `gate:harness-lint`.
pub trait HostAssertionPredicate {
    /// Returns whether one host-side assertion leaf is true at `observed`.
    fn leaf_is_true(&self, observed: ObservedState<'_>, leaf: ConditionLeaf<'_>) -> bool;
}

impl<F> HostAssertionPredicate for F
where
    F: for<'log, 'leaf> Fn(ObservedState<'log>, ConditionLeaf<'leaf>) -> bool,
{
    fn leaf_is_true(&self, observed: ObservedState<'_>, leaf: ConditionLeaf<'_>) -> bool {
        self(observed, leaf)
    }
}

/// Lint proof for host-authored assertion harness source.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HostAssertionHarnessLint {
    source_len: usize,
}

impl HostAssertionHarnessLint {
    /// Returns the byte length of the linted harness source.
    #[must_use]
    pub const fn source_len(&self) -> usize {
        self.source_len
    }
}

/// Custom host assertion oracle paired with a successful harness-lint proof.
#[derive(Clone, Debug)]
pub struct LintedHostAssertionOracle<O> {
    oracle: O,
    lint: HostAssertionHarnessLint,
}

impl<O> LintedHostAssertionOracle<O> {
    fn new(oracle: O, lint: HostAssertionHarnessLint) -> Self {
        Self { oracle, lint }
    }

    /// Returns the wrapped oracle.
    #[must_use]
    pub fn oracle(&self) -> &O {
        &self.oracle
    }

    /// Returns the wrapped oracle mutably.
    #[must_use]
    pub fn oracle_mut(&mut self) -> &mut O {
        &mut self.oracle
    }

    /// Consumes this wrapper and returns the wrapped oracle.
    #[must_use]
    pub fn into_inner(self) -> O {
        self.oracle
    }

    /// Returns the lint proof used to authorize this oracle.
    #[must_use]
    pub const fn lint(&self) -> &HostAssertionHarnessLint {
        &self.lint
    }
}

#[cfg(any(debug_assertions, feature = "test-support"))]
pub(crate) fn unchecked_host_assertion_oracle_for_test<O>(oracle: O) -> LintedHostAssertionOracle<O>
where
    O: HostAssertionPredicate,
{
    LintedHostAssertionOracle::new(oracle, HostAssertionHarnessLint { source_len: 0 })
}

mod host_assertion_oracle_sealed {
    pub trait Sealed {}
}

/// Assertion oracle accepted by the evaluator.
///
/// This trait is sealed so external host predicate code must flow through
/// [`LintedHostAssertionOracle`] instead of implementing the evaluator-facing
/// oracle directly.
pub trait HostAssertionOracle: host_assertion_oracle_sealed::Sealed {
    /// Returns whether one host-side assertion leaf is true at `observed`.
    fn leaf_is_true(&mut self, observed: ObservedState<'_>, leaf: ConditionLeaf<'_>) -> bool;
}

/// Default zero-guest-cooperation assertion oracle.
///
/// The oracle supplies no named host predicates. Properties that use only the
/// built-in black-box observable vocabulary still evaluate through the checked
/// event-log prefix.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlackBoxHostOracle;

impl host_assertion_oracle_sealed::Sealed for BlackBoxHostOracle {}

impl HostAssertionOracle for BlackBoxHostOracle {
    fn leaf_is_true(&mut self, _observed: ObservedState<'_>, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { .. } | ConditionLeaf::GuestMarker { .. } => false,
        }
    }
}

/// Data-only key for a named predicate over search-reconstructed schedule facts.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SearchScheduleNamedPredicateKey {
    name: String,
    nodes: Vec<NodeId>,
    active_fault_tags: Vec<FaultTag>,
}

impl SearchScheduleNamedPredicateKey {
    /// Builds a canonical named-predicate key.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        nodes: Vec<NodeId>,
        mut active_fault_tags: Vec<FaultTag>,
    ) -> Self {
        active_fault_tags.sort();
        active_fault_tags.dedup();
        Self {
            name: name.into(),
            nodes,
            active_fault_tags,
        }
    }

    /// Returns the named predicate identity.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the declared node references for the named predicate.
    #[must_use]
    pub fn nodes(&self) -> &[NodeId] {
        &self.nodes
    }

    /// Returns schedule-derived fault tags active at the evaluated prefix.
    #[must_use]
    pub fn active_fault_tags(&self) -> &[FaultTag] {
        &self.active_fault_tags
    }
}

/// Deterministic truth table for search-time named predicate lowering.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SearchScheduleNamedPredicateTruths {
    truths: BTreeMap<SearchScheduleNamedPredicateKey, bool>,
}

impl SearchScheduleNamedPredicateTruths {
    /// Builds an empty truth table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one deterministic named-predicate truth entry.
    #[must_use]
    pub fn with_truth(mut self, key: SearchScheduleNamedPredicateKey, value: bool) -> Self {
        self.insert_truth(key, value);
        self
    }

    /// Inserts one deterministic named-predicate truth entry.
    pub fn insert_truth(&mut self, key: SearchScheduleNamedPredicateKey, value: bool) {
        self.truths.insert(key, value);
    }

    /// Returns the truth value for `key`, if the table declares one.
    #[must_use]
    pub fn truth_for(&self, key: &SearchScheduleNamedPredicateKey) -> Option<bool> {
        self.truths.get(key).copied()
    }

    /// Returns whether the table has no declared named-predicate truths.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.truths.is_empty()
    }
}

pub(crate) struct SearchScheduleNamedPredicateHostOracle<'truths> {
    truths: &'truths SearchScheduleNamedPredicateTruths,
    missing_truths: BTreeSet<SearchScheduleNamedPredicateKey>,
}

impl<'truths> SearchScheduleNamedPredicateHostOracle<'truths> {
    pub(crate) const fn new(truths: &'truths SearchScheduleNamedPredicateTruths) -> Self {
        Self {
            truths,
            missing_truths: BTreeSet::new(),
        }
    }

    pub(crate) fn clear_missing_truths(&mut self) {
        self.missing_truths.clear();
    }

    pub(crate) fn has_missing_truths(&self) -> bool {
        !self.missing_truths.is_empty()
    }
}

impl host_assertion_oracle_sealed::Sealed for SearchScheduleNamedPredicateHostOracle<'_> {}

impl HostAssertionOracle for SearchScheduleNamedPredicateHostOracle<'_> {
    fn leaf_is_true(&mut self, observed: ObservedState<'_>, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { name, nodes } => {
                let key = SearchScheduleNamedPredicateKey::new(
                    name.to_owned(),
                    nodes.to_vec(),
                    active_search_fault_tags(observed.fault_facts()),
                );
                match self.truths.truth_for(&key) {
                    Some(value) => value,
                    None => {
                        self.missing_truths.insert(key);
                        false
                    }
                }
            }
            ConditionLeaf::GuestMarker { .. } => false,
        }
    }
}

fn active_search_fault_tags(facts: &[ObservedFaultFact]) -> Vec<FaultTag> {
    let mut active = BTreeSet::new();
    for fact in facts {
        match fact {
            ObservedFaultFact::ControlInjected { tag, .. }
            | ObservedFaultFact::TriggerInjected { tag, .. } => {
                active.insert(tag.clone());
            }
            ObservedFaultFact::ControlHealed { tag, .. }
            | ObservedFaultFact::TriggerHealed { tag, .. } => {
                active.remove(tag);
            }
            ObservedFaultFact::ScheduledActivation { .. }
            | ObservedFaultFact::ScheduledProbabilisticChoice { .. }
            | ObservedFaultFact::ProbabilisticOutcome { .. } => {}
        }
    }
    active.into_iter().collect()
}

impl<O> host_assertion_oracle_sealed::Sealed for LintedHostAssertionOracle<O> where
    O: HostAssertionPredicate
{
}

impl<O> HostAssertionOracle for LintedHostAssertionOracle<O>
where
    O: HostAssertionPredicate,
{
    fn leaf_is_true(&mut self, observed: ObservedState<'_>, leaf: ConditionLeaf<'_>) -> bool {
        HostAssertionPredicate::leaf_is_true(&self.oracle, observed, leaf)
    }
}

/// One banned host assertion harness pattern found by linting.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HostAssertionHarnessLintViolation {
    /// Source token or path fragment that matched.
    pub pattern: String,
    /// Determinism contract violated by the matched pattern.
    pub reason: String,
}

/// Error returned when host assertion harness source fails determinism linting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostAssertionHarnessLintError {
    violations: Vec<HostAssertionHarnessLintViolation>,
}

impl HostAssertionHarnessLintError {
    /// Returns every banned host assertion source pattern that was found.
    #[must_use]
    pub fn violations(&self) -> &[HostAssertionHarnessLintViolation] {
        &self.violations
    }
}

impl fmt::Display for HostAssertionHarnessLintError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "host assertion harness source contains {} banned determinism pattern(s)",
            self.violations.len()
        )
    }
}

impl Error for HostAssertionHarnessLintError {}

/// Lints host-authored assertion predicate source for banned nondeterminism.
///
/// This helper is the assertion layer's `gate:harness-lint` hook. It catches
/// host wall-clock reads, thread RNG, unordered-map/set use, filesystem/process
/// access, and `unsafe` blocks in host predicate harness source before those
/// predicates can grade a run.
///
/// # Errors
///
/// Returns [`HostAssertionHarnessLintError`] with every matched banned pattern.
pub fn lint_host_assertion_harness_source(
    source: &str,
) -> Result<HostAssertionHarnessLint, HostAssertionHarnessLintError> {
    const BANNED_PATTERNS: &[(&str, &str)] = &[
        (
            "HashMap",
            "unordered map iteration can perturb outcome order",
        ),
        (
            "HashSet",
            "unordered set iteration can perturb outcome order",
        ),
        ("SystemTime", "host wall-clock reads are nondeterministic"),
        ("Instant", "host wall-clock reads are nondeterministic"),
        ("std::time", "host wall-clock reads are nondeterministic"),
        ("chrono::", "host wall-clock reads are nondeterministic"),
        (
            "OffsetDateTime::now",
            "host wall-clock reads are nondeterministic",
        ),
        ("getrandom", "direct host RNG access is nondeterministic"),
        ("OsRng", "direct host RNG access is nondeterministic"),
        ("thread_rng", "thread-local RNG is nondeterministic"),
        ("rand::", "direct host RNG access is nondeterministic"),
        ("rand::rng", "direct host RNG access is nondeterministic"),
        ("rand::random", "direct host RNG access is nondeterministic"),
        ("from_entropy", "host entropy seeding is nondeterministic"),
        (
            "DefaultHasher",
            "randomized hash seeding can perturb outcome order",
        ),
        (
            "RandomState",
            "randomized hash seeding can perturb outcome order",
        ),
        (
            "std::env",
            "environment access is outside the recorded observed state",
        ),
        (
            "env::",
            "environment access is outside the recorded observed state",
        ),
        (
            "std::thread",
            "host thread access is outside the deterministic evaluator",
        ),
        (
            "thread::",
            "host thread access is outside the deterministic evaluator",
        ),
        (
            "thread_local!",
            "host thread-local state is outside the recorded observed state",
        ),
        (
            "std::fs",
            "filesystem access is outside the recorded observed state",
        ),
        (
            "std::{fs",
            "filesystem access is outside the recorded observed state",
        ),
        (
            "fs::",
            "filesystem access is outside the recorded observed state",
        ),
        (
            "std::process",
            "process access is outside the recorded observed state",
        ),
        (
            "std::{process",
            "process access is outside the recorded observed state",
        ),
        (
            "process::Command",
            "process access is outside the recorded observed state",
        ),
        (
            "Command::new",
            "process access is outside the recorded observed state",
        ),
        (
            "std::net",
            "network access is outside the recorded observed state",
        ),
        (
            "TcpStream",
            "network access is outside the recorded observed state",
        ),
        (
            "UdpSocket",
            "network access is outside the recorded observed state",
        ),
        ("std::io", "host I/O is outside the recorded observed state"),
        ("stdin", "host I/O is outside the recorded observed state"),
        ("stdout", "host I/O is outside the recorded observed state"),
        ("stderr", "host I/O is outside the recorded observed state"),
        (
            "println!",
            "host I/O is outside the recorded observed state",
        ),
        (
            "eprintln!",
            "host I/O is outside the recorded observed state",
        ),
        (
            "OpenOptions",
            "filesystem access is outside the recorded observed state",
        ),
        (
            "File::",
            "filesystem access is outside the recorded observed state",
        ),
        (
            "tokio::select",
            "host scheduling races are nondeterministic",
        ),
        ("tokio::spawn", "host task scheduling is nondeterministic"),
        ("select!", "host scheduling races are nondeterministic"),
        (
            "Atomic",
            "shared host state can make predicate output order-dependent",
        ),
        (
            "Mutex",
            "shared host state can make predicate output order-dependent",
        ),
        (
            "RwLock",
            "shared host state can make predicate output order-dependent",
        ),
        (
            "OnceLock",
            "shared host state can make predicate output order-dependent",
        ),
        (
            "LazyLock",
            "shared host state can make predicate output order-dependent",
        ),
        (
            "OnceCell",
            "shared host state can make predicate output order-dependent",
        ),
        (
            "lazy_static",
            "shared host state can make predicate output order-dependent",
        ),
        (
            "Cell<",
            "interior mutability can make predicate output order-dependent",
        ),
        (
            "RefCell",
            "interior mutability can make predicate output order-dependent",
        ),
        (
            "UnsafeCell",
            "interior mutability can make predicate output order-dependent",
        ),
        (
            "borrow_mut",
            "interior mutability can make predicate output order-dependent",
        ),
        (
            "parking_lot",
            "shared host state can make predicate output order-dependent",
        ),
        (
            "crossbeam",
            "shared host state can make predicate output order-dependent",
        ),
        (
            "unsafe",
            "unsafe host predicates bypass the read-only state contract",
        ),
    ];
    let violations = BANNED_PATTERNS
        .iter()
        .filter(|(pattern, _reason)| source.contains(pattern))
        .map(|(pattern, reason)| HostAssertionHarnessLintViolation {
            pattern: (*pattern).to_owned(),
            reason: (*reason).to_owned(),
        })
        .collect::<Vec<_>>();
    if violations.is_empty() {
        Ok(HostAssertionHarnessLint {
            source_len: source.len(),
        })
    } else {
        Err(HostAssertionHarnessLintError { violations })
    }
}

/// Terminal kind for one host-side assertion outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HostAssertionOutcomeKind {
    /// The assertion completed with its safety-style obligation intact.
    Passed,
    /// The assertion discharged an existential or liveness obligation.
    Satisfied,
    /// The assertion failed and contributes to the run verdict.
    Violated,
    /// The assertion produced a non-failing diagnostic outcome.
    Warning,
    /// The assertion had no evaluation point in its declared scope.
    NeverEvaluated,
    /// The assertion's trigger never fired during the run.
    NeverTriggered,
    /// A warn-disposition reachability marker was never reached.
    NeverReachedWarn,
    /// A fail-disposition reachability marker was never reached.
    NeverReachedFail,
}

/// Assertion quantifier or marker flavor attached to outcomes and violations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AssertionQuantifierKind {
    /// Host-side invariant over every evaluated point.
    Always,
    /// Host-side existential over the whole run.
    Sometimes,
    /// Host-side deadline-bound liveness assertion.
    Eventually,
    /// Host-side terminal quiescence assertion.
    AfterQuiescence,
    /// Host-side reachability or unreachability assertion.
    Reachable,
    /// Guest-side invariant marker.
    GuestAlways,
    /// Guest-side existential marker.
    GuestSometimes,
    /// Guest-side reachability marker.
    GuestReachable,
    /// Guest-side unreachability marker.
    GuestUnreachable,
}

/// Lifecycle state of one declared property during deterministic evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PropertyLifecycleState {
    /// The property is registered but has not yet been evaluated.
    Declared,
    /// The property has been evaluated without a broken obligation.
    Passing,
    /// The property discharged an existential or liveness obligation.
    Satisfied,
    /// The property has an open failing-in-progress obligation.
    Failing,
    /// The property reached a terminal failing state.
    Violated,
}

/// Current lifecycle state for one assertion in the unified outcome engine.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HostAssertionLifecycle {
    /// Assertion whose lifecycle state is reported.
    pub assertion: AssertionId,
    /// Current deterministic lifecycle state.
    pub state: PropertyLifecycleState,
}

/// Terminal result for one host-side assertion.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HostAssertionOutcome {
    /// Assertion that produced the outcome.
    pub assertion: AssertionId,
    /// Assertion quantifier or guest marker flavor that produced the outcome.
    pub quantifier: AssertionQuantifierKind,
    /// Deterministic virtual time where the outcome was recorded.
    pub at: VirtualTime,
    /// Terminal outcome kind.
    pub kind: HostAssertionOutcomeKind,
    /// Terminal lifecycle state.
    pub lifecycle: PropertyLifecycleState,
    /// Human-readable assertion message from the properties bundle.
    pub message: String,
    /// Stable assertion-layer reason.
    pub reason: String,
    evidence: Option<HostAssertionViolationEvidence>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct HostAssertionViolationEvidence {
    at_icount: Option<Icount>,
    node: Option<NodeId>,
    observed: String,
}

/// Deterministic violation record derived from the retained event log.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HostAssertionViolation {
    /// Assertion that failed.
    pub assertion: AssertionId,
    /// Author-facing assertion message.
    pub message: String,
    /// Assertion quantifier or guest marker flavor that failed.
    pub quantifier: AssertionQuantifierKind,
    /// Catalog event kind for the event-log site that produced the violation.
    pub event_kind: String,
    /// Exact guest instruction count when the site is icount-stamped.
    pub at_icount: Option<Icount>,
    /// Exact virtual-time site where the violation was attributed.
    pub at_virtual_time: VirtualTime,
    /// Node-local site owner when the deterministic log identifies one.
    pub node: Option<NodeId>,
    /// Expected-vs-observed detail drawn from assertion outcome and observed state.
    pub detail: String,
    /// Content-addressed reproduction artifact for this run.
    pub reproduction_artifact: ContentHash,
}

/// Assertion event log produced while replaying one reproduction artifact.
///
/// This value binds the retained assertion log to the reduction-oracle replay of
/// the same self-contained `(seed, scenario, schedule)` artifact. Callers cannot
/// construct it from raw fields; they must reduce a [`ReproductionArtifact`] and
/// supply the assertion log emitted by that replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssertionViolationArtifactReplay {
    replay: ReproductionReplay,
    assertion_log: RecordedAssertionLog,
}

impl AssertionViolationArtifactReplay {
    /// Binds `assertion_log` to a replay of `artifact`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] if the artifact's embedded scenario and schedule
    /// cannot be reduced by the replay oracle.
    pub fn from_artifact(
        artifact: &ReproductionArtifact,
        assertion_log: RecordedAssertionLog,
    ) -> Result<Self, EngineError> {
        Ok(Self {
            replay: artifact.replay()?,
            assertion_log,
        })
    }

    /// Returns the reduction-oracle replay that produced this assertion log.
    #[must_use]
    pub fn replay(&self) -> &ReproductionReplay {
        &self.replay
    }

    /// Returns the retained assertion log emitted by the artifact replay.
    #[must_use]
    pub fn assertion_log(&self) -> &RecordedAssertionLog {
        &self.assertion_log
    }
}

/// Bisection handoff requested for a non-reproduced assertion violation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssertionViolationBisectionRequest {
    /// Self-contained reproduction artifact whose replay diverged.
    pub artifact: ContentHash,
    /// Last event-log prefix length known to be identical.
    pub last_matching_event_prefix_len: usize,
    /// First event-log prefix length known to differ, or the terminal prefix for
    /// report-only divergences where event logs match but assertion reports do not.
    pub first_different_event_prefix_len: usize,
    /// Number of decisions in the replayed artifact schedule.
    pub schedule_decision_count: usize,
    /// First differing schedule-decision prefix length, when the logs expose one.
    pub first_different_decision_prefix_len: Option<usize>,
    /// First differing causal event-log entry reported to `gate:divergence-bisect`.
    pub first_different_causal_entry: Option<EventLogCausalDivergencePoint>,
    /// Stable reason for invoking `gate:divergence-bisect`.
    pub reason: &'static str,
}

/// Successful replay check for a violation-bearing assertion report.
///
/// The `expected` and `reproduced` reports have all violation artifact links
/// rebound to [`Self::artifact`], not to the retained-log trace hash used while
/// a live run is still being folded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssertionViolationReplayReport {
    /// Self-contained `(seed, scenario, schedule)` artifact that was replayed.
    pub artifact: ContentHash,
    /// Result of replaying the artifact through the reduction oracle.
    pub replay: ReproductionReplay,
    /// Assertion report produced from the originally recorded deterministic log.
    pub expected: HostAssertionReport,
    /// Assertion report produced from the replayed deterministic log.
    pub reproduced: HostAssertionReport,
}

/// Localized mismatch between a recorded assertion violation and its replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssertionViolationDivergence {
    /// Self-contained reproduction artifact whose replay diverged.
    pub artifact: ContentHash,
    /// First deterministic event-log prefix length whose replay no longer matches.
    pub first_different_prefix_len: usize,
    /// Icount associated with the first differing event or violation, when known.
    pub first_different_icount: Option<Icount>,
    /// First differing causal event-log entry, when the event log differs.
    pub first_different_causal_entry: Option<EventLogCausalDivergencePoint>,
    /// Recorded event-log entry at the first differing prefix position.
    pub expected_event: Option<SchedulerEventLogEntry>,
    /// Replayed event-log entry at the first differing prefix position.
    pub reproduced_event: Option<SchedulerEventLogEntry>,
    /// Recorded violation at the first differing violation slot.
    pub expected_violation: Option<HostAssertionViolation>,
    /// Replayed violation at the first differing violation slot.
    pub reproduced_violation: Option<HostAssertionViolation>,
    /// Required `gate:divergence-bisect` handoff for this non-reproduction.
    pub bisection: AssertionViolationBisectionRequest,
}

/// Error returned when assertion violation reproduction fails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssertionViolationReplayError {
    /// The artifact's embedded scenario and schedule could not be reduced.
    ArtifactReplay {
        /// Artifact whose reduction failed.
        artifact: ContentHash,
        /// Stable error text from the reduction oracle.
        reason: String,
    },
    /// Replay evidence was reduced from a different artifact tuple.
    ReplayArtifactMismatch {
        /// Artifact replay expected from the checked reproduction artifact.
        expected: Box<ReproductionReplay>,
        /// Artifact replay supplied with the reproduced assertion log.
        reproduced: Box<ReproductionReplay>,
    },
    /// The original retained log did not contain an assertion violation.
    MissingRecordedViolation {
        /// Artifact checked for a violation reproduction.
        artifact: ContentHash,
    },
    /// The original retained log could not be assertion-checked.
    RecordedAssertionCheck(OfflineAssertionCheckError),
    /// The replayed retained log could not be assertion-checked.
    ReproducedAssertionCheck(OfflineAssertionCheckError),
    /// The replay completed but did not reproduce the same violation report.
    Divergence {
        /// Localized assertion-replay divergence.
        divergence: Box<AssertionViolationDivergence>,
    },
}

impl fmt::Display for AssertionViolationReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArtifactReplay { reason, .. } => {
                write!(
                    formatter,
                    "assertion violation artifact replay failed: {reason}"
                )
            }
            Self::ReplayArtifactMismatch {
                expected,
                reproduced,
            } => write!(
                formatter,
                "assertion violation replay artifact mismatch: expected state {} reproduced state {}",
                expected.state.to_hex(),
                reproduced.state.to_hex()
            ),
            Self::MissingRecordedViolation { .. } => {
                write!(
                    formatter,
                    "recorded assertion log did not contain a violation"
                )
            }
            Self::RecordedAssertionCheck(error) => {
                write!(
                    formatter,
                    "recorded assertion log could not be checked: {error}"
                )
            }
            Self::ReproducedAssertionCheck(error) => {
                write!(
                    formatter,
                    "reproduced assertion log could not be checked: {error}"
                )
            }
            Self::Divergence { divergence } => write!(
                formatter,
                "assertion violation replay diverged at prefix {}",
                divergence.first_different_prefix_len
            ),
        }
    }
}

impl Error for AssertionViolationReplayError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RecordedAssertionCheck(error) | Self::ReproducedAssertionCheck(error) => {
                Some(error)
            }
            Self::ArtifactReplay { .. }
            | Self::ReplayArtifactMismatch { .. }
            | Self::MissingRecordedViolation { .. }
            | Self::Divergence { .. } => None,
        }
    }
}

/// Final host-side assertion report for one run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostAssertionReport {
    outcomes: Vec<HostAssertionOutcome>,
    violations: Vec<HostAssertionViolation>,
    proximities: Vec<HostAssertionProximity>,
    verdict: AssertionRunVerdict,
}

impl HostAssertionReport {
    /// Returns terminal assertion outcomes in canonical assertion order.
    #[must_use]
    pub fn outcomes(&self) -> &[HostAssertionOutcome] {
        &self.outcomes
    }

    /// Returns deterministic violation records in canonical assertion order.
    #[must_use]
    pub fn violations(&self) -> &[HostAssertionViolation] {
        &self.violations
    }

    /// Returns steering-only assertion proximity projections in canonical order.
    ///
    /// These distances are pure projections of the retained event log. They do
    /// not contribute to assertion outcomes, run verdicts, or reproduction
    /// fingerprints.
    #[must_use]
    pub fn proximities(&self) -> &[HostAssertionProximity] {
        &self.proximities
    }

    /// Returns the assertion-layer pass/fail verdict.
    #[must_use]
    pub fn verdict(&self) -> &AssertionRunVerdict {
        &self.verdict
    }
}

/// Steering-only distance-to-satisfaction for one unsatisfied assertion.
///
/// A proximity record is produced only for unsatisfied liveness/existential
/// properties whose predicates have a useful guidance signal: unsatisfied
/// `Sometimes`, armed-but-undischarged `Eventually`, and expected-reachable
/// properties that were never reached. The distance is the minimum value observed
/// along the checked event-log trajectory.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HostAssertionProximity {
    /// Assertion whose predicate produced this distance.
    pub assertion: AssertionId,
    /// Assertion quantifier that owns the steering obligation.
    pub quantifier: AssertionQuantifierKind,
    /// Non-negative structural distance; zero means the predicate was satisfied.
    pub distance: u128,
    /// Evaluation time where the minimum distance was observed.
    pub at: VirtualTime,
    /// Event-log prefix that produced the minimum distance.
    pub event_log_offset: EventLogOffset,
}

/// Replays an assertion violation artifact and verifies bit-identical violations.
///
/// `reproduced` is the execution-layer bridge: it carries the deterministic
/// assertion event log emitted by replaying `artifact`, plus the reduction-oracle
/// replay that proves the same embedded scenario and schedule were reduced. This
/// function verifies the artifact with the reduction oracle, re-grades the
/// original and reproduced logs against the scenario's embedded properties, and
/// treats any event-log or assertion-report mismatch as a localized divergence.
///
/// # Errors
///
/// Returns [`AssertionViolationReplayError`] when artifact reduction fails, the
/// reproduced log was not reduced from the same artifact tuple, the recorded log
/// contains no violation, either retained assertion log is invalid, or the replay
/// does not reproduce the same assertion report.
pub fn check_assertion_violation_reproduction(
    artifact: &ReproductionArtifact,
    recorded_log: &RecordedAssertionLog,
    reproduced: &AssertionViolationArtifactReplay,
) -> Result<AssertionViolationReplayReport, AssertionViolationReplayError> {
    let mut expected_oracle = BlackBoxHostOracle;
    let mut reproduced_oracle = BlackBoxHostOracle;
    check_assertion_violation_reproduction_with_oracles(
        artifact,
        recorded_log,
        reproduced,
        &mut expected_oracle,
        &mut reproduced_oracle,
    )
}

/// Replays an assertion violation artifact with caller-supplied host oracles.
///
/// This is the offset-preserving variant for linted named host predicates. The
/// supplied oracles grade the recorded and reproduced retained logs respectively;
/// both logs must carry exact segment offsets for every observed prefix the
/// oracle can inspect.
///
/// # Errors
///
/// Returns [`AssertionViolationReplayError`] when artifact reduction fails, the
/// reproduced log was not reduced from the same artifact tuple, the recorded log
/// contains no violation, either retained assertion log is invalid for its oracle,
/// or the replay does not reproduce the same assertion report.
pub fn check_assertion_violation_reproduction_with_oracles<ExpectedOracle, ReproducedOracle>(
    artifact: &ReproductionArtifact,
    recorded_log: &RecordedAssertionLog,
    reproduced: &AssertionViolationArtifactReplay,
    expected_oracle: &mut ExpectedOracle,
    reproduced_oracle: &mut ReproducedOracle,
) -> Result<AssertionViolationReplayReport, AssertionViolationReplayError>
where
    ExpectedOracle: HostAssertionOracle + ?Sized,
    ReproducedOracle: HostAssertionOracle + ?Sized,
{
    let artifact_id = artifact.id();
    let replay =
        artifact
            .replay()
            .map_err(|source| AssertionViolationReplayError::ArtifactReplay {
                artifact: artifact_id,
                reason: engine_error_message(&source),
            })?;
    if reproduced.replay() != &replay {
        return Err(AssertionViolationReplayError::ReplayArtifactMismatch {
            expected: Box::new(replay),
            reproduced: Box::new(reproduced.replay().clone()),
        });
    }
    let properties = artifact.scenario_form().properties();
    let world = artifact.scenario_form().world();
    let expected = assertion_replay_report_for_log_with_oracle(
        artifact_id,
        properties,
        world,
        recorded_log,
        expected_oracle,
    )
    .map_err(AssertionViolationReplayError::RecordedAssertionCheck)?;
    if expected.violations().is_empty() {
        return Err(AssertionViolationReplayError::MissingRecordedViolation {
            artifact: artifact_id,
        });
    }

    let reproduced_log = reproduced.assertion_log();
    let reproduced = assertion_replay_report_for_log_with_oracle(
        artifact_id,
        properties,
        world,
        reproduced_log,
        reproduced_oracle,
    )
    .map_err(AssertionViolationReplayError::ReproducedAssertionCheck)?;

    let event_logs_differ =
        !event_log_causal_projections_match(recorded_log.entries(), reproduced_log.entries());
    if event_logs_differ || expected != reproduced {
        return Err(AssertionViolationReplayError::Divergence {
            divergence: Box::new(assertion_violation_replay_divergence(
                artifact_id,
                artifact.schedule(),
                properties,
                world,
                recorded_log,
                reproduced_log,
                &expected,
                &reproduced,
            )),
        });
    }

    Ok(AssertionViolationReplayReport {
        artifact: artifact_id,
        replay,
        expected,
        reproduced,
    })
}

/// Deterministic trace artifact intended for external formal tooling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalFormalTraceExport {
    bytes: Vec<u8>,
    content_hash: ContentHash,
    entry_count: u64,
}

impl ExternalFormalTraceExport {
    /// Returns the stable export format label.
    #[must_use]
    pub fn format(&self) -> &'static str {
        "crucible.external-formal-trace.v1"
    }

    /// Returns deterministic trace bytes for external consumers.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the content address of [`Self::bytes`].
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        self.content_hash
    }

    /// Returns the number of scheduler event-log entries exported.
    #[must_use]
    pub fn entry_count(&self) -> u64 {
        self.entry_count
    }
}

/// Exporter for external formal trace consumers.
///
/// This type only serializes a retained scheduler event log. It does not load,
/// interpret, or evaluate an external specification.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExternalFormalTraceExporter;

impl ExternalFormalTraceExporter {
    /// Exports a retained scheduler event log as deterministic trace bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ConditionEvaluationError`] when the entries are not a dense,
    /// hash-valid scheduler log prefix.
    pub fn export_event_log(
        entries: &[SchedulerEventLogEntry],
    ) -> Result<ExternalFormalTraceExport, ConditionEvaluationError> {
        validate_recorded_event_log_entries(entries)?;
        let entry_count = u64::try_from(entries.len()).map_err(|_| {
            ConditionEvaluationError::NonPrefixEventLogSequence {
                expected: u64::MAX,
                actual: u64::MAX,
            }
        })?;
        let bytes = external_formal_trace_bytes(entries);
        let content_hash = ContentHash::from_bytes(&bytes);
        Ok(ExternalFormalTraceExport {
            bytes,
            content_hash,
            entry_count,
        })
    }
}

/// Offline assertion checker for a retained scheduler event log.
///
/// The checker never drives guests or scheduler state. It reconstructs checked
/// [`ConditionEventLogPrefix`] values from recorded [`SchedulerEventLogEntry`]
/// values and feeds them through [`HostAssertionEvaluator`], so amended property
/// sets can be graded against retained runs.
#[derive(Clone, Debug, Default)]
pub struct OfflineAssertionChecker {
    white_box_policies: BTreeMap<NodeId, WhiteBoxPolicy>,
    guest_assertion_catalog: Vec<GuestAssertionMarker>,
    code_points: BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>,
    mem_places: BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>,
    terminal_quiescence: Option<SchedulerQuiescence>,
}

impl OfflineAssertionChecker {
    /// Builds an offline checker with no white-box marker policy.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds authoritative white-box opt-in policies for guest marker evaluation.
    #[must_use]
    pub fn with_white_box_policies(
        mut self,
        policies: impl IntoIterator<Item = (NodeId, WhiteBoxPolicy)>,
    ) -> Self {
        self.white_box_policies = policies.into_iter().collect();
        self
    }

    /// Adds authoritative white-box opt-in policies from a world definition.
    #[must_use]
    pub fn with_world_white_box_policies(self, world: &World) -> Self {
        self.with_white_box_policies(
            world
                .nodes()
                .iter()
                .map(|node| (node.id.clone(), node.white_box)),
        )
    }

    /// Adds catalog-declared guest assertion markers for offline finalization.
    #[must_use]
    pub fn with_guest_assertion_catalog(
        mut self,
        catalog: impl IntoIterator<Item = GuestAssertionMarker>,
    ) -> Self {
        self.guest_assertion_catalog = catalog.into_iter().collect();
        self
    }

    /// Adds host-side code point resolutions visible to coverage predicates.
    #[must_use]
    pub fn with_resolved_code_points(
        mut self,
        code_points: impl IntoIterator<Item = ((NodeId, CodePoint), ResolvedCodePoint)>,
    ) -> Self {
        self.code_points = code_points.into_iter().collect();
        self
    }

    /// Adds host-side memory place resolutions visible to memory predicates.
    #[must_use]
    pub fn with_resolved_mem_places(
        mut self,
        mem_places: impl IntoIterator<Item = ((NodeId, MemPlace), ResolvedMemPlace)>,
    ) -> Self {
        self.mem_places = mem_places.into_iter().collect();
        self
    }

    /// Adds terminal scheduler-quiescence evidence for after-quiescence checks.
    #[must_use]
    pub fn with_terminal_scheduler_quiescence(mut self, quiescence: SchedulerQuiescence) -> Self {
        self.terminal_quiescence = Some(quiescence);
        self
    }

    /// Grades `properties` against a retained event log using the black-box oracle.
    ///
    /// This entry point is for built-in black-box predicates and guest markers.
    /// Named host predicates that inspect [`ObservedState::event_log_offset`]
    /// should use [`Self::check_run_with_oracle`] with a [`RecordedAssertionLog`]
    /// carrying the exact recorded prefix offsets.
    ///
    /// # Errors
    ///
    /// Returns [`OfflineAssertionCheckError::ConditionEvaluation`] when the
    /// recorded entries are not a dense, hash-valid scheduler log prefix.
    pub fn check_run(
        &self,
        properties: &Properties,
        event_log: &[SchedulerEventLogEntry],
    ) -> Result<HostAssertionReport, OfflineAssertionCheckError> {
        let mut oracle = BlackBoxHostOracle;
        let recorded = RecordedAssertionLog::from_entries(event_log.to_vec());
        self.check_run_internal(properties, &recorded, &mut oracle, false)
    }

    /// Grades `properties` against a retained event log using `oracle`.
    ///
    /// The event log is read-only input. Evaluation observes every recorded
    /// event-log prefix except the terminal prefix, then lets
    /// [`HostAssertionEvaluator::finalize_prefix`] observe that terminal prefix
    /// exactly once before applying end-of-run policies. Each observed point is
    /// reconstructed as a [`ConditionEventLogPrefix`] before evaluation. The
    /// supplied [`RecordedAssertionLog`] should carry exact event-log offsets for
    /// every prefix that can be observed by a named host predicate. Intermediate
    /// prefixes without retained offsets are skipped for custom-oracle checks;
    /// the terminal prefix must always have an exact offset.
    ///
    /// # Errors
    ///
    /// Returns [`OfflineAssertionCheckError::ConditionEvaluation`] when the
    /// recorded entries are not a dense, hash-valid scheduler log prefix,
    /// [`OfflineAssertionCheckError::MissingEventLogOffset`] when the terminal
    /// prefix has no recorded offset, or
    /// [`OfflineAssertionCheckError::EventLogOffsetMismatch`] when a supplied
    /// offset's event count does not match the evaluated prefix length.
    pub fn check_run_with_oracle<O>(
        &self,
        properties: &Properties,
        recorded_log: &RecordedAssertionLog,
        oracle: &mut O,
    ) -> Result<HostAssertionReport, OfflineAssertionCheckError>
    where
        O: HostAssertionOracle + ?Sized,
    {
        self.check_run_internal(properties, recorded_log, oracle, true)
    }

    fn check_run_internal<O>(
        &self,
        properties: &Properties,
        recorded_log: &RecordedAssertionLog,
        oracle: &mut O,
        require_recorded_offsets: bool,
    ) -> Result<HostAssertionReport, OfflineAssertionCheckError>
    where
        O: HostAssertionOracle + ?Sized,
    {
        let mut evaluator = HostAssertionEvaluator::new(properties)
            .with_white_box_policies(self.white_box_policies.clone())
            .with_guest_assertion_catalog(self.guest_assertion_catalog.clone())
            .with_resolved_code_points(
                self.code_points
                    .iter()
                    .map(|(key, value)| ((key.0.clone(), key.1.clone()), *value)),
            )
            .with_resolved_mem_places(
                self.mem_places
                    .iter()
                    .map(|(key, value)| ((key.0.clone(), key.1.clone()), value.clone())),
            );
        if let Some(quiescence) = self.terminal_quiescence.clone() {
            evaluator = evaluator.with_terminal_scheduler_quiescence(quiescence);
        }
        let event_log = recorded_log.entries();
        let terminal_prefix_len = event_log.len();

        for index in 0..event_log.len() {
            let prefix_len = index + 1;
            if prefix_len == terminal_prefix_len {
                continue;
            }
            if require_recorded_offsets
                && recorded_log
                    .event_log_offset(u64::try_from(prefix_len).map_err(|_| {
                        OfflineAssertionCheckError::PrefixLengthOverflow { prefix_len }
                    })?)
                    .is_none()
            {
                continue;
            }
            let prefix = condition_prefix_from_recorded_log(
                recorded_log,
                prefix_len,
                require_recorded_offsets,
            )?;
            evaluator.observe_prefix(&prefix, oracle);
        }

        let terminal_prefix = condition_prefix_from_recorded_log(
            recorded_log,
            terminal_prefix_len,
            require_recorded_offsets,
        )?;
        Ok(evaluator.finalize_prefix(&terminal_prefix, oracle))
    }
}

/// Retained assertion-checking view of a recorded scheduler event log.
///
/// Custom host predicate oracles can inspect [`ObservedState::event_log_offset`].
/// To make those predicates byte-identical online and offline, this value stores
/// the scheduler entries plus offsets reconstructed from retained event-log
/// segments using the scheduler's canonical segment and prefix hashing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedAssertionLog {
    entries: Vec<SchedulerEventLogEntry>,
    prefix_offsets: BTreeMap<u64, EventLogOffset>,
}

impl RecordedAssertionLog {
    /// Builds a recorded log from scheduler entries without segment offsets.
    ///
    /// This is sufficient for [`OfflineAssertionChecker::check_run`], whose
    /// default black-box oracle cannot inspect event-log offsets. Custom host
    /// oracles should use [`Self::from_segments`] so evaluated prefixes carry the
    /// same offsets the scheduler observed online.
    #[must_use]
    pub fn from_entries(entries: Vec<SchedulerEventLogEntry>) -> Self {
        Self {
            entries,
            prefix_offsets: BTreeMap::new(),
        }
    }

    /// Builds a recorded log and appends one terminal quantum evaluation boundary.
    #[must_use]
    pub fn from_entries_with_quantum_evaluation_boundary(
        mut entries: Vec<SchedulerEventLogEntry>,
        sequence: u64,
        at: VirtualTime,
    ) -> Self {
        entries.push(SchedulerEventLogEntry::evaluation_boundary(
            sequence,
            at,
            SchedulerEvaluationBoundaryKind::Quantum,
        ));
        Self::from_entries(entries)
    }

    /// Builds a recorded log from retained scheduler event-log segments.
    ///
    /// Each segment is folded in order with the same canonical segment bytes and
    /// prefix hash material used by scheduler EMIT. Offsets are recorded at every
    /// segment boundary, including the zero-entry genesis prefix.
    ///
    /// # Errors
    ///
    /// Returns [`OfflineAssertionCheckError::EventLogSegmentLengthOverflow`] when
    /// a segment byte length cannot fit in `u64`,
    /// [`OfflineAssertionCheckError::EventLogByteOffsetOverflow`] when cumulative
    /// bytes overflow, or [`OfflineAssertionCheckError::EventLogEventCountOverflow`]
    /// when cumulative event count overflows.
    pub fn from_segments(
        segments: impl IntoIterator<Item = Vec<SchedulerEventLogEntry>>,
    ) -> Result<Self, OfflineAssertionCheckError> {
        let mut entries = Vec::new();
        let mut prefix_offsets = BTreeMap::new();
        let mut prefix = scheduler_event_log_empty_prefix();
        let mut bytes = 0_u64;
        let mut events = 0_u64;
        prefix_offsets.insert(events, EventLogOffset::new(prefix, bytes, events));

        for segment in segments {
            if segment.is_empty() {
                continue;
            }
            let segment_bytes = scheduler_event_log_segment_bytes(prefix, &segment);
            let segment_hash = ContentHash::from_bytes(&segment_bytes);
            let previous_prefix = prefix;
            let appended_bytes = u64::try_from(segment_bytes.len()).map_err(|_| {
                OfflineAssertionCheckError::EventLogSegmentLengthOverflow {
                    segment_len: segment_bytes.len(),
                }
            })?;
            bytes = bytes.checked_add(appended_bytes).ok_or(
                OfflineAssertionCheckError::EventLogByteOffsetOverflow {
                    bytes,
                    appended_bytes,
                },
            )?;
            let appended_events = u64::try_from(segment.len()).map_err(|_| {
                OfflineAssertionCheckError::EventLogEventCountOverflow {
                    events,
                    appended_events: u64::MAX,
                }
            })?;
            events = events.checked_add(appended_events).ok_or(
                OfflineAssertionCheckError::EventLogEventCountOverflow {
                    events,
                    appended_events,
                },
            )?;
            let prefix_material = format!(
                "previous_prefix={}\nappended_segment={}\nbytes={bytes}\nevents={events}",
                previous_prefix.to_hex(),
                segment_hash.to_hex(),
            );
            prefix = ContentHash::from_canonical_material(
                "crucible.scheduler.event-log.prefix.v1",
                &prefix_material,
            );
            prefix_offsets.insert(
                events,
                EventLogOffset::with_appended_segment(previous_prefix, bytes, events, segment_hash),
            );
            entries.extend(segment);
        }

        Ok(Self {
            entries,
            prefix_offsets,
        })
    }

    /// Returns retained scheduler event-log entries.
    #[must_use]
    pub fn entries(&self) -> &[SchedulerEventLogEntry] {
        &self.entries
    }

    /// Returns the reconstructed event-log offset for `prefix_len`, if retained.
    #[must_use]
    pub fn event_log_offset(&self, prefix_len: u64) -> Option<EventLogOffset> {
        self.prefix_offsets.get(&prefix_len).copied()
    }
}

/// Error returned by offline assertion checking.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OfflineAssertionCheckError {
    /// A recorded scheduler prefix failed condition-prefix validation.
    ConditionEvaluation(ConditionEvaluationError),
    /// A custom-oracle check lacks the exact event-log offset for a prefix.
    MissingEventLogOffset {
        /// Number of scheduler entries visible in the evaluated prefix.
        prefix_len: u64,
    },
    /// A supplied event-log offset does not describe the evaluated prefix.
    EventLogOffsetMismatch {
        /// Number of scheduler entries visible in the evaluated prefix.
        prefix_len: u64,
        /// Event count stored in the supplied offset.
        offset_events: u64,
    },
    /// The platform prefix length could not be represented in the recorded format.
    PrefixLengthOverflow {
        /// Number of scheduler entries visible in the evaluated prefix.
        prefix_len: usize,
    },
    /// A retained event-log segment's canonical byte length exceeded `u64`.
    EventLogSegmentLengthOverflow {
        /// Segment byte length that could not be represented.
        segment_len: usize,
    },
    /// Cumulative event-log byte offsets overflowed.
    EventLogByteOffsetOverflow {
        /// Cumulative bytes before the segment was folded.
        bytes: u64,
        /// Bytes appended by the segment.
        appended_bytes: u64,
    },
    /// Cumulative event-log event counts overflowed.
    EventLogEventCountOverflow {
        /// Cumulative events before the segment was folded.
        events: u64,
        /// Events appended by the segment.
        appended_events: u64,
    },
}

impl fmt::Display for OfflineAssertionCheckError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConditionEvaluation(error) => write!(formatter, "{error}"),
            Self::MissingEventLogOffset { prefix_len } => write!(
                formatter,
                "offline assertion log is missing event-log offset for prefix length {prefix_len}"
            ),
            Self::EventLogOffsetMismatch {
                prefix_len,
                offset_events,
            } => write!(
                formatter,
                "offline assertion log offset for prefix length {prefix_len} carries event count {offset_events}"
            ),
            Self::PrefixLengthOverflow { prefix_len } => write!(
                formatter,
                "offline assertion log prefix length {prefix_len} does not fit in u64"
            ),
            Self::EventLogSegmentLengthOverflow { segment_len } => write!(
                formatter,
                "offline assertion log segment length {segment_len} does not fit in u64"
            ),
            Self::EventLogByteOffsetOverflow {
                bytes,
                appended_bytes,
            } => write!(
                formatter,
                "offline assertion log byte offset overflow: bytes={bytes} appended_bytes={appended_bytes}"
            ),
            Self::EventLogEventCountOverflow {
                events,
                appended_events,
            } => write!(
                formatter,
                "offline assertion log event count overflow: events={events} appended_events={appended_events}"
            ),
        }
    }
}

impl Error for OfflineAssertionCheckError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ConditionEvaluation(error) => Some(error),
            Self::MissingEventLogOffset { .. }
            | Self::EventLogOffsetMismatch { .. }
            | Self::PrefixLengthOverflow { .. }
            | Self::EventLogSegmentLengthOverflow { .. }
            | Self::EventLogByteOffsetOverflow { .. }
            | Self::EventLogEventCountOverflow { .. } => None,
        }
    }
}

impl From<ConditionEvaluationError> for OfflineAssertionCheckError {
    fn from(error: ConditionEvaluationError) -> Self {
        Self::ConditionEvaluation(error)
    }
}

/// Streaming host-side assertion evaluator over checked observable state.
#[derive(Clone, Debug)]
pub struct HostAssertionEvaluator {
    states: Vec<HostAssertionState>,
    guest_marker_states: Vec<GuestMarkerAssertionState>,
    once_latches: Vec<Condition>,
    white_box_policies: BTreeMap<NodeId, WhiteBoxPolicy>,
    code_points: BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>,
    mem_places: BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>,
    terminal_quiescence: Option<SchedulerQuiescence>,
    last_prefix: Option<ConditionEventLogPrefix>,
}

impl HostAssertionEvaluator {
    /// Builds an evaluator for the assertions in canonical property order.
    #[must_use]
    pub fn new(properties: &Properties) -> Self {
        Self {
            states: properties
                .assertions()
                .iter()
                .map(HostAssertionState::new)
                .collect(),
            guest_marker_states: Vec::new(),
            once_latches: Vec::new(),
            white_box_policies: BTreeMap::new(),
            code_points: BTreeMap::new(),
            mem_places: BTreeMap::new(),
            terminal_quiescence: None,
            last_prefix: None,
        }
    }

    /// Adds authoritative white-box opt-in policies for guest marker evaluation.
    #[must_use]
    pub fn with_white_box_policies(
        mut self,
        policies: impl IntoIterator<Item = (NodeId, WhiteBoxPolicy)>,
    ) -> Self {
        self.white_box_policies = policies.into_iter().collect();
        self
    }

    /// Adds authoritative white-box opt-in policies from a world definition.
    #[must_use]
    pub fn with_world_white_box_policies(self, world: &World) -> Self {
        self.with_white_box_policies(
            world
                .nodes()
                .iter()
                .map(|node| (node.id.clone(), node.white_box)),
        )
    }

    /// Adds catalog-declared guest assertion markers before event-log evaluation.
    #[must_use]
    pub fn with_guest_assertion_catalog(
        mut self,
        catalog: impl IntoIterator<Item = GuestAssertionMarker>,
    ) -> Self {
        for marker in catalog {
            let _ = guest_marker_assertion_state_for(&mut self.guest_marker_states, &marker);
        }
        self
    }

    /// Adds host-side code point resolutions visible to coverage predicates.
    #[must_use]
    pub fn with_resolved_code_points(
        mut self,
        code_points: impl IntoIterator<Item = ((NodeId, CodePoint), ResolvedCodePoint)>,
    ) -> Self {
        self.code_points = code_points.into_iter().collect();
        self
    }

    /// Adds host-side memory place resolutions visible to memory predicates.
    #[must_use]
    pub fn with_resolved_mem_places(
        mut self,
        mem_places: impl IntoIterator<Item = ((NodeId, MemPlace), ResolvedMemPlace)>,
    ) -> Self {
        self.mem_places = mem_places.into_iter().collect();
        self
    }

    /// Adds terminal scheduler-quiescence evidence for after-quiescence checks.
    #[must_use]
    pub fn with_terminal_scheduler_quiescence(mut self, quiescence: SchedulerQuiescence) -> Self {
        self.terminal_quiescence = Some(quiescence);
        self
    }

    /// Observes one checked event-log prefix and returns newly terminal outcomes.
    pub fn observe_prefix<O>(
        &mut self,
        prefix: &ConditionEventLogPrefix,
        oracle: &mut O,
    ) -> Vec<HostAssertionOutcome>
    where
        O: HostAssertionOracle + ?Sized,
    {
        let mut outcomes = Vec::new();
        outcomes.extend(self.observe_due_eventually_deadlines(prefix, oracle));
        let once_latches = &mut self.once_latches;
        for state in &mut self.states {
            if let Some(outcome) = observe_host_assertion_state(
                state,
                prefix,
                oracle,
                once_latches,
                &self.white_box_policies,
                &self.code_points,
                &self.mem_places,
            ) {
                outcomes.push(outcome);
            }
        }
        outcomes.extend(observe_guest_marker_assertions(
            &mut self.guest_marker_states,
            prefix,
            &self.white_box_policies,
        ));
        self.last_prefix = Some(prefix.clone());
        sort_host_assertion_outcomes(&mut outcomes);
        outcomes
    }

    /// Returns current lifecycle states in canonical assertion order.
    #[must_use]
    pub fn lifecycle_states(&self) -> Vec<HostAssertionLifecycle> {
        let mut states = self
            .states
            .iter()
            .map(HostAssertionState::lifecycle)
            .chain(
                self.guest_marker_states
                    .iter()
                    .map(GuestMarkerAssertionState::lifecycle),
            )
            .collect::<Vec<_>>();
        states.sort_by(|left, right| {
            left.assertion
                .cmp(&right.assertion)
                .then_with(|| left.state.cmp(&right.state))
        });
        states
    }

    fn observe_due_eventually_deadlines<O>(
        &mut self,
        prefix: &ConditionEventLogPrefix,
        oracle: &mut O,
    ) -> Vec<HostAssertionOutcome>
    where
        O: HostAssertionOracle + ?Sized,
    {
        let Some(previous_prefix) = self.last_prefix.clone() else {
            return Vec::new();
        };
        let previous_at = previous_prefix.point().at().ticks;
        let next_at = prefix.point().at().ticks;
        if next_at <= previous_at {
            return Vec::new();
        }

        let mut deadlines = BTreeSet::new();
        for state in &self.states {
            if state.terminal.is_some() {
                continue;
            }
            for obligation in &state.pending_eventually {
                if obligation.deadline.ticks > previous_at && obligation.deadline.ticks < next_at {
                    deadlines.insert(obligation.deadline);
                }
            }
        }

        let mut outcomes = Vec::new();
        for deadline in deadlines {
            let Some(deadline_prefix) =
                prefix.with_facts_through_point(EventEvaluationPoint::assertion_deadline(deadline))
            else {
                continue;
            };
            let once_latches = &mut self.once_latches;
            for state in &mut self.states {
                if let Some(outcome) = observe_eventually_deadline_state(
                    state,
                    &deadline_prefix,
                    oracle,
                    once_latches,
                    &self.white_box_policies,
                    &self.code_points,
                    &self.mem_places,
                ) {
                    outcomes.push(outcome);
                }
            }
        }
        outcomes
    }

    /// Finalizes all assertions at the supplied terminal event-log prefix.
    pub fn finalize_prefix<O>(
        &mut self,
        prefix: &ConditionEventLogPrefix,
        oracle: &mut O,
    ) -> HostAssertionReport
    where
        O: HostAssertionOracle + ?Sized,
    {
        self.observe_prefix(prefix, oracle);
        let once_latches = &mut self.once_latches;
        for state in &mut self.states {
            finalize_host_assertion_state(
                state,
                prefix,
                oracle,
                once_latches,
                &self.white_box_policies,
                &self.code_points,
                &self.mem_places,
                self.terminal_quiescence.as_ref(),
            );
        }
        for state in &mut self.guest_marker_states {
            finalize_guest_marker_assertion_state(state, prefix.point().at());
        }
        let outcomes = self
            .states
            .iter()
            .filter_map(HostAssertionState::outcome)
            .chain(
                self.guest_marker_states
                    .iter()
                    .filter_map(GuestMarkerAssertionState::outcome),
            )
            .collect::<Vec<_>>();
        let mut outcomes = outcomes;
        sort_host_assertion_outcomes(&mut outcomes);
        let failures = outcomes
            .iter()
            .filter(|outcome| host_assertion_outcome_fails_run(outcome.kind))
            .map(|outcome| {
                AssertionVerdictFailure::new(
                    outcome.assertion.clone(),
                    outcome.at,
                    outcome.reason.clone(),
                )
            })
            .collect::<Vec<_>>();
        let reproduction_artifact = assertion_reproduction_artifact_from_prefix(prefix);
        let violations =
            host_assertion_violations_from_outcomes(&outcomes, prefix, reproduction_artifact);
        let mut proximities = self
            .states
            .iter()
            .filter_map(HostAssertionState::proximity)
            .collect::<Vec<_>>();
        sort_host_assertion_proximities(&mut proximities);
        HostAssertionReport {
            outcomes,
            violations,
            proximities,
            verdict: AssertionRunVerdict::failed(failures),
        }
    }
}

#[derive(Clone, Debug)]
struct HostAssertionState {
    assertion: AssertionDef,
    lifecycle: PropertyLifecycleState,
    terminal: Option<HostAssertionTerminal>,
    evaluated: bool,
    eventually_triggered: bool,
    eventually_satisfied_at: Option<VirtualTime>,
    pending_eventually: Vec<EventuallyObligation>,
    proximity: Option<HostAssertionProximityMinimum>,
}

#[derive(Clone, Debug)]
struct GuestMarkerAssertionState {
    id: AssertionId,
    lifecycle: PropertyLifecycleState,
    message: String,
    kind: GuestAssertionKind,
    must_hit: bool,
    details: Vec<GuestAssertionDetail>,
    location: String,
    observed_true: bool,
    last_icount: Option<Icount>,
    last_node: Option<NodeId>,
    terminal: Option<HostAssertionTerminal>,
}

impl GuestMarkerAssertionState {
    fn new(marker: &GuestAssertionMarker) -> Self {
        Self {
            id: marker.id.clone(),
            lifecycle: PropertyLifecycleState::Declared,
            message: marker.message.clone(),
            kind: marker.kind,
            must_hit: marker.must_hit,
            details: marker.details.clone(),
            location: marker.location.clone(),
            observed_true: false,
            last_icount: None,
            last_node: None,
            terminal: None,
        }
    }

    fn observe_payload(
        &mut self,
        retired_icount: Icount,
        node: &NodeId,
        marker: &GuestAssertionMarker,
    ) {
        self.must_hit |= marker.must_hit;
        self.message = marker.message.clone();
        self.location = marker.location.clone();
        self.details = marker.details.clone();
        self.last_icount = Some(retired_icount);
        self.last_node = Some(node.clone());
        if self.lifecycle == PropertyLifecycleState::Declared {
            self.lifecycle = PropertyLifecycleState::Passing;
        }
        if marker.condition {
            self.observed_true = true;
        }
    }

    fn lifecycle(&self) -> HostAssertionLifecycle {
        HostAssertionLifecycle {
            assertion: self.id.clone(),
            state: self.lifecycle,
        }
    }

    fn outcome(&self) -> Option<HostAssertionOutcome> {
        self.terminal.as_ref().map(|terminal| HostAssertionOutcome {
            assertion: self.id.clone(),
            quantifier: guest_assertion_quantifier_kind(self.kind),
            at: terminal.at,
            kind: terminal.kind,
            lifecycle: terminal.lifecycle,
            message: self.message.clone(),
            reason: terminal.reason.clone(),
            evidence: terminal.evidence.clone(),
        })
    }

    fn terminal(
        &mut self,
        kind: HostAssertionOutcomeKind,
        at: VirtualTime,
        reason: impl Into<String>,
    ) -> Option<HostAssertionOutcome> {
        self.terminal_with_evidence(kind, at, reason, None)
    }

    fn terminal_with_evidence(
        &mut self,
        kind: HostAssertionOutcomeKind,
        at: VirtualTime,
        reason: impl Into<String>,
        evidence: Option<HostAssertionViolationEvidence>,
    ) -> Option<HostAssertionOutcome> {
        if self.terminal.is_some() {
            return None;
        }
        let lifecycle = lifecycle_for_outcome_kind(kind);
        self.lifecycle = lifecycle;
        self.terminal = Some(HostAssertionTerminal {
            kind,
            lifecycle,
            at,
            reason: reason.into(),
            evidence,
        });
        self.outcome()
    }
}

impl HostAssertionState {
    fn new(assertion: &AssertionDef) -> Self {
        Self {
            assertion: assertion.clone(),
            lifecycle: PropertyLifecycleState::Declared,
            terminal: None,
            evaluated: false,
            eventually_triggered: false,
            eventually_satisfied_at: None,
            pending_eventually: Vec::new(),
            proximity: None,
        }
    }

    fn lifecycle(&self) -> HostAssertionLifecycle {
        HostAssertionLifecycle {
            assertion: self.assertion.id.clone(),
            state: self.lifecycle,
        }
    }

    fn outcome(&self) -> Option<HostAssertionOutcome> {
        self.terminal.as_ref().map(|terminal| HostAssertionOutcome {
            assertion: self.assertion.id.clone(),
            quantifier: property_quantifier_kind(&self.assertion.property),
            at: terminal.at,
            kind: terminal.kind,
            lifecycle: terminal.lifecycle,
            message: self.assertion.message.clone(),
            reason: terminal.reason.clone(),
            evidence: terminal.evidence.clone(),
        })
    }

    fn terminal(
        &mut self,
        kind: HostAssertionOutcomeKind,
        at: VirtualTime,
        reason: impl Into<String>,
    ) -> Option<HostAssertionOutcome> {
        self.terminal_with_evidence(kind, at, reason, None)
    }

    fn terminal_with_evidence(
        &mut self,
        kind: HostAssertionOutcomeKind,
        at: VirtualTime,
        reason: impl Into<String>,
        evidence: Option<HostAssertionViolationEvidence>,
    ) -> Option<HostAssertionOutcome> {
        if self.terminal.is_some() {
            return None;
        }
        let lifecycle = lifecycle_for_outcome_kind(kind);
        self.lifecycle = lifecycle;
        self.terminal = Some(HostAssertionTerminal {
            kind,
            lifecycle,
            at,
            reason: reason.into(),
            evidence,
        });
        self.outcome()
    }

    fn observe_proximity(&mut self, prefix: &ConditionEventLogPrefix, distance: u128) {
        let candidate = HostAssertionProximityMinimum {
            distance,
            at: prefix.point().at(),
            event_log_offset: prefix.event_log_offset(),
        };
        let should_replace = match self.proximity.as_ref() {
            Some(current) => candidate.is_better_than(current),
            None => true,
        };
        if should_replace {
            self.proximity = Some(candidate);
        }
    }

    fn proximity(&self) -> Option<HostAssertionProximity> {
        let terminal = self.terminal.as_ref()?;
        if !property_proximity_is_reportable(
            &self.assertion.property,
            terminal.kind,
            self.eventually_triggered,
        ) {
            return None;
        }
        let minimum = self.proximity.as_ref()?;
        Some(HostAssertionProximity {
            assertion: self.assertion.id.clone(),
            quantifier: property_quantifier_kind(&self.assertion.property),
            distance: minimum.distance,
            at: minimum.at,
            event_log_offset: minimum.event_log_offset,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HostAssertionTerminal {
    kind: HostAssertionOutcomeKind,
    lifecycle: PropertyLifecycleState,
    at: VirtualTime,
    reason: String,
    evidence: Option<HostAssertionViolationEvidence>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HostAssertionProximityMinimum {
    distance: u128,
    at: VirtualTime,
    event_log_offset: EventLogOffset,
}

impl HostAssertionProximityMinimum {
    fn is_better_than(&self, current: &Self) -> bool {
        self.distance
            .cmp(&current.distance)
            .then_with(|| self.at.ticks.cmp(&current.at.ticks))
            .then_with(|| {
                self.event_log_offset
                    .events
                    .cmp(&current.event_log_offset.events)
            })
            .then_with(|| {
                self.event_log_offset
                    .bytes
                    .cmp(&current.event_log_offset.bytes)
            })
            .is_lt()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EventuallyObligation {
    triggered_at: VirtualTime,
    deadline: VirtualTime,
}

fn observe_host_assertion_state<O>(
    state: &mut HostAssertionState,
    prefix: &ConditionEventLogPrefix,
    oracle: &mut O,
    once_latches: &mut Vec<Condition>,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
    code_points: &BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>,
    mem_places: &BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>,
) -> Option<HostAssertionOutcome>
where
    O: HostAssertionOracle + ?Sized,
{
    if state.terminal.is_some() {
        return None;
    }

    let at = prefix.point().at();
    let property = state.assertion.property.clone();
    match property {
        Property::Always { predicate } => {
            if prefix.event_log_offset().events == 0 {
                return None;
            }
            state.evaluated = true;
            state.lifecycle = PropertyLifecycleState::Passing;
            if host_condition_is_true(
                prefix,
                &predicate,
                oracle,
                once_latches,
                white_box_policies,
                code_points,
                mem_places,
                None,
            ) {
                None
            } else {
                state.terminal_with_evidence(
                    HostAssertionOutcomeKind::Violated,
                    at,
                    "always predicate was false",
                    Some(condition_violation_evidence(
                        prefix,
                        &predicate,
                        false,
                        white_box_policies,
                    )),
                )
            }
        }
        Property::Sometimes { predicate } => {
            state.evaluated = true;
            state.lifecycle = PropertyLifecycleState::Passing;
            let mut leaf_cache = HostConditionEvaluationCache::new();
            let satisfied = host_condition_is_true_with_cache(
                prefix,
                &predicate,
                oracle,
                once_latches,
                &mut leaf_cache,
                white_box_policies,
                code_points,
                mem_places,
                None,
            );
            let distance = host_condition_distance_to_satisfaction(
                prefix,
                &predicate,
                oracle,
                once_latches,
                &mut leaf_cache,
                white_box_policies,
                code_points,
                mem_places,
                None,
            );
            state.observe_proximity(prefix, distance);
            if satisfied {
                state.terminal(
                    HostAssertionOutcomeKind::Satisfied,
                    at,
                    "sometimes predicate became true",
                )
            } else {
                None
            }
        }
        Property::Eventually {
            trigger,
            property,
            deadline,
        } => {
            let mut leaf_cache = HostConditionEvaluationCache::new();
            observe_eventually_assertion(
                state,
                prefix,
                oracle,
                &trigger,
                &property,
                deadline,
                once_latches,
                &mut leaf_cache,
                white_box_policies,
                code_points,
                mem_places,
            )
        }
        Property::AfterQuiescence { .. } => None,
        Property::Reachable {
            predicate,
            expectation,
        } => observe_reachability_assertion(
            state,
            prefix,
            oracle,
            once_latches,
            white_box_policies,
            code_points,
            mem_places,
            &predicate,
            expectation,
        ),
    }
}

// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::too_many_arguments)]
fn observe_eventually_assertion<O>(
    state: &mut HostAssertionState,
    prefix: &ConditionEventLogPrefix,
    oracle: &mut O,
    trigger: &Condition,
    property: &Condition,
    deadline: VirtualTime,
    once_latches: &mut Vec<Condition>,
    leaf_cache: &mut HostConditionEvaluationCache,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
    code_points: &BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>,
    mem_places: &BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>,
) -> Option<HostAssertionOutcome>
where
    O: HostAssertionOracle + ?Sized,
{
    let at = prefix.point().at();
    state.evaluated = true;
    if state.lifecycle == PropertyLifecycleState::Declared {
        state.lifecycle = PropertyLifecycleState::Passing;
    }
    if let Some(expired) = state
        .pending_eventually
        .iter()
        .copied()
        .find(|obligation| at.ticks > obligation.deadline.ticks)
    {
        return state.terminal_with_evidence(
            HostAssertionOutcomeKind::Violated,
            expired.deadline,
            format!(
                "eventually deadline expired after trigger at {}",
                expired.triggered_at.ticks
            ),
            Some(condition_violation_evidence_at(
                prefix,
                EventEvaluationPoint::assertion_deadline(expired.deadline),
                property,
                false,
                white_box_policies,
            )),
        );
    }

    if !state.eventually_triggered
        && host_condition_is_true_with_cache(
            prefix,
            trigger,
            oracle,
            once_latches,
            leaf_cache,
            white_box_policies,
            code_points,
            mem_places,
            None,
        )
    {
        state.eventually_triggered = true;
        state.lifecycle = PropertyLifecycleState::Failing;
        state.pending_eventually.push(EventuallyObligation {
            triggered_at: at,
            deadline: eventually_deadline(at, deadline),
        });
    }

    let property_satisfied = !state.pending_eventually.is_empty()
        && host_condition_is_true_with_cache(
            prefix,
            property,
            oracle,
            once_latches,
            leaf_cache,
            white_box_policies,
            code_points,
            mem_places,
            None,
        );
    if !state.pending_eventually.is_empty() {
        let distance = host_condition_distance_to_satisfaction(
            prefix,
            property,
            oracle,
            once_latches,
            leaf_cache,
            white_box_policies,
            code_points,
            mem_places,
            None,
        );
        state.observe_proximity(prefix, distance);
    }
    if property_satisfied {
        state.pending_eventually.clear();
        state.eventually_satisfied_at = Some(at);
        state.lifecycle = PropertyLifecycleState::Satisfied;
    } else if let Some(expired) = state
        .pending_eventually
        .iter()
        .copied()
        .find(|obligation| at.ticks >= obligation.deadline.ticks)
    {
        return state.terminal_with_evidence(
            HostAssertionOutcomeKind::Violated,
            expired.deadline,
            format!(
                "eventually deadline expired after trigger at {}",
                expired.triggered_at.ticks
            ),
            Some(condition_violation_evidence_at(
                prefix,
                EventEvaluationPoint::assertion_deadline(expired.deadline),
                property,
                false,
                white_box_policies,
            )),
        );
    }

    None
}

fn observe_eventually_deadline_state<O>(
    state: &mut HostAssertionState,
    prefix: &ConditionEventLogPrefix,
    oracle: &mut O,
    once_latches: &mut Vec<Condition>,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
    code_points: &BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>,
    mem_places: &BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>,
) -> Option<HostAssertionOutcome>
where
    O: HostAssertionOracle + ?Sized,
{
    if state.terminal.is_some() || state.pending_eventually.is_empty() {
        return None;
    }

    let Property::Eventually { property, .. } = state.assertion.property.clone() else {
        return None;
    };
    let at = prefix.point().at();
    state.lifecycle = PropertyLifecycleState::Failing;
    let mut leaf_cache = HostConditionEvaluationCache::new();
    if host_condition_is_true_with_cache(
        prefix,
        &property,
        oracle,
        once_latches,
        &mut leaf_cache,
        white_box_policies,
        code_points,
        mem_places,
        None,
    ) {
        state.pending_eventually.clear();
        state.eventually_satisfied_at = Some(at);
        state.lifecycle = PropertyLifecycleState::Satisfied;
        return None;
    }
    let distance = host_condition_distance_to_satisfaction(
        prefix,
        &property,
        oracle,
        once_latches,
        &mut leaf_cache,
        white_box_policies,
        code_points,
        mem_places,
        None,
    );
    state.observe_proximity(prefix, distance);

    let expired = state
        .pending_eventually
        .iter()
        .copied()
        .find(|obligation| at.ticks >= obligation.deadline.ticks)?;
    state.terminal_with_evidence(
        HostAssertionOutcomeKind::Violated,
        expired.deadline,
        format!(
            "eventually deadline expired after trigger at {}",
            expired.triggered_at.ticks
        ),
        Some(condition_violation_evidence(
            prefix,
            &property,
            false,
            white_box_policies,
        )),
    )
}

// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::too_many_arguments)]
fn observe_reachability_assertion<O>(
    state: &mut HostAssertionState,
    prefix: &ConditionEventLogPrefix,
    oracle: &mut O,
    once_latches: &mut Vec<Condition>,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
    code_points: &BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>,
    mem_places: &BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>,
    predicate: &Condition,
    expectation: ReachabilityExpectation,
) -> Option<HostAssertionOutcome>
where
    O: HostAssertionOracle + ?Sized,
{
    state.evaluated = true;
    state.lifecycle = PropertyLifecycleState::Passing;
    let mut leaf_cache = HostConditionEvaluationCache::new();
    let reached = host_condition_is_true_with_cache(
        prefix,
        predicate,
        oracle,
        once_latches,
        &mut leaf_cache,
        white_box_policies,
        code_points,
        mem_places,
        None,
    );
    if matches!(expectation, ReachabilityExpectation::Reachable { .. }) {
        let distance = host_condition_distance_to_satisfaction(
            prefix,
            predicate,
            oracle,
            once_latches,
            &mut leaf_cache,
            white_box_policies,
            code_points,
            mem_places,
            None,
        );
        state.observe_proximity(prefix, distance);
    }
    match (expectation, reached) {
        (ReachabilityExpectation::Reachable { .. }, true) => state.terminal(
            HostAssertionOutcomeKind::Satisfied,
            prefix.point().at(),
            "reachable predicate became true",
        ),
        (ReachabilityExpectation::Unreachable, true) => state.terminal_with_evidence(
            HostAssertionOutcomeKind::Violated,
            prefix.point().at(),
            "unreachable predicate became true",
            Some(condition_violation_evidence(
                prefix,
                predicate,
                true,
                white_box_policies,
            )),
        ),
        (
            ReachabilityExpectation::Reachable { .. } | ReachabilityExpectation::Unreachable,
            false,
        ) => None,
    }
}

// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::too_many_arguments)]
fn finalize_host_assertion_state<O>(
    state: &mut HostAssertionState,
    prefix: &ConditionEventLogPrefix,
    oracle: &mut O,
    once_latches: &mut Vec<Condition>,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
    code_points: &BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>,
    mem_places: &BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>,
    terminal_quiescence: Option<&SchedulerQuiescence>,
) where
    O: HostAssertionOracle + ?Sized,
{
    if state.terminal.is_some() {
        return;
    }

    let at = prefix.point().at();
    let property = state.assertion.property.clone();
    match property {
        Property::Always { .. } => {
            if state.evaluated {
                state.terminal(
                    HostAssertionOutcomeKind::Passed,
                    at,
                    "always predicate stayed true",
                );
            } else {
                state.terminal(
                    HostAssertionOutcomeKind::NeverEvaluated,
                    at,
                    "always predicate scope was never evaluated",
                );
            }
        }
        Property::Sometimes { predicate } => {
            state.terminal_with_evidence(
                HostAssertionOutcomeKind::Violated,
                at,
                "sometimes predicate never became true",
                Some(condition_violation_evidence(
                    prefix,
                    &predicate,
                    false,
                    white_box_policies,
                )),
            );
        }
        Property::Eventually {
            trigger, property, ..
        } => {
            finalize_eventually_assertion(state, prefix, &trigger, &property, white_box_policies);
        }
        Property::AfterQuiescence { predicate } => {
            if host_condition_is_true(
                prefix,
                &predicate,
                oracle,
                once_latches,
                white_box_policies,
                code_points,
                mem_places,
                terminal_quiescence,
            ) {
                state.terminal(
                    HostAssertionOutcomeKind::Passed,
                    at,
                    "after-quiescence predicate was true",
                );
            } else {
                state.terminal_with_evidence(
                    HostAssertionOutcomeKind::Violated,
                    at,
                    "after-quiescence predicate was false",
                    Some(condition_violation_evidence(
                        prefix,
                        &predicate,
                        false,
                        white_box_policies,
                    )),
                );
            }
        }
        Property::Reachable {
            predicate,
            expectation,
        } => match expectation {
            ReachabilityExpectation::Reachable { on_unreached } => match on_unreached {
                ReachableDisposition::Warn => {
                    state.terminal(
                        HostAssertionOutcomeKind::NeverReachedWarn,
                        at,
                        "reachable predicate was never reached",
                    );
                }
                ReachableDisposition::Fail => {
                    state.terminal_with_evidence(
                        HostAssertionOutcomeKind::NeverReachedFail,
                        at,
                        "reachable predicate was never reached",
                        Some(condition_violation_evidence(
                            prefix,
                            &predicate,
                            false,
                            white_box_policies,
                        )),
                    );
                }
            },
            ReachabilityExpectation::Unreachable => {
                state.terminal(
                    HostAssertionOutcomeKind::Passed,
                    at,
                    "unreachable predicate stayed false",
                );
            }
        },
    }
}

fn finalize_eventually_assertion(
    state: &mut HostAssertionState,
    prefix: &ConditionEventLogPrefix,
    trigger: &Condition,
    property: &Condition,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
) {
    let at = prefix.point().at();
    if let Some(expired) = state
        .pending_eventually
        .iter()
        .copied()
        .find(|obligation| at.ticks > obligation.deadline.ticks)
    {
        state.terminal_with_evidence(
            HostAssertionOutcomeKind::Violated,
            expired.deadline,
            format!(
                "eventually deadline expired after trigger at {}",
                expired.triggered_at.ticks
            ),
            Some(condition_violation_evidence_at(
                prefix,
                EventEvaluationPoint::assertion_deadline(expired.deadline),
                property,
                false,
                white_box_policies,
            )),
        );
    } else if !state.pending_eventually.is_empty() {
        state.terminal_with_evidence(
            HostAssertionOutcomeKind::Violated,
            at,
            "eventually run ended while triggered",
            Some(condition_violation_evidence(
                prefix,
                property,
                false,
                white_box_policies,
            )),
        );
    } else if let Some(satisfied_at) = state.eventually_satisfied_at {
        state.terminal(
            HostAssertionOutcomeKind::Satisfied,
            satisfied_at,
            "eventually predicate became true",
        );
    } else if state.eventually_triggered {
        state.terminal_with_evidence(
            HostAssertionOutcomeKind::Violated,
            at,
            "eventually trigger fired without a satisfiable obligation",
            Some(condition_violation_evidence(
                prefix,
                trigger,
                true,
                white_box_policies,
            )),
        );
    } else {
        state.terminal(
            HostAssertionOutcomeKind::NeverTriggered,
            at,
            "eventually trigger never fired",
        );
    }
}

fn property_quantifier_kind(property: &Property) -> AssertionQuantifierKind {
    match property {
        Property::Always { .. } => AssertionQuantifierKind::Always,
        Property::Sometimes { .. } => AssertionQuantifierKind::Sometimes,
        Property::Eventually { .. } => AssertionQuantifierKind::Eventually,
        Property::AfterQuiescence { .. } => AssertionQuantifierKind::AfterQuiescence,
        Property::Reachable { .. } => AssertionQuantifierKind::Reachable,
    }
}

fn guest_assertion_quantifier_kind(kind: GuestAssertionKind) -> AssertionQuantifierKind {
    match kind {
        GuestAssertionKind::Always => AssertionQuantifierKind::GuestAlways,
        GuestAssertionKind::Sometimes => AssertionQuantifierKind::GuestSometimes,
        GuestAssertionKind::Reachable => AssertionQuantifierKind::GuestReachable,
        GuestAssertionKind::Unreachable => AssertionQuantifierKind::GuestUnreachable,
    }
}

fn host_assertion_violations_from_outcomes(
    outcomes: &[HostAssertionOutcome],
    prefix: &ConditionEventLogPrefix,
    reproduction_artifact: ContentHash,
) -> Vec<HostAssertionViolation> {
    let mut violations = outcomes
        .iter()
        .filter(|outcome| host_assertion_outcome_fails_run(outcome.kind))
        .map(|outcome| {
            let evidence = outcome
                .evidence
                .clone()
                .unwrap_or_else(|| outcome_point_evidence(prefix, outcome));
            HostAssertionViolation {
                assertion: outcome.assertion.clone(),
                message: outcome.message.clone(),
                quantifier: outcome.quantifier,
                event_kind: String::from("assertion_state_changed"),
                at_icount: evidence.at_icount,
                at_virtual_time: outcome.at,
                node: evidence.node.clone(),
                detail: violation_detail(outcome, &evidence),
                reproduction_artifact,
            }
        })
        .collect::<Vec<_>>();
    violations.sort_by(|left, right| {
        left.assertion
            .cmp(&right.assertion)
            .then_with(|| left.quantifier.cmp(&right.quantifier))
            .then_with(|| left.event_kind.cmp(&right.event_kind))
            .then_with(|| left.at_virtual_time.cmp(&right.at_virtual_time))
            .then_with(|| left.node.cmp(&right.node))
            .then_with(|| left.detail.cmp(&right.detail))
            .then_with(|| left.reproduction_artifact.cmp(&right.reproduction_artifact))
    });
    violations
}

fn assertion_replay_report_for_log_with_oracle<O>(
    artifact: ContentHash,
    properties: &Properties,
    world: &World,
    recorded_log: &RecordedAssertionLog,
    oracle: &mut O,
) -> Result<HostAssertionReport, OfflineAssertionCheckError>
where
    O: HostAssertionOracle + ?Sized,
{
    let report = OfflineAssertionChecker::new()
        .with_world_white_box_policies(world)
        .check_run_with_oracle(properties, recorded_log, oracle)?;
    Ok(host_assertion_report_with_reproduction_artifact(
        report, artifact,
    ))
}

fn host_assertion_report_with_reproduction_artifact(
    mut report: HostAssertionReport,
    artifact: ContentHash,
) -> HostAssertionReport {
    for violation in &mut report.violations {
        violation.reproduction_artifact = artifact;
    }
    report
}

// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::too_many_arguments)]
fn assertion_violation_replay_divergence(
    artifact: ContentHash,
    schedule: &Schedule,
    properties: &Properties,
    world: &World,
    expected_log: &RecordedAssertionLog,
    reproduced_log: &RecordedAssertionLog,
    expected_report: &HostAssertionReport,
    reproduced_report: &HostAssertionReport,
) -> AssertionViolationDivergence {
    let event_log_comparison =
        compare_event_log_determinism(expected_log.entries(), reproduced_log.entries());
    let event_logs_differ = !event_log_comparison.passes();
    let event_mismatch = event_log_comparison.mismatch().cloned();
    let first_different_causal_entry = event_mismatch
        .as_ref()
        .and_then(|mismatch| mismatch.first_location().cloned());
    let event_prefix = if event_logs_differ {
        first_different_assertion_replay_prefix(expected_log, reproduced_log)
    } else {
        CausalEventLogPrefixDivergence::terminal(expected_log, reproduced_log)
    };
    let bisection = AssertionViolationBisectionRequest {
        artifact,
        last_matching_event_prefix_len: event_prefix.expected_last_matching_event_prefix_len,
        first_different_event_prefix_len: event_prefix.expected_first_different_event_prefix_len,
        schedule_decision_count: schedule.len(),
        first_different_decision_prefix_len: first_different_decision_prefix_len(
            expected_log,
            reproduced_log,
        ),
        first_different_causal_entry: first_different_causal_entry.clone(),
        reason: "assertion violation did not reproduce bit-identically",
    };
    let expected_prefix_report = assertion_replay_report_for_prefix(
        artifact,
        properties,
        world,
        expected_log,
        event_prefix.expected_first_different_event_prefix_len,
    )
    .unwrap_or_else(|_| expected_report.clone());
    let reproduced_prefix_report = assertion_replay_report_for_prefix(
        artifact,
        properties,
        world,
        reproduced_log,
        event_prefix.reproduced_first_different_event_prefix_len,
    )
    .unwrap_or_else(|_| reproduced_report.clone());
    let (expected_violation, reproduced_violation) = first_differing_violation(
        expected_prefix_report.violations(),
        reproduced_prefix_report.violations(),
    )
    .unwrap_or_else(|| {
        first_differing_violation(expected_report.violations(), reproduced_report.violations())
            .unwrap_or((None, None))
    });
    let expected_event = event_mismatch
        .as_ref()
        .and_then(|mismatch| mismatch.expected_raw_index)
        .and_then(|raw_index| expected_log.entries().get(raw_index))
        .cloned();
    let reproduced_event = event_mismatch
        .as_ref()
        .and_then(|mismatch| mismatch.reproduced_raw_index)
        .and_then(|raw_index| reproduced_log.entries().get(raw_index))
        .cloned();
    let first_different_icount = first_different_causal_entry
        .as_ref()
        .map(|entry| entry.at.icount)
        .or_else(|| {
            expected_violation
                .as_ref()
                .and_then(|violation| violation.at_icount)
        })
        .or_else(|| {
            reproduced_violation
                .as_ref()
                .and_then(|violation| violation.at_icount)
        });

    AssertionViolationDivergence {
        artifact,
        first_different_prefix_len: event_prefix.expected_first_different_event_prefix_len,
        first_different_icount,
        first_different_causal_entry,
        expected_event,
        reproduced_event,
        expected_violation,
        reproduced_violation,
        bisection,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CausalEventLogPrefixDivergence {
    expected_last_matching_event_prefix_len: usize,
    expected_first_different_event_prefix_len: usize,
    reproduced_first_different_event_prefix_len: usize,
}

impl CausalEventLogPrefixDivergence {
    fn terminal(
        expected_log: &RecordedAssertionLog,
        reproduced_log: &RecordedAssertionLog,
    ) -> Self {
        Self {
            expected_last_matching_event_prefix_len: expected_log.entries().len(),
            expected_first_different_event_prefix_len: expected_log.entries().len(),
            reproduced_first_different_event_prefix_len: reproduced_log.entries().len(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProjectedCausalEventLogEntry<'log> {
    raw_index: usize,
    entry: &'log SchedulerEventLogEntry,
}

impl<'log> ProjectedCausalEventLogEntry<'log> {
    fn raw_prefix_len(self) -> usize {
        self.raw_index.saturating_add(1)
    }
}

fn first_different_assertion_replay_prefix(
    expected_log: &RecordedAssertionLog,
    reproduced_log: &RecordedAssertionLog,
) -> CausalEventLogPrefixDivergence {
    let expected = event_log_causal_projection(expected_log.entries());
    let reproduced = event_log_causal_projection(reproduced_log.entries());
    let max_len = expected.len().max(reproduced.len());
    if max_len == 0 {
        return CausalEventLogPrefixDivergence::terminal(expected_log, reproduced_log);
    }
    let mut low = 0;
    let mut high = max_len;
    while low < high {
        let middle = low + (high - low) / 2;
        if event_log_causal_projection_prefixes_match(&expected, &reproduced, middle) {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    CausalEventLogPrefixDivergence {
        expected_last_matching_event_prefix_len: event_log_raw_prefix_for_causal_prefix(
            &expected,
            low.saturating_sub(1),
            expected_log.entries().len(),
        ),
        expected_first_different_event_prefix_len: event_log_raw_prefix_for_causal_prefix(
            &expected,
            low,
            expected_log.entries().len(),
        ),
        reproduced_first_different_event_prefix_len: event_log_raw_prefix_for_causal_prefix(
            &reproduced,
            low,
            reproduced_log.entries().len(),
        ),
    }
}

fn event_log_causal_projection(
    entries: &[SchedulerEventLogEntry],
) -> Vec<ProjectedCausalEventLogEntry<'_>> {
    entries
        .iter()
        .enumerate()
        .filter_map(|(raw_index, entry)| {
            (entry.class() == SchedulerEventLogClass::Causal)
                .then_some(ProjectedCausalEventLogEntry { raw_index, entry })
        })
        .collect()
}

fn event_log_raw_prefix_for_causal_prefix(
    projection: &[ProjectedCausalEventLogEntry<'_>],
    causal_prefix_len: usize,
    total_entries: usize,
) -> usize {
    if causal_prefix_len == 0 {
        return 0;
    }
    projection
        .get(causal_prefix_len - 1)
        .map(|entry| entry.raw_prefix_len())
        .unwrap_or_else(|| total_entries.saturating_add(1))
}

fn event_log_causal_projection_prefixes_match(
    expected: &[ProjectedCausalEventLogEntry<'_>],
    reproduced: &[ProjectedCausalEventLogEntry<'_>],
    causal_prefix_len: usize,
) -> bool {
    let Some(expected_entries) = expected.get(..causal_prefix_len) else {
        return false;
    };
    let Some(reproduced_entries) = reproduced.get(..causal_prefix_len) else {
        return false;
    };
    let expected_entries = expected_entries
        .iter()
        .map(|entry| entry.entry.clone())
        .collect::<Vec<_>>();
    let reproduced_entries = reproduced_entries
        .iter()
        .map(|entry| entry.entry.clone())
        .collect::<Vec<_>>();
    compare_event_log_determinism(&expected_entries, &reproduced_entries).passes()
}

fn event_log_causal_projections_match(
    expected: &[SchedulerEventLogEntry],
    reproduced: &[SchedulerEventLogEntry],
) -> bool {
    compare_event_log_determinism(expected, reproduced).passes()
}

fn assertion_replay_report_for_prefix(
    artifact: ContentHash,
    properties: &Properties,
    world: &World,
    recorded_log: &RecordedAssertionLog,
    prefix_len: usize,
) -> Result<HostAssertionReport, OfflineAssertionCheckError> {
    let prefix_len = prefix_len.min(recorded_log.entries().len());
    let prefix_log =
        RecordedAssertionLog::from_entries(recorded_log.entries()[..prefix_len].to_vec());
    let report = OfflineAssertionChecker::new()
        .with_world_white_box_policies(world)
        .check_run(properties, prefix_log.entries())?;
    Ok(host_assertion_report_with_reproduction_artifact(
        report, artifact,
    ))
}

fn first_differing_violation(
    expected: &[HostAssertionViolation],
    reproduced: &[HostAssertionViolation],
) -> Option<(
    Option<HostAssertionViolation>,
    Option<HostAssertionViolation>,
)> {
    let max_len = expected.len().max(reproduced.len());
    (0..max_len).find_map(|index| {
        let expected = expected.get(index).cloned();
        let reproduced = reproduced.get(index).cloned();
        (expected != reproduced).then_some((expected, reproduced))
    })
}

fn first_different_decision_prefix_len(
    expected_log: &RecordedAssertionLog,
    reproduced_log: &RecordedAssertionLog,
) -> Option<usize> {
    let expected = scheduler_decisions(expected_log);
    let reproduced = scheduler_decisions(reproduced_log);
    let max_len = expected.len().max(reproduced.len());
    (0..max_len).find_map(|index| {
        let expected = expected.get(index);
        let reproduced = reproduced.get(index);
        (expected != reproduced).then_some(index + 1)
    })
}

fn scheduler_decisions(recorded_log: &RecordedAssertionLog) -> Vec<Decision> {
    recorded_log
        .entries()
        .iter()
        .filter_map(|entry| match entry.payload() {
            SchedulerEventLogPayload::Decision(decision) => Some(decision.clone()),
            SchedulerEventLogPayload::ResolvedHappening(_)
            | SchedulerEventLogPayload::Observable(_)
            | SchedulerEventLogPayload::EvaluationBoundary(_)
            | SchedulerEventLogPayload::TriggerFired(_)
            | SchedulerEventLogPayload::TriggerActionApplied(_)
            | SchedulerEventLogPayload::Diagnostic(_) => None,
        })
        .collect()
}

fn engine_error_message(error: &EngineError) -> String {
    error.to_string()
}

fn observable_event_violation_site(
    event: &ObservableEvent,
) -> Option<(Option<Icount>, Option<NodeId>)> {
    match event.payload() {
        ObservableEventPayload::CoverageBlock {
            execution_icount,
            node,
            ..
        } => Some((Some(*execution_icount), Some(node.clone()))),
        ObservableEventPayload::MemorySample {
            sample_icount,
            node,
            ..
        } => Some((Some(*sample_icount), Some(node.clone()))),
        ObservableEventPayload::GuestMarker {
            retired_icount,
            node,
            ..
        }
        | ObservableEventPayload::CoverageMarker {
            retired_icount,
            node,
            ..
        }
        | ObservableEventPayload::GuestAssertionMarker {
            retired_icount,
            node,
            ..
        } => Some((Some(*retired_icount), Some(node.clone()))),
        ObservableEventPayload::ConsoleOutput { node, .. }
        | ObservableEventPayload::IoCompletion { node, .. }
        | ObservableEventPayload::NodeState { node, .. } => Some((None, Some(node.clone()))),
        ObservableEventPayload::NetworkDelivered { .. }
        | ObservableEventPayload::AssertionStateChanged { .. }
        | ObservableEventPayload::AssertionEvaluated { .. }
        | ObservableEventPayload::AssertionProximity { .. } => None,
    }
}

fn observable_event_evidence(
    event: &ObservableEvent,
    observed: impl Into<String>,
) -> HostAssertionViolationEvidence {
    let (at_icount, node) = observable_event_violation_site(event).unwrap_or((None, None));
    HostAssertionViolationEvidence {
        at_icount: at_icount.or(Some(Icount {
            retired: event.at().ticks,
        })),
        node,
        observed: observed.into(),
    }
}

fn evaluation_point_evidence(
    point: EventEvaluationPoint,
    observed: impl Into<String>,
) -> HostAssertionViolationEvidence {
    HostAssertionViolationEvidence {
        at_icount: Some(Icount {
            retired: point.at().ticks,
        }),
        node: None,
        observed: observed.into(),
    }
}

fn outcome_point_evidence(
    prefix: &ConditionEventLogPrefix,
    outcome: &HostAssertionOutcome,
) -> HostAssertionViolationEvidence {
    evaluation_point_evidence(
        EventEvaluationPoint::assertion_deadline(outcome.at),
        format!(
            "assertion outcome reason=\"{}\" entries={}",
            outcome.reason,
            prefix.scheduler_entries.len()
        ),
    )
}

fn violation_detail(
    outcome: &HostAssertionOutcome,
    evidence: &HostAssertionViolationEvidence,
) -> String {
    format!(
        "expected={}; observed={}; reason={}",
        violation_expectation(outcome),
        evidence.observed,
        outcome.reason
    )
}

fn violation_expectation(outcome: &HostAssertionOutcome) -> &'static str {
    match (outcome.quantifier, outcome.kind) {
        (AssertionQuantifierKind::Always, _) => "always predicate remains true",
        (AssertionQuantifierKind::Sometimes, _) => "sometimes predicate becomes true",
        (AssertionQuantifierKind::Eventually, _) => "eventually property satisfies before deadline",
        (AssertionQuantifierKind::AfterQuiescence, _) => {
            "after-quiescence predicate is true at terminal quiescence"
        }
        (AssertionQuantifierKind::Reachable, HostAssertionOutcomeKind::NeverReachedFail) => {
            "reachable predicate is reached"
        }
        (AssertionQuantifierKind::Reachable, _) => "unreachable predicate remains unreached",
        (AssertionQuantifierKind::GuestAlways, _) => "guest always marker remains true",
        (AssertionQuantifierKind::GuestSometimes, _) => "guest sometimes marker becomes true",
        (AssertionQuantifierKind::GuestReachable, HostAssertionOutcomeKind::NeverReachedFail) => {
            "guest reachable marker is reached"
        }
        (AssertionQuantifierKind::GuestReachable, _) => "guest reachable marker remains consistent",
        (AssertionQuantifierKind::GuestUnreachable, _) => "guest unreachable marker remains false",
    }
}

fn assertion_reproduction_artifact_from_prefix(prefix: &ConditionEventLogPrefix) -> ContentHash {
    ContentHash::from_bytes(&external_formal_trace_bytes(&prefix.scheduler_entries))
}

fn condition_violation_evidence(
    prefix: &ConditionEventLogPrefix,
    condition: &Condition,
    actual: bool,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
) -> HostAssertionViolationEvidence {
    condition_violation_evidence_at(
        prefix,
        prefix.point(),
        condition,
        actual,
        white_box_policies,
    )
}

fn condition_violation_evidence_at(
    prefix: &ConditionEventLogPrefix,
    point: EventEvaluationPoint,
    condition: &Condition,
    actual: bool,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
) -> HostAssertionViolationEvidence {
    let scoped_prefix = condition_prefix_for_evidence_at(prefix, point);
    condition_observed_evidence(&scoped_prefix, condition, actual, white_box_policies)
        .unwrap_or_else(|| {
            evaluation_point_evidence(
                point,
                format!(
                    "predicate {} at virtual_time={} entries={}",
                    bool_observed_label(actual),
                    point.at().ticks,
                    scoped_prefix.scheduler_entries.len()
                ),
            )
        })
}

fn condition_prefix_for_evidence_at(
    prefix: &ConditionEventLogPrefix,
    point: EventEvaluationPoint,
) -> ConditionEventLogPrefix {
    let through = point.at().ticks;
    let entries = prefix
        .scheduler_entries
        .iter()
        .take_while(|entry| entry.at().ticks <= through)
        .cloned()
        .collect::<Vec<_>>();
    if entries.is_empty() {
        return ConditionEventLogPrefix::genesis().with_point(point);
    }
    ConditionEventLogPrefix::from_scheduler_event_log_entries(entries)
        .map(|prefix| prefix.with_point(point))
        .unwrap_or_else(|_| prefix.clone().with_point(point))
}

fn condition_observed_evidence(
    prefix: &ConditionEventLogPrefix,
    condition: &Condition,
    actual: bool,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
) -> Option<HostAssertionViolationEvidence> {
    match condition {
        Condition::Not { predicate } => {
            let mut evidence =
                condition_observed_evidence(prefix, predicate, !actual, white_box_policies)?;
            evidence.observed = format!("not predicate was {actual}; inner {}", evidence.observed);
            Some(evidence)
        }
        Condition::AllOf { predicates } => {
            let predicate = predicates.iter().find(|predicate| {
                logged_condition_truth(prefix, predicate, white_box_policies) == actual
            })?;
            condition_observed_evidence(prefix, predicate, actual, white_box_policies)
        }
        Condition::AnyOf { predicates } => {
            let predicate = predicates.iter().find(|predicate| {
                logged_condition_truth(prefix, predicate, white_box_policies) == actual
            })?;
            condition_observed_evidence(prefix, predicate, actual, white_box_policies)
        }
        Condition::Once { predicate } => {
            condition_observed_evidence(prefix, predicate, actual, white_box_policies)
        }
        Condition::NetworkMatch { link, predicate } if actual => prefix
            .observable_events()
            .iter()
            .find(|event| {
                event.at() == prefix.point().at()
                    && network_event_matches(event.payload(), link.as_ref(), predicate)
            })
            .map(|event| {
                observable_event_evidence(
                    event,
                    format!(
                        "network frame matched link={} payload_event",
                        optional_link_label(link.as_ref())
                    ),
                )
            }),
        Condition::ConsoleMatch { node, regex } if actual => prefix
            .observable_events()
            .iter()
            .find(|event| {
                event.at() == prefix.point().at()
                    && matches!(
                        event.payload(),
                        ObservableEventPayload::ConsoleOutput {
                            node: observed_node,
                            ..
                        } if observed_node == node
                    )
            })
            .map(|event| {
                observable_event_evidence(
                    event,
                    format!(
                        "console output on node={} matched regex={}",
                        node.name, regex.pattern
                    ),
                )
            }),
        Condition::CoveragePoint { node, point } if actual => {
            let resolved = match point {
                CodePoint::GuestAddress { address } => {
                    Some(ResolvedCodePoint::guest_address(*address))
                }
                CodePoint::Symbol { .. } => None,
            }?;
            prefix
                .observable_events()
                .iter()
                .find(|event| {
                    event.at() == prefix.point().at()
                        && coverage_event_matches(event.payload(), node, resolved)
                })
                .map(|event| {
                    observable_event_evidence(
                        event,
                        format!(
                            "coverage point node={} address={}",
                            node.name,
                            resolved.address()
                        ),
                    )
                })
        }
        Condition::MemoryPredicate {
            node,
            place,
            cmp,
            value,
        } if actual => {
            let resolved = resolved_mem_place_for_evidence(place)?;
            prefix
                .observable_events()
                .iter()
                .find(|event| {
                    event.at() == prefix.point().at()
                        && memory_event_matches(event.payload(), node, &resolved, *cmp, *value)
                })
                .map(|event| {
                    observable_event_evidence(
                        event,
                        format!(
                            "memory predicate node={} place={} cmp={} expected={}",
                            node.name,
                            resolved_mem_place_label(&resolved),
                            memory_cmp_label(*cmp),
                            value
                        ),
                    )
                })
        }
        Condition::IoPattern { node, kind } if actual => prefix
            .observable_events()
            .iter()
            .find(|event| {
                event.at() == prefix.point().at() && io_event_matches(event.payload(), node, *kind)
            })
            .map(|event| {
                observable_event_evidence(
                    event,
                    format!(
                        "io completion node={} kind={}",
                        node.name,
                        io_kind_label(*kind)
                    ),
                )
            }),
        Condition::NodeState { node, state } if actual => prefix
            .observable_events()
            .iter()
            .find(|event| {
                event.at() == prefix.point().at()
                    && node_state_event_matches(event.payload(), node, *state)
            })
            .map(|event| {
                observable_event_evidence(
                    event,
                    format!(
                        "node state node={} state={}",
                        node.name,
                        external_node_lifecycle_label(*state)
                    ),
                )
            }),
        Condition::AssertionState { name, state } if actual => prefix
            .observable_events()
            .iter()
            .find(|event| {
                event.at() == prefix.point().at()
                    && assertion_state_event_matches(event.payload(), name, *state)
            })
            .map(|event| {
                observable_event_evidence(
                    event,
                    format!(
                        "assertion state assertion={} state={}",
                        name.name,
                        external_assertion_phase_label(*state)
                    ),
                )
            }),
        Condition::GuestMarker { marker } if actual => prefix
            .observable_events()
            .iter()
            .find(|event| {
                event.at() == prefix.point().at()
                    && guest_marker_event_matches_policies(
                        event.payload(),
                        marker,
                        white_box_policies,
                    )
            })
            .map(|event| {
                observable_event_evidence(
                    event,
                    format!("guest marker marker={} matched", marker.name),
                )
            }),
        Condition::Named { name, nodes } => Some(evaluation_point_evidence(
            prefix.point(),
            format!(
                "named predicate name={} nodes={} returned {}",
                name,
                nodes.len(),
                actual
            ),
        )),
        Condition::At { at } => Some(evaluation_point_evidence(
            prefix.point(),
            format!(
                "time predicate expected={} actual={} returned {}",
                at.ticks,
                prefix.point().at().ticks,
                actual
            ),
        )),
        Condition::After { duration, of } => Some(evaluation_point_evidence(
            prefix.point(),
            format!(
                "after predicate event={} duration={} returned {}",
                of.name, duration.nanos, actual
            ),
        )),
        Condition::Timer { name } => Some(evaluation_point_evidence(
            prefix.point(),
            format!("timer predicate name={} returned {}", name.name, actual),
        )),
        Condition::Quiescent => Some(evaluation_point_evidence(
            prefix.point(),
            format!("quiescence predicate returned {actual}"),
        )),
        Condition::FaultActive { tag } => Some(evaluation_point_evidence(
            prefix.point(),
            format!("fault-active predicate tag={} returned {actual}", tag.name),
        )),
        Condition::NetworkMatch { .. }
        | Condition::ConsoleMatch { .. }
        | Condition::CoveragePoint { .. }
        | Condition::MemoryPredicate { .. }
        | Condition::IoPattern { .. }
        | Condition::NodeState { .. }
        | Condition::AssertionState { .. }
        | Condition::GuestMarker { .. } => Some(evaluation_point_evidence(
            prefix.point(),
            false_observed_condition_summary(condition, prefix.point().at()),
        )),
    }
}

fn logged_condition_truth(
    prefix: &ConditionEventLogPrefix,
    condition: &Condition,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
) -> bool {
    let mut evaluation = ConditionEvaluation::from_log_prefix(prefix.clone(), false_condition_leaf)
        .with_white_box_policies(white_box_policies.clone());
    evaluation.evaluate_condition(condition)
}

fn false_condition_leaf(_leaf: ConditionLeaf<'_>) -> bool {
    false
}

fn guest_marker_event_matches_policies(
    event: &ObservableEventPayload,
    expected_marker: &MarkerId,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
) -> bool {
    match event {
        ObservableEventPayload::GuestMarker { node, marker, .. } => {
            marker == expected_marker
                && white_box_policies.get(node) == Some(&WhiteBoxPolicy::Enabled)
        }
        ObservableEventPayload::GuestAssertionMarker { .. }
        | ObservableEventPayload::NetworkDelivered { .. }
        | ObservableEventPayload::ConsoleOutput { .. }
        | ObservableEventPayload::CoverageBlock { .. }
        | ObservableEventPayload::CoverageMarker { .. }
        | ObservableEventPayload::MemorySample { .. }
        | ObservableEventPayload::IoCompletion { .. }
        | ObservableEventPayload::NodeState { .. }
        | ObservableEventPayload::AssertionStateChanged { .. }
        | ObservableEventPayload::AssertionEvaluated { .. }
        | ObservableEventPayload::AssertionProximity { .. } => false,
    }
}

fn resolved_mem_place_for_evidence(place: &MemPlace) -> Option<ResolvedMemPlace> {
    match place {
        MemPlace::PhysicalAddress { address, width } => {
            Some(ResolvedMemPlace::physical_address(*address, width.bytes()))
        }
        MemPlace::Register { name, width } => {
            Some(ResolvedMemPlace::register(name.clone(), width.bytes()))
        }
        MemPlace::VirtualAddress { .. } | MemPlace::Symbol { .. } => None,
    }
}

fn false_observed_condition_summary(condition: &Condition, at: VirtualTime) -> String {
    match condition {
        Condition::NetworkMatch { .. } => {
            format!("no matching network frame at virtual_time={}", at.ticks)
        }
        Condition::ConsoleMatch { node, regex } => format!(
            "no console output match node={} regex={} at virtual_time={}",
            node.name, regex.pattern, at.ticks
        ),
        Condition::CoveragePoint { node, .. } => format!(
            "no matching coverage point node={} at virtual_time={}",
            node.name, at.ticks
        ),
        Condition::MemoryPredicate { node, .. } => format!(
            "no matching memory sample node={} at virtual_time={}",
            node.name, at.ticks
        ),
        Condition::IoPattern { node, kind } => format!(
            "no matching io completion node={} kind={} at virtual_time={}",
            node.name,
            io_kind_label(*kind),
            at.ticks
        ),
        Condition::NodeState { node, state } => format!(
            "no node state node={} state={} at virtual_time={}",
            node.name,
            external_node_lifecycle_label(*state),
            at.ticks
        ),
        Condition::AssertionState { name, state } => format!(
            "no assertion state assertion={} state={} at virtual_time={}",
            name.name,
            external_assertion_phase_label(*state),
            at.ticks
        ),
        Condition::GuestMarker { marker } => format!(
            "no guest marker marker={} at virtual_time={}",
            marker.name, at.ticks
        ),
        Condition::FaultActive { tag } => format!(
            "fault tag {} was not active at virtual_time={}",
            tag.name, at.ticks
        ),
        Condition::At { .. }
        | Condition::After { .. }
        | Condition::Timer { .. }
        | Condition::Quiescent
        | Condition::Named { .. }
        | Condition::AllOf { .. }
        | Condition::AnyOf { .. }
        | Condition::Once { .. }
        | Condition::Not { .. } => {
            format!("predicate was false at virtual_time={}", at.ticks)
        }
    }
}

fn guest_assertion_marker_event_evidence(
    event: &ObservableEvent,
    marker: &GuestAssertionMarker,
) -> HostAssertionViolationEvidence {
    observable_event_evidence(
        event,
        format!(
            "guest assertion marker id={} kind={} condition={} location={} details={}",
            marker.id.name,
            external_guest_assertion_kind_label(marker.kind),
            marker.condition,
            marker.location,
            details_reason(&marker.details)
        ),
    )
}

fn guest_assertion_state_evidence(
    state: &GuestMarkerAssertionState,
    at: VirtualTime,
) -> HostAssertionViolationEvidence {
    HostAssertionViolationEvidence {
        at_icount: state.last_icount.or(Some(Icount { retired: at.ticks })),
        node: state.last_node.clone(),
        observed: format!(
            "guest assertion marker id={} kind={} observed_true={} location={} details={}",
            state.id.name,
            external_guest_assertion_kind_label(state.kind),
            state.observed_true,
            state.location,
            details_reason(&state.details)
        ),
    }
}

fn bool_observed_label(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

fn optional_link_label(link: Option<&LinkId>) -> String {
    link.map(|link| link.name.clone())
        .unwrap_or_else(|| String::from("*"))
}

fn resolved_mem_place_label(place: &ResolvedMemPlace) -> String {
    match place {
        ResolvedMemPlace::PhysicalAddress { address, bytes } => {
            format!("physical:{address}:{bytes}")
        }
        ResolvedMemPlace::VirtualAddress { address, bytes } => {
            format!("virtual:{address}:{bytes}")
        }
        ResolvedMemPlace::Register { name, bytes } => format!("register:{name}:{bytes}"),
    }
}

fn memory_cmp_label(cmp: MemoryCmp) -> &'static str {
    match cmp {
        MemoryCmp::Eq => "eq",
        MemoryCmp::Ne => "ne",
        MemoryCmp::Lt => "lt",
        MemoryCmp::Le => "le",
        MemoryCmp::Gt => "gt",
        MemoryCmp::Ge => "ge",
    }
}

fn io_kind_label(kind: IoEventKind) -> &'static str {
    match kind {
        IoEventKind::Any => "any",
        IoEventKind::BlockRead => "block-read",
        IoEventKind::BlockWrite => "block-write",
        IoEventKind::Fsync => "fsync",
        IoEventKind::NineP => "9p",
        IoEventKind::Network => "network",
    }
}

fn eventually_deadline(triggered_at: VirtualTime, deadline: VirtualTime) -> VirtualTime {
    VirtualTime {
        ticks: triggered_at.ticks.saturating_add(deadline.ticks),
    }
}

fn condition_prefix_from_recorded_entries(
    entries: &[SchedulerEventLogEntry],
) -> Result<ConditionEventLogPrefix, ConditionEvaluationError> {
    if entries.is_empty() {
        Ok(ConditionEventLogPrefix::genesis())
    } else {
        ConditionEventLogPrefix::from_scheduler_event_log_entries(entries.to_vec())
    }
}

fn validate_recorded_event_log_entries(
    entries: &[SchedulerEventLogEntry],
) -> Result<(), ConditionEvaluationError> {
    if entries.is_empty() {
        return Ok(());
    }
    ConditionEventLogPrefix::from_scheduler_event_log_entries(entries.to_vec()).map(|_| ())
}

fn external_formal_trace_bytes(entries: &[SchedulerEventLogEntry]) -> Vec<u8> {
    let previous_prefix = scheduler_event_log_empty_prefix();
    let mut lines = Vec::new();
    lines.push(String::from("format=crucible.external-formal-trace.v1"));
    lines.push(format!(
        "scheduler_event_log_previous_prefix={}",
        previous_prefix.to_hex()
    ));
    lines.push(format!("entries={}", entries.len()));
    for entry in entries {
        lines.push(external_formal_trace_entry_material(entry));
    }
    lines.join("\n").into_bytes()
}

fn external_formal_trace_entry_material(entry: &SchedulerEventLogEntry) -> String {
    let mut lines = Vec::new();
    lines.push(String::from("entry_begin"));
    lines.push(format!("entry.sequence={}", entry.sequence()));
    lines.push(format!("entry.at_ticks={}", entry.at().ticks));
    lines.push(format!(
        "entry.class={}",
        external_scheduler_event_log_class_label(entry.class())
    ));
    lines.push(format!("entry.hash={}", entry.content_hash().to_hex()));
    lines.push(String::from("entry.payload_begin"));
    lines.push(external_scheduler_event_log_payload_material(
        entry.payload(),
    ));
    lines.push(String::from("entry.payload_end"));
    lines.push(String::from("entry_end"));
    lines.join("\n")
}

fn external_scheduler_event_log_class_label(class: SchedulerEventLogClass) -> &'static str {
    match class {
        SchedulerEventLogClass::Causal => "causal",
        SchedulerEventLogClass::Observational => "observational",
    }
}

fn external_scheduler_event_log_payload_material(payload: &SchedulerEventLogPayload) -> String {
    let mut lines = Vec::new();
    match payload {
        SchedulerEventLogPayload::ResolvedHappening(event) => {
            lines.push(String::from("payload=resolved-happening"));
            lines.push(external_scheduled_event_material(event));
        }
        SchedulerEventLogPayload::Decision(decision) => {
            lines.push(String::from("payload=decision"));
            lines.push(external_decision_material(decision));
        }
        SchedulerEventLogPayload::Observable(observable) => {
            lines.push(String::from("payload=observable"));
            lines.push(external_observable_event_payload_material(observable));
        }
        SchedulerEventLogPayload::EvaluationBoundary(kind) => {
            lines.push(String::from("payload=evaluation-boundary"));
            lines.push(format!(
                "boundary.kind={}",
                external_scheduler_evaluation_boundary_kind_label(*kind)
            ));
        }
        SchedulerEventLogPayload::TriggerFired(firing) => {
            lines.push(String::from("payload=trigger-fired"));
            lines.push(external_event_firing_material(firing));
        }
        SchedulerEventLogPayload::TriggerActionApplied(application) => {
            lines.push(String::from("payload=trigger-action-applied"));
            lines.push(external_trigger_action_application_material(application));
        }
        SchedulerEventLogPayload::Diagnostic(diagnostic) => {
            lines.push(String::from("payload=diagnostic"));
            lines.push(external_string_material(
                "diagnostic.name",
                &diagnostic.name,
            ));
            lines.push(format!(
                "diagnostic.level={}",
                external_event_level_label(diagnostic.level)
            ));
            lines.push(format!("diagnostic.details={}", diagnostic.details.len()));
            for (index, (name, value)) in diagnostic.details.iter().enumerate() {
                lines.push(external_string_material(
                    &format!("diagnostic.detail.{index}.name"),
                    name,
                ));
                lines.push(external_event_attribute_value_material(
                    &format!("diagnostic.detail.{index}.value"),
                    value,
                ));
            }
        }
    }
    lines.join("\n")
}

fn external_event_attribute_value_material(prefix: &str, value: &EventAttributeValue) -> String {
    let mut lines = Vec::new();
    match value {
        EventAttributeValue::Bool(value) => {
            lines.push(format!("{prefix}.type=bool"));
            lines.push(format!("{prefix}.bool={value}"));
        }
        EventAttributeValue::U64(value) => {
            lines.push(format!("{prefix}.type=u64"));
            lines.push(format!("{prefix}.u64={value}"));
        }
        EventAttributeValue::U128(value) => {
            lines.push(format!("{prefix}.type=u128"));
            lines.push(format!("{prefix}.u128={value}"));
        }
        EventAttributeValue::String(value) => {
            lines.push(format!("{prefix}.type=string"));
            lines.push(external_string_material(&format!("{prefix}.string"), value));
        }
        EventAttributeValue::Bytes(value) => {
            lines.push(format!("{prefix}.type=bytes"));
            lines.push(format!("{prefix}.bytes_len={}", value.len()));
            lines.push(format!("{prefix}.bytes={}", external_hex_bytes(value)));
        }
        EventAttributeValue::Node(value) => {
            lines.push(format!("{prefix}.type=node"));
            lines.push(external_node_id_material(&format!("{prefix}.node"), value));
        }
        EventAttributeValue::Event(value) => {
            lines.push(format!("{prefix}.type=event"));
            lines.push(external_event_id_material(
                &format!("{prefix}.event"),
                value,
            ));
        }
        EventAttributeValue::Fault(value) => {
            lines.push(format!("{prefix}.type=fault"));
            lines.push(external_fault_id_material(
                &format!("{prefix}.fault"),
                value,
            ));
        }
        EventAttributeValue::VirtualTime(value) => {
            lines.push(format!("{prefix}.type=virtual-time"));
            lines.push(format!("{prefix}.ticks={}", value.ticks));
        }
        EventAttributeValue::Icount(value) => {
            lines.push(format!("{prefix}.type=icount"));
            lines.push(format!("{prefix}.retired={}", value.retired));
        }
        EventAttributeValue::Level(value) => {
            lines.push(format!("{prefix}.type=level"));
            lines.push(format!(
                "{prefix}.level={}",
                external_event_level_label(*value)
            ));
        }
    }
    lines.join("\n")
}

fn external_scheduled_event_material(event: &ScheduledEvent) -> String {
    let mut lines = Vec::new();
    lines.push(external_scheduled_event_key_material(&event.key));
    lines.push(format!(
        "event.resolve_class={}",
        external_scheduled_event_resolve_class_label(scheduled_event_resolve_class(event))
    ));
    lines.push(external_scheduled_event_payload_material(&event.payload));
    lines.join("\n")
}

fn external_scheduled_event_key_material(key: &ScheduledEventKey) -> String {
    let mut lines = Vec::new();
    lines.push(format!("event.time_ticks={}", key.virtual_time().ticks));
    lines.push(external_scheduler_node_material(
        "event.consumer",
        key.consumer(),
    ));
    lines.push(external_scheduler_node_material(
        "event.producer",
        key.producer(),
    ));
    lines.push(format!("event.sequence={}", key.sequence()));
    lines.join("\n")
}

fn external_scheduled_event_payload_material(payload: &ScheduledEventPayload) -> String {
    let mut lines = Vec::new();
    match payload {
        ScheduledEventPayload::BackendInput(input) => {
            lines.push(String::from("event.payload=backend-input"));
            lines.push(external_node_id_material("event.payload.node", &input.node));
            lines.push(format!(
                "event.payload.bytes={}",
                external_hex_bytes(&input.payload)
            ));
        }
        ScheduledEventPayload::IoCompletion(completion) => {
            lines.push(String::from("event.payload=io-completion"));
            lines.push(external_scheduler_node_material(
                "event.payload.sub_node",
                &completion.sub_node,
            ));
            lines.push(external_node_id_material(
                "event.payload.target",
                &completion.target,
            ));
            lines.push(format!(
                "event.payload.delivery_icount={}",
                completion.delivery_icount.retired
            ));
            lines.push(format!(
                "event.payload.bytes={}",
                external_hex_bytes(&completion.payload)
            ));
        }
        ScheduledEventPayload::FaultActivation(fault) => {
            lines.push(String::from("event.payload=fault-activation"));
            lines.push(external_fault_id_material("event.payload.fault", fault));
        }
        ScheduledEventPayload::ProbabilisticFault(choice) => {
            lines.push(String::from("event.payload=probabilistic-fault"));
            lines.push(external_fault_id_material(
                "event.payload.fault",
                &choice.fault,
            ));
            lines.push(external_rng_stream_material(
                "event.payload.stream",
                &choice.stream,
            ));
            lines.push(format!(
                "event.payload.rate_basis_points={}",
                choice.rate.basis_points()
            ));
        }
        ScheduledEventPayload::Control(operation) => {
            lines.push(String::from("event.payload=control"));
            lines.push(format!(
                "event.payload.control.sequence={}",
                operation.sequence
            ));
            lines.push(external_control_operation_kind_material(
                "event.payload.control.kind",
                &operation.kind,
            ));
        }
    }
    lines.join("\n")
}

fn external_decision_material(decision: &Decision) -> String {
    use Decision as D;

    let mut lines = Vec::new();
    match decision {
        D::DeliveryOrder(order) => {
            lines.push(String::from("decision=delivery-order"));
            lines.push(format!("decision.at_ticks={}", order.at.ticks));
            lines.push(format!("decision.events={}", order.order.len()));
            for (index, event) in order.order.iter().enumerate() {
                lines.push(external_event_key_material(
                    &format!("decision.event.{index}"),
                    event,
                ));
            }
        }
        D::FaultFires(fault) => {
            lines.push(String::from("decision=fault-fires"));
            lines.push(format!("decision.at_ticks={}", fault.at.ticks));
            lines.push(external_fault_id_material("decision.fault", &fault.fault));
            lines.push(format!("decision.fired={}", fault.fired));
        }
        D::RngDraw(draw) => {
            lines.push(String::from("decision=rng-draw"));
            lines.push(external_rng_stream_material(
                "decision.stream",
                &draw.stream,
            ));
            lines.push(format!("decision.value={}", draw.value));
        }
        D::Override(override_decision) => {
            lines.push(String::from("decision=override"));
            lines.push(external_string_material(
                "decision.point",
                &override_decision.point.key,
            ));
            lines.push(external_string_material(
                "decision.choice",
                &override_decision.choice.name,
            ));
        }
        D::Preemption(preemption) => {
            lines.push(String::from("decision=preemption"));
            lines.push(external_node_id_material("decision.node", &preemption.node));
            lines.push(format!("decision.at_retired={}", preemption.at.retired));
            lines.push(external_preemption_kind_material(
                "decision.preemption",
                &preemption.kind,
            ));
        }
        D::AppRandom(random) => {
            lines.push(String::from("decision=app-random"));
            lines.push(external_node_id_material("decision.node", &random.node));
            lines.push(external_rng_stream_material(
                "decision.stream",
                &random.stream,
            ));
            lines.push(format!("decision.request_id={}", random.request_id));
            lines.push(format!("decision.width={}", random.width));
            lines.push(format!("decision.value={}", random.value));
        }
        D::ControlFault(control) => {
            lines.push(String::from("decision=control-fault"));
            lines.push(format!("decision.at_ticks={}", control.at.ticks));
            lines.push(format!("decision.control.sequence={}", control.sequence));
            lines.push(external_control_fault_action_material(
                "decision.control.action",
                &control.action,
            ));
        }
    }
    lines.join("\n")
}

fn external_observable_event_payload_material(observable: &ObservableEventPayload) -> String {
    let mut lines = Vec::new();
    match observable {
        ObservableEventPayload::NetworkDelivered { link, payload } => {
            lines.push(String::from("observable=network-delivered"));
            lines.push(external_optional_link_material("observable.link", link));
            lines.push(format!(
                "observable.payload_bytes={}",
                external_hex_bytes(payload)
            ));
        }
        ObservableEventPayload::ConsoleOutput { node, bytes } => {
            lines.push(String::from("observable=console-output"));
            lines.push(external_node_id_material("observable.node", node));
            lines.push(format!("observable.bytes={}", external_hex_bytes(bytes)));
        }
        ObservableEventPayload::CoverageBlock {
            execution_icount,
            node,
            guest_pc,
            block_len,
        } => {
            lines.push(String::from("observable=coverage-block"));
            lines.push(format!(
                "observable.execution_icount={}",
                execution_icount.retired
            ));
            lines.push(external_node_id_material("observable.node", node));
            lines.push(format!("observable.guest_pc={guest_pc}"));
            lines.push(format!("observable.block_len={block_len}"));
        }
        ObservableEventPayload::CoverageMarker {
            retired_icount,
            node,
            marker,
        } => {
            lines.push(String::from("observable=coverage-marker"));
            lines.push(format!(
                "observable.retired_icount={}",
                retired_icount.retired
            ));
            lines.push(external_node_id_material("observable.node", node));
            lines.push(external_marker_id_material("observable.marker", marker));
        }
        ObservableEventPayload::MemorySample {
            sample_icount,
            node,
            place,
            value,
        } => {
            lines.push(String::from("observable=memory-sample"));
            lines.push(format!(
                "observable.sample_icount={}",
                sample_icount.retired
            ));
            lines.push(external_node_id_material("observable.node", node));
            lines.push(external_resolved_mem_place_material(
                "observable.place",
                place,
            ));
            lines.push(format!("observable.value={value}"));
        }
        ObservableEventPayload::IoCompletion {
            node,
            kind,
            payload,
        } => {
            lines.push(String::from("observable=io-completion"));
            lines.push(external_node_id_material("observable.node", node));
            lines.push(format!(
                "observable.kind={}",
                external_io_event_kind_label(*kind)
            ));
            lines.push(format!(
                "observable.payload_bytes={}",
                external_hex_bytes(payload)
            ));
        }
        ObservableEventPayload::NodeState { node, state } => {
            lines.push(String::from("observable=node-state"));
            lines.push(external_node_id_material("observable.node", node));
            lines.push(format!(
                "observable.state={}",
                external_node_lifecycle_label(*state)
            ));
        }
        ObservableEventPayload::AssertionStateChanged { name, state } => {
            lines.push(String::from("observable=assertion-state-changed"));
            lines.push(external_assertion_id_material("observable.assertion", name));
            lines.push(format!(
                "observable.state={}",
                external_assertion_phase_label(*state)
            ));
        }
        ObservableEventPayload::AssertionEvaluated {
            name,
            flavor,
            condition,
            message,
            details,
        } => {
            lines.push(String::from("observable=assertion-evaluated"));
            lines.push(external_assertion_id_material("observable.assertion", name));
            lines.push(format!(
                "observable.flavor={}",
                external_assertion_quantifier_label(*flavor)
            ));
            lines.push(format!("observable.condition={condition}"));
            lines.push(external_string_material("observable.message", message));
            lines.push(format!("observable.details={}", details.len()));
            for (index, detail) in details.iter().enumerate() {
                lines.push(external_string_material(
                    &format!("observable.detail.{index}.key"),
                    &detail.key,
                ));
                lines.push(external_string_material(
                    &format!("observable.detail.{index}.value"),
                    &detail.value,
                ));
            }
        }
        ObservableEventPayload::AssertionProximity {
            assertion,
            quantifier,
            distance,
            node,
        } => {
            lines.push(String::from("observable=assertion-proximity"));
            lines.push(external_assertion_id_material(
                "observable.assertion",
                assertion,
            ));
            lines.push(format!(
                "observable.quantifier={}",
                external_assertion_quantifier_label(*quantifier)
            ));
            lines.push(format!("observable.distance={distance}"));
            lines.push(external_optional_node_id_material("observable.node", node));
        }
        ObservableEventPayload::GuestMarker {
            retired_icount,
            node,
            marker,
        } => {
            lines.push(String::from("observable=guest-marker"));
            lines.push(format!(
                "observable.retired_icount={}",
                retired_icount.retired
            ));
            lines.push(external_node_id_material("observable.node", node));
            lines.push(external_marker_id_material("observable.marker", marker));
        }
        ObservableEventPayload::GuestAssertionMarker {
            retired_icount,
            node,
            marker,
        } => {
            lines.push(String::from("observable=guest-assertion-marker"));
            lines.push(format!(
                "observable.retired_icount={}",
                retired_icount.retired
            ));
            lines.push(external_node_id_material("observable.node", node));
            lines.push(external_assertion_id_material(
                "observable.marker.id",
                &marker.id,
            ));
            lines.push(external_string_material(
                "observable.marker.message",
                &marker.message,
            ));
            lines.push(format!(
                "observable.marker.kind={}",
                external_guest_assertion_kind_label(marker.kind)
            ));
            lines.push(format!("observable.marker.condition={}", marker.condition));
            lines.push(format!("observable.marker.must_hit={}", marker.must_hit));
            lines.push(format!(
                "observable.marker.details={}",
                marker.details.len()
            ));
            for (index, detail) in marker.details.iter().enumerate() {
                lines.push(external_string_material(
                    &format!("observable.marker.detail.{index}.key"),
                    &detail.key,
                ));
                lines.push(external_string_material(
                    &format!("observable.marker.detail.{index}.value"),
                    &detail.value,
                ));
            }
            lines.push(external_string_material(
                "observable.marker.location",
                &marker.location,
            ));
        }
    }
    lines.join("\n")
}

fn external_event_firing_material(firing: &EventFiring) -> String {
    let mut lines = Vec::new();
    lines.push(external_event_id_material("firing.event", firing.event()));
    lines.push(format!("firing.at_ticks={}", firing.at().ticks));
    lines.push(external_action_material("firing.action", firing.action()));
    lines.join("\n")
}

fn external_trigger_action_application_material(application: &TriggerActionApplication) -> String {
    let mut lines = Vec::new();
    lines.push(format!("application.sequence={}", application.sequence));
    lines.push(external_event_id_material(
        "application.event",
        &application.event,
    ));
    lines.push(format!("application.at_ticks={}", application.at.ticks));
    lines.push(format!("application.path_len={}", application.path.len()));
    for (index, path) in application.path.iter().enumerate() {
        lines.push(format!("application.path.{index}={path}"));
    }
    lines.push(external_action_material(
        "application.action",
        &application.action,
    ));
    lines.join("\n")
}

fn external_action_material(prefix: &str, action: &Action) -> String {
    let mut lines = Vec::new();
    match action {
        Action::InjectFault { tag, fault } => {
            lines.push(format!("{prefix}=inject-fault"));
            lines.push(external_fault_tag_material(&format!("{prefix}.tag"), tag));
            lines.push(external_membership_fault_material(
                &format!("{prefix}.fault"),
                fault,
            ));
        }
        Action::HealFault { tag } => {
            lines.push(format!("{prefix}=heal-fault"));
            lines.push(external_fault_tag_material(&format!("{prefix}.tag"), tag));
        }
        Action::ArmTimer { name, after } => {
            lines.push(format!("{prefix}=arm-timer"));
            lines.push(external_timer_id_material(&format!("{prefix}.timer"), name));
            lines.push(format!("{prefix}.after_nanos={}", after.nanos));
        }
        Action::CancelTimer { name } => {
            lines.push(format!("{prefix}=cancel-timer"));
            lines.push(external_timer_id_material(&format!("{prefix}.timer"), name));
        }
        Action::StartNode { node } => {
            lines.push(format!("{prefix}=start-node"));
            lines.push(external_node_id_material(&format!("{prefix}.node"), node));
        }
        Action::StopNode { node } => {
            lines.push(format!("{prefix}=stop-node"));
            lines.push(external_node_id_material(&format!("{prefix}.node"), node));
        }
        Action::CreateSavepoint { label } => {
            lines.push(format!("{prefix}=create-savepoint"));
            lines.push(external_optional_label_material(
                &format!("{prefix}.label"),
                label,
            ));
        }
        Action::Fork { label } => {
            lines.push(format!("{prefix}=fork"));
            lines.push(external_optional_label_material(
                &format!("{prefix}.label"),
                label,
            ));
        }
        Action::Pass => {
            lines.push(format!("{prefix}=pass"));
        }
        Action::Fail { reason } => {
            lines.push(format!("{prefix}=fail"));
            lines.push(external_string_material(
                &format!("{prefix}.reason"),
                reason,
            ));
        }
        Action::Log { level, message } => {
            lines.push(format!("{prefix}=log"));
            lines.push(format!(
                "{prefix}.level={}",
                external_log_level_label(*level)
            ));
            lines.push(external_string_material(
                &format!("{prefix}.message"),
                message,
            ));
        }
        Action::Group(actions) => {
            lines.push(format!("{prefix}=group"));
            lines.push(format!("{prefix}.actions={}", actions.len()));
            for (index, action) in actions.iter().enumerate() {
                lines.push(external_action_material(
                    &format!("{prefix}.action.{index}"),
                    action,
                ));
            }
        }
    }
    lines.join("\n")
}

fn external_membership_fault_material(prefix: &str, fault: &MembershipFault) -> String {
    let mut lines = Vec::new();
    match fault {
        MembershipFault::Crash { node, restart } => {
            lines.push(format!("{prefix}=crash"));
            lines.push(external_node_id_material(&format!("{prefix}.node"), node));
            lines.push(format!(
                "{prefix}.restart={}",
                external_restart_policy_label(*restart)
            ));
        }
        MembershipFault::Partition {
            endpoint_a,
            endpoint_b,
            direction,
        } => {
            lines.push(format!("{prefix}=partition"));
            lines.push(external_node_id_material(
                &format!("{prefix}.endpoint_a"),
                endpoint_a,
            ));
            lines.push(external_node_id_material(
                &format!("{prefix}.endpoint_b"),
                endpoint_b,
            ));
            lines.push(format!(
                "{prefix}.direction={}",
                external_partition_direction_label(*direction)
            ));
        }
        MembershipFault::Isolate { node } => {
            lines.push(format!("{prefix}=isolate"));
            lines.push(external_node_id_material(&format!("{prefix}.node"), node));
        }
        MembershipFault::NotYetJoined { node } => {
            lines.push(format!("{prefix}=not-yet-joined"));
            lines.push(external_node_id_material(&format!("{prefix}.node"), node));
        }
        MembershipFault::Taxonomy { fault } => {
            lines.push(format!("{prefix}=taxonomy"));
            lines.push(external_string_material(
                &format!("{prefix}.taxonomy_material"),
                &fault.canonical_material(),
            ));
        }
    }
    lines.join("\n")
}

fn external_control_fault_action_material(prefix: &str, action: &ControlFaultAction) -> String {
    let mut lines = Vec::new();
    match action {
        ControlFaultAction::Inject { tag, fault } => {
            lines.push(format!("{prefix}=inject-fault"));
            lines.push(external_fault_tag_material(&format!("{prefix}.tag"), tag));
            lines.push(external_string_material(
                &format!("{prefix}.fault_material"),
                &fault.canonical_material(),
            ));
        }
        ControlFaultAction::Heal { tag } => {
            lines.push(format!("{prefix}=heal-fault"));
            lines.push(external_fault_tag_material(&format!("{prefix}.tag"), tag));
        }
    }
    lines.join("\n")
}

fn external_control_operation_kind_material(prefix: &str, kind: &ControlOperationKind) -> String {
    let mut lines = Vec::new();
    match kind {
        ControlOperationKind::Pause => lines.push(format!("{prefix}=pause")),
        ControlOperationKind::Resume => lines.push(format!("{prefix}=resume")),
        ControlOperationKind::Step => lines.push(format!("{prefix}=step")),
        ControlOperationKind::Snapshot => lines.push(format!("{prefix}=snapshot")),
        ControlOperationKind::Fork => lines.push(format!("{prefix}=fork")),
        ControlOperationKind::Inject => lines.push(format!("{prefix}=inject")),
        ControlOperationKind::Query => lines.push(format!("{prefix}=query")),
        ControlOperationKind::InjectFault { tag, fault } => {
            lines.push(format!("{prefix}=inject-fault"));
            lines.push(external_fault_tag_material(&format!("{prefix}.tag"), tag));
            lines.push(external_string_material(
                &format!("{prefix}.fault_material"),
                &fault.canonical_material(),
            ));
        }
        ControlOperationKind::HealFault { tag } => {
            lines.push(format!("{prefix}=heal-fault"));
            lines.push(external_fault_tag_material(&format!("{prefix}.tag"), tag));
        }
    }
    lines.join("\n")
}

fn external_event_key_material(prefix: &str, key: &EventKey) -> String {
    let mut lines = Vec::new();
    lines.push(format!("{prefix}.time_ticks={}", key.virtual_time.ticks));
    lines.push(external_scheduler_node_material(
        &format!("{prefix}.consumer"),
        &key.consumer,
    ));
    lines.push(external_scheduler_node_material(
        &format!("{prefix}.producer"),
        &key.producer,
    ));
    lines.push(format!("{prefix}.sequence={}", key.sequence));
    lines.join("\n")
}

fn external_scheduler_node_material(prefix: &str, node: &SchedulerNodeId) -> String {
    format!(
        "{}\n{prefix}.kind={}",
        external_node_id_material(&format!("{prefix}.node"), &node.node),
        external_scheduling_node_kind_label(node.kind)
    )
}

fn external_node_id_material(prefix: &str, node: &NodeId) -> String {
    external_string_material(prefix, &node.name)
}

fn external_event_id_material(prefix: &str, id: &EventId) -> String {
    external_string_material(prefix, &id.name)
}

fn external_assertion_id_material(prefix: &str, id: &AssertionId) -> String {
    external_string_material(prefix, &id.name)
}

fn external_marker_id_material(prefix: &str, id: &MarkerId) -> String {
    external_string_material(prefix, &id.name)
}

fn external_fault_id_material(prefix: &str, id: &FaultId) -> String {
    external_string_material(prefix, &id.name)
}

fn external_fault_tag_material(prefix: &str, tag: &FaultTag) -> String {
    external_string_material(prefix, &tag.name)
}

fn external_timer_id_material(prefix: &str, id: &TimerId) -> String {
    external_string_material(prefix, &id.name)
}

fn external_rng_stream_material(prefix: &str, stream: &RngStreamId) -> String {
    format!(
        "{}\n{}",
        external_string_material(&format!("{prefix}.domain"), &stream.domain),
        external_string_material(&format!("{prefix}.name"), &stream.name)
    )
}

fn external_optional_label_material(prefix: &str, label: &Option<String>) -> String {
    match label {
        Some(label) => format!(
            "{prefix}.present=true\n{}",
            external_string_material(prefix, label)
        ),
        None => format!("{prefix}.present=false"),
    }
}

fn external_optional_link_material(prefix: &str, link: &Option<LinkId>) -> String {
    match link {
        Some(link) => format!(
            "{prefix}.present=true\n{}",
            external_link_id_material(prefix, link)
        ),
        None => format!("{prefix}.present=false"),
    }
}

fn external_optional_node_id_material(prefix: &str, node: &Option<NodeId>) -> String {
    match node {
        Some(node) => format!(
            "{prefix}.present=true\n{}",
            external_node_id_material(prefix, node)
        ),
        None => format!("{prefix}.present=false"),
    }
}

fn external_link_id_material(prefix: &str, id: &LinkId) -> String {
    external_string_material(prefix, &id.name)
}

fn external_resolved_mem_place_material(prefix: &str, place: &ResolvedMemPlace) -> String {
    match place {
        ResolvedMemPlace::PhysicalAddress { address, bytes } => {
            format!("{prefix}=physical-address\n{prefix}.address={address}\n{prefix}.bytes={bytes}")
        }
        ResolvedMemPlace::VirtualAddress { address, bytes } => {
            format!("{prefix}=virtual-address\n{prefix}.address={address}\n{prefix}.bytes={bytes}")
        }
        ResolvedMemPlace::Register { name, bytes } => format!(
            "{prefix}=register\n{}\n{prefix}.bytes={bytes}",
            external_string_material(&format!("{prefix}.name"), name)
        ),
    }
}

fn external_string_material(prefix: &str, value: &str) -> String {
    format!(
        "{prefix}.bytes_len={}\n{prefix}.bytes={}",
        value.len(),
        external_hex_bytes(value.as_bytes())
    )
}

fn external_preemption_kind_material(prefix: &str, kind: &PreemptionKind) -> String {
    match kind {
        PreemptionKind::VcpuSwitch { from_vcpu, to_vcpu } => format!(
            "{prefix}=vcpu-switch\n{prefix}.from_vcpu={}\n{prefix}.to_vcpu={}",
            from_vcpu.index, to_vcpu.index
        ),
        PreemptionKind::InterruptAt { target_vcpu, irq } => format!(
            "{prefix}=interrupt-at\n{prefix}.target_vcpu={}\n{prefix}.irq={}",
            target_vcpu.index, irq.vector
        ),
    }
}

fn external_scheduler_evaluation_boundary_kind_label(
    kind: SchedulerEvaluationBoundaryKind,
) -> &'static str {
    match kind {
        SchedulerEvaluationBoundaryKind::Quantum => "quantum",
        SchedulerEvaluationBoundaryKind::Rendezvous => "rendezvous",
    }
}

fn external_scheduled_event_resolve_class_label(class: ScheduledEventResolveClass) -> &'static str {
    match class {
        ScheduledEventResolveClass::FrameDelivery => "frame-delivery",
        ScheduledEventResolveClass::IoCompletion => "io-completion",
        ScheduledEventResolveClass::FaultActivation => "fault-activation",
        ScheduledEventResolveClass::ProbabilisticFault => "probabilistic-fault",
        ScheduledEventResolveClass::Control => "control",
    }
}

fn external_scheduling_node_kind_label(kind: SchedulingNodeKind) -> &'static str {
    match kind {
        SchedulingNodeKind::Vm => "vm",
        SchedulingNodeKind::Disk => "disk",
        SchedulingNodeKind::NineP => "9p",
        SchedulingNodeKind::Network => "network",
        SchedulingNodeKind::ControlPlane => "control-plane",
    }
}

fn external_io_event_kind_label(kind: IoEventKind) -> &'static str {
    match kind {
        IoEventKind::Any => "any",
        IoEventKind::BlockRead => "block-read",
        IoEventKind::BlockWrite => "block-write",
        IoEventKind::Fsync => "fsync",
        IoEventKind::NineP => "9p",
        IoEventKind::Network => "network",
    }
}

fn external_node_lifecycle_label(state: NodeLifecycle) -> &'static str {
    match state {
        NodeLifecycle::Started => "started",
        NodeLifecycle::Crashed => "crashed",
        NodeLifecycle::Hung => "hung",
        NodeLifecycle::Exited => "exited",
    }
}

fn external_assertion_phase_label(phase: AssertionPhase) -> &'static str {
    match phase {
        AssertionPhase::Satisfied => "satisfied",
        AssertionPhase::Violated => "violated",
    }
}

fn external_assertion_quantifier_label(flavor: AssertionQuantifierKind) -> &'static str {
    match flavor {
        AssertionQuantifierKind::Always => "always",
        AssertionQuantifierKind::Sometimes => "sometimes",
        AssertionQuantifierKind::Eventually => "eventually",
        AssertionQuantifierKind::AfterQuiescence => "after-quiescence",
        AssertionQuantifierKind::Reachable => "reachable",
        AssertionQuantifierKind::GuestAlways => "guest-always",
        AssertionQuantifierKind::GuestSometimes => "guest-sometimes",
        AssertionQuantifierKind::GuestReachable => "guest-reachable",
        AssertionQuantifierKind::GuestUnreachable => "guest-unreachable",
    }
}

fn external_guest_assertion_kind_label(kind: GuestAssertionKind) -> &'static str {
    match kind {
        GuestAssertionKind::Always => "always",
        GuestAssertionKind::Sometimes => "sometimes",
        GuestAssertionKind::Reachable => "reachable",
        GuestAssertionKind::Unreachable => "unreachable",
    }
}

fn external_restart_policy_label(policy: RestartPolicy) -> &'static str {
    match policy {
        RestartPolicy::FromReadyPoint => "from-ready-point",
        RestartPolicy::FromLastCheckpoint => "from-last-checkpoint",
        RestartPolicy::StayDown => "stay-down",
    }
}

fn external_partition_direction_label(direction: PartitionDirection) -> &'static str {
    match direction {
        PartitionDirection::Bidirectional => "bidirectional",
        PartitionDirection::EndpointAToEndpointB => "endpoint-a-to-endpoint-b",
        PartitionDirection::EndpointBToEndpointA => "endpoint-b-to-endpoint-a",
    }
}

fn external_log_level_label(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Debug => "debug",
        LogLevel::Info => "info",
        LogLevel::Warn => "warn",
        LogLevel::Error => "error",
    }
}

fn external_event_level_label(level: EventLevel) -> &'static str {
    match level {
        EventLevel::Trace => "trace",
        EventLevel::Debug => "debug",
        EventLevel::Info => "info",
        EventLevel::Warn => "warn",
        EventLevel::Error => "error",
    }
}

fn external_hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn condition_prefix_from_recorded_log(
    recorded_log: &RecordedAssertionLog,
    prefix_len: usize,
    require_recorded_offset: bool,
) -> Result<ConditionEventLogPrefix, OfflineAssertionCheckError> {
    let entries = &recorded_log.entries()[..prefix_len];
    let prefix = condition_prefix_from_recorded_entries(entries)?
        .with_prefix_offsets(recorded_log.prefix_offsets.clone());
    let prefix_len = u64::try_from(prefix_len)
        .map_err(|_| OfflineAssertionCheckError::PrefixLengthOverflow { prefix_len })?;
    let Some(offset) = recorded_log.event_log_offset(prefix_len) else {
        return if require_recorded_offset {
            Err(OfflineAssertionCheckError::MissingEventLogOffset { prefix_len })
        } else {
            Ok(prefix)
        };
    };
    if offset.events != prefix_len {
        return Err(OfflineAssertionCheckError::EventLogOffsetMismatch {
            prefix_len,
            offset_events: offset.events,
        });
    }
    Ok(prefix.with_event_log_offset(offset))
}

fn observe_guest_marker_assertions(
    states: &mut Vec<GuestMarkerAssertionState>,
    prefix: &ConditionEventLogPrefix,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
) -> Vec<HostAssertionOutcome> {
    let mut outcomes = Vec::new();
    let at = prefix.point().at();
    for event in prefix.observable_events() {
        if event.at() != at {
            continue;
        }
        let ObservableEventPayload::GuestAssertionMarker {
            retired_icount,
            node,
            marker,
        } = event.payload()
        else {
            continue;
        };
        if white_box_policies.get(node) != Some(&WhiteBoxPolicy::Enabled) {
            continue;
        }
        let state = guest_marker_assertion_state_for(states, marker);
        if state.terminal.is_some() {
            continue;
        }
        state.observe_payload(*retired_icount, node, marker);
        if let Some(outcome) = observe_guest_marker_assertion_state(state, at, event, marker) {
            outcomes.push(outcome);
        }
    }
    outcomes
}

fn guest_marker_assertion_state_for<'a>(
    states: &'a mut Vec<GuestMarkerAssertionState>,
    marker: &GuestAssertionMarker,
) -> &'a mut GuestMarkerAssertionState {
    match states.binary_search_by(|state| state.id.cmp(&marker.id)) {
        Ok(index) => &mut states[index],
        Err(index) => {
            states.insert(index, GuestMarkerAssertionState::new(marker));
            &mut states[index]
        }
    }
}

fn observe_guest_marker_assertion_state(
    state: &mut GuestMarkerAssertionState,
    at: VirtualTime,
    event: &ObservableEvent,
    marker: &GuestAssertionMarker,
) -> Option<HostAssertionOutcome> {
    if state.terminal.is_some() {
        return None;
    }

    if marker.kind != state.kind {
        return state.terminal_with_evidence(
            HostAssertionOutcomeKind::Violated,
            at,
            guest_marker_payload_reason(
                marker,
                &format!(
                    "guest marker assertion kind mismatch: declared {:?}, observed {:?}",
                    state.kind, marker.kind
                ),
            ),
            Some(guest_assertion_marker_event_evidence(event, marker)),
        );
    }

    match state.kind {
        GuestAssertionKind::Always if !marker.condition => state.terminal_with_evidence(
            HostAssertionOutcomeKind::Violated,
            at,
            guest_marker_payload_reason(marker, "guest always marker condition was false"),
            Some(guest_assertion_marker_event_evidence(event, marker)),
        ),
        GuestAssertionKind::Sometimes if marker.condition => state.terminal(
            HostAssertionOutcomeKind::Satisfied,
            at,
            guest_marker_payload_reason(marker, "guest sometimes marker became true"),
        ),
        GuestAssertionKind::Reachable if marker.condition => state.terminal(
            HostAssertionOutcomeKind::Satisfied,
            at,
            guest_marker_payload_reason(marker, "guest reachable marker was reached"),
        ),
        GuestAssertionKind::Unreachable if marker.condition => state.terminal_with_evidence(
            HostAssertionOutcomeKind::Violated,
            at,
            guest_marker_payload_reason(marker, "guest unreachable marker was reached"),
            Some(guest_assertion_marker_event_evidence(event, marker)),
        ),
        GuestAssertionKind::Always
        | GuestAssertionKind::Sometimes
        | GuestAssertionKind::Reachable
        | GuestAssertionKind::Unreachable => None,
    }
}

fn finalize_guest_marker_assertion_state(
    state: &mut GuestMarkerAssertionState,
    at: VirtualTime,
) -> Option<HostAssertionOutcome> {
    if state.terminal.is_some() {
        return None;
    }

    match state.kind {
        GuestAssertionKind::Always => state.terminal(
            HostAssertionOutcomeKind::Passed,
            at,
            guest_marker_reason(state, "guest always marker stayed true"),
        ),
        GuestAssertionKind::Sometimes => state.terminal_with_evidence(
            HostAssertionOutcomeKind::Violated,
            at,
            guest_marker_reason(state, "guest sometimes marker never became true"),
            Some(guest_assertion_state_evidence(state, at)),
        ),
        GuestAssertionKind::Reachable if state.observed_true => state.terminal(
            HostAssertionOutcomeKind::Satisfied,
            at,
            guest_marker_reason(state, "guest reachable marker was reached"),
        ),
        GuestAssertionKind::Reachable if state.must_hit => state.terminal_with_evidence(
            HostAssertionOutcomeKind::NeverReachedFail,
            at,
            guest_marker_reason(state, "guest reachable marker was never reached"),
            Some(guest_assertion_state_evidence(state, at)),
        ),
        GuestAssertionKind::Reachable => state.terminal(
            HostAssertionOutcomeKind::NeverReachedWarn,
            at,
            guest_marker_reason(state, "guest reachable marker was never reached"),
        ),
        GuestAssertionKind::Unreachable => state.terminal(
            HostAssertionOutcomeKind::Passed,
            at,
            guest_marker_reason(state, "guest unreachable marker stayed unreached"),
        ),
    }
}

fn guest_marker_reason(state: &GuestMarkerAssertionState, summary: &str) -> String {
    let details = details_reason(&state.details);
    format!("{summary}; location={}; details={details}", state.location)
}

fn guest_marker_payload_reason(marker: &GuestAssertionMarker, summary: &str) -> String {
    let details = details_reason(&marker.details);
    format!("{summary}; location={}; details={details}", marker.location)
}

fn details_reason(details: &[GuestAssertionDetail]) -> String {
    details
        .iter()
        .map(|detail| format!("{}={}", detail.key, detail.value))
        .collect::<Vec<_>>()
        .join(",")
}

fn sort_host_assertion_outcomes(outcomes: &mut [HostAssertionOutcome]) {
    outcomes.sort_by(|left, right| {
        left.assertion
            .cmp(&right.assertion)
            .then_with(|| left.at.cmp(&right.at))
            .then_with(|| {
                host_assertion_outcome_kind_rank(left.kind)
                    .cmp(&host_assertion_outcome_kind_rank(right.kind))
            })
            .then_with(|| left.reason.cmp(&right.reason))
    });
}

fn sort_host_assertion_proximities(proximities: &mut [HostAssertionProximity]) {
    proximities.sort_by(|left, right| {
        left.assertion
            .cmp(&right.assertion)
            .then_with(|| left.quantifier.cmp(&right.quantifier))
            .then_with(|| left.distance.cmp(&right.distance))
            .then_with(|| left.at.cmp(&right.at))
            .then_with(|| {
                left.event_log_offset
                    .events
                    .cmp(&right.event_log_offset.events)
            })
            .then_with(|| {
                left.event_log_offset
                    .bytes
                    .cmp(&right.event_log_offset.bytes)
            })
    });
}

fn lifecycle_for_outcome_kind(kind: HostAssertionOutcomeKind) -> PropertyLifecycleState {
    match kind {
        HostAssertionOutcomeKind::Passed
        | HostAssertionOutcomeKind::Warning
        | HostAssertionOutcomeKind::NeverTriggered
        | HostAssertionOutcomeKind::NeverReachedWarn => PropertyLifecycleState::Passing,
        HostAssertionOutcomeKind::Satisfied => PropertyLifecycleState::Satisfied,
        HostAssertionOutcomeKind::NeverEvaluated => PropertyLifecycleState::Declared,
        HostAssertionOutcomeKind::Violated | HostAssertionOutcomeKind::NeverReachedFail => {
            PropertyLifecycleState::Violated
        }
    }
}

fn host_assertion_outcome_kind_rank(kind: HostAssertionOutcomeKind) -> u8 {
    match kind {
        HostAssertionOutcomeKind::Passed => 0,
        HostAssertionOutcomeKind::Satisfied => 1,
        HostAssertionOutcomeKind::Warning => 2,
        HostAssertionOutcomeKind::NeverEvaluated => 3,
        HostAssertionOutcomeKind::NeverTriggered => 4,
        HostAssertionOutcomeKind::NeverReachedWarn => 5,
        HostAssertionOutcomeKind::NeverReachedFail => 6,
        HostAssertionOutcomeKind::Violated => 7,
    }
}

fn host_assertion_outcome_fails_run(kind: HostAssertionOutcomeKind) -> bool {
    matches!(
        kind,
        HostAssertionOutcomeKind::Violated | HostAssertionOutcomeKind::NeverReachedFail
    )
}

struct HostConditionEvaluation<'prefix, 'state, O: ?Sized> {
    observed: ObservedState<'prefix>,
    oracle: &'state mut O,
    once_latches: &'state mut Vec<Condition>,
    leaf_cache: &'state mut HostConditionEvaluationCache,
    white_box_policies: &'state BTreeMap<NodeId, WhiteBoxPolicy>,
    code_points: &'state BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>,
    mem_places: &'state BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>,
    scheduler_quiescence: Option<&'state SchedulerQuiescence>,
}

type HostConditionEvaluationCache = BTreeMap<HostConditionLeafKey, bool>;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum HostConditionLeafKey {
    Named { name: String, nodes: Vec<NodeId> },
    GuestMarker { marker: MarkerId },
}

impl HostConditionLeafKey {
    fn from_leaf(leaf: ConditionLeaf<'_>) -> Self {
        match leaf {
            ConditionLeaf::Named { name, nodes } => Self::Named {
                name: name.to_owned(),
                nodes: nodes.to_vec(),
            },
            ConditionLeaf::GuestMarker { marker } => Self::GuestMarker {
                marker: marker.clone(),
            },
        }
    }
}

impl<O> condition_evaluator_sealed::Sealed for HostConditionEvaluation<'_, '_, O> where
    O: HostAssertionOracle + ?Sized
{
}

impl<O> ConditionEvaluator for HostConditionEvaluation<'_, '_, O>
where
    O: HostAssertionOracle + ?Sized,
{
    fn evaluation_point(&self) -> EventEvaluationPoint {
        self.observed.point()
    }

    fn event_log_offset(&self) -> EventLogOffset {
        self.observed.event_log_offset()
    }

    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        let key = HostConditionLeafKey::from_leaf(leaf);
        if let Some(value) = self.leaf_cache.get(&key).copied() {
            return value;
        }
        let value = HostAssertionOracle::leaf_is_true(self.oracle, self.observed, leaf);
        self.leaf_cache.insert(key, value);
        value
    }

    fn observable_events(&self) -> &[ObservableEvent] {
        self.observed.observable_events()
    }

    fn fault_facts(&self) -> &[ObservedFaultFact] {
        self.observed.fault_facts()
    }

    fn scheduler_quiescence(&self) -> Option<&SchedulerQuiescence> {
        self.scheduler_quiescence
    }

    fn white_box_policy_for_node(&self, node: &NodeId) -> Option<WhiteBoxPolicy> {
        self.white_box_policies.get(node).copied()
    }

    fn once_condition_is_latched(&self, condition: &Condition) -> bool {
        self.once_latches.iter().any(|latched| latched == condition)
    }

    fn latch_once_condition(&mut self, condition: &Condition) {
        if !self.once_condition_is_latched(condition) {
            self.once_latches.push(condition.clone());
        }
    }

    fn resolve_code_point(&self, node: &NodeId, point: &CodePoint) -> Option<ResolvedCodePoint> {
        match point {
            CodePoint::GuestAddress { address } => Some(ResolvedCodePoint::guest_address(*address)),
            CodePoint::Symbol { .. } => self
                .code_points
                .get(&(node.clone(), point.clone()))
                .copied(),
        }
    }

    fn resolve_mem_place(&self, node: &NodeId, place: &MemPlace) -> Option<ResolvedMemPlace> {
        match place {
            MemPlace::PhysicalAddress { address, width } => {
                Some(ResolvedMemPlace::physical_address(*address, width.bytes()))
            }
            MemPlace::Register { name, width } => {
                Some(ResolvedMemPlace::register(name.clone(), width.bytes()))
            }
            MemPlace::VirtualAddress { .. } | MemPlace::Symbol { .. } => {
                self.mem_places.get(&(node.clone(), place.clone())).cloned()
            }
        }
    }
}

// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::too_many_arguments)]
fn host_condition_is_true<O>(
    prefix: &ConditionEventLogPrefix,
    condition: &Condition,
    oracle: &mut O,
    once_latches: &mut Vec<Condition>,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
    code_points: &BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>,
    mem_places: &BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>,
    scheduler_quiescence: Option<&SchedulerQuiescence>,
) -> bool
where
    O: HostAssertionOracle + ?Sized,
{
    let mut leaf_cache = HostConditionEvaluationCache::new();
    host_condition_is_true_with_cache(
        prefix,
        condition,
        oracle,
        once_latches,
        &mut leaf_cache,
        white_box_policies,
        code_points,
        mem_places,
        scheduler_quiescence,
    )
}

// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::too_many_arguments)]
fn host_condition_is_true_with_cache<O>(
    prefix: &ConditionEventLogPrefix,
    condition: &Condition,
    oracle: &mut O,
    once_latches: &mut Vec<Condition>,
    leaf_cache: &mut HostConditionEvaluationCache,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
    code_points: &BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>,
    mem_places: &BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>,
    scheduler_quiescence: Option<&SchedulerQuiescence>,
) -> bool
where
    O: HostAssertionOracle + ?Sized,
{
    let mut evaluator = HostConditionEvaluation {
        observed: prefix.observed_state(),
        oracle,
        once_latches,
        leaf_cache,
        white_box_policies,
        code_points,
        mem_places,
        scheduler_quiescence,
    };
    evaluate_condition(&mut evaluator, condition)
}

const ASSERTION_PROXIMITY_UNIT: u128 = 1;
const ASSERTION_PROXIMITY_UNOBSERVED_NUMERIC: u128 = u128::MAX;

fn property_proximity_is_reportable(
    property: &Property,
    terminal_kind: HostAssertionOutcomeKind,
    eventually_triggered: bool,
) -> bool {
    match property {
        Property::Sometimes { .. } => terminal_kind == HostAssertionOutcomeKind::Violated,
        Property::Eventually { .. } => {
            eventually_triggered && terminal_kind == HostAssertionOutcomeKind::Violated
        }
        Property::Reachable {
            expectation: ReachabilityExpectation::Reachable { .. },
            ..
        } => matches!(
            terminal_kind,
            HostAssertionOutcomeKind::NeverReachedWarn | HostAssertionOutcomeKind::NeverReachedFail
        ),
        Property::Always { .. }
        | Property::AfterQuiescence { .. }
        | Property::Reachable {
            expectation: ReachabilityExpectation::Unreachable,
            ..
        } => false,
    }
}

// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::too_many_arguments)]
fn host_condition_distance_to_satisfaction<O>(
    prefix: &ConditionEventLogPrefix,
    condition: &Condition,
    oracle: &mut O,
    once_latches: &[Condition],
    leaf_cache: &mut HostConditionEvaluationCache,
    white_box_policies: &BTreeMap<NodeId, WhiteBoxPolicy>,
    code_points: &BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>,
    mem_places: &BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>,
    scheduler_quiescence: Option<&SchedulerQuiescence>,
) -> u128
where
    O: HostAssertionOracle + ?Sized,
{
    let mut local_once_latches = once_latches.to_vec();
    let mut evaluator = HostConditionEvaluation {
        observed: prefix.observed_state(),
        oracle,
        once_latches: &mut local_once_latches,
        leaf_cache,
        white_box_policies,
        code_points,
        mem_places,
        scheduler_quiescence,
    };
    condition_distance_to_satisfaction(&mut evaluator, condition)
}

fn condition_distance_to_satisfaction<E>(evaluator: &mut E, condition: &Condition) -> u128
where
    E: ConditionEvaluator + ?Sized,
{
    match condition {
        Condition::MemoryPredicate {
            node,
            place,
            cmp,
            value,
        } => memory_predicate_distance_to_satisfaction(evaluator, node, place, *cmp, *value),
        Condition::AllOf { predicates } => predicates.iter().fold(0_u128, |sum, predicate| {
            sum.saturating_add(condition_distance_to_satisfaction(evaluator, predicate))
        }),
        Condition::AnyOf { predicates } => predicates
            .iter()
            .map(|predicate| condition_distance_to_satisfaction(evaluator, predicate))
            .min()
            .unwrap_or(ASSERTION_PROXIMITY_UNIT),
        Condition::Once { predicate } => {
            if evaluator.once_condition_is_latched(predicate) {
                0
            } else {
                condition_distance_to_satisfaction(evaluator, predicate)
            }
        }
        Condition::At { .. }
        | Condition::After { .. }
        | Condition::Timer { .. }
        | Condition::NetworkMatch { .. }
        | Condition::ConsoleMatch { .. }
        | Condition::CoveragePoint { .. }
        | Condition::IoPattern { .. }
        | Condition::NodeState { .. }
        | Condition::AssertionState { .. }
        | Condition::Quiescent
        | Condition::FaultActive { .. }
        | Condition::Named { .. }
        | Condition::GuestMarker { .. }
        | Condition::Not { .. } => boolean_condition_distance(evaluator, condition),
    }
}

fn boolean_condition_distance<E>(evaluator: &mut E, condition: &Condition) -> u128
where
    E: ConditionEvaluator + ?Sized,
{
    if evaluate_condition(evaluator, condition) {
        0
    } else {
        ASSERTION_PROXIMITY_UNIT
    }
}

fn memory_predicate_distance_to_satisfaction<E>(
    evaluator: &mut E,
    expected_node: &NodeId,
    place: &MemPlace,
    cmp: MemoryCmp,
    expected_value: u64,
) -> u128
where
    E: ConditionEvaluator + ?Sized,
{
    let Some(resolved) = evaluator.resolve_mem_place(expected_node, place) else {
        return ASSERTION_PROXIMITY_UNOBSERVED_NUMERIC;
    };
    evaluator
        .observable_events()
        .iter()
        .filter(|event| event.at() == evaluator.evaluation_point().at())
        .filter_map(|event| {
            let ObservableEventPayload::MemorySample {
                sample_icount: _,
                node,
                place,
                value,
            } = event.payload()
            else {
                return None;
            };
            (node == expected_node && place == &resolved)
                .then(|| memory_cmp_distance_to_satisfaction(cmp, *value, expected_value))
        })
        .min()
        .unwrap_or(ASSERTION_PROXIMITY_UNOBSERVED_NUMERIC)
}

fn memory_cmp_distance_to_satisfaction(cmp: MemoryCmp, actual: u64, expected: u64) -> u128 {
    match cmp {
        MemoryCmp::Eq => u128::from(actual.max(expected) - actual.min(expected)),
        MemoryCmp::Ne => {
            if actual != expected {
                0
            } else {
                ASSERTION_PROXIMITY_UNIT
            }
        }
        MemoryCmp::Lt => {
            if actual < expected {
                0
            } else {
                u128::from(actual) - u128::from(expected) + 1
            }
        }
        MemoryCmp::Le => {
            if actual <= expected {
                0
            } else {
                u128::from(actual) - u128::from(expected)
            }
        }
        MemoryCmp::Gt => {
            if actual > expected {
                0
            } else {
                u128::from(expected) - u128::from(actual) + 1
            }
        }
        MemoryCmp::Ge => {
            if actual >= expected {
                0
            } else {
                u128::from(expected) - u128::from(actual)
            }
        }
    }
}

fn push_observed_state_facts(
    entry: &SchedulerEventLogEntry,
    observable_events: &mut Vec<ObservableEvent>,
    black_box_observation_kinds: &mut BTreeSet<BlackBoxObservationKind>,
    ordering_facts: &mut Vec<ObservedOrderingFact>,
    fault_facts: &mut Vec<ObservedFaultFact>,
) -> Result<(), ConditionEvaluationError> {
    match entry.payload() {
        SchedulerEventLogPayload::Observable(payload) => {
            let event = ObservableEvent {
                at: entry.at(),
                payload: payload.clone(),
            };
            if let Some(kind) = event.black_box_observation_kind() {
                validate_black_box_observation_entry(entry, &event, kind)?;
                black_box_observation_kinds.insert(kind);
            }
            observable_events.push(event);
        }
        SchedulerEventLogPayload::ResolvedHappening(event) => {
            push_resolved_happening_observed_facts(
                entry.sequence(),
                entry.at(),
                event,
                ordering_facts,
                fault_facts,
            );
        }
        SchedulerEventLogPayload::Decision(Decision::DeliveryOrder(order)) => {
            ordering_facts.push(ObservedOrderingFact::DeliveryOrder {
                sequence: entry.sequence(),
                at: entry.at(),
                order: order.order.clone(),
            });
        }
        SchedulerEventLogPayload::Decision(Decision::FaultFires(fault)) => {
            fault_facts.push(ObservedFaultFact::ProbabilisticOutcome {
                sequence: entry.sequence(),
                at: entry.at(),
                fault: fault.fault.clone(),
                fired: fault.fired,
            });
        }
        SchedulerEventLogPayload::Decision(Decision::ControlFault(control)) => {
            push_control_fault_fact(
                entry.sequence(),
                entry.at(),
                control.sequence,
                &control.action,
                fault_facts,
            );
        }
        SchedulerEventLogPayload::TriggerActionApplied(application) => {
            push_trigger_fault_fact(entry.sequence(), entry.at(), application, fault_facts);
        }
        SchedulerEventLogPayload::Decision(
            Decision::RngDraw(_)
            | Decision::Override(_)
            | Decision::Preemption(_)
            | Decision::AppRandom(_),
        )
        | SchedulerEventLogPayload::EvaluationBoundary(_)
        | SchedulerEventLogPayload::TriggerFired(_)
        | SchedulerEventLogPayload::Diagnostic(_) => {}
    }
    Ok(())
}

fn push_condition_runtime_facts(
    entry: &SchedulerEventLogEntry,
    event_firings: &mut BTreeMap<EventId, VirtualTime>,
    timer_fires: &mut BTreeMap<TimerId, VirtualTime>,
) {
    match entry.payload() {
        SchedulerEventLogPayload::TriggerFired(firing) => {
            event_firings.insert(firing.event().clone(), firing.at());
        }
        SchedulerEventLogPayload::TriggerActionApplied(application) => match &application.action {
            Action::ArmTimer { name, after } => {
                if let Some(ticks) = application.at.ticks.checked_add(after.nanos) {
                    timer_fires.insert(name.clone(), VirtualTime { ticks });
                }
            }
            Action::CancelTimer { name } => {
                timer_fires.remove(name);
            }
            Action::InjectFault { .. }
            | Action::HealFault { .. }
            | Action::StartNode { .. }
            | Action::StopNode { .. }
            | Action::CreateSavepoint { .. }
            | Action::Fork { .. }
            | Action::Pass
            | Action::Fail { .. }
            | Action::Log { .. }
            | Action::Group(_) => {}
        },
        SchedulerEventLogPayload::ResolvedHappening(_)
        | SchedulerEventLogPayload::Decision(_)
        | SchedulerEventLogPayload::Observable(_)
        | SchedulerEventLogPayload::EvaluationBoundary(_)
        | SchedulerEventLogPayload::Diagnostic(_) => {}
    }
}

fn scheduler_entry_black_box_observation_kind(
    entry: &SchedulerEventLogEntry,
) -> Option<BlackBoxObservationKind> {
    let SchedulerEventLogPayload::Observable(payload) = entry.payload() else {
        return None;
    };
    payload.black_box_observation_kind()
}

fn validate_black_box_observation_entry(
    entry: &SchedulerEventLogEntry,
    event: &ObservableEvent,
    kind: BlackBoxObservationKind,
) -> Result<(), ConditionEvaluationError> {
    if entry.class() != SchedulerEventLogClass::Observational {
        return Err(ConditionEvaluationError::InvalidBlackBoxObservationClass {
            sequence: entry.sequence(),
            kind,
            class: entry.class(),
        });
    }
    let expected = black_box_observation_icount_stamp(event.at(), event.payload());
    if entry.time().icount != expected {
        return Err(ConditionEvaluationError::InvalidBlackBoxObservationStamp {
            sequence: entry.sequence(),
            kind,
            expected,
            actual: entry.time().icount.clone(),
        });
    }
    Ok(())
}

fn black_box_observation_icount_stamp(
    at: VirtualTime,
    payload: &ObservableEventPayload,
) -> EventLogIcountStamp {
    match payload {
        ObservableEventPayload::NetworkDelivered { .. } => black_box_boundary_icount(at),
        ObservableEventPayload::ConsoleOutput { node, .. }
        | ObservableEventPayload::IoCompletion {
            kind:
                IoEventKind::BlockRead
                | IoEventKind::BlockWrite
                | IoEventKind::Fsync
                | IoEventKind::NineP
                | IoEventKind::Network,
            node,
            ..
        }
        | ObservableEventPayload::NodeState { node, .. } => {
            black_box_node_boundary_icount(at, node)
        }
        ObservableEventPayload::CoverageBlock {
            execution_icount,
            node,
            ..
        } => EventLogIcountStamp {
            node: Some(node.clone()),
            icount: *execution_icount,
        },
        ObservableEventPayload::MemorySample {
            sample_icount,
            node,
            ..
        } => EventLogIcountStamp {
            node: Some(node.clone()),
            icount: *sample_icount,
        },
        ObservableEventPayload::IoCompletion {
            kind: IoEventKind::Any,
            ..
        }
        | ObservableEventPayload::CoverageMarker { .. }
        | ObservableEventPayload::AssertionProximity { .. }
        | ObservableEventPayload::AssertionStateChanged { .. }
        | ObservableEventPayload::AssertionEvaluated { .. }
        | ObservableEventPayload::GuestMarker { .. }
        | ObservableEventPayload::GuestAssertionMarker { .. } => black_box_boundary_icount(at),
    }
}

fn black_box_boundary_icount(at: VirtualTime) -> EventLogIcountStamp {
    EventLogIcountStamp {
        node: None,
        icount: Icount { retired: at.ticks },
    }
}

fn black_box_node_boundary_icount(at: VirtualTime, node: &NodeId) -> EventLogIcountStamp {
    EventLogIcountStamp {
        node: Some(node.clone()),
        icount: Icount { retired: at.ticks },
    }
}

fn push_resolved_happening_observed_facts(
    sequence: u64,
    at: VirtualTime,
    event: &ScheduledEvent,
    ordering_facts: &mut Vec<ObservedOrderingFact>,
    fault_facts: &mut Vec<ObservedFaultFact>,
) {
    ordering_facts.push(ObservedOrderingFact::ResolvedHappening {
        sequence,
        at,
        key: event.key.clone(),
        class: scheduled_event_resolve_class(event),
    });
    match &event.payload {
        ScheduledEventPayload::FaultActivation(fault) => {
            fault_facts.push(ObservedFaultFact::ScheduledActivation {
                sequence,
                at,
                fault: fault.clone(),
            });
        }
        ScheduledEventPayload::ProbabilisticFault(choice) => {
            fault_facts.push(ObservedFaultFact::ScheduledProbabilisticChoice {
                sequence,
                at,
                fault: choice.fault.clone(),
            });
        }
        ScheduledEventPayload::BackendInput(_)
        | ScheduledEventPayload::IoCompletion(_)
        | ScheduledEventPayload::Control(_) => {}
    }
}

fn push_control_fault_fact(
    sequence: u64,
    at: VirtualTime,
    control_sequence: u64,
    action: &ControlFaultAction,
    fault_facts: &mut Vec<ObservedFaultFact>,
) {
    match action {
        ControlFaultAction::Inject { tag, fault } => {
            fault_facts.push(ObservedFaultFact::ControlInjected {
                sequence,
                at,
                control_sequence,
                tag: tag.clone(),
                fault: fault.clone(),
            });
        }
        ControlFaultAction::Heal { tag } => {
            fault_facts.push(ObservedFaultFact::ControlHealed {
                sequence,
                at,
                control_sequence,
                tag: tag.clone(),
            });
        }
    }
}

fn push_trigger_fault_fact(
    sequence: u64,
    at: VirtualTime,
    application: &crate::scheduler::TriggerActionApplication,
    fault_facts: &mut Vec<ObservedFaultFact>,
) {
    match &application.action {
        Action::InjectFault { tag, fault } => {
            fault_facts.push(ObservedFaultFact::TriggerInjected {
                sequence,
                at,
                trigger_sequence: application.sequence,
                event: application.event.clone(),
                tag: tag.clone(),
                fault: fault.clone(),
            });
        }
        Action::HealFault { tag } => {
            fault_facts.push(ObservedFaultFact::TriggerHealed {
                sequence,
                at,
                trigger_sequence: application.sequence,
                event: application.event.clone(),
                tag: tag.clone(),
            });
        }
        Action::ArmTimer { .. }
        | Action::CancelTimer { .. }
        | Action::StartNode { .. }
        | Action::StopNode { .. }
        | Action::CreateSavepoint { .. }
        | Action::Fork { .. }
        | Action::Pass
        | Action::Fail { .. }
        | Action::Log { .. }
        | Action::Group(_) => {}
    }
}

/// Evaluates a condition through the shared assertion/trigger evaluator.
///
/// The recursive structure lives in this non-overridable function. Implementors
/// of [`ConditionEvaluator`] provide leaf truth, deterministic observation
/// sources, and `Once` latch storage at a deterministic evaluation point, so
/// assertion and trigger consumers cannot diverge on compound predicate
/// traversal.
pub(crate) fn evaluate_condition<E>(evaluator: &mut E, condition: &Condition) -> bool
where
    E: ConditionEvaluator + ?Sized,
{
    match condition {
        Condition::At { at } => evaluator.evaluation_point().at() == *at,
        Condition::After { duration, of } => evaluator
            .last_event_firing(of)
            .and_then(|fired_at| fired_at.ticks.checked_add(duration.nanos))
            .is_some_and(|fire_at| fire_at == evaluator.evaluation_point().at().ticks),
        Condition::Timer { name } => evaluator
            .timer_fire_time(name)
            .is_some_and(|fire_at| fire_at == evaluator.evaluation_point().at()),
        Condition::NetworkMatch { link, predicate } => observable_event_matches(
            evaluator.evaluation_point().at(),
            evaluator.observable_events(),
            |event| network_event_matches(event, link.as_ref(), predicate),
        ),
        Condition::ConsoleMatch { node, regex } => console_stream_matches(
            evaluator.evaluation_point().at(),
            evaluator.observable_events(),
            node,
            regex,
        ),
        Condition::CoveragePoint { node, point } => coverage_point_matches(evaluator, node, point),
        Condition::MemoryPredicate {
            node,
            place,
            cmp,
            value,
        } => memory_predicate_matches(evaluator, node, place, *cmp, *value),
        Condition::IoPattern { node, kind } => observable_event_matches(
            evaluator.evaluation_point().at(),
            evaluator.observable_events(),
            |event| io_event_matches(event, node, *kind),
        ),
        Condition::NodeState { node, state } => observable_event_matches(
            evaluator.evaluation_point().at(),
            evaluator.observable_events(),
            |event| node_state_event_matches(event, node, *state),
        ),
        Condition::AssertionState { name, state } => observable_event_matches(
            evaluator.evaluation_point().at(),
            evaluator.observable_events(),
            |event| assertion_state_event_matches(event, name, *state),
        ),
        Condition::Quiescent => evaluator
            .scheduler_quiescence()
            .is_some_and(SchedulerQuiescence::is_quiescent),
        Condition::FaultActive { tag } => fault_tag_is_active(evaluator.fault_facts(), tag),
        Condition::Named { name, nodes } => evaluator.leaf_is_true(ConditionLeaf::Named {
            name: name.as_str(),
            nodes,
        }),
        Condition::GuestMarker { marker } => guest_marker_matches(evaluator, marker),
        Condition::AllOf { predicates } => {
            let mut all_true = true;
            for condition in predicates {
                all_true &= evaluate_condition(evaluator, condition);
            }
            all_true
        }
        Condition::AnyOf { predicates } => {
            let mut any_true = false;
            for condition in predicates {
                any_true |= evaluate_condition(evaluator, condition);
            }
            any_true
        }
        Condition::Once { predicate } => {
            if evaluator.once_condition_is_latched(predicate) {
                true
            } else if evaluate_condition(evaluator, predicate) {
                evaluator.latch_once_condition(predicate);
                true
            } else {
                false
            }
        }
        Condition::Not { predicate } => !evaluate_condition(evaluator, predicate),
    }
}

fn fault_tag_is_active(facts: &[ObservedFaultFact], expected_tag: &FaultTag) -> bool {
    let mut active = false;
    for fact in facts {
        match fact {
            ObservedFaultFact::ControlInjected { tag, .. }
            | ObservedFaultFact::TriggerInjected { tag, .. }
                if tag == expected_tag =>
            {
                active = true;
            }
            ObservedFaultFact::ControlHealed { tag, .. }
            | ObservedFaultFact::TriggerHealed { tag, .. }
                if tag == expected_tag =>
            {
                active = false;
            }
            ObservedFaultFact::ScheduledActivation { .. }
            | ObservedFaultFact::ScheduledProbabilisticChoice { .. }
            | ObservedFaultFact::ProbabilisticOutcome { .. }
            | ObservedFaultFact::ControlInjected { .. }
            | ObservedFaultFact::ControlHealed { .. }
            | ObservedFaultFact::TriggerInjected { .. }
            | ObservedFaultFact::TriggerHealed { .. } => {}
        }
    }
    active
}

fn observable_event_matches(
    at: VirtualTime,
    events: &[ObservableEvent],
    matches_payload: impl Fn(&ObservableEventPayload) -> bool,
) -> bool {
    events
        .iter()
        .any(|event| event.at() == at && matches_payload(event.payload()))
}

fn network_event_matches(
    event: &ObservableEventPayload,
    expected_link: Option<&LinkId>,
    predicate: &FramePredicate,
) -> bool {
    let ObservableEventPayload::NetworkDelivered { link, payload } = event else {
        return false;
    };
    let link_matches = expected_link.is_none_or(|expected| link.as_ref() == Some(expected));
    link_matches && frame_predicate_matches(predicate, payload)
}

fn frame_predicate_matches(predicate: &FramePredicate, payload: &[u8]) -> bool {
    match predicate {
        FramePredicate::Any => true,
        FramePredicate::Exact(expected) => payload == expected,
        FramePredicate::Contains(needle) => {
            needle.is_empty()
                || payload
                    .windows(needle.len())
                    .any(|window| window == needle.as_slice())
        }
        FramePredicate::Prefix(prefix) => payload.starts_with(prefix),
    }
}

fn console_stream_matches(
    at: VirtualTime,
    events: &[ObservableEvent],
    expected_node: &NodeId,
    regex: &RegexProgram,
) -> bool {
    let Ok(program) = regex::bytes::Regex::new(&regex.pattern) else {
        return false;
    };
    let mut stream = Vec::new();
    let mut current_start = None;
    for event in events {
        let ObservableEventPayload::ConsoleOutput { node, bytes } = event.payload() else {
            continue;
        };
        if node != expected_node {
            continue;
        }
        if event.at() < at {
            stream.extend_from_slice(bytes);
        } else if event.at() == at {
            current_start.get_or_insert(stream.len());
            stream.extend_from_slice(bytes);
        }
    }
    let Some(current_start) = current_start else {
        return false;
    };
    program
        .find_iter(&stream)
        .any(|matched| matched.end() > current_start)
}

fn coverage_point_matches<E>(evaluator: &E, expected_node: &NodeId, point: &CodePoint) -> bool
where
    E: ConditionEvaluator + ?Sized,
{
    let Some(resolved) = evaluator.resolve_code_point(expected_node, point) else {
        return false;
    };
    let at = evaluator.evaluation_point().at();
    let events = evaluator.observable_events();
    let matches_current = events.iter().any(|event| {
        event.at() == at && coverage_event_matches(event.payload(), expected_node, resolved)
    });
    let seen_before = events.iter().any(|event| {
        event.at() < at && coverage_event_matches(event.payload(), expected_node, resolved)
    });
    matches_current && !seen_before
}

fn coverage_event_matches(
    event: &ObservableEventPayload,
    expected_node: &NodeId,
    expected_point: ResolvedCodePoint,
) -> bool {
    let ObservableEventPayload::CoverageBlock {
        execution_icount: _,
        node,
        guest_pc,
        block_len,
    } = event
    else {
        return false;
    };
    node == expected_node && block_contains_address(*guest_pc, *block_len, expected_point.address())
}

fn block_contains_address(guest_pc: u64, block_len: u32, address: u64) -> bool {
    let Some(end) = guest_pc.checked_add(u64::from(block_len)) else {
        return false;
    };
    guest_pc <= address && address < end
}

fn memory_predicate_matches<E>(
    evaluator: &E,
    expected_node: &NodeId,
    place: &MemPlace,
    cmp: MemoryCmp,
    expected_value: u64,
) -> bool
where
    E: ConditionEvaluator + ?Sized,
{
    let Some(resolved) = evaluator.resolve_mem_place(expected_node, place) else {
        return false;
    };
    observable_event_matches(
        evaluator.evaluation_point().at(),
        evaluator.observable_events(),
        |event| memory_event_matches(event, expected_node, &resolved, cmp, expected_value),
    )
}

fn memory_event_matches(
    event: &ObservableEventPayload,
    expected_node: &NodeId,
    expected_place: &ResolvedMemPlace,
    cmp: MemoryCmp,
    expected_value: u64,
) -> bool {
    let ObservableEventPayload::MemorySample {
        sample_icount: _,
        node,
        place,
        value,
    } = event
    else {
        return false;
    };
    node == expected_node
        && place == expected_place
        && memory_cmp_matches(cmp, *value, expected_value)
}

fn memory_cmp_matches(cmp: MemoryCmp, actual: u64, expected: u64) -> bool {
    match cmp {
        MemoryCmp::Eq => actual == expected,
        MemoryCmp::Ne => actual != expected,
        MemoryCmp::Lt => actual < expected,
        MemoryCmp::Le => actual <= expected,
        MemoryCmp::Gt => actual > expected,
        MemoryCmp::Ge => actual >= expected,
    }
}

fn io_event_matches(
    event: &ObservableEventPayload,
    expected_node: &NodeId,
    expected_kind: IoEventKind,
) -> bool {
    let ObservableEventPayload::IoCompletion { node, kind, .. } = event else {
        return false;
    };
    node == expected_node && (expected_kind == IoEventKind::Any || expected_kind == *kind)
}

fn node_state_event_matches(
    event: &ObservableEventPayload,
    expected_node: &NodeId,
    expected_state: NodeLifecycle,
) -> bool {
    let ObservableEventPayload::NodeState { node, state } = event else {
        return false;
    };
    node == expected_node && *state == expected_state
}

fn assertion_state_event_matches(
    event: &ObservableEventPayload,
    expected_name: &AssertionId,
    expected_state: AssertionPhase,
) -> bool {
    let ObservableEventPayload::AssertionStateChanged { name, state } = event else {
        return false;
    };
    name == expected_name && *state == expected_state
}

fn guest_marker_matches<E>(evaluator: &E, expected_marker: &MarkerId) -> bool
where
    E: ConditionEvaluator + ?Sized,
{
    observable_event_matches(
        evaluator.evaluation_point().at(),
        evaluator.observable_events(),
        |event| guest_marker_event_matches(evaluator, event, expected_marker),
    )
}

fn guest_marker_event_matches<E>(
    evaluator: &E,
    event: &ObservableEventPayload,
    expected_marker: &MarkerId,
) -> bool
where
    E: ConditionEvaluator + ?Sized,
{
    match event {
        ObservableEventPayload::GuestMarker {
            retired_icount: _,
            node,
            marker,
        } => {
            marker == expected_marker
                && evaluator.white_box_policy_for_node(node) == Some(WhiteBoxPolicy::Enabled)
        }
        ObservableEventPayload::GuestAssertionMarker { .. } => false,
        ObservableEventPayload::NetworkDelivered { .. }
        | ObservableEventPayload::ConsoleOutput { .. }
        | ObservableEventPayload::CoverageBlock { .. }
        | ObservableEventPayload::CoverageMarker { .. }
        | ObservableEventPayload::MemorySample { .. }
        | ObservableEventPayload::IoCompletion { .. }
        | ObservableEventPayload::NodeState { .. }
        | ObservableEventPayload::AssertionStateChanged { .. }
        | ObservableEventPayload::AssertionEvaluated { .. }
        | ObservableEventPayload::AssertionProximity { .. } => false,
    }
}

/// Condition evaluator backed by a leaf oracle.
#[derive(Clone, Debug)]
pub struct ConditionEvaluation<O> {
    point: EventEvaluationPoint,
    event_log_offset: EventLogOffset,
    oracle: O,
    event_firings: BTreeMap<EventId, VirtualTime>,
    timer_fires: BTreeMap<TimerId, VirtualTime>,
    observable_events: Vec<ObservableEvent>,
    ordering_facts: Vec<ObservedOrderingFact>,
    fault_facts: Vec<ObservedFaultFact>,
    scheduler_quiescence: Option<SchedulerQuiescence>,
    white_box_policies: BTreeMap<NodeId, WhiteBoxPolicy>,
    once_latches: Vec<Condition>,
    code_points: BTreeMap<(NodeId, CodePoint), ResolvedCodePoint>,
    mem_places: BTreeMap<(NodeId, MemPlace), ResolvedMemPlace>,
}

impl<O> ConditionEvaluation<O> {
    /// Builds a condition evaluator for one deterministic event-log prefix.
    #[must_use]
    pub fn from_log_prefix(prefix: ConditionEventLogPrefix, oracle: O) -> Self {
        Self {
            point: prefix.point,
            event_log_offset: prefix.event_log_offset,
            oracle,
            event_firings: prefix.event_firings,
            timer_fires: prefix.timer_fires,
            observable_events: prefix.observable_events,
            ordering_facts: prefix.ordering_facts,
            fault_facts: prefix.fault_facts,
            scheduler_quiescence: None,
            white_box_policies: BTreeMap::new(),
            once_latches: Vec::new(),
            code_points: BTreeMap::new(),
            mem_places: BTreeMap::new(),
        }
    }

    /// Returns the deterministic point where this evaluator observes the log.
    #[must_use]
    pub fn point(&self) -> EventEvaluationPoint {
        self.point
    }

    /// Returns the event-log prefix identity visible to this evaluator.
    #[must_use]
    pub fn event_log_offset(&self) -> EventLogOffset {
        self.event_log_offset
    }

    /// Returns the read-only observed-state view for this evaluation pass.
    #[must_use]
    pub fn observed_state(&self) -> ObservedState<'_> {
        ObservedState {
            point: self.point,
            event_log_offset: self.event_log_offset,
            observable_events: &self.observable_events,
            ordering_facts: &self.ordering_facts,
            fault_facts: &self.fault_facts,
        }
    }

    /// Adds event firing history visible to `After` predicates.
    #[must_use]
    pub fn with_event_firings(mut self, event_firings: BTreeMap<EventId, VirtualTime>) -> Self {
        self.event_firings = event_firings;
        self
    }

    /// Adds timer fire times visible to `Timer` predicates.
    #[must_use]
    pub fn with_timer_fires(mut self, timer_fires: BTreeMap<TimerId, VirtualTime>) -> Self {
        self.timer_fires = timer_fires;
        self
    }

    /// Adds scheduler-owned quiescence evidence visible to `Quiescent` leaves.
    #[must_use]
    pub fn with_scheduler_quiescence(mut self, quiescence: SchedulerQuiescence) -> Self {
        self.scheduler_quiescence = Some(quiescence);
        self
    }

    /// Adds authoritative white-box opt-in policies for guest-marker leaves.
    #[must_use]
    pub fn with_white_box_policies(
        mut self,
        policies: impl IntoIterator<Item = (NodeId, WhiteBoxPolicy)>,
    ) -> Self {
        self.white_box_policies = policies.into_iter().collect();
        self
    }

    /// Adds authoritative white-box opt-in policies from a world definition.
    #[must_use]
    pub fn with_world_white_box_policies(self, world: &World) -> Self {
        self.with_white_box_policies(
            world
                .nodes()
                .iter()
                .map(|node| (node.id.clone(), node.white_box)),
        )
    }

    /// Adds host-side code point resolutions visible to coverage leaves.
    #[must_use]
    pub fn with_resolved_code_points(
        mut self,
        code_points: impl IntoIterator<Item = ((NodeId, CodePoint), ResolvedCodePoint)>,
    ) -> Self {
        self.code_points = code_points.into_iter().collect();
        self
    }

    /// Adds host-side memory place resolutions visible to memory predicates.
    #[must_use]
    pub fn with_resolved_mem_places(
        mut self,
        mem_places: impl IntoIterator<Item = ((NodeId, MemPlace), ResolvedMemPlace)>,
    ) -> Self {
        self.mem_places = mem_places.into_iter().collect();
        self
    }

    /// Evaluates a condition through the shared evaluator function.
    pub(crate) fn evaluate_condition(&mut self, condition: &Condition) -> bool
    where
        O: ConditionLeafOracle,
    {
        evaluate_condition(self, condition)
    }
}

/// Shared assertion/trigger condition-evaluation pass for one log prefix.
#[derive(Clone, Debug)]
pub struct ConditionEvaluationPass<O> {
    evaluation: ConditionEvaluation<O>,
}

impl<O> ConditionEvaluationPass<O> {
    /// Builds a shared pass over one deterministic event-log prefix.
    #[must_use]
    pub fn from_log_prefix(prefix: ConditionEventLogPrefix, oracle: O) -> Self {
        Self {
            evaluation: ConditionEvaluation::from_log_prefix(prefix, oracle),
        }
    }

    /// Adds event firing history visible to `After` predicates.
    #[must_use]
    pub fn with_event_firings(mut self, event_firings: BTreeMap<EventId, VirtualTime>) -> Self {
        self.evaluation = self.evaluation.with_event_firings(event_firings);
        self
    }

    /// Adds timer fire times visible to `Timer` predicates.
    #[must_use]
    pub fn with_timer_fires(mut self, timer_fires: BTreeMap<TimerId, VirtualTime>) -> Self {
        self.evaluation = self.evaluation.with_timer_fires(timer_fires);
        self
    }

    /// Adds scheduler-owned quiescence evidence visible to `Quiescent` leaves.
    #[must_use]
    pub fn with_scheduler_quiescence(mut self, quiescence: SchedulerQuiescence) -> Self {
        self.evaluation = self.evaluation.with_scheduler_quiescence(quiescence);
        self
    }

    /// Adds previously latched `Once` predicates visible to this pass.
    #[must_use]
    pub fn with_once_latches(mut self, once_latches: Vec<Condition>) -> Self {
        self.evaluation.once_latches = once_latches;
        self
    }

    /// Returns the `Once` predicates latched by this pass.
    #[must_use]
    pub fn once_latches(&self) -> &[Condition] {
        &self.evaluation.once_latches
    }

    /// Adds authoritative white-box opt-in policies for guest-marker leaves.
    #[must_use]
    pub fn with_white_box_policies(
        mut self,
        policies: impl IntoIterator<Item = (NodeId, WhiteBoxPolicy)>,
    ) -> Self {
        self.evaluation = self.evaluation.with_white_box_policies(policies);
        self
    }

    /// Adds authoritative white-box opt-in policies from a world definition.
    #[must_use]
    pub fn with_world_white_box_policies(mut self, world: &World) -> Self {
        self.evaluation = self.evaluation.with_world_white_box_policies(world);
        self
    }

    /// Adds host-side code point resolutions visible to coverage leaves.
    #[must_use]
    pub fn with_resolved_code_points(
        mut self,
        code_points: impl IntoIterator<Item = ((NodeId, CodePoint), ResolvedCodePoint)>,
    ) -> Self {
        self.evaluation = self.evaluation.with_resolved_code_points(code_points);
        self
    }

    /// Adds host-side memory place resolutions visible to memory predicates.
    #[must_use]
    pub fn with_resolved_mem_places(
        mut self,
        mem_places: impl IntoIterator<Item = ((NodeId, MemPlace), ResolvedMemPlace)>,
    ) -> Self {
        self.evaluation = self.evaluation.with_resolved_mem_places(mem_places);
        self
    }

    /// Returns the deterministic evaluation point for this pass.
    #[must_use]
    pub fn point(&self) -> EventEvaluationPoint {
        self.evaluation.point()
    }

    /// Returns the underlying condition evaluator.
    #[must_use]
    pub fn evaluator(&self) -> &ConditionEvaluation<O> {
        &self.evaluation
    }

    /// Returns the read-only observed-state view for this pass.
    #[must_use]
    pub fn observed_state(&self) -> ObservedState<'_> {
        self.evaluation.observed_state()
    }

    /// Evaluates an assertion predicate in this deterministic pass.
    pub fn evaluate_assertion_condition(&mut self, condition: &Condition) -> bool
    where
        O: ConditionLeafOracle,
    {
        self.evaluation.evaluate_condition(condition)
    }

    /// Evaluates trigger conditions in this deterministic pass.
    pub fn evaluate_event_graph(
        &mut self,
        graph: &EventGraph,
        state: &mut EventGraphState,
    ) -> EventFirings
    where
        O: ConditionLeafOracle,
    {
        state.evaluate(graph, &mut self.evaluation)
    }
}

impl<O> condition_evaluator_sealed::Sealed for ConditionEvaluation<O> where O: ConditionLeafOracle {}

impl<O> ConditionEvaluator for ConditionEvaluation<O>
where
    O: ConditionLeafOracle,
{
    fn evaluation_point(&self) -> EventEvaluationPoint {
        self.point
    }

    fn event_log_offset(&self) -> EventLogOffset {
        self.event_log_offset
    }

    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        self.oracle.leaf_is_true(leaf)
    }

    fn last_event_firing(&self, event: &EventId) -> Option<VirtualTime> {
        self.event_firings.get(event).copied()
    }

    fn timer_fire_time(&self, timer: &TimerId) -> Option<VirtualTime> {
        self.timer_fires.get(timer).copied()
    }

    fn timer_fires(&self) -> BTreeMap<TimerId, VirtualTime> {
        self.timer_fires.clone()
    }

    fn observable_events(&self) -> &[ObservableEvent] {
        &self.observable_events
    }

    fn scheduler_quiescence(&self) -> Option<&SchedulerQuiescence> {
        self.scheduler_quiescence.as_ref()
    }

    fn fault_facts(&self) -> &[ObservedFaultFact] {
        &self.fault_facts
    }

    fn white_box_policy_for_node(&self, node: &NodeId) -> Option<WhiteBoxPolicy> {
        self.white_box_policies.get(node).copied()
    }

    fn once_condition_is_latched(&self, condition: &Condition) -> bool {
        self.once_latches.iter().any(|latched| latched == condition)
    }

    fn latch_once_condition(&mut self, condition: &Condition) {
        if !self.once_condition_is_latched(condition) {
            self.once_latches.push(condition.clone());
        }
    }

    fn resolve_code_point(&self, node: &NodeId, point: &CodePoint) -> Option<ResolvedCodePoint> {
        match point {
            CodePoint::GuestAddress { address } => Some(ResolvedCodePoint::guest_address(*address)),
            CodePoint::Symbol { .. } => self
                .code_points
                .get(&(node.clone(), point.clone()))
                .copied(),
        }
    }

    fn resolve_mem_place(&self, node: &NodeId, place: &MemPlace) -> Option<ResolvedMemPlace> {
        match place {
            MemPlace::PhysicalAddress { address, width } => {
                Some(ResolvedMemPlace::physical_address(*address, width.bytes()))
            }
            MemPlace::Register { name, width } => {
                Some(ResolvedMemPlace::register(name.clone(), width.bytes()))
            }
            MemPlace::VirtualAddress { .. } | MemPlace::Symbol { .. } => {
                self.mem_places.get(&(node.clone(), place.clone())).cloned()
            }
        }
    }
}

/// Whether an event fires once or on each false-to-true trigger transition.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum FirePolicy {
    /// Fire at most once, the first time the trigger is true.
    #[default]
    Once,
    /// Fire on every false-to-true trigger transition.
    Repeatable,
}

/// What an event does when it fires.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    /// Activate a membership fault under a stable tag.
    InjectFault {
        /// Tag used by later heal actions.
        tag: FaultTag,
        /// Membership fault to activate.
        fault: MembershipFault,
    },
    /// Heal a previously activated fault tag.
    HealFault {
        /// Tag to heal.
        tag: FaultTag,
    },
    /// Arm a named virtual-time timer.
    ArmTimer {
        /// Timer to arm.
        name: TimerId,
        /// Virtual duration from the firing point to the timer fire point.
        after: SimDuration,
    },
    /// Cancel a named timer.
    CancelTimer {
        /// Timer to cancel.
        name: TimerId,
    },
    /// Start a declared, baked node.
    StartNode {
        /// Node to schedule as started.
        node: NodeId,
    },
    /// Stop a declared node without removing it from the world.
    StopNode {
        /// Node to stop.
        node: NodeId,
    },
    /// Create a savepoint at the firing point.
    CreateSavepoint {
        /// Optional stable savepoint label.
        label: Option<String>,
    },
    /// Fork the temporal graph at the firing point.
    Fork {
        /// Optional stable fork label.
        label: Option<String>,
    },
    /// Declare the run passed.
    Pass,
    /// Declare the run failed.
    Fail {
        /// Stable failure reason.
        reason: String,
    },
    /// Append an observational diagnostic entry.
    Log {
        /// Diagnostic level.
        level: LogLevel,
        /// Stable diagnostic message.
        message: String,
    },
    /// Group multiple action payloads in declared order.
    Group(Vec<Action>),
}

impl Action {
    /// Builds an [`Action::InjectFault`] action.
    #[must_use]
    pub fn inject_fault(tag: FaultTag, fault: MembershipFault) -> Self {
        Self::InjectFault { tag, fault }
    }

    /// Builds an [`Action::HealFault`] action.
    #[must_use]
    pub fn heal_fault(tag: FaultTag) -> Self {
        Self::HealFault { tag }
    }

    /// Builds an [`Action::ArmTimer`] action.
    #[must_use]
    pub fn arm_timer(name: TimerId, after: SimDuration) -> Self {
        Self::ArmTimer { name, after }
    }

    /// Builds an [`Action::CancelTimer`] action.
    #[must_use]
    pub fn cancel_timer(name: TimerId) -> Self {
        Self::CancelTimer { name }
    }

    /// Builds an [`Action::StartNode`] action.
    #[must_use]
    pub fn start_node(node: NodeId) -> Self {
        Self::StartNode { node }
    }

    /// Builds an [`Action::StopNode`] action.
    #[must_use]
    pub fn stop_node(node: NodeId) -> Self {
        Self::StopNode { node }
    }

    /// Builds an [`Action::CreateSavepoint`] action.
    #[must_use]
    pub fn create_savepoint(label: Option<String>) -> Self {
        Self::CreateSavepoint { label }
    }

    /// Builds an [`Action::Fork`] action.
    #[must_use]
    pub fn fork(label: Option<String>) -> Self {
        Self::Fork { label }
    }

    /// Builds an [`Action::Pass`] action.
    #[must_use]
    pub const fn pass() -> Self {
        Self::Pass
    }

    /// Builds an [`Action::Fail`] action.
    #[must_use]
    pub fn fail(reason: impl Into<String>) -> Self {
        Self::Fail {
            reason: reason.into(),
        }
    }

    /// Builds an [`Action::Log`] action.
    #[must_use]
    pub fn log(level: LogLevel, message: impl Into<String>) -> Self {
        Self::Log {
            level,
            message: message.into(),
        }
    }

    /// Builds an [`Action::Group`] action.
    #[must_use]
    pub fn group(actions: Vec<Action>) -> Self {
        Self::Group(actions)
    }
}

/// Diagnostic level for an [`Action::Log`] payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LogLevel {
    /// Fine-grained diagnostic output.
    Debug,
    /// Informational diagnostic output.
    Info,
    /// Warning diagnostic output.
    Warn,
    /// Error diagnostic output.
    Error,
}

/// One node in the event graph.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Event {
    /// Stable, author-assigned event identity.
    pub id: EventId,
    /// Trigger predicate; `None` is an entrypoint fired at genesis.
    pub trigger: Option<Condition>,
    /// Action emitted when the trigger fires.
    pub action: Action,
    /// Firing policy for this event.
    pub policy: FirePolicy,
}

impl Event {
    /// Builds a fire-once event.
    #[must_use]
    pub fn once(id: EventId, trigger: Option<Condition>, action: Action) -> Self {
        Self {
            id,
            trigger,
            action,
            policy: FirePolicy::Once,
        }
    }

    /// Builds a repeatable event.
    #[must_use]
    pub fn repeatable(id: EventId, trigger: Option<Condition>, action: Action) -> Self {
        Self {
            id,
            trigger,
            action,
            policy: FirePolicy::Repeatable,
        }
    }
}

/// Code-first event-graph authoring surface.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EventGraphBuilder {
    events: Vec<Event>,
}

impl EventGraphBuilder {
    /// Starts declaring a new event.
    #[must_use]
    pub fn event(self, id: impl Into<String>) -> EventGraphEventBuilder {
        EventGraphEventBuilder {
            builder: self,
            id: EventId::from_name(id),
            trigger: None,
            policy: FirePolicy::Once,
        }
    }

    /// Adds an already-built event to the builder.
    #[must_use]
    pub fn push_event(mut self, event: Event) -> Self {
        self.events.push(event);
        self
    }

    /// Builds and validates the event graph with no world or assertion namespace.
    ///
    /// # Errors
    ///
    /// Returns the validation errors described by [`EventGraph::new`].
    pub fn build(self) -> Result<EventGraph, EventGraphError> {
        EventGraph::new(self.events)
    }

    /// Builds and validates the event graph with declared assertion ids.
    ///
    /// # Errors
    ///
    /// Returns the validation errors described by [`EventGraph::new_with_assertions`].
    pub fn build_with_assertions(
        self,
        assertions: impl IntoIterator<Item = AssertionId>,
    ) -> Result<EventGraph, EventGraphError> {
        EventGraph::new_with_assertions(self.events, assertions)
    }

    /// Builds and validates the event graph against a world namespace.
    ///
    /// # Errors
    ///
    /// Returns the validation errors described by [`EventGraph::new_for_world`].
    pub fn build_for_world(self, world: &World) -> Result<EventGraph, EventGraphError> {
        EventGraph::new_for_world(self.events, world)
    }

    /// Builds and validates the event graph against assertion and world namespaces.
    ///
    /// # Errors
    ///
    /// Returns the validation errors described by
    /// [`EventGraph::new_with_assertions_for_world`].
    pub fn build_with_assertions_for_world(
        self,
        assertions: impl IntoIterator<Item = AssertionId>,
        world: &World,
    ) -> Result<EventGraph, EventGraphError> {
        EventGraph::new_with_assertions_for_world(self.events, assertions, world)
    }
}

/// In-progress event declaration produced by [`EventGraphBuilder::event`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventGraphEventBuilder {
    builder: EventGraphBuilder,
    id: EventId,
    trigger: Option<Condition>,
    policy: FirePolicy,
}

impl EventGraphEventBuilder {
    /// Sets the trigger condition for this event.
    #[must_use]
    pub fn when(mut self, condition: Condition) -> Self {
        self.trigger = Some(condition);
        self
    }

    /// Marks this event as an entrypoint fired at genesis.
    #[must_use]
    pub fn entrypoint(mut self) -> Self {
        self.trigger = None;
        self
    }

    /// Sets this event's fire policy.
    #[must_use]
    pub fn policy(mut self, policy: FirePolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Marks this event as repeatable.
    #[must_use]
    pub fn repeatable(self) -> Self {
        self.policy(FirePolicy::Repeatable)
    }

    /// Marks this event as fire-once.
    #[must_use]
    pub fn once(self) -> Self {
        self.policy(FirePolicy::Once)
    }

    /// Finishes this event with its action and returns to the graph builder.
    #[must_use]
    pub fn action(mut self, action: Action) -> EventGraphBuilder {
        self.builder.events.push(Event {
            id: self.id,
            trigger: self.trigger,
            action,
            policy: self.policy,
        });
        self.builder
    }
}

fn lower_plan_entry_to_event((index, entry): (usize, &PlanEntry)) -> Event {
    match entry {
        PlanEntry::Activate { at, tag, fault } => Event::once(
            lowered_plan_event_id(index, "activate", tag),
            Some(Condition::At { at: *at }),
            Action::InjectFault {
                tag: tag.clone(),
                fault: fault.clone(),
            },
        ),
        PlanEntry::Heal { at, tag } => Event::once(
            lowered_plan_event_id(index, "heal", tag),
            Some(Condition::At { at: *at }),
            Action::HealFault { tag: tag.clone() },
        ),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FaultPlanLoweredAction {
    at: VirtualTime,
    kind: &'static str,
    kind_order: u8,
    tag: FaultTag,
    material: String,
    action: Action,
}

fn lower_fault_plan_actions(entries: &[FaultPlanEntry]) -> Vec<FaultPlanLoweredAction> {
    let mut actions = Vec::new();
    for entry in entries {
        match entry {
            FaultPlanEntry::At {
                at,
                duration,
                tag,
                fault,
            } => {
                actions.push(inject_fault_plan_action(*at, tag, fault));
                if let Some(heal_at) = at.ticks.checked_add(duration.nanos()) {
                    actions.push(heal_fault_plan_action(
                        VirtualTime { ticks: heal_at },
                        "heal",
                        tag,
                    ));
                }
            }
            FaultPlanEntry::PermanentAt { at, tag, fault } => {
                actions.push(inject_fault_plan_action(*at, tag, fault));
            }
            FaultPlanEntry::Heal { at, tag } => {
                actions.push(heal_fault_plan_action(*at, "heal", tag));
            }
        }
    }
    actions.sort_by(|left, right| {
        left.at
            .cmp(&right.at)
            .then_with(|| left.kind_order.cmp(&right.kind_order))
            .then_with(|| left.material.cmp(&right.material))
    });
    actions
}

fn inject_fault_plan_action(
    at: VirtualTime,
    tag: &FaultTag,
    fault: &Fault,
) -> FaultPlanLoweredAction {
    FaultPlanLoweredAction {
        at,
        kind: "inject",
        kind_order: 0,
        tag: tag.clone(),
        material: format!(
            "inject\n{}\n{}",
            fault_tag_sort_material(tag),
            fault.canonical_material()
        ),
        action: Action::InjectFault {
            tag: tag.clone(),
            fault: MembershipFault::taxonomy(fault.clone()),
        },
    }
}

fn heal_fault_plan_action(
    at: VirtualTime,
    kind: &'static str,
    tag: &FaultTag,
) -> FaultPlanLoweredAction {
    FaultPlanLoweredAction {
        at,
        kind,
        kind_order: 1,
        tag: tag.clone(),
        material: format!("heal\n{}", fault_tag_sort_material(tag)),
        action: Action::HealFault { tag: tag.clone() },
    }
}

fn fault_tag_sort_material(tag: &FaultTag) -> String {
    format!("tag_len={}\ntag={}", tag.name.len(), tag.name)
}

fn lower_fault_plan_action_to_event((index, action): (usize, &FaultPlanLoweredAction)) -> Event {
    Event::once(
        lowered_plan_event_id(index, action.kind, &action.tag),
        Some(Condition::At { at: action.at }),
        action.action.clone(),
    )
}

fn lowered_plan_event_id(index: usize, kind: &str, tag: &FaultTag) -> EventId {
    EventId::from_name(format!("plan:{index:016}:{kind}:{}", tag.name))
}

fn plan_evaluation_times(entries: &[PlanEntry]) -> Vec<VirtualTime> {
    entries
        .iter()
        .map(|entry| match entry {
            PlanEntry::Activate { at, .. } | PlanEntry::Heal { at, .. } => *at,
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn fault_plan_action_evaluation_times(actions: &[FaultPlanLoweredAction]) -> Vec<VirtualTime> {
    actions
        .iter()
        .map(|action| action.at)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Scenario control flow expressed as declared events.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EventGraph {
    events: Vec<Event>,
}

impl EventGraph {
    /// Starts code-first event-graph authoring.
    #[must_use]
    pub fn builder() -> EventGraphBuilder {
        EventGraphBuilder::default()
    }

    pub(crate) fn from_unchecked_events_for_model(events: Vec<Event>) -> Self {
        Self { events }
    }

    /// Builds an event graph with no declared assertion or white-box namespace.
    ///
    /// # Errors
    ///
    /// Returns [`EventGraphError::DuplicateEventId`] when two events carry the
    /// same stable id, [`EventGraphError::RepeatableEntrypoint`] when an
    /// entrypoint tries to use repeatable firing policy,
    /// [`EventGraphError::UnknownEventReference`] when an `After` predicate
    /// names no declared event, [`EventGraphError::UnknownTimerReference`] when
    /// a `Timer` predicate names no armable timer,
    /// [`EventGraphError::EmptyCompound`] when an `AllOf` or `AnyOf` predicate
    /// has no children, or [`EventGraphError::InvalidRegex`] when a console
    /// predicate has an invalid regex.
    ///
    /// This constructor has no world or assertion namespace, so it also returns
    /// [`EventGraphError::UnknownAssertionReference`] for assertion-state
    /// triggers, [`EventGraphError::GuestMarkerWithoutWhiteBoxOptIn`] for
    /// guest-marker triggers, [`EventGraphError::NodeReferenceRequiresWorld`]
    /// or [`EventGraphError::LinkReferenceRequiresWorld`] for topology-bearing
    /// references, and [`EventGraphError::NodeScheduleTargetRequiresWorld`] for
    /// `StartNode` or `StopNode`. It returns
    /// [`EventGraphError::UnknownFaultTagReference`] when a `HealFault` action
    /// or `FaultActive` predicate references a tag that no graph action injects,
    /// [`EventGraphError::NonRepeatableCycle`] for a hard dependency cycle among
    /// non-repeatable events, or
    /// [`EventGraphError::UnreachableEvent`] when an event cannot be reached
    /// from an entrypoint.
    pub fn new(events: Vec<Event>) -> Result<Self, EventGraphError> {
        Self::new_with_assertions_and_world(events, [], None)
    }

    /// Builds an event graph with declared assertion ids available to triggers.
    ///
    /// # Errors
    ///
    /// Returns the common event-id, trigger-reference, assertion-reference,
    /// compound, regex, fault-tag, cycle, and reachability errors described on
    /// [`Self::new`]. Because this constructor has no world namespace, it also
    /// returns [`EventGraphError::GuestMarkerWithoutWhiteBoxOptIn`] for
    /// guest-marker triggers, [`EventGraphError::NodeReferenceRequiresWorld`] or
    /// [`EventGraphError::LinkReferenceRequiresWorld`] for topology-bearing
    /// references, and [`EventGraphError::NodeScheduleTargetRequiresWorld`] when
    /// `StartNode` or `StopNode` is present.
    pub fn new_with_assertions(
        events: Vec<Event>,
        assertions: impl IntoIterator<Item = AssertionId>,
    ) -> Result<Self, EventGraphError> {
        Self::new_with_assertions_and_world(events, assertions, None)
    }

    /// Builds an event graph using white-box opt-in data from `world`.
    ///
    /// # Errors
    ///
    /// Returns the common event-id, trigger-reference, assertion-reference,
    /// compound, regex, fault-tag, cycle, and reachability errors described on
    /// [`Self::new`]. It also returns
    /// [`EventGraphError::GuestMarkerWithoutWhiteBoxOptIn`] when a guest-marker
    /// trigger is present but `world` has no white-box-enabled node,
    /// [`EventGraphError::UnknownNodeReference`] or
    /// [`EventGraphError::UnknownLinkReference`] for topology-bearing
    /// references outside `world`, [`EventGraphError::UndeclaredNodeScheduleTarget`]
    /// when `StartNode` or `StopNode` references a node outside `world`, or
    /// [`EventGraphError::UnbakedNodeScheduleTarget`] when that action references
    /// a declared node outside the world's bake set.
    pub fn new_for_world(events: Vec<Event>, world: &World) -> Result<Self, EventGraphError> {
        Self::new_with_assertions_and_world(events, [], Some(world))
    }

    /// Builds an event graph using assertion and white-box data from `world`.
    ///
    /// # Errors
    ///
    /// Returns the common event-id, trigger-reference, assertion-reference,
    /// compound, regex, fault-tag, cycle, and reachability errors described on
    /// [`Self::new`]. It also returns
    /// [`EventGraphError::GuestMarkerWithoutWhiteBoxOptIn`] when a guest-marker
    /// trigger is present but `world` has no white-box-enabled node,
    /// [`EventGraphError::UnknownNodeReference`] or
    /// [`EventGraphError::UnknownLinkReference`] for topology-bearing
    /// references outside `world`, [`EventGraphError::UndeclaredNodeScheduleTarget`]
    /// when `StartNode` or `StopNode` references a node outside `world`, or
    /// [`EventGraphError::UnbakedNodeScheduleTarget`] when that action references
    /// a declared node outside the world's bake set.
    pub fn new_with_assertions_for_world(
        events: Vec<Event>,
        assertions: impl IntoIterator<Item = AssertionId>,
        world: &World,
    ) -> Result<Self, EventGraphError> {
        Self::new_with_assertions_and_world(events, assertions, Some(world))
    }

    fn new_with_assertions_and_world(
        events: Vec<Event>,
        assertions: impl IntoIterator<Item = AssertionId>,
        world: Option<&World>,
    ) -> Result<Self, EventGraphError> {
        let assertion_ids = assertions.into_iter().collect::<BTreeSet<_>>();
        let white_box_nodes = world
            .map(enabled_white_box_nodes)
            .unwrap_or_default()
            .into_iter()
            .collect::<BTreeSet<_>>();
        let static_topology = world.map(World::static_topology);
        let topology = world.map(EventGraphTopology::from_world);
        let mut seen = BTreeSet::new();
        for event in &events {
            if !seen.insert(event.id.clone()) {
                return Err(EventGraphError::DuplicateEventId {
                    event: event.id.clone(),
                });
            }
            if event.trigger.is_none() && event.policy == FirePolicy::Repeatable {
                return Err(EventGraphError::RepeatableEntrypoint {
                    event: event.id.clone(),
                });
            }
        }
        let timer_names = armed_timer_names(&events);
        let injected_tags = injected_fault_tags(&events);
        for event in &events {
            if let Some(condition) = &event.trigger {
                validate_condition_references(
                    event,
                    condition,
                    &seen,
                    &timer_names,
                    &assertion_ids,
                    &white_box_nodes,
                    &injected_tags,
                    topology.as_ref(),
                )?;
            }
            validate_action_references(
                event,
                &event.action,
                static_topology.as_ref(),
                topology.as_ref(),
                &injected_tags,
            )?;
        }
        validate_event_graph_dependencies(&events, &timer_names)?;
        Ok(Self { events })
    }

    /// Returns the events in declared deterministic order.
    #[must_use]
    pub fn events(&self) -> &[Event] {
        &self.events
    }

    /// Returns whether the graph contains no events.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

/// A deterministic point where event triggers are evaluated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EventEvaluationPoint {
    at: VirtualTime,
    kind: EventEvaluationKind,
}

impl EventEvaluationPoint {
    /// Returns the genesis evaluation point.
    #[must_use]
    pub const fn genesis() -> Self {
        Self {
            at: VirtualTime { ticks: 0 },
            kind: EventEvaluationKind::Genesis,
        }
    }

    /// Returns a deterministic event-log-entry boundary.
    #[must_use]
    pub(crate) const fn event_boundary(at: VirtualTime) -> Self {
        Self {
            at,
            kind: EventEvaluationKind::EventBoundary,
        }
    }

    /// Returns a deterministic event-log-entry boundary for `entry`.
    #[must_use]
    pub fn event_log_entry(entry: &SchedulerEventLogEntry) -> Self {
        match entry.payload() {
            SchedulerEventLogPayload::EvaluationBoundary(
                SchedulerEvaluationBoundaryKind::Quantum,
            ) => Self::quantum_boundary(entry.at()),
            SchedulerEventLogPayload::EvaluationBoundary(
                SchedulerEvaluationBoundaryKind::Rendezvous,
            ) => Self::rendezvous_boundary(entry.at()),
            _ => Self::event_boundary(entry.at()),
        }
    }

    /// Returns a deterministic quantum boundary.
    #[must_use]
    pub(crate) const fn quantum_boundary(at: VirtualTime) -> Self {
        Self {
            at,
            kind: EventEvaluationKind::QuantumBoundary,
        }
    }

    /// Returns a deterministic rendezvous boundary.
    #[must_use]
    pub(crate) const fn rendezvous_boundary(at: VirtualTime) -> Self {
        Self {
            at,
            kind: EventEvaluationKind::RendezvousBoundary,
        }
    }

    pub(crate) const fn assertion_deadline(at: VirtualTime) -> Self {
        Self {
            at,
            kind: EventEvaluationKind::AssertionDeadline,
        }
    }

    /// Returns the virtual time of the evaluation point.
    #[must_use]
    pub fn at(self) -> VirtualTime {
        self.at
    }

    /// Returns whether this is the genesis entrypoint evaluation.
    #[must_use]
    pub fn kind(self) -> EventEvaluationKind {
        self.kind
    }
}

/// Kind of deterministic evaluation point.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EventEvaluationKind {
    /// The run-start genesis point; entrypoint events fire here.
    Genesis,
    /// A deterministic boundary produced by an event-log entry.
    EventBoundary,
    /// A deterministic scheduler quantum boundary.
    QuantumBoundary,
    /// A deterministic scheduler rendezvous boundary.
    RendezvousBoundary,
    /// A synthetic assertion deadline point derived from pending obligations.
    AssertionDeadline,
}

/// One action fired by the event graph at an evaluation point.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EventFiring {
    event: EventId,
    at: VirtualTime,
    condition_summary: String,
    action: Action,
}

/// Ordered trigger firings computed by one deterministic evaluation pass.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EventFirings {
    point: EventEvaluationPoint,
    event_log_offset: EventLogOffset,
    timer_fires: BTreeMap<TimerId, VirtualTime>,
    firings: Vec<EventFiring>,
}

impl EventFirings {
    pub(crate) fn new(
        point: EventEvaluationPoint,
        event_log_offset: EventLogOffset,
        timer_fires: BTreeMap<TimerId, VirtualTime>,
        firings: Vec<EventFiring>,
    ) -> Self {
        Self {
            point,
            event_log_offset,
            timer_fires,
            firings,
        }
    }

    /// Returns the deterministic point where these firings were computed.
    #[must_use]
    pub fn point(&self) -> EventEvaluationPoint {
        self.point
    }

    /// Returns the event-log prefix identity where these firings were computed.
    #[must_use]
    pub fn event_log_offset(&self) -> EventLogOffset {
        self.event_log_offset
    }

    /// Returns the timer-fire map visible when these firings were computed.
    #[must_use]
    pub fn timer_fires(&self) -> &BTreeMap<TimerId, VirtualTime> {
        &self.timer_fires
    }

    /// Returns the number of firings in the ordered batch.
    #[must_use]
    pub fn len(&self) -> usize {
        self.firings.len()
    }

    /// Returns whether no trigger fired in this pass.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.firings.is_empty()
    }

    /// Returns the ordered firings as a read-only slice.
    #[must_use]
    pub fn as_slice(&self) -> &[EventFiring] {
        &self.firings
    }

    /// Iterates over the ordered firings.
    pub fn iter(&self) -> std::slice::Iter<'_, EventFiring> {
        self.firings.iter()
    }
}

impl Deref for EventFirings {
    type Target = [EventFiring];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl EventFiring {
    /// Returns the event that fired.
    #[must_use]
    pub fn event(&self) -> &EventId {
        &self.event
    }

    /// Returns the virtual time where the event fired.
    #[must_use]
    pub fn at(&self) -> VirtualTime {
        self.at
    }

    /// Returns the action emitted by the event.
    #[must_use]
    pub fn action(&self) -> &Action {
        &self.action
    }

    /// Returns the stable condition summary recorded with the firing.
    #[must_use]
    pub fn condition_summary(&self) -> &str {
        &self.condition_summary
    }
}

/// Stateful event-graph evaluator.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EventGraphState {
    consumed_once: BTreeSet<EventId>,
    previous_truth: BTreeMap<EventId, bool>,
    last_firing: BTreeMap<EventId, VirtualTime>,
    once_latches: Vec<Condition>,
}

impl EventGraphState {
    /// Builds a fresh event-graph state with no prior firings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the last firing time for an event, when that event has fired.
    #[must_use]
    pub fn last_firing(&self, event: &EventId) -> Option<VirtualTime> {
        self.last_firing.get(event).copied()
    }

    /// Evaluates every event in declared order and returns fired actions.
    ///
    /// `evaluator` is the deterministic predicate evaluator for non-entrypoint
    /// conditions. This method is the single local producer of [`EventFiring`]
    /// values; callers apply the returned actions at the same quantum boundary.
    pub(crate) fn evaluate<E>(&mut self, graph: &EventGraph, evaluator: &mut E) -> EventFirings
    where
        E: ConditionEvaluator,
    {
        let mut firings = Vec::new();
        let point = evaluator.evaluation_point();
        let event_log_offset = evaluator.event_log_offset();
        let timer_fires = evaluator.timer_fires();
        for event in graph.events() {
            let truth = match &event.trigger {
                Some(condition) => {
                    let mut graph_evaluator = EventGraphConditionEvaluator {
                        state: self,
                        inner: evaluator,
                    };
                    evaluate_condition(&mut graph_evaluator, condition)
                }
                None => point.kind() == EventEvaluationKind::Genesis,
            };
            let previously_true = self
                .previous_truth
                .insert(event.id.clone(), truth)
                .unwrap_or(false);
            let should_fire = match event.policy {
                FirePolicy::Once => truth && !self.consumed_once.contains(&event.id),
                FirePolicy::Repeatable => truth && !previously_true,
            };
            if should_fire {
                if event.policy == FirePolicy::Once {
                    self.consumed_once.insert(event.id.clone());
                }
                firings.push(EventFiring {
                    event: event.id.clone(),
                    at: point.at(),
                    condition_summary: event
                        .trigger
                        .as_ref()
                        .map_or_else(|| String::from("entrypoint"), Condition::canonical_summary),
                    action: event.action.clone(),
                });
                self.last_firing.insert(event.id.clone(), point.at());
            }
        }
        EventFirings::new(point, event_log_offset, timer_fires, firings)
    }
}

struct EventGraphConditionEvaluator<'state, 'inner, E> {
    state: &'state mut EventGraphState,
    inner: &'inner mut E,
}

impl<E> condition_evaluator_sealed::Sealed for EventGraphConditionEvaluator<'_, '_, E> where
    E: ConditionEvaluator
{
}

impl<E> ConditionEvaluator for EventGraphConditionEvaluator<'_, '_, E>
where
    E: ConditionEvaluator,
{
    fn evaluation_point(&self) -> EventEvaluationPoint {
        self.inner.evaluation_point()
    }

    fn event_log_offset(&self) -> EventLogOffset {
        self.inner.event_log_offset()
    }

    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        self.inner.leaf_is_true(leaf)
    }

    fn last_event_firing(&self, event: &EventId) -> Option<VirtualTime> {
        self.state
            .last_firing(event)
            .or_else(|| self.inner.last_event_firing(event))
    }

    fn timer_fire_time(&self, timer: &TimerId) -> Option<VirtualTime> {
        self.inner.timer_fire_time(timer)
    }

    fn timer_fires(&self) -> BTreeMap<TimerId, VirtualTime> {
        self.inner.timer_fires()
    }

    fn observable_events(&self) -> &[ObservableEvent] {
        self.inner.observable_events()
    }

    fn scheduler_quiescence(&self) -> Option<&SchedulerQuiescence> {
        self.inner.scheduler_quiescence()
    }

    fn fault_facts(&self) -> &[ObservedFaultFact] {
        self.inner.fault_facts()
    }

    fn white_box_policy_for_node(&self, node: &NodeId) -> Option<WhiteBoxPolicy> {
        self.inner.white_box_policy_for_node(node)
    }

    fn once_condition_is_latched(&self, condition: &Condition) -> bool {
        self.state
            .once_latches
            .iter()
            .any(|latched| latched == condition)
    }

    fn latch_once_condition(&mut self, condition: &Condition) {
        if !self
            .state
            .once_latches
            .iter()
            .any(|latched| latched == condition)
        {
            self.state.once_latches.push(condition.clone());
        }
    }

    fn resolve_code_point(&self, node: &NodeId, point: &CodePoint) -> Option<ResolvedCodePoint> {
        self.inner.resolve_code_point(node, point)
    }

    fn resolve_mem_place(&self, node: &NodeId, place: &MemPlace) -> Option<ResolvedMemPlace> {
        self.inner.resolve_mem_place(node, place)
    }
}

/// Event graph construction errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventGraphError {
    /// Two events declared the same stable id.
    DuplicateEventId {
        /// Duplicated event id.
        event: EventId,
    },
    /// An entrypoint attempted to fire more than once.
    RepeatableEntrypoint {
        /// Invalid entrypoint event id.
        event: EventId,
    },
    /// An `After` predicate references no declared event.
    UnknownEventReference {
        /// Event containing the invalid reference.
        event: EventId,
        /// Referenced event id.
        reference: EventId,
    },
    /// A `Timer` predicate references no timer that can be armed.
    UnknownTimerReference {
        /// Event containing the invalid timer reference.
        event: EventId,
        /// Referenced timer id.
        timer: TimerId,
    },
    /// An `AssertionState` predicate references no declared assertion.
    UnknownAssertionReference {
        /// Event containing the invalid assertion reference.
        event: EventId,
        /// Referenced assertion id.
        assertion: AssertionId,
    },
    /// An `AllOf` or `AnyOf` predicate has no children.
    EmptyCompound {
        /// Event containing the empty compound.
        event: EventId,
        /// Stable compound predicate kind.
        kind: &'static str,
    },
    /// A `GuestMarker` trigger was used without any white-box-enabled node.
    GuestMarkerWithoutWhiteBoxOptIn {
        /// Event containing the guest-marker trigger.
        event: EventId,
        /// Referenced guest marker.
        marker: MarkerId,
    },
    /// A topology-bearing node reference was used without a world.
    NodeReferenceRequiresWorld {
        /// Event containing the invalid reference.
        event: EventId,
        /// Referenced node id.
        node: NodeId,
    },
    /// A topology-bearing link reference was used without a world.
    LinkReferenceRequiresWorld {
        /// Event containing the invalid reference.
        event: EventId,
        /// Referenced link id.
        link: LinkId,
    },
    /// A topology-bearing node reference names no world participant.
    UnknownNodeReference {
        /// Event containing the invalid reference.
        event: EventId,
        /// Referenced node id.
        node: NodeId,
    },
    /// A topology-bearing link reference names no world link.
    UnknownLinkReference {
        /// Event containing the invalid reference.
        event: EventId,
        /// Referenced link id.
        link: LinkId,
    },
    /// A topology-bearing device reference names no declared world device.
    UnknownDeviceReference {
        /// Event containing the invalid reference.
        event: EventId,
        /// Referenced device id.
        device: DeviceId,
    },
    /// A `StartNode` or `StopNode` action was used without a world.
    NodeScheduleTargetRequiresWorld {
        /// Event containing the invalid action.
        event: EventId,
        /// Referenced node id.
        node: NodeId,
    },
    /// A `StartNode` or `StopNode` action references no world participant.
    UndeclaredNodeScheduleTarget {
        /// Event containing the invalid action.
        event: EventId,
        /// Referenced node id.
        node: NodeId,
    },
    /// A `StartNode` or `StopNode` action references no baked node.
    UnbakedNodeScheduleTarget {
        /// Event containing the invalid action.
        event: EventId,
        /// Referenced node id.
        node: NodeId,
    },
    /// A `HealFault` action or `FaultActive` predicate references no injected tag.
    UnknownFaultTagReference {
        /// Event containing the invalid fault tag reference.
        event: EventId,
        /// Referenced fault tag.
        tag: FaultTag,
    },
    /// Non-repeatable events contain a dependency cycle.
    NonRepeatableCycle {
        /// Participating event ids in deterministic DFS order.
        events: Vec<EventId>,
    },
    /// An event cannot be reached from any graph entrypoint.
    UnreachableEvent {
        /// Unreachable event id.
        event: EventId,
    },
    /// A console-match predicate contains an invalid regex program.
    InvalidRegex {
        /// Event containing the invalid regex.
        event: EventId,
        /// Regex pattern that failed validation.
        pattern: String,
        /// Stable validation failure text from the regex compiler.
        reason: String,
    },
}

impl fmt::Display for EventGraphError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateEventId { event } => {
                write!(
                    formatter,
                    "event graph contains duplicate event `{}`",
                    event.name
                )
            }
            Self::RepeatableEntrypoint { event } => {
                write!(
                    formatter,
                    "event graph entrypoint `{}` cannot be repeatable",
                    event.name
                )
            }
            Self::UnknownEventReference { event, reference } => {
                write!(
                    formatter,
                    "event `{}` references unknown event `{}`",
                    event.name, reference.name
                )
            }
            Self::UnknownTimerReference { event, timer } => {
                write!(
                    formatter,
                    "event `{}` references unknown timer `{}`",
                    event.name, timer.name
                )
            }
            Self::UnknownAssertionReference { event, assertion } => {
                write!(
                    formatter,
                    "event `{}` references unknown assertion `{}`",
                    event.name, assertion.name
                )
            }
            Self::EmptyCompound { event, kind } => {
                write!(
                    formatter,
                    "event `{}` contains empty compound predicate `{kind}`",
                    event.name
                )
            }
            Self::GuestMarkerWithoutWhiteBoxOptIn { event, marker } => {
                write!(
                    formatter,
                    "event `{}` uses guest marker `{}` without a white-box-enabled node",
                    event.name, marker.name
                )
            }
            Self::NodeReferenceRequiresWorld { event, node } => {
                write!(
                    formatter,
                    "event `{}` references node `{}` without a world",
                    event.name, node.name
                )
            }
            Self::LinkReferenceRequiresWorld { event, link } => {
                write!(
                    formatter,
                    "event `{}` references link `{}` without a world",
                    event.name, link.name
                )
            }
            Self::UnknownNodeReference { event, node } => {
                write!(
                    formatter,
                    "event `{}` references unknown node `{}`",
                    event.name, node.name
                )
            }
            Self::UnknownLinkReference { event, link } => {
                write!(
                    formatter,
                    "event `{}` references unknown link `{}`",
                    event.name, link.name
                )
            }
            Self::UnknownDeviceReference { event, device } => {
                write!(
                    formatter,
                    "event `{}` references unknown device `{}`",
                    event.name, device.name
                )
            }
            Self::NodeScheduleTargetRequiresWorld { event, node } => {
                write!(
                    formatter,
                    "event `{}` schedules node `{}` without a world",
                    event.name, node.name
                )
            }
            Self::UndeclaredNodeScheduleTarget { event, node } => {
                write!(
                    formatter,
                    "event `{}` schedules undeclared node `{}`",
                    event.name, node.name
                )
            }
            Self::UnbakedNodeScheduleTarget { event, node } => {
                write!(
                    formatter,
                    "event `{}` schedules unbaked node `{}`",
                    event.name, node.name
                )
            }
            Self::UnknownFaultTagReference { event, tag } => {
                write!(
                    formatter,
                    "event `{}` references unknown fault tag `{}`",
                    event.name, tag.name
                )
            }
            Self::NonRepeatableCycle { events } => {
                let names = events
                    .iter()
                    .map(|event| event.name.as_str())
                    .collect::<Vec<_>>()
                    .join(" -> ");
                write!(
                    formatter,
                    "event graph contains non-repeatable dependency cycle `{names}`"
                )
            }
            Self::UnreachableEvent { event } => {
                write!(formatter, "event `{}` is unreachable", event.name)
            }
            Self::InvalidRegex { event, reason, .. } => {
                write!(
                    formatter,
                    "event `{}` has invalid regex: {reason}",
                    event.name
                )
            }
        }
    }
}

impl Error for EventGraphError {}

#[derive(Clone, Debug)]
struct EventGraphTopology {
    nodes: BTreeSet<NodeId>,
    links: BTreeSet<LinkId>,
}

impl EventGraphTopology {
    fn from_world(world: &World) -> Self {
        Self {
            nodes: world
                .static_topology()
                .participants
                .into_iter()
                .collect::<BTreeSet<_>>(),
            links: event_graph_link_ids(world.links()),
        }
    }
}

fn event_graph_link_ids(links: &[LinkDef]) -> BTreeSet<LinkId> {
    let mut ids = BTreeSet::new();
    for link in links {
        ids.insert(canonical_link_id_for_world_link(link));
        ids.insert(legacy_link_id_for_world_link(link));
    }
    ids
}

fn canonical_link_id_for_world_link(link: &LinkDef) -> LinkId {
    let (endpoint_a, endpoint_b) = link.endpoints();
    LinkId::from_name(format!(
        "link_endpoint_a_len={}\nlink_endpoint_a={}\nlink_endpoint_b_len={}\nlink_endpoint_b={}",
        endpoint_a.name.len(),
        endpoint_a.name,
        endpoint_b.name.len(),
        endpoint_b.name
    ))
}

fn legacy_link_id_for_world_link(link: &LinkDef) -> LinkId {
    let (endpoint_a, endpoint_b) = link.endpoints();
    LinkId::from_name(format!("{}--{}", endpoint_a.name, endpoint_b.name))
}

fn link_id_for_endpoint_pair(left: &NodeId, right: &NodeId) -> LinkId {
    let (endpoint_a, endpoint_b) = if left <= right {
        (left, right)
    } else {
        (right, left)
    };
    LinkId::from_name(format!(
        "link_endpoint_a_len={}\nlink_endpoint_a={}\nlink_endpoint_b_len={}\nlink_endpoint_b={}",
        endpoint_a.name.len(),
        endpoint_a.name,
        endpoint_b.name.len(),
        endpoint_b.name
    ))
}

fn armed_timer_names(events: &[Event]) -> BTreeSet<TimerId> {
    let mut timers = BTreeSet::new();
    for event in events {
        collect_timer_names(&event.action, &mut timers);
    }
    timers
}

fn collect_timer_names(action: &Action, timers: &mut BTreeSet<TimerId>) {
    match action {
        Action::ArmTimer { name, .. } => {
            timers.insert(name.clone());
        }
        Action::Group(actions) => {
            for action in actions {
                collect_timer_names(action, timers);
            }
        }
        Action::InjectFault { .. }
        | Action::HealFault { .. }
        | Action::CancelTimer { .. }
        | Action::StartNode { .. }
        | Action::StopNode { .. }
        | Action::CreateSavepoint { .. }
        | Action::Fork { .. }
        | Action::Pass
        | Action::Fail { .. }
        | Action::Log { .. } => {}
    }
}

fn injected_fault_tags(events: &[Event]) -> BTreeSet<FaultTag> {
    let mut tags = BTreeSet::new();
    for event in events {
        collect_injected_fault_tags(&event.action, &mut tags);
    }
    tags
}

fn collect_injected_fault_tags(action: &Action, tags: &mut BTreeSet<FaultTag>) {
    match action {
        Action::InjectFault { tag, .. } => {
            tags.insert(tag.clone());
        }
        Action::Group(actions) => {
            for action in actions {
                collect_injected_fault_tags(action, tags);
            }
        }
        Action::HealFault { .. }
        | Action::ArmTimer { .. }
        | Action::CancelTimer { .. }
        | Action::StartNode { .. }
        | Action::StopNode { .. }
        | Action::CreateSavepoint { .. }
        | Action::Fork { .. }
        | Action::Pass
        | Action::Fail { .. }
        | Action::Log { .. } => {}
    }
}

fn validate_action_references(
    event: &Event,
    action: &Action,
    static_topology: Option<&WorldStaticTopology>,
    topology: Option<&EventGraphTopology>,
    injected_tags: &BTreeSet<FaultTag>,
) -> Result<(), EventGraphError> {
    match action {
        Action::InjectFault { fault, .. } => {
            validate_membership_fault_reference(event, fault, topology)
        }
        Action::HealFault { tag } => {
            if injected_tags.contains(tag) {
                Ok(())
            } else {
                Err(EventGraphError::UnknownFaultTagReference {
                    event: event.id.clone(),
                    tag: tag.clone(),
                })
            }
        }
        Action::StartNode { node } | Action::StopNode { node } => {
            let Some(static_topology) = static_topology else {
                return Err(EventGraphError::NodeScheduleTargetRequiresWorld {
                    event: event.id.clone(),
                    node: node.clone(),
                });
            };
            if !static_topology.participants.contains(node) {
                return Err(EventGraphError::UndeclaredNodeScheduleTarget {
                    event: event.id.clone(),
                    node: node.clone(),
                });
            }
            if !static_topology.bake_nodes.contains(node) {
                return Err(EventGraphError::UnbakedNodeScheduleTarget {
                    event: event.id.clone(),
                    node: node.clone(),
                });
            }
            Ok(())
        }
        Action::Group(actions) => {
            for action in actions {
                validate_action_references(
                    event,
                    action,
                    static_topology,
                    topology,
                    injected_tags,
                )?;
            }
            Ok(())
        }
        Action::ArmTimer { .. }
        | Action::CancelTimer { .. }
        | Action::CreateSavepoint { .. }
        | Action::Fork { .. }
        | Action::Pass
        | Action::Fail { .. }
        | Action::Log { .. } => Ok(()),
    }
}

fn validate_membership_fault_reference(
    event: &Event,
    fault: &MembershipFault,
    topology: Option<&EventGraphTopology>,
) -> Result<(), EventGraphError> {
    match fault {
        MembershipFault::Crash { node, .. }
        | MembershipFault::Isolate { node }
        | MembershipFault::NotYetJoined { node } => validate_node_reference(event, node, topology),
        MembershipFault::Partition {
            endpoint_a,
            endpoint_b,
            ..
        } => {
            validate_node_reference(event, endpoint_a, topology)?;
            validate_node_reference(event, endpoint_b, topology)?;
            validate_link_reference(
                event,
                &link_id_for_endpoint_pair(endpoint_a, endpoint_b),
                topology,
            )
        }
        MembershipFault::Taxonomy { fault } => {
            validate_taxonomy_fault_reference(event, fault, topology)
        }
    }
}

fn validate_taxonomy_fault_reference(
    event: &Event,
    fault: &Fault,
    topology: Option<&EventGraphTopology>,
) -> Result<(), EventGraphError> {
    match fault {
        Fault::Network(fault) => validate_network_fault_reference(event, fault, topology),
        Fault::Node(fault) => validate_node_fault_reference(event, fault, topology),
        Fault::Block(fault) => Err(EventGraphError::UnknownDeviceReference {
            event: event.id.clone(),
            device: block_fault_device(fault).clone(),
        }),
        Fault::NineP(fault) => Err(EventGraphError::UnknownDeviceReference {
            event: event.id.clone(),
            device: ninep_fault_device(fault).clone(),
        }),
    }
}

fn validate_network_fault_reference(
    event: &Event,
    fault: &NetworkFault,
    topology: Option<&EventGraphTopology>,
) -> Result<(), EventGraphError> {
    validate_link_reference(event, network_fault_link(fault), topology)
}

fn validate_node_fault_reference(
    event: &Event,
    fault: &NodeFault,
    topology: Option<&EventGraphTopology>,
) -> Result<(), EventGraphError> {
    validate_node_reference(event, node_fault_node(fault), topology)
}

fn network_fault_link(fault: &NetworkFault) -> &LinkId {
    match fault {
        NetworkFault::Partition { link, .. }
        | NetworkFault::Loss { link, .. }
        | NetworkFault::Reorder { link, .. }
        | NetworkFault::Duplicate { link, .. }
        | NetworkFault::Corruption { link, .. }
        | NetworkFault::Bandwidth { link, .. }
        | NetworkFault::LatencyBump { link, .. } => link,
    }
}

fn node_fault_node(fault: &NodeFault) -> &NodeId {
    match fault {
        NodeFault::Crash { node, .. }
        | NodeFault::Slow { node, .. }
        | NodeFault::ClockSkew { node, .. } => node,
    }
}

fn block_fault_device(fault: &BlockFault) -> &DeviceId {
    match fault {
        BlockFault::Latency { device, .. }
        | BlockFault::Failure { device, .. }
        | BlockFault::Reorder { device, .. }
        | BlockFault::Duplicate { device, .. }
        | BlockFault::Corruption { device, .. }
        | BlockFault::Bandwidth { device, .. } => device,
    }
}

fn ninep_fault_device(fault: &NinePFault) -> &DeviceId {
    match fault {
        NinePFault::Latency { device, .. }
        | NinePFault::Failure { device, .. }
        | NinePFault::Reorder { device, .. }
        | NinePFault::Duplicate { device, .. }
        | NinePFault::Corruption { device, .. }
        | NinePFault::Bandwidth { device, .. } => device,
    }
}

fn enabled_white_box_nodes(world: &World) -> BTreeSet<NodeId> {
    world
        .nodes()
        .iter()
        .filter(|node| node.white_box == WhiteBoxPolicy::Enabled)
        .map(|node| node.id.clone())
        .collect()
}

// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::too_many_arguments)]
fn validate_condition_references(
    event: &Event,
    condition: &Condition,
    event_ids: &BTreeSet<EventId>,
    timer_names: &BTreeSet<TimerId>,
    assertion_ids: &BTreeSet<AssertionId>,
    white_box_nodes: &BTreeSet<NodeId>,
    injected_tags: &BTreeSet<FaultTag>,
    topology: Option<&EventGraphTopology>,
) -> Result<(), EventGraphError> {
    match condition {
        Condition::After { of, .. } => {
            if event_ids.contains(of) {
                Ok(())
            } else {
                Err(EventGraphError::UnknownEventReference {
                    event: event.id.clone(),
                    reference: of.clone(),
                })
            }
        }
        Condition::Timer { name } => {
            if timer_names.contains(name) {
                Ok(())
            } else {
                Err(EventGraphError::UnknownTimerReference {
                    event: event.id.clone(),
                    timer: name.clone(),
                })
            }
        }
        Condition::NetworkMatch { link, .. } => match link {
            Some(link) => validate_link_reference(event, link, topology),
            None => Ok(()),
        },
        Condition::ConsoleMatch { node, regex } => {
            validate_node_reference(event, node, topology)?;
            validate_condition_regex(event, regex)
        }
        Condition::CoveragePoint { node, .. }
        | Condition::MemoryPredicate { node, .. }
        | Condition::IoPattern { node, .. }
        | Condition::NodeState { node, .. } => validate_node_reference(event, node, topology),
        Condition::Named { nodes, .. } => {
            for node in nodes {
                validate_node_reference(event, node, topology)?;
            }
            Ok(())
        }
        Condition::AssertionState { name, .. } => {
            if assertion_ids.contains(name) {
                Ok(())
            } else {
                Err(EventGraphError::UnknownAssertionReference {
                    event: event.id.clone(),
                    assertion: name.clone(),
                })
            }
        }
        Condition::FaultActive { tag } => {
            if injected_tags.contains(tag) {
                Ok(())
            } else {
                Err(EventGraphError::UnknownFaultTagReference {
                    event: event.id.clone(),
                    tag: tag.clone(),
                })
            }
        }
        Condition::GuestMarker { marker } => {
            if white_box_nodes.is_empty() {
                Err(EventGraphError::GuestMarkerWithoutWhiteBoxOptIn {
                    event: event.id.clone(),
                    marker: marker.clone(),
                })
            } else {
                Ok(())
            }
        }
        Condition::AllOf { predicates } => validate_compound_condition_references(
            event,
            "all-of",
            predicates,
            event_ids,
            timer_names,
            assertion_ids,
            white_box_nodes,
            injected_tags,
            topology,
        ),
        Condition::AnyOf { predicates } => validate_compound_condition_references(
            event,
            "any-of",
            predicates,
            event_ids,
            timer_names,
            assertion_ids,
            white_box_nodes,
            injected_tags,
            topology,
        ),
        Condition::Once { predicate } | Condition::Not { predicate } => {
            validate_condition_references(
                event,
                predicate,
                event_ids,
                timer_names,
                assertion_ids,
                white_box_nodes,
                injected_tags,
                topology,
            )
        }
        Condition::At { .. } | Condition::Quiescent => Ok(()),
    }
}

// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::too_many_arguments)]
fn validate_compound_condition_references(
    event: &Event,
    kind: &'static str,
    predicates: &[Condition],
    event_ids: &BTreeSet<EventId>,
    timer_names: &BTreeSet<TimerId>,
    assertion_ids: &BTreeSet<AssertionId>,
    white_box_nodes: &BTreeSet<NodeId>,
    injected_tags: &BTreeSet<FaultTag>,
    topology: Option<&EventGraphTopology>,
) -> Result<(), EventGraphError> {
    if predicates.is_empty() {
        return Err(EventGraphError::EmptyCompound {
            event: event.id.clone(),
            kind,
        });
    }

    for predicate in predicates {
        validate_condition_references(
            event,
            predicate,
            event_ids,
            timer_names,
            assertion_ids,
            white_box_nodes,
            injected_tags,
            topology,
        )?;
    }

    Ok(())
}

fn validate_node_reference(
    event: &Event,
    node: &NodeId,
    topology: Option<&EventGraphTopology>,
) -> Result<(), EventGraphError> {
    let Some(topology) = topology else {
        return Err(EventGraphError::NodeReferenceRequiresWorld {
            event: event.id.clone(),
            node: node.clone(),
        });
    };
    if topology.nodes.contains(node) {
        Ok(())
    } else {
        Err(EventGraphError::UnknownNodeReference {
            event: event.id.clone(),
            node: node.clone(),
        })
    }
}

fn validate_link_reference(
    event: &Event,
    link: &LinkId,
    topology: Option<&EventGraphTopology>,
) -> Result<(), EventGraphError> {
    let Some(topology) = topology else {
        return Err(EventGraphError::LinkReferenceRequiresWorld {
            event: event.id.clone(),
            link: link.clone(),
        });
    };
    if topology.links.contains(link) {
        Ok(())
    } else {
        Err(EventGraphError::UnknownLinkReference {
            event: event.id.clone(),
            link: link.clone(),
        })
    }
}

fn validate_condition_regex(event: &Event, regex: &RegexProgram) -> Result<(), EventGraphError> {
    regex::bytes::Regex::new(&regex.pattern)
        .map(|_| ())
        .map_err(|source| EventGraphError::InvalidRegex {
            event: event.id.clone(),
            pattern: regex.pattern.clone(),
            reason: source.to_string(),
        })
}

fn validate_event_graph_dependencies(
    events: &[Event],
    timer_names: &BTreeSet<TimerId>,
) -> Result<(), EventGraphError> {
    let armers = timer_armers(events);
    validate_non_repeatable_cycles(events, &armers)?;
    validate_event_reachability(events, timer_names, &armers)
}

fn timer_armers(events: &[Event]) -> BTreeMap<TimerId, BTreeSet<EventId>> {
    let mut armers = BTreeMap::new();
    for event in events {
        collect_timer_armers(&event.action, &event.id, &mut armers);
    }
    armers
}

fn collect_timer_armers(
    action: &Action,
    event: &EventId,
    armers: &mut BTreeMap<TimerId, BTreeSet<EventId>>,
) {
    match action {
        Action::ArmTimer { name, .. } => {
            armers
                .entry(name.clone())
                .or_default()
                .insert(event.clone());
        }
        Action::Group(actions) => {
            for action in actions {
                collect_timer_armers(action, event, armers);
            }
        }
        Action::InjectFault { .. }
        | Action::HealFault { .. }
        | Action::CancelTimer { .. }
        | Action::StartNode { .. }
        | Action::StopNode { .. }
        | Action::CreateSavepoint { .. }
        | Action::Fork { .. }
        | Action::Pass
        | Action::Fail { .. }
        | Action::Log { .. } => {}
    }
}

fn validate_non_repeatable_cycles(
    events: &[Event],
    armers: &BTreeMap<TimerId, BTreeSet<EventId>>,
) -> Result<(), EventGraphError> {
    let policies = events
        .iter()
        .map(|event| (event.id.clone(), event.policy))
        .collect::<BTreeMap<_, _>>();
    let mut graph = BTreeMap::<EventId, BTreeSet<EventId>>::new();
    for event in events {
        if event.policy == FirePolicy::Repeatable {
            continue;
        }
        let dependencies = event
            .trigger
            .as_ref()
            .map(|condition| hard_event_dependencies(condition, armers))
            .unwrap_or_default()
            .into_iter()
            .filter(|dependency| policies.get(dependency) != Some(&FirePolicy::Repeatable))
            .collect::<BTreeSet<_>>();
        graph.insert(event.id.clone(), dependencies);
    }

    let mut marks = BTreeMap::<EventId, DfsMark>::new();
    let mut stack = Vec::new();
    for event in events {
        if event.policy != FirePolicy::Repeatable {
            visit_non_repeatable_event(&event.id, &graph, &mut marks, &mut stack)?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DfsMark {
    Gray,
    Black,
}

fn visit_non_repeatable_event(
    event: &EventId,
    graph: &BTreeMap<EventId, BTreeSet<EventId>>,
    marks: &mut BTreeMap<EventId, DfsMark>,
    stack: &mut Vec<EventId>,
) -> Result<(), EventGraphError> {
    match marks.get(event) {
        Some(DfsMark::Black) => return Ok(()),
        Some(DfsMark::Gray) => {
            let start = stack
                .iter()
                .position(|stacked| stacked == event)
                .unwrap_or(0);
            let mut cycle = stack[start..].to_vec();
            cycle.push(event.clone());
            return Err(EventGraphError::NonRepeatableCycle { events: cycle });
        }
        None => {}
    }

    marks.insert(event.clone(), DfsMark::Gray);
    stack.push(event.clone());
    if let Some(dependencies) = graph.get(event) {
        for dependency in dependencies {
            if graph.contains_key(dependency) {
                visit_non_repeatable_event(dependency, graph, marks, stack)?;
            }
        }
    }
    stack.pop();
    marks.insert(event.clone(), DfsMark::Black);
    Ok(())
}

fn hard_event_dependencies(
    condition: &Condition,
    armers: &BTreeMap<TimerId, BTreeSet<EventId>>,
) -> BTreeSet<EventId> {
    match condition {
        Condition::After { of, .. } => BTreeSet::from([of.clone()]),
        Condition::Timer { name } => armers
            .get(name)
            .filter(|timer_armers| timer_armers.len() == 1)
            .cloned()
            .unwrap_or_default(),
        Condition::AllOf { predicates } => predicates
            .iter()
            .flat_map(|predicate| hard_event_dependencies(predicate, armers))
            .collect(),
        Condition::AnyOf { predicates } => {
            let mut iter = predicates
                .iter()
                .map(|predicate| hard_event_dependencies(predicate, armers));
            let Some(first) = iter.next() else {
                return BTreeSet::new();
            };
            iter.fold(first, |common, dependencies| {
                common.intersection(&dependencies).cloned().collect()
            })
        }
        Condition::Once { predicate } => hard_event_dependencies(predicate, armers),
        Condition::Not { .. }
        | Condition::At { .. }
        | Condition::NetworkMatch { .. }
        | Condition::ConsoleMatch { .. }
        | Condition::CoveragePoint { .. }
        | Condition::MemoryPredicate { .. }
        | Condition::IoPattern { .. }
        | Condition::NodeState { .. }
        | Condition::AssertionState { .. }
        | Condition::FaultActive { .. }
        | Condition::Quiescent
        | Condition::Named { .. }
        | Condition::GuestMarker { .. } => BTreeSet::new(),
    }
}

fn validate_event_reachability(
    events: &[Event],
    timer_names: &BTreeSet<TimerId>,
    armers: &BTreeMap<TimerId, BTreeSet<EventId>>,
) -> Result<(), EventGraphError> {
    let mut alternatives = BTreeMap::<EventId, Vec<BTreeSet<EventId>>>::new();
    for event in events {
        let event_alternatives = event
            .trigger
            .as_ref()
            .map(|condition| possible_dependency_alternatives(condition, timer_names, armers))
            .unwrap_or_else(|| vec![BTreeSet::new()]);
        alternatives.insert(event.id.clone(), event_alternatives);
    }

    let mut reachable = BTreeSet::<EventId>::new();
    loop {
        let mut changed = false;
        for event in events {
            if reachable.contains(&event.id) {
                continue;
            }
            let Some(event_alternatives) = alternatives.get(&event.id) else {
                continue;
            };
            if event_alternatives
                .iter()
                .any(|alternative| alternative.is_subset(&reachable))
            {
                reachable.insert(event.id.clone());
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    for event in events {
        if !reachable.contains(&event.id) {
            return Err(EventGraphError::UnreachableEvent {
                event: event.id.clone(),
            });
        }
    }
    Ok(())
}

fn possible_dependency_alternatives(
    condition: &Condition,
    timer_names: &BTreeSet<TimerId>,
    armers: &BTreeMap<TimerId, BTreeSet<EventId>>,
) -> Vec<BTreeSet<EventId>> {
    match condition {
        Condition::After { of, .. } => vec![BTreeSet::from([of.clone()])],
        Condition::Timer { name } => {
            if timer_names.contains(name) {
                armers
                    .get(name)
                    .into_iter()
                    .flat_map(|timer_armers| timer_armers.iter().cloned())
                    .map(|event| BTreeSet::from([event]))
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            }
        }
        Condition::AllOf { predicates } => {
            let mut alternatives = vec![BTreeSet::new()];
            for predicate in predicates {
                let child_alternatives =
                    possible_dependency_alternatives(predicate, timer_names, armers);
                alternatives = combine_dependency_alternatives(&alternatives, &child_alternatives);
            }
            alternatives
        }
        Condition::AnyOf { predicates } => predicates
            .iter()
            .flat_map(|predicate| possible_dependency_alternatives(predicate, timer_names, armers))
            .collect(),
        Condition::Once { predicate } => {
            possible_dependency_alternatives(predicate, timer_names, armers)
        }
        Condition::Not { .. }
        | Condition::At { .. }
        | Condition::NetworkMatch { .. }
        | Condition::ConsoleMatch { .. }
        | Condition::CoveragePoint { .. }
        | Condition::MemoryPredicate { .. }
        | Condition::IoPattern { .. }
        | Condition::NodeState { .. }
        | Condition::AssertionState { .. }
        | Condition::FaultActive { .. }
        | Condition::Quiescent
        | Condition::Named { .. }
        | Condition::GuestMarker { .. } => vec![BTreeSet::new()],
    }
}

fn combine_dependency_alternatives(
    left: &[BTreeSet<EventId>],
    right: &[BTreeSet<EventId>],
) -> Vec<BTreeSet<EventId>> {
    let mut combined = Vec::new();
    for left_alternative in left {
        for right_alternative in right {
            let mut dependency_set = left_alternative.clone();
            dependency_set.extend(right_alternative.iter().cloned());
            combined.push(dependency_set);
        }
    }
    combined
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#[allow(clippy::expect_used)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::model::RngDecision;
    use crate::scheduler::EventDiagnosticPayload;

    #[test]
    fn causal_projection_comparison_ignores_observational_entries() {
        let causal = SchedulerEventLogEntry::with_payload_for_test(
            0,
            VirtualTime { ticks: 0 },
            SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
                stream: RngStreamId::from_name("causal-projection"),
                value: 11,
            })),
        );
        let diagnostic = SchedulerEventLogEntry::with_payload_for_test(
            1,
            VirtualTime { ticks: 0 },
            SchedulerEventLogPayload::Diagnostic(EventDiagnosticPayload::new(
                "executor.poll",
                EventLevel::Warn,
                BTreeMap::new(),
            )),
        );

        let expected = vec![causal.clone()];
        let reproduced = vec![diagnostic, causal];

        assert_ne!(expected, reproduced);
        assert!(event_log_causal_projections_match(&expected, &reproduced));
    }

    #[test]
    fn facts_through_point_preserves_resumed_event_log_base_sequence() {
        let first = SchedulerEventLogEntry::with_payload_for_test(
            5,
            VirtualTime { ticks: 5 },
            SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
                stream: RngStreamId::from_name("resumed-prefix-a"),
                value: 17,
            })),
        );
        let second = SchedulerEventLogEntry::with_payload_for_test(
            6,
            VirtualTime { ticks: 7 },
            SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
                stream: RngStreamId::from_name("resumed-prefix-b"),
                value: 23,
            })),
        );
        let prefix = ConditionEventLogPrefix::from_scheduler_event_log_entries_with_base(
            vec![first.clone(), second],
            5,
        )
        .expect("resumed nonzero event-log sequence should build");

        let through_first = prefix
            .with_facts_through_point(EventEvaluationPoint::event_log_entry(&first))
            .expect("resumed prefix through first entry should be retained");

        assert_eq!(through_first.scheduler_entries.len(), 1);
        assert_eq!(through_first.scheduler_entries[0].sequence(), 5);
        assert_eq!(through_first.base_sequence, 5);
        assert_eq!(through_first.event_log_offset().events, 6);
    }
}
