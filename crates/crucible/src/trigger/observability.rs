//! Plan lowering, coverage collection, black-box contracts, and readiness.

use super::*;
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

pub(super) fn graph_static_evaluation_times(events: &[Event]) -> Vec<VirtualTime> {
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

pub(super) fn event_graph_assertion_references(events: &[Event]) -> Vec<AssertionId> {
    let mut assertions = BTreeSet::new();
    for event in events {
        if let Some(trigger) = &event.trigger {
            collect_condition_assertion_references(trigger, &mut assertions);
        }
    }
    assertions.into_iter().collect()
}

pub(super) fn collect_condition_assertion_references(
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

pub(super) fn validate_basic_block_coverage_map_entries(
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
        .vm_nodes()
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

pub(super) fn resolution_from_icount(
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

pub(super) fn resolution_from_virtual_time(
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

pub(super) fn resolve_network_idle_ready_point(
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

pub(super) fn resolve_console_marker_ready_point(
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

pub(super) fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|candidate| candidate == needle)
}

pub(super) fn incident_link_ids(world: &World, node: &NodeId) -> BTreeSet<LinkId> {
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
