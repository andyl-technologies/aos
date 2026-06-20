//! Content-addressed execution-model vocabulary.
//!
//! This module owns the pure, content-addressed data contracts shared by the
//! scheduler, temporal graph, checkpoint cache, fault engine, assertions, and
//! event log. It deliberately contains no backend-specific driver state.

use std::error::Error;
use std::fmt;

/// A stable content address used by the execution-model spine.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentHash {
    /// The canonical hash bytes for the addressed content.
    pub bytes: [u8; 32],
}

/// A handle to an immutable scenario definition.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScenarioDef {
    /// The content address of the scenario definition.
    pub id: ContentHash,
}

/// The only identity-bearing execution configuration.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Configuration {
    /// The immutable definition of the run.
    pub def: ScenarioDef,
    /// The ordered decisions already taken for this definition.
    pub schedule: Schedule,
}

impl Configuration {
    /// Builds the genesis configuration for `def`.
    #[must_use]
    pub fn genesis(def: ScenarioDef) -> Self {
        Self {
            def,
            schedule: Schedule::empty(),
        }
    }

    /// Returns whether this configuration has an empty schedule.
    #[must_use]
    pub fn is_genesis(&self) -> bool {
        self.schedule.is_empty()
    }
}

/// One resolved nondeterministic choice at a scheduling point.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Decision {
    /// A deterministic or recorded ordering of events at one virtual time.
    DeliveryOrder(DeliveryOrderDecision),
    /// The recorded outcome of a probabilistic fault.
    FaultFires(FaultDecision),
    /// A raw draw from a named deterministic decision stream.
    RngDraw(RngDecision),
    /// A search or fuzzing override at a scheduling point.
    Override(OverrideDecision),
    /// A vCPU switch or interrupt-preemption decision.
    Preemption(PreemptionDecision),
    /// A served application-requested random value.
    AppRandom(AppRandomDecision),
}

/// A totally ordered sequence of [`Decision`] values.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Schedule {
    decisions: Vec<Decision>,
}

impl Schedule {
    /// Builds an empty schedule.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            decisions: Vec::new(),
        }
    }

    /// Returns whether the schedule has no decisions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.decisions.is_empty()
    }

    /// Returns the number of decisions in this schedule.
    #[must_use]
    pub fn len(&self) -> usize {
        self.decisions.len()
    }

    /// Returns the decisions in their canonical order.
    #[must_use]
    pub fn decisions(&self) -> &[Decision] {
        &self.decisions
    }

    /// Returns a schedule containing the first `len` decisions.
    ///
    /// # Errors
    ///
    /// Returns [`ScheduleError::PrefixTooLong`] when `len` is greater than the
    /// number of decisions in this schedule.
    pub fn prefix(&self, len: usize) -> Result<Self, ScheduleError> {
        if len > self.decisions.len() {
            return Err(ScheduleError::PrefixTooLong {
                requested: len,
                available: self.decisions.len(),
            });
        }

        Ok(Self {
            decisions: self.decisions[..len].to_vec(),
        })
    }

    /// Returns a new schedule with `decision` appended.
    #[must_use]
    pub fn appended(&self, decision: Decision) -> Self {
        let mut decisions = self.decisions.clone();
        decisions.push(decision);
        Self { decisions }
    }
}

/// An error produced by schedule shape helpers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScheduleError {
    /// The requested prefix is longer than the schedule.
    PrefixTooLong {
        /// The requested prefix length.
        requested: usize,
        /// The number of available decisions.
        available: usize,
    },
}

impl fmt::Display for ScheduleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrefixTooLong {
                requested,
                available,
            } => write!(
                f,
                "schedule prefix length {requested} exceeds available length {available}"
            ),
        }
    }
}

impl Error for ScheduleError {}

/// A virtual time value used by the execution-model signatures.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VirtualTime {
    /// The canonical virtual-time tick.
    pub ticks: u64,
}

/// An instruction-count value used by backend and preemption signatures.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Icount {
    /// The retired-instruction count.
    pub retired: u64,
}

/// A node identifier inside a scenario definition.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId {
    /// The canonical node name.
    pub name: String,
}

/// A vCPU identifier within one node.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VcpuId {
    /// The zero-based vCPU index.
    pub index: u32,
}

/// An interrupt vector identifier.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IrqVector {
    /// The interrupt vector number.
    pub vector: u32,
}

/// A deterministic event-key placeholder for delivery-order decisions.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventKey {
    /// The event sequence key.
    pub sequence: u64,
}

/// A fault identifier inside a scenario plan.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FaultId {
    /// The canonical fault name.
    pub name: String,
}

/// A deterministic decision-stream identifier.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RngStreamId {
    /// The canonical stream name.
    pub name: String,
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

/// A probabilistic fault decision payload.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FaultDecision {
    /// The virtual time at which the fault was resolved.
    pub at: VirtualTime,
    /// The fault whose outcome was resolved.
    pub fault: FaultId,
    /// Whether the fault fired.
    pub fired: bool,
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

/// A checkpoint handle in the temporal graph.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Checkpoint {
    /// The checkpoint content address.
    pub id: ContentHash,
    /// The configuration this checkpoint materializes.
    pub configuration: ContentHash,
    /// Whether this is a fat or thin checkpoint.
    pub kind: CheckpointKind,
}

/// The storage shape of a checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CheckpointKind {
    /// A self-contained materialized checkpoint.
    Fat,
    /// A checkpoint represented by ancestor plus schedule delta.
    Thin,
}

/// A baked genesis checkpoint handle.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GenesisCheckpoint {
    /// The checkpoint content address.
    pub checkpoint: Checkpoint,
}

/// A world handle used by the `bake` signature.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct World {
    /// The world content address.
    pub id: ContentHash,
}

/// An abstract reduced state handle.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct State {
    /// The reduced state's content address.
    pub id: ContentHash,
}

/// A temporal graph handle used by the `instantiate` signature.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TemporalGraph {
    /// The temporal graph content address.
    pub id: ContentHash,
}

/// A live runtime-state handle produced by `instantiate`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RuntimeState {
    /// The runtime state's content address.
    pub id: ContentHash,
}

/// Appends one decision to a configuration without materializing runtime state.
#[must_use]
pub fn step(config: &Configuration, decision: Decision) -> Configuration {
    Configuration {
        def: config.def.clone(),
        schedule: config.schedule.appended(decision),
    }
}

/// Computes the abstract state denoted by `def` and `schedule`.
///
/// # Errors
///
/// Returns [`EngineError::NotImplemented`] until the reduction semantics land in
/// their owning execution-model task.
pub fn reduce(_def: &ScenarioDef, _schedule: &Schedule) -> Result<State, EngineError> {
    Err(EngineError::NotImplemented {
        operation: "reduce",
    })
}

/// Materializes `config` into a live runtime through `graph`.
///
/// # Errors
///
/// Returns [`EngineError::NotImplemented`] until recursive materialization lands
/// in its owning execution-model task.
pub fn instantiate(
    _graph: &TemporalGraph,
    _config: &Configuration,
) -> Result<RuntimeState, EngineError> {
    Err(EngineError::NotImplemented {
        operation: "instantiate",
    })
}

/// Produces the genesis checkpoint for `world`.
///
/// # Errors
///
/// Returns [`EngineError::NotImplemented`] until the genesis baking workflow
/// lands in its owning execution-model task.
pub fn bake(_world: &World) -> Result<GenesisCheckpoint, EngineError> {
    Err(EngineError::NotImplemented { operation: "bake" })
}

/// An engine-spine error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineError {
    /// The operation's signature is fixed but its behavior is not implemented.
    NotImplemented {
        /// The operation whose implementation is deferred.
        operation: &'static str,
    },
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotImplemented { operation } => {
                write!(f, "{operation} is not implemented yet")
            }
        }
    }
}

impl Error for EngineError {}
