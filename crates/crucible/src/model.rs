//! Content-addressed execution-model vocabulary.
//!
//! This module owns the pure, content-addressed data contracts shared by the
//! scheduler, temporal graph, checkpoint cache, fault engine, assertions, and
//! event log. It deliberately contains no backend-specific driver state.

use std::error::Error;
use std::fmt;
use std::ops;

mod canonical;

/// A stable content address used by the execution-model spine.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentHash {
    /// The canonical hash bytes for the addressed content.
    pub bytes: [u8; 32],
}

impl ContentHash {
    /// Computes a stable content hash from canonical material.
    ///
    /// `domain` separates independently versioned material streams, and
    /// `material` is the canonical byte representation of the addressed
    /// content.
    #[must_use]
    pub fn from_canonical_material(domain: &str, material: &str) -> Self {
        canonical::content_hash_from_canonical_material(domain, material)
    }
}

/// A handle to an immutable scenario definition.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScenarioDef {
    /// The content address of the scenario definition.
    pub id: ContentHash,
}

impl ScenarioDef {
    /// Builds a scenario definition from canonical material.
    ///
    /// This helper is the engine-side content-addressing entry point for
    /// backend-produced canonical material.
    #[must_use]
    pub fn from_canonical_material(domain: &str, material: &str) -> Self {
        Self {
            id: ContentHash::from_canonical_material(domain, material),
        }
    }
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

    /// Computes the canonical identity of this configuration.
    ///
    /// The configuration identity is a pure function of the immutable scenario
    /// definition and the recorded schedule prefix. Runtime caches and
    /// materialized checkpoints do not contribute to this identity.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        canonical::configuration_hash(self)
    }

    /// Computes the RFC-named content-addressed configuration id.
    ///
    /// This is an alias for [`Configuration::content_hash`]. It exists so the
    /// execution model exposes the `Configuration::id()` API named in RFC-0010.
    #[must_use]
    pub fn id(&self) -> ContentHash {
        self.content_hash()
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

    /// Computes the canonical identity of this schedule.
    ///
    /// The hash includes every decision in order and changes when a decision is
    /// reordered, inserted, or modified.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        canonical::schedule_hash(self)
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

impl Icount {
    /// Converts this instruction count into a virtual-time point.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError::InvalidShift`] when `shift` cannot name a
    /// `u64` power-of-two scale, or [`TimeConversionError::VirtualTimeOverflow`]
    /// when `retired << shift` cannot be represented as `u64` virtual
    /// nanoseconds.
    pub fn to_virtual(self, shift: Shift) -> Result<VirtualInstant, TimeConversionError> {
        let scale = scale_for_shift(shift)?;
        let nanos =
            self.retired
                .checked_mul(scale)
                .ok_or(TimeConversionError::VirtualTimeOverflow {
                    icount: self,
                    shift,
                })?;
        Ok(VirtualInstant { nanos })
    }
}

/// A monotone per-node counter projected onto the shared virtual timeline.
///
/// VM nodes construct this from retired guest instructions; deterministic I/O
/// sub-nodes construct it from their model-owned completion counter. Both use
/// the same `counter << shift` projection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeCounter {
    /// The node-local counter value.
    pub ticks: u64,
}

impl NodeCounter {
    /// Converts a VM retired-instruction count into a scheduler node counter.
    #[must_use]
    pub fn from_icount(icount: Icount) -> Self {
        Self {
            ticks: icount.retired,
        }
    }

    /// Converts this node-local counter into a shared virtual-time point.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError::InvalidShift`] when `shift` cannot name a
    /// `u64` power-of-two scale, or [`TimeConversionError::VirtualTimeOverflow`]
    /// when `ticks << shift` cannot be represented as `u64` virtual
    /// nanoseconds.
    pub fn to_virtual(self, shift: Shift) -> Result<VirtualInstant, TimeConversionError> {
        Icount {
            retired: self.ticks,
        }
        .to_virtual(shift)
    }
}

/// The fixed `-icount shift=N` scale.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Shift {
    /// The number of low-order virtual-nanosecond bits per instruction.
    pub bits: u8,
}

impl Shift {
    /// Builds a fixed icount shift.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError::InvalidShift`] when `bits >= 64`, because
    /// that shift cannot be represented as a `u64` power-of-two scale.
    pub fn new(bits: u8) -> Result<Self, TimeConversionError> {
        let shift = Self { bits };
        let _ = scale_for_shift(shift)?;
        Ok(shift)
    }
}

/// A point on the shared virtual timeline.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VirtualInstant {
    /// Virtual nanoseconds since Crucible's fixed virtual epoch.
    pub nanos: u64,
}

impl VirtualInstant {
    /// The fixed virtual-time epoch.
    pub const EPOCH: Self = Self { nanos: 0 };

    /// Converts this virtual-time point to the containing instruction count.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError::InvalidShift`] when `shift` cannot name a
    /// `u64` power-of-two scale.
    pub fn to_icount_floor(self, shift: Shift) -> Result<Icount, TimeConversionError> {
        let scale = scale_for_shift(shift)?;
        Ok(Icount {
            retired: self.nanos / scale,
        })
    }

    /// Converts this virtual-time point to the first instruction boundary at or after it.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError::InvalidShift`] when `shift` cannot name a
    /// `u64` power-of-two scale.
    pub fn to_icount_ceil(self, shift: Shift) -> Result<Icount, TimeConversionError> {
        let scale = scale_for_shift(shift)?;
        let quotient = self.nanos / scale;
        let remainder = self.nanos % scale;
        Ok(Icount {
            retired: quotient + u64::from(remainder != 0),
        })
    }

    /// Returns the saturating non-negative span since `earlier`.
    #[must_use]
    pub fn duration_since(self, earlier: Self) -> SimDuration {
        SimDuration {
            nanos: self.nanos.saturating_sub(earlier.nanos),
        }
    }

    /// Applies a signed virtual-time offset, saturating at the virtual epoch.
    #[must_use]
    pub fn with_skew(self, offset: SimOffset) -> Self {
        let shifted = i128::from(self.nanos) + i128::from(offset.nanos);
        if shifted <= 0 {
            Self::EPOCH
        } else if shifted > i128::from(u64::MAX) {
            Self { nanos: u64::MAX }
        } else {
            Self {
                nanos: shifted as u64,
            }
        }
    }
}

impl ops::Add<SimDuration> for VirtualInstant {
    type Output = Self;

    fn add(self, duration: SimDuration) -> Self::Output {
        Self {
            nanos: self.nanos.saturating_add(duration.nanos),
        }
    }
}

/// Alias for the shared-timeline reading of a point.
pub type SimInstant = VirtualInstant;

/// An unsigned virtual-time span.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SimDuration {
    /// Virtual nanoseconds in the span.
    pub nanos: u64,
}

impl ops::Add for SimDuration {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            nanos: self.nanos.saturating_add(rhs.nanos),
        }
    }
}

impl ops::Mul<u64> for SimDuration {
    type Output = Self;

    fn mul(self, rhs: u64) -> Self::Output {
        Self {
            nanos: self.nanos.saturating_mul(rhs),
        }
    }
}

/// A signed virtual-time offset used for configured clock skew.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SimOffset {
    /// Signed virtual nanoseconds in the offset.
    pub nanos: i64,
}

/// A fixed-point clock drift rate applied to guest-visible time reads.
///
/// The rate is stored as an exact rational `numerator / denominator`. Applying
/// the rate uses multiply-then-divide integer arithmetic and rounds down toward
/// zero, matching RFC-0010 TIME-17.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClockDriftRate {
    /// The drift-rate numerator.
    pub numerator: u64,
    /// The drift-rate denominator.
    pub denominator: u64,
}

impl ClockDriftRate {
    /// The perfect no-drift rate.
    pub const ONE: Self = Self {
        numerator: 1,
        denominator: 1,
    };

    /// Builds a fixed-point clock drift rate.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError::InvalidDriftRate`] when `denominator` is
    /// zero.
    pub fn new(numerator: u64, denominator: u64) -> Result<Self, TimeConversionError> {
        let drift_rate = Self {
            numerator,
            denominator,
        };
        if denominator == 0 {
            Err(TimeConversionError::InvalidDriftRate { drift_rate })
        } else {
            Ok(drift_rate)
        }
    }

    /// Applies the fixed-point drift rate with floor rounding.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError::InvalidDriftRate`] when the denominator is
    /// zero, or [`TimeConversionError::GuestVisibleTimeOverflow`] when the
    /// drifted virtual time cannot fit in `u64` nanoseconds.
    pub fn apply_floor(
        self,
        virtual_time: VirtualInstant,
    ) -> Result<VirtualInstant, TimeConversionError> {
        if self.denominator == 0 {
            return Err(TimeConversionError::InvalidDriftRate { drift_rate: self });
        }

        let drifted = u128::from(virtual_time.nanos) * u128::from(self.numerator);
        let drifted = drifted / u128::from(self.denominator);
        let nanos =
            u64::try_from(drifted).map_err(|_| TimeConversionError::GuestVisibleTimeOverflow {
                virtual_time,
                drift_rate: self,
            })?;
        Ok(VirtualInstant { nanos })
    }

    /// Returns whether this rate is exactly one.
    #[must_use]
    pub fn is_one(self) -> bool {
        self.denominator != 0 && self.numerator == self.denominator
    }
}

impl Default for ClockDriftRate {
    fn default() -> Self {
        Self::ONE
    }
}

/// Deterministic clock skew applied only to guest-visible clock reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NodeClockSkew {
    /// The signed guest-visible offset in virtual nanoseconds.
    pub offset: SimOffset,
    /// The fixed-point drift rate.
    pub drift_rate: ClockDriftRate,
}

impl NodeClockSkew {
    /// The default perfect clock, byte-identical to omitting skew.
    pub const PERFECT: Self = Self {
        offset: SimOffset { nanos: 0 },
        drift_rate: ClockDriftRate::ONE,
    };

    /// Applies skew to an unskewed scheduler virtual-time point.
    ///
    /// The returned value is guest-visible only. The input point remains the
    /// unskewed scheduling axis used for horizon computation, cross-node
    /// ordering, and delivery-icount conversion.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError`] when the drift rate is invalid or the
    /// drifted guest-visible time cannot fit in `u64` nanoseconds.
    pub fn guest_visible_time(
        self,
        scheduler_time: VirtualInstant,
    ) -> Result<VirtualInstant, TimeConversionError> {
        let drifted = self.drift_rate.apply_floor(scheduler_time)?;
        let shifted = i128::from(drifted.nanos) + i128::from(self.offset.nanos);
        if shifted <= 0 {
            Ok(VirtualInstant::EPOCH)
        } else {
            let nanos = u64::try_from(shifted).map_err(|_| {
                TimeConversionError::GuestVisibleTimeOffsetOverflow {
                    virtual_time: drifted,
                    offset: self.offset,
                }
            })?;
            Ok(VirtualInstant { nanos })
        }
    }

    /// Returns whether this skew leaves guest-visible time unchanged.
    #[must_use]
    pub fn is_perfect(self) -> bool {
        self.offset.nanos == 0 && self.drift_rate.is_one()
    }

    /// Returns canonical scenario material for non-perfect skew.
    ///
    /// The perfect clock returns `None`, so omitting skew and explicitly using
    /// the default remain byte-identical at the scenario material layer.
    ///
    /// # Errors
    ///
    /// Returns [`TimeConversionError::InvalidDriftRate`] when public-field
    /// construction supplied a zero denominator.
    pub fn scenario_hash_material(self) -> Result<Option<String>, TimeConversionError> {
        if self.drift_rate.denominator == 0 {
            return Err(TimeConversionError::InvalidDriftRate {
                drift_rate: self.drift_rate,
            });
        }

        Ok((!self.is_perfect()).then(|| {
            [
                format!("clock_skew_offset_ns={}", self.offset.nanos),
                format!(
                    "clock_drift_rate={}/{}",
                    self.drift_rate.numerator, self.drift_rate.denominator
                ),
                "clock_drift_rounding=floor".to_owned(),
                "clock_skew_applies_to=guest-visible-only".to_owned(),
                "clock_skew_scheduling_axis=unskewed-icount-derived".to_owned(),
            ]
            .join("\n")
        }))
    }
}

impl Default for NodeClockSkew {
    fn default() -> Self {
        Self::PERFECT
    }
}

/// A virtual-time conversion error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeConversionError {
    /// The shift cannot name a `u64` power-of-two scale.
    InvalidShift {
        /// The invalid shift.
        shift: Shift,
    },
    /// The converted virtual-time point would overflow `u64`.
    VirtualTimeOverflow {
        /// The input instruction count.
        icount: Icount,
        /// The fixed shift.
        shift: Shift,
    },
    /// The drift rate is invalid.
    InvalidDriftRate {
        /// The invalid drift rate.
        drift_rate: ClockDriftRate,
    },
    /// The guest-visible time conversion overflowed.
    GuestVisibleTimeOverflow {
        /// The input unskewed scheduler time.
        virtual_time: VirtualInstant,
        /// The drift rate being applied.
        drift_rate: ClockDriftRate,
    },
    /// Guest-visible offset application overflowed.
    GuestVisibleTimeOffsetOverflow {
        /// The drifted guest-visible time before offset application.
        virtual_time: VirtualInstant,
        /// The offset being applied.
        offset: SimOffset,
    },
}

impl fmt::Display for TimeConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidShift { shift } => {
                write!(
                    f,
                    "icount shift {} cannot be represented as u64",
                    shift.bits
                )
            }
            Self::VirtualTimeOverflow { icount, shift } => write!(
                f,
                "virtual time overflow for icount {} with shift {}",
                icount.retired, shift.bits
            ),
            Self::InvalidDriftRate { drift_rate } => write!(
                f,
                "clock drift rate {}/{} is invalid",
                drift_rate.numerator, drift_rate.denominator
            ),
            Self::GuestVisibleTimeOverflow {
                virtual_time,
                drift_rate,
            } => write!(
                f,
                "guest-visible time overflow for virtual time {} with drift rate {}/{}",
                virtual_time.nanos, drift_rate.numerator, drift_rate.denominator
            ),
            Self::GuestVisibleTimeOffsetOverflow {
                virtual_time,
                offset,
            } => write!(
                f,
                "guest-visible time overflow for virtual time {} with offset {}",
                virtual_time.nanos, offset.nanos
            ),
        }
    }
}

impl Error for TimeConversionError {}

fn scale_for_shift(shift: Shift) -> Result<u64, TimeConversionError> {
    1_u64
        .checked_shl(u32::from(shift.bits))
        .ok_or(TimeConversionError::InvalidShift { shift })
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
/// This reducer is total for the current pure execution spine and therefore
/// does not currently return an error. The `Result` shape is retained for later
/// semantic validation as richer `Decision` variants become executable.
pub fn reduce(def: &ScenarioDef, schedule: &Schedule) -> Result<State, EngineError> {
    Ok(State {
        id: canonical::reduced_state_hash(def, schedule),
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
