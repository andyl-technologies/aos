//! Content-addressed execution-model vocabulary.
//!
//! This module owns the pure, content-addressed data contracts shared by the
//! scheduler, temporal graph, checkpoint cache, fault engine, assertions, and
//! event log. It deliberately contains no backend-specific driver state.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
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

impl World {
    /// Builds an opaque world handle from an already-computed content address.
    ///
    /// This is the compatibility path for backend tests and adapters that do
    /// not yet carry full spatial-graph node material.
    #[must_use]
    pub fn from_content_hash(id: ContentHash) -> Self {
        Self {
            id,
            nodes: Vec::new(),
        }
    }

    /// Builds a canonical world from node ready-point configuration.
    ///
    /// Nodes are sorted by [`NodeId`] before hashing so authoring order does not
    /// affect the world identity.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::DuplicateWorldNodeId`] when a node id appears
    /// more than once, or [`EngineError::WhiteBoxReadyPointWithoutOptIn`] when
    /// a node selects [`ReadyPoint::AgentSignal`] without enabling
    /// [`WhiteBoxPolicy::Enabled`].
    pub fn from_nodes(nodes: Vec<WorldNode>) -> Result<Self, EngineError> {
        let nodes = canonical_world_nodes(&nodes);
        validate_world_nodes(&nodes)?;
        Ok(Self {
            id: ContentHash::from_canonical_material(
                "crucible.model.world.v1",
                &world_nodes_material(&nodes),
            ),
            nodes,
        })
    }

    /// Validates the world's ready-point policy configuration.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::DuplicateWorldNodeId`] when a node id appears
    /// more than once, or [`EngineError::WhiteBoxReadyPointWithoutOptIn`] when
    /// a node selects [`ReadyPoint::AgentSignal`] without enabling
    /// [`WhiteBoxPolicy::Enabled`].
    pub fn validate_ready_point_policies(&self) -> Result<(), EngineError> {
        validate_world_nodes(&self.nodes)
    }

    /// Builds the canonical genesis scenario definition for this world.
    ///
    /// The full `ScenarioDef` schema will carry `World`, plan, properties, and
    /// seed components. Until that schema lands, this helper makes the model's
    /// world-to-genesis relationship explicit without weakening checkpoint
    /// validation.
    #[must_use]
    pub fn scenario_def(&self) -> ScenarioDef {
        ScenarioDef::from_canonical_material(
            "crucible.model.world-scenario.v1",
            &world_hash_material(self),
        )
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

    /// Returns the suffix after the first `len` decisions.
    ///
    /// # Errors
    ///
    /// Returns [`ScheduleError::PrefixTooLong`] when `len` is greater than the
    /// number of decisions in this schedule.
    pub fn suffix_from(&self, len: usize) -> Result<Self, ScheduleError> {
        if len > self.decisions.len() {
            return Err(ScheduleError::PrefixTooLong {
                requested: len,
                available: self.decisions.len(),
            });
        }

        Ok(Self {
            decisions: self.decisions[len..].to_vec(),
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

/// One node's model-level ready-point configuration inside a [`World`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WorldNode {
    /// Stable node identity within the world.
    pub id: NodeId,
    /// The deterministic point where this node reaches `t = 0`.
    pub ready_point: ReadyPoint,
    /// Whether this node opts into the white-box guest-host channel.
    pub white_box: WhiteBoxPolicy,
}

/// The deterministic ready-point policy used by `bake`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ReadyPoint {
    /// Snapshot after retiring exactly this many guest instructions.
    FixedIcount {
        /// The target retired-instruction count.
        icount: Icount,
    },
    /// Snapshot after the first network-idle quiescence window.
    NetworkIdle {
        /// Required idle span before the node is considered ready.
        window: SimDuration,
    },
    /// Snapshot when a marker appears on the guest console.
    ConsoleMarker {
        /// Marker matched on the guest console stream.
        marker: String,
    },
    /// Snapshot when the optional in-guest agent signals readiness.
    AgentSignal,
}

/// Whether a node opts into the white-box guest-host channel.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum WhiteBoxPolicy {
    /// The guest-host channel is disabled.
    #[default]
    Disabled,
    /// The guest-host channel is enabled.
    Enabled,
}

impl WhiteBoxPolicy {
    /// Returns whether this policy enables the white-box channel.
    #[must_use]
    pub fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

/// A homogeneous content-addressed VM-state reference for one node.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum NodeBlobRef {
    /// The baked ready-point VM blob for a node in the world's genesis.
    Baked(ContentHash),
    /// A copy-on-write delta layered over a parent VM blob.
    CowDelta {
        /// The parent VM blob content address.
        parent: ContentHash,
        /// The delta content address.
        delta: ContentHash,
        /// The resolved VM-state content address after applying `delta`.
        resolved: ContentHash,
    },
}

impl NodeBlobRef {
    /// Builds a baked ready-point VM blob reference.
    #[must_use]
    pub fn baked(blob: ContentHash) -> Self {
        Self::Baked(blob)
    }

    /// Builds a copy-on-write delta VM blob reference.
    #[must_use]
    pub fn cow_delta(parent: ContentHash, delta: ContentHash, resolved: ContentHash) -> Self {
        Self::CowDelta {
            parent,
            delta,
            resolved,
        }
    }

    /// Returns the resolved VM-state content address denoted by this blob reference.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        match self {
            Self::Baked(blob) => *blob,
            Self::CowDelta { resolved, .. } => *resolved,
        }
    }
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

/// The cached realization carried by a fat checkpoint.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MaterializedState {
    /// Content address of the materialized runtime/cache payload.
    pub id: ContentHash,
}

impl MaterializedState {
    /// Builds a materialized-state handle from an existing content address.
    #[must_use]
    pub fn from_content_hash(id: ContentHash) -> Self {
        Self { id }
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
    /// Identity-irrelevant metadata for humans and cache policy.
    pub metadata: CheckpointMeta,
    /// Per-node VM-state blob references.
    pub node_blobs: BTreeMap<NodeId, NodeBlobRef>,
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
        Ok(Self {
            id: configuration.id(),
            configuration: configuration.id(),
            scenario_ref: configuration.def.id,
            parent,
            schedule_delta,
            virtual_time,
            node_icounts,
            state: materialized_state_for_kind(kind, configuration.id()),
            coverage_fingerprint: ContentHash::default(),
            metadata: CheckpointMeta::empty(),
            node_blobs,
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
            state: materialized_state_for_kind(kind, configuration),
            coverage_fingerprint: ContentHash::default(),
            metadata: CheckpointMeta::empty(),
            node_blobs,
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

    /// Replaces the observation-only coverage fingerprint without changing identity.
    #[must_use]
    pub fn with_coverage_fingerprint(mut self, coverage_fingerprint: ContentHash) -> Self {
        self.coverage_fingerprint = coverage_fingerprint;
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
    /// Canonicalized node ready-point configuration for this world.
    pub nodes: Vec<WorldNode>,
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
    recorded_configurations: BTreeMap<ContentHash, Configuration>,
    checkpoint_nodes: BTreeMap<ContentHash, Checkpoint>,
    cached_snapshots: BTreeMap<ContentHash, Checkpoint>,
    baked_genesis: BTreeMap<ContentHash, GenesisCheckpoint>,
}

impl TemporalGraph {
    /// Builds an empty temporal graph cache with `id`.
    #[must_use]
    pub fn new(id: ContentHash) -> Self {
        Self {
            id,
            recorded_configurations: BTreeMap::new(),
            checkpoint_nodes: BTreeMap::new(),
            cached_snapshots: BTreeMap::new(),
            baked_genesis: BTreeMap::new(),
        }
    }

    /// Builds an empty temporal graph cache with the default test identity.
    #[must_use]
    pub fn empty() -> Self {
        Self::new(ContentHash::default())
    }

    /// Returns a graph with a loadable snapshot registered for `configuration`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::CheckpointConfigurationMismatch`] when the
    /// checkpoint does not name `configuration`, or
    /// [`EngineError::CheckpointNotLoadable`] when `checkpoint` is not fat.
    /// Returns [`EngineError::GenesisSnapshotMustBeBaked`] when
    /// `configuration` is the scenario genesis.
    pub fn with_cached_snapshot(
        mut self,
        configuration: &Configuration,
        checkpoint: Checkpoint,
    ) -> Result<Self, EngineError> {
        self.cache_snapshot(configuration, checkpoint)?;
        Ok(self)
    }

    /// Registers a loadable snapshot for `configuration`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::CheckpointConfigurationMismatch`] when the
    /// checkpoint does not name `configuration`, or
    /// [`EngineError::CheckpointNotLoadable`] when `checkpoint` is not fat.
    /// Returns [`EngineError::GenesisSnapshotMustBeBaked`] when
    /// `configuration` is the scenario genesis.
    pub fn cache_snapshot(
        &mut self,
        configuration: &Configuration,
        checkpoint: Checkpoint,
    ) -> Result<(), EngineError> {
        if configuration.is_genesis() {
            return Err(EngineError::GenesisSnapshotMustBeBaked {
                configuration: configuration.id(),
            });
        }
        validate_loadable_checkpoint(&checkpoint, configuration)?;
        if self.genesis_snapshot(&configuration.def).is_some() {
            self.record_checkpoint_closure(configuration)?;
            self.checkpoint_nodes
                .insert(configuration.id(), checkpoint.clone());
        }
        self.record_configuration(configuration.clone());
        self.cached_snapshots.insert(configuration.id(), checkpoint);
        Ok(())
    }

    /// Returns a graph with the baked genesis checkpoint registered for `def`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::CheckpointConfigurationMismatch`] when the baked
    /// checkpoint does not name the genesis configuration for `def`, or
    /// [`EngineError::CheckpointNotLoadable`] when the baked checkpoint is not
    /// fat.
    pub fn with_baked_genesis(
        mut self,
        def: &ScenarioDef,
        genesis: GenesisCheckpoint,
    ) -> Result<Self, EngineError> {
        self.cache_baked_genesis(def, genesis)?;
        Ok(self)
    }

    /// Registers the baked genesis checkpoint for `def`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::CheckpointConfigurationMismatch`] when the baked
    /// checkpoint does not name the genesis configuration for `def`, or
    /// [`EngineError::CheckpointNotLoadable`] when the baked checkpoint is not
    /// fat.
    pub fn cache_baked_genesis(
        &mut self,
        def: &ScenarioDef,
        genesis: GenesisCheckpoint,
    ) -> Result<(), EngineError> {
        let genesis_config = Configuration::genesis(def.clone());
        validate_loadable_checkpoint(&genesis.checkpoint, &genesis_config)?;
        self.record_configuration(genesis_config);
        self.checkpoint_nodes
            .insert(genesis.checkpoint.id, genesis.checkpoint.clone());
        self.baked_genesis.insert(def.id, genesis);
        Ok(())
    }

    /// Saves `configuration` as a fat checkpoint in the temporal graph.
    ///
    /// The checkpoint cache key is the configuration's content address. Saving
    /// the same configuration repeatedly is idempotent and returns the existing
    /// checkpoint instead of re-materializing a duplicate node.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::MissingBakedGenesis`] when materialization reaches
    /// genesis without a baked genesis checkpoint. Returns other
    /// [`EngineError`] variants when cached checkpoint metadata is invalid.
    pub fn save_checkpoint(
        &mut self,
        configuration: &Configuration,
    ) -> Result<Checkpoint, EngineError> {
        self.record_configuration(configuration.clone());
        if configuration.is_genesis() {
            let genesis = self.genesis_snapshot(&configuration.def).ok_or(
                EngineError::MissingBakedGenesis {
                    scenario: configuration.def.id,
                },
            )?;
            return Ok(genesis.checkpoint.clone());
        }
        if let Some(checkpoint) = self.cached_snapshot(configuration) {
            return Ok(checkpoint.clone());
        }

        let runtime = instantiate(self, configuration)?;
        let checkpoint = materialized_checkpoint_for_runtime(configuration, runtime)?;
        self.cache_snapshot(configuration, checkpoint.clone())?;
        Ok(checkpoint)
    }

    /// Checks a stored fat checkpoint against its thin replay derivation.
    ///
    /// This is the on-demand replay operation: the supplied fat checkpoint is
    /// validated, the same configuration is reconstructed from an ancestor or
    /// baked genesis without using the target exact snapshot, and both
    /// checkpoint identities are compared.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::CheckpointConfigurationMismatch`] or
    /// [`EngineError::CheckpointNotLoadable`] when the fat checkpoint metadata
    /// is invalid. Returns [`EngineError::ReplayOracleMismatch`] when the thin
    /// derivation does not reproduce the fat checkpoint identity.
    pub fn replay_checkpoint(
        &self,
        configuration: &Configuration,
        checkpoint: &Checkpoint,
    ) -> Result<ReplayOracleCheck, EngineError> {
        validate_loadable_checkpoint(checkpoint, configuration)?;
        let thin_runtime = instantiate_thin_replay(self, configuration)?;
        let thin_checkpoint = if configuration.is_genesis() {
            self.genesis_snapshot(&configuration.def)
                .ok_or(EngineError::MissingBakedGenesis {
                    scenario: configuration.def.id,
                })?
                .checkpoint
                .clone()
        } else {
            materialized_checkpoint_for_runtime(configuration, thin_runtime)?
        };
        if checkpoint.id != thin_checkpoint.id {
            return Err(EngineError::ReplayOracleMismatch {
                checkpoint: checkpoint.id,
                expected: thin_checkpoint.id,
                actual: checkpoint.id,
            });
        }

        Ok(ReplayOracleCheck {
            configuration: configuration.id(),
            fat_checkpoint: checkpoint.id,
            thin_checkpoint: thin_checkpoint.id,
        })
    }

    /// Enumerates frontier checkpoint children by applying decisions with `step`.
    ///
    /// The temporal graph records the frontier and each unique child in the
    /// baked-genesis-rooted checkpoint DAG. Duplicate child configurations are
    /// returned once, in stable content-address order, and previously recorded
    /// children are marked so a search driver can avoid re-materializing them.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::MissingBakedGenesis`] when the scenario has no
    /// baked root. Returns other [`EngineError`] variants if the frontier or a
    /// child cannot be represented as a valid checkpoint edge.
    pub fn enumerate_frontier<I>(
        &mut self,
        frontier: &Configuration,
        decisions: I,
    ) -> Result<Vec<FrontierChild>, EngineError>
    where
        I: IntoIterator<Item = Decision>,
    {
        self.record_checkpoint_closure(frontier)?;
        let mut children = BTreeMap::new();
        for decision in decisions {
            let configuration = step(frontier, decision.clone());
            children.entry(configuration.id()).or_insert(FrontierChild {
                decision,
                configuration,
                already_recorded: false,
            });
        }

        let mut result = Vec::new();
        for mut child in children.into_values() {
            child.already_recorded = !self.record_checkpoint_closure(&child.configuration)?;
            result.push(child);
        }
        Ok(result)
    }

    /// Records one `step` edge in the checkpoint DAG.
    ///
    /// The graph must already contain the baked genesis checkpoint for the
    /// scenario. The returned checkpoint is a thin recorded child unless an
    /// identical configuration was already present, in which case the existing
    /// checkpoint node is returned.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::MissingBakedGenesis`] when the scenario has no
    /// baked root. Returns other [`EngineError`] variants if the parent/delta
    /// edge cannot be represented as a valid checkpoint.
    pub fn record_step(
        &mut self,
        parent: &Configuration,
        decision: Decision,
    ) -> Result<Checkpoint, EngineError> {
        self.record_checkpoint_closure(parent)?;
        let child = step(parent, decision);
        self.record_checkpoint_closure(&child)?;
        self.checkpoint_node(child.id())
            .cloned()
            .ok_or(EngineError::CheckpointNotRecorded {
                checkpoint: child.id(),
            })
    }

    /// Returns a recorded checkpoint DAG node by id.
    #[must_use]
    pub fn checkpoint_node(&self, checkpoint: ContentHash) -> Option<&Checkpoint> {
        self.checkpoint_nodes.get(&checkpoint)
    }

    /// Returns the number of deduplicated checkpoint DAG nodes.
    #[must_use]
    pub fn checkpoint_node_count(&self) -> usize {
        self.checkpoint_nodes.len()
    }

    /// Returns the root-to-target parent chain for `checkpoint`.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::CheckpointNotRecorded`] when the target or one of
    /// its parents is absent from the graph.
    pub fn checkpoint_parent_chain(
        &self,
        checkpoint: ContentHash,
    ) -> Result<Vec<Checkpoint>, EngineError> {
        let mut current = checkpoint;
        let mut reversed = Vec::new();
        let mut seen = BTreeSet::new();
        loop {
            if !seen.insert(current) {
                return Err(EngineError::CheckpointTopologyMismatch {
                    checkpoint: current,
                    reason: "parent-cycle",
                });
            }
            let node = self
                .checkpoint_node(current)
                .ok_or(EngineError::CheckpointNotRecorded {
                    checkpoint: current,
                })?;
            reversed.push(node.clone());
            let Some(parent) = node.parent else {
                break;
            };
            current = parent;
        }
        reversed.reverse();
        Ok(reversed)
    }

    /// Returns whether `configuration` is recorded in the temporal graph.
    #[must_use]
    pub fn contains_configuration(&self, configuration: &Configuration) -> bool {
        self.recorded_configurations
            .contains_key(&configuration.id())
    }

    /// Returns the number of deduplicated configurations recorded by the graph.
    #[must_use]
    pub fn recorded_configuration_count(&self) -> usize {
        self.recorded_configurations.len()
    }

    /// Returns the number of saved non-genesis fat checkpoints in the graph.
    #[must_use]
    pub fn cached_snapshot_count(&self) -> usize {
        self.cached_snapshots.len()
    }

    fn record_configuration(&mut self, configuration: Configuration) -> bool {
        let id = configuration.id();
        match self.recorded_configurations.entry(id) {
            Entry::Vacant(entry) => {
                entry.insert(configuration);
                true
            }
            Entry::Occupied(_) => false,
        }
    }

    fn record_checkpoint_closure(
        &mut self,
        configuration: &Configuration,
    ) -> Result<bool, EngineError> {
        if self.checkpoint_nodes.contains_key(&configuration.id()) {
            self.record_configuration(configuration.clone());
            return Ok(false);
        }
        if configuration.is_genesis() {
            let checkpoint = self
                .genesis_snapshot(&configuration.def)
                .ok_or(EngineError::MissingBakedGenesis {
                    scenario: configuration.def.id,
                })?
                .checkpoint
                .clone();
            self.record_configuration(configuration.clone());
            self.checkpoint_nodes.insert(configuration.id(), checkpoint);
            return Ok(true);
        }

        let parent = immediate_parent_configuration(configuration)?.ok_or(
            EngineError::CheckpointTopologyMismatch {
                checkpoint: configuration.id(),
                reason: "descendant-missing-parent",
            },
        )?;
        self.record_checkpoint_closure(&parent)?;
        let checkpoint = Checkpoint::from_recorded_configuration(
            configuration,
            Some(&parent),
            VirtualTime::default(),
            BTreeMap::new(),
            CheckpointKind::Thin,
            BTreeMap::new(),
        )?;
        self.record_configuration(configuration.clone());
        self.checkpoint_nodes.insert(configuration.id(), checkpoint);
        Ok(true)
    }

    /// Returns the exact loadable snapshot for `configuration`, if one exists.
    #[must_use]
    pub fn cached_snapshot(&self, configuration: &Configuration) -> Option<&Checkpoint> {
        self.cached_snapshots.get(&configuration.id())
    }

    /// Returns the baked genesis snapshot for `def`, if one exists.
    #[must_use]
    pub fn genesis_snapshot(&self, def: &ScenarioDef) -> Option<&GenesisCheckpoint> {
        self.baked_genesis.get(&def.id)
    }

    /// Returns the nearest cached ancestor of `configuration`, excluding itself.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] if a schedule prefix cannot be constructed.
    pub fn nearest_cached_ancestor(
        &self,
        configuration: &Configuration,
    ) -> Result<Option<Configuration>, EngineError> {
        for prefix_len in (0..configuration.schedule.len()).rev() {
            let schedule = configuration
                .schedule
                .prefix(prefix_len)
                .map_err(EngineError::SchedulePrefix)?;
            let ancestor = Configuration {
                def: configuration.def.clone(),
                schedule,
            };
            if self.cached_snapshot(&ancestor).is_some() {
                return Ok(Some(ancestor));
            }
        }

        Ok(None)
    }
}

/// Result of an on-demand replay-oracle check.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReplayOracleCheck {
    /// Configuration whose fat and thin checkpoint identities were compared.
    pub configuration: ContentHash,
    /// Content address of the supplied fat checkpoint.
    pub fat_checkpoint: ContentHash,
    /// Content address of the checkpoint reconstructed by thin replay.
    pub thin_checkpoint: ContentHash,
}

/// One unique child produced by frontier decision enumeration.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FrontierChild {
    /// Decision applied to the frontier configuration.
    pub decision: Decision,
    /// Child configuration produced by `step`.
    pub configuration: Configuration,
    /// Whether the child was already present in the temporal graph.
    pub already_recorded: bool,
}

/// A live runtime-state handle produced by `instantiate`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RuntimeState {
    /// The runtime state's content address.
    pub id: ContentHash,
    /// The configuration materialized by this runtime state.
    pub configuration: ContentHash,
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
/// Returns [`EngineError::MissingBakedGenesis`] when materialization reaches
/// genesis and the graph has no baked genesis checkpoint for the scenario.
/// Returns other [`EngineError`] variants when cached checkpoint metadata is
/// invalid or suffix replay does not reconstruct the requested configuration.
pub fn instantiate(
    graph: &TemporalGraph,
    config: &Configuration,
) -> Result<RuntimeState, EngineError> {
    if config.is_genesis() {
        let genesis =
            graph
                .genesis_snapshot(&config.def)
                .ok_or(EngineError::MissingBakedGenesis {
                    scenario: config.def.id,
                })?;
        return load_snapshot(config, &genesis.checkpoint);
    }

    if let Some(snapshot) = graph.cached_snapshot(config) {
        return load_snapshot(config, snapshot);
    }

    if let Some(ancestor) = graph.nearest_cached_ancestor(config)? {
        let ancestor_runtime = instantiate(graph, &ancestor)?;
        let suffix = config
            .schedule
            .suffix_from(ancestor.schedule.len())
            .map_err(EngineError::SchedulePrefix)?;
        return replay_suffix(ancestor_runtime, &ancestor, &suffix, config);
    }

    let genesis = Configuration::genesis(config.def.clone());
    let genesis_runtime = instantiate(graph, &genesis)?;
    let suffix = config
        .schedule
        .suffix_from(genesis.schedule.len())
        .map_err(EngineError::SchedulePrefix)?;
    replay_suffix(genesis_runtime, &genesis, &suffix, config)
}

/// Produces the genesis checkpoint for `world`.
///
/// # Errors
///
/// This pure model helper is total for a content-addressed [`World`] handle.
/// Backend-specific bake implementations may still return backend errors while
/// starting guests to their ready point and saving VM state.
pub fn bake(world: &World) -> Result<GenesisCheckpoint, EngineError> {
    world.validate_ready_point_policies()?;
    let def = world.scenario_def();
    let genesis = Configuration::genesis(def);
    let material = format!(
        "{}\ngenesis_configuration={}",
        world_hash_material(world),
        content_hash_hex(genesis.id()),
    );

    let checkpoint = Checkpoint::from_recorded_configuration(
        &genesis,
        None,
        VirtualTime::default(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        baked_node_blobs(world),
    )?
    .with_materialized_state(Some(MaterializedState::from_content_hash(
        ContentHash::from_canonical_material(
            "crucible.model.baked-genesis-checkpoint.v1",
            &material,
        ),
    )));

    Ok(GenesisCheckpoint { checkpoint })
}

/// An engine-spine error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineError {
    /// The operation's signature is fixed but its behavior is not implemented.
    NotImplemented {
        /// The operation whose implementation is deferred.
        operation: &'static str,
    },
    /// A cached checkpoint is not a fat loadable snapshot.
    CheckpointNotLoadable {
        /// The checkpoint that cannot be loaded.
        checkpoint: ContentHash,
        /// The checkpoint storage kind.
        kind: CheckpointKind,
    },
    /// A cached checkpoint names a different configuration than requested.
    CheckpointConfigurationMismatch {
        /// The checkpoint whose metadata was invalid.
        checkpoint: ContentHash,
        /// The requested configuration id.
        expected: ContentHash,
        /// The configuration id recorded by the checkpoint.
        actual: ContentHash,
    },
    /// A checkpoint's recorded node id does not match its configuration id.
    CheckpointIdentityMismatch {
        /// The checkpoint whose identity was invalid.
        checkpoint: ContentHash,
        /// The expected checkpoint id.
        expected: ContentHash,
        /// The actual checkpoint id.
        actual: ContentHash,
    },
    /// A checkpoint's parent/delta/scenario fields do not match its configuration.
    CheckpointTopologyMismatch {
        /// The checkpoint whose topology was invalid.
        checkpoint: ContentHash,
        /// Stable reason for the topology rejection.
        reason: &'static str,
    },
    /// A checkpoint DAG node was requested before it was recorded.
    CheckpointNotRecorded {
        /// The absent checkpoint id.
        checkpoint: ContentHash,
    },
    /// No baked genesis checkpoint exists for the scenario.
    MissingBakedGenesis {
        /// The scenario id missing a baked genesis checkpoint.
        scenario: ContentHash,
    },
    /// A genesis snapshot was registered through the ordinary snapshot cache.
    GenesisSnapshotMustBeBaked {
        /// The genesis configuration that must use the baked genesis cache.
        configuration: ContentHash,
    },
    /// A world contains duplicate node identifiers.
    DuplicateWorldNodeId {
        /// The duplicate node id.
        node: NodeId,
    },
    /// An agent-signal ready point was configured without white-box opt-in.
    WhiteBoxReadyPointWithoutOptIn {
        /// The node whose ready-point configuration is invalid.
        node: NodeId,
    },
    /// A runtime was replayed from a configuration it does not materialize.
    RuntimeConfigurationMismatch {
        /// The runtime-state id whose metadata was invalid.
        runtime: ContentHash,
        /// The configuration expected by the replay start.
        expected: ContentHash,
        /// The configuration recorded by the runtime state.
        actual: ContentHash,
    },
    /// Replaying a suffix did not reconstruct the requested configuration.
    ReplayTargetMismatch {
        /// The requested target configuration.
        expected: ContentHash,
        /// The configuration produced by replaying the suffix.
        actual: ContentHash,
    },
    /// A fat checkpoint did not match its thin replay derivation.
    ReplayOracleMismatch {
        /// The fat checkpoint under test.
        checkpoint: ContentHash,
        /// The checkpoint identity reconstructed by thin replay.
        expected: ContentHash,
        /// The supplied fat checkpoint identity.
        actual: ContentHash,
    },
    /// A schedule prefix or suffix could not be constructed.
    SchedulePrefix(
        /// The schedule prefix error.
        ScheduleError,
    ),
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotImplemented { operation } => {
                write!(f, "{operation} is not implemented yet")
            }
            Self::CheckpointNotLoadable { kind, .. } => {
                write!(
                    f,
                    "checkpoint is not loadable because it is {}",
                    checkpoint_kind_label(*kind)
                )
            }
            Self::CheckpointConfigurationMismatch { .. } => {
                f.write_str("checkpoint configuration does not match requested configuration")
            }
            Self::CheckpointIdentityMismatch { .. } => {
                f.write_str("checkpoint id does not match requested configuration")
            }
            Self::CheckpointTopologyMismatch { reason, .. } => {
                write!(f, "checkpoint topology is invalid: {reason}")
            }
            Self::CheckpointNotRecorded { .. } => {
                f.write_str("checkpoint is not recorded in the temporal graph")
            }
            Self::MissingBakedGenesis { .. } => {
                f.write_str("missing baked genesis checkpoint for scenario")
            }
            Self::GenesisSnapshotMustBeBaked { .. } => {
                f.write_str("genesis snapshots must be registered as baked genesis checkpoints")
            }
            Self::DuplicateWorldNodeId { .. } => f.write_str("world contains a duplicate node id"),
            Self::WhiteBoxReadyPointWithoutOptIn { .. } => {
                f.write_str("agent-signal ready point requires white-box opt-in")
            }
            Self::RuntimeConfigurationMismatch { .. } => {
                f.write_str("runtime configuration does not match replay start configuration")
            }
            Self::ReplayTargetMismatch { .. } => {
                f.write_str("replayed suffix did not produce requested configuration")
            }
            Self::ReplayOracleMismatch { .. } => {
                f.write_str("replay oracle mismatch between fat checkpoint and thin derivation")
            }
            Self::SchedulePrefix(error) => write!(f, "schedule prefix failed: {error}"),
        }
    }
}

impl Error for EngineError {}

fn load_snapshot(
    configuration: &Configuration,
    checkpoint: &Checkpoint,
) -> Result<RuntimeState, EngineError> {
    validate_loadable_checkpoint(checkpoint, configuration)?;
    runtime_for_configuration(configuration)
}

fn runtime_for_configuration(configuration: &Configuration) -> Result<RuntimeState, EngineError> {
    Ok(RuntimeState {
        id: reduce(&configuration.def, &configuration.schedule)?.id,
        configuration: configuration.id(),
    })
}

fn replay_suffix(
    runtime: RuntimeState,
    start: &Configuration,
    suffix: &Schedule,
    target: &Configuration,
) -> Result<RuntimeState, EngineError> {
    if runtime.configuration != start.id() {
        return Err(EngineError::RuntimeConfigurationMismatch {
            runtime: runtime.id,
            expected: start.id(),
            actual: runtime.configuration,
        });
    }

    let mut replayed = start.clone();
    for decision in suffix.decisions() {
        replayed = step(&replayed, decision.clone());
    }

    if replayed.id() != target.id() {
        return Err(EngineError::ReplayTargetMismatch {
            expected: target.id(),
            actual: replayed.id(),
        });
    }

    runtime_for_configuration(&replayed)
}

fn instantiate_thin_replay(
    graph: &TemporalGraph,
    config: &Configuration,
) -> Result<RuntimeState, EngineError> {
    if config.is_genesis() {
        let genesis =
            graph
                .genesis_snapshot(&config.def)
                .ok_or(EngineError::MissingBakedGenesis {
                    scenario: config.def.id,
                })?;
        return load_snapshot(config, &genesis.checkpoint);
    }

    if let Some(ancestor) = graph.nearest_cached_ancestor(config)? {
        let ancestor_runtime = instantiate(graph, &ancestor)?;
        let suffix = config
            .schedule
            .suffix_from(ancestor.schedule.len())
            .map_err(EngineError::SchedulePrefix)?;
        return replay_suffix(ancestor_runtime, &ancestor, &suffix, config);
    }

    let genesis = Configuration::genesis(config.def.clone());
    let genesis_runtime = instantiate(graph, &genesis)?;
    let suffix = config
        .schedule
        .suffix_from(genesis.schedule.len())
        .map_err(EngineError::SchedulePrefix)?;
    replay_suffix(genesis_runtime, &genesis, &suffix, config)
}

fn materialized_checkpoint_for_runtime(
    configuration: &Configuration,
    runtime: RuntimeState,
) -> Result<Checkpoint, EngineError> {
    let parent = immediate_parent_configuration(configuration)?;
    let checkpoint = Checkpoint::from_recorded_configuration(
        configuration,
        parent.as_ref(),
        VirtualTime::default(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )?
    .with_materialized_state(Some(MaterializedState::from_content_hash(
        ContentHash::from_canonical_material(
            "crucible.model.fat-checkpoint.v1",
            &format!(
                "configuration={}\nruntime_configuration={}\nruntime={}\n",
                content_hash_hex(configuration.id()),
                content_hash_hex(runtime.configuration),
                content_hash_hex(runtime.id),
            ),
        ),
    )));
    Ok(checkpoint)
}

fn validate_loadable_checkpoint(
    checkpoint: &Checkpoint,
    configuration: &Configuration,
) -> Result<(), EngineError> {
    if checkpoint.kind != CheckpointKind::Fat {
        return Err(EngineError::CheckpointNotLoadable {
            checkpoint: checkpoint.id,
            kind: checkpoint.kind,
        });
    }
    if checkpoint.configuration != configuration.id() {
        return Err(EngineError::CheckpointConfigurationMismatch {
            checkpoint: checkpoint.id,
            expected: configuration.id(),
            actual: checkpoint.configuration,
        });
    }
    if checkpoint.id != configuration.id() {
        return Err(EngineError::CheckpointIdentityMismatch {
            checkpoint: checkpoint.id,
            expected: configuration.id(),
            actual: checkpoint.id,
        });
    }
    if checkpoint.scenario_ref != configuration.def.id {
        return Err(EngineError::CheckpointTopologyMismatch {
            checkpoint: checkpoint.id,
            reason: "scenario-ref-mismatch",
        });
    }

    let expected_parent_config = immediate_parent_configuration(configuration)?;
    let (expected_parent, expected_delta) =
        checkpoint_edge(configuration, expected_parent_config.as_ref())?;
    if checkpoint.parent != expected_parent {
        return Err(EngineError::CheckpointTopologyMismatch {
            checkpoint: checkpoint.id,
            reason: "parent-mismatch",
        });
    }
    if checkpoint.schedule_delta != expected_delta {
        return Err(EngineError::CheckpointTopologyMismatch {
            checkpoint: checkpoint.id,
            reason: "schedule-delta-mismatch",
        });
    }

    Ok(())
}

fn checkpoint_kind_label(kind: CheckpointKind) -> &'static str {
    match kind {
        CheckpointKind::Fat => "fat",
        CheckpointKind::Thin => "thin",
    }
}

fn materialized_state_for_kind(
    kind: CheckpointKind,
    configuration: ContentHash,
) -> Option<MaterializedState> {
    match kind {
        CheckpointKind::Fat => Some(MaterializedState::from_content_hash(configuration)),
        CheckpointKind::Thin => None,
    }
}

fn checkpoint_edge(
    configuration: &Configuration,
    parent: Option<&Configuration>,
) -> Result<(Option<ContentHash>, Schedule), EngineError> {
    match (configuration.is_genesis(), parent) {
        (true, None) => Ok((None, Schedule::empty())),
        (true, Some(_)) => Err(EngineError::CheckpointTopologyMismatch {
            checkpoint: configuration.id(),
            reason: "genesis-has-parent",
        }),
        (false, None) => Err(EngineError::CheckpointTopologyMismatch {
            checkpoint: configuration.id(),
            reason: "descendant-missing-parent",
        }),
        (false, Some(parent)) => {
            if parent.def.id != configuration.def.id {
                return Err(EngineError::CheckpointTopologyMismatch {
                    checkpoint: configuration.id(),
                    reason: "parent-scenario-mismatch",
                });
            }
            let prefix = configuration
                .schedule
                .prefix(parent.schedule.len())
                .map_err(EngineError::SchedulePrefix)?;
            if prefix != parent.schedule {
                return Err(EngineError::CheckpointTopologyMismatch {
                    checkpoint: configuration.id(),
                    reason: "parent-not-schedule-prefix",
                });
            }
            let delta = configuration
                .schedule
                .suffix_from(parent.schedule.len())
                .map_err(EngineError::SchedulePrefix)?;
            if delta.is_empty() {
                return Err(EngineError::CheckpointTopologyMismatch {
                    checkpoint: configuration.id(),
                    reason: "empty-descendant-delta",
                });
            }
            Ok((Some(parent.id()), delta))
        }
    }
}

fn immediate_parent_configuration(
    configuration: &Configuration,
) -> Result<Option<Configuration>, EngineError> {
    if configuration.is_genesis() {
        Ok(None)
    } else {
        let schedule = configuration
            .schedule
            .prefix(configuration.schedule.len().saturating_sub(1))
            .map_err(EngineError::SchedulePrefix)?;
        Ok(Some(Configuration {
            def: configuration.def.clone(),
            schedule,
        }))
    }
}

fn validate_world_nodes(nodes: &[WorldNode]) -> Result<(), EngineError> {
    let mut seen = BTreeSet::new();
    for node in nodes {
        if !seen.insert(node.id.clone()) {
            return Err(EngineError::DuplicateWorldNodeId {
                node: node.id.clone(),
            });
        }
        if matches!(node.ready_point, ReadyPoint::AgentSignal) && !node.white_box.is_enabled() {
            return Err(EngineError::WhiteBoxReadyPointWithoutOptIn {
                node: node.id.clone(),
            });
        }
    }

    Ok(())
}

fn canonical_world_nodes(nodes: &[WorldNode]) -> Vec<WorldNode> {
    let mut nodes = nodes.to_vec();
    nodes.sort_by(|left, right| left.id.cmp(&right.id));
    nodes
}

fn baked_node_blobs(world: &World) -> BTreeMap<NodeId, NodeBlobRef> {
    canonical_world_nodes(&world.nodes)
        .into_iter()
        .map(|node| {
            let blob = ContentHash::from_canonical_material(
                "crucible.model.node-baked-blob.v1",
                &format!(
                    "world_id={}\n{}",
                    content_hash_hex(world.id),
                    world_node_material(&node)
                ),
            );
            (node.id, NodeBlobRef::baked(blob))
        })
        .collect()
}

fn world_hash_material(world: &World) -> String {
    let nodes = canonical_world_nodes(&world.nodes);
    format!(
        "world_id={}\n{}",
        content_hash_hex(world.id),
        world_nodes_material(&nodes)
    )
}

fn world_nodes_material(nodes: &[WorldNode]) -> String {
    let mut lines = Vec::with_capacity(nodes.len().saturating_mul(5) + 1);
    lines.push(format!("nodes={}", nodes.len()));
    for node in nodes {
        lines.push(world_node_material(node));
    }
    lines.join("\n")
}

fn world_node_material(node: &WorldNode) -> String {
    format!(
        "node_id_len={}\nnode_id={}\n{}\nwhite_box={}",
        node.id.name.len(),
        node.id.name,
        ready_point_material(&node.ready_point),
        white_box_material(node.white_box)
    )
}

fn ready_point_material(ready_point: &ReadyPoint) -> String {
    match ready_point {
        ReadyPoint::FixedIcount { icount } => {
            format!("ready_point=fixed-icount\nready_icount={}", icount.retired)
        }
        ReadyPoint::NetworkIdle { window } => {
            format!("ready_point=network-idle\nidle_window_ns={}", window.nanos)
        }
        ReadyPoint::ConsoleMarker { marker } => format!(
            "ready_point=console-marker\nmarker_len={}\nmarker={marker}",
            marker.len()
        ),
        ReadyPoint::AgentSignal => String::from("ready_point=agent-signal"),
    }
}

fn white_box_material(policy: WhiteBoxPolicy) -> &'static str {
    match policy {
        WhiteBoxPolicy::Disabled => "disabled",
        WhiteBoxPolicy::Enabled => "enabled",
    }
}

fn content_hash_hex(hash: ContentHash) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(64);
    for byte in hash.bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}
