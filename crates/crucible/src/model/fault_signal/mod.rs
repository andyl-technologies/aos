//! Typed, deterministic signal programs for hardware fault modeling.
//!
//! A signal program describes causes independently from the network, storage,
//! or node adapter that applies an effect. Programs are finite directed acyclic
//! graphs. Every node has an explicit value type, unit, decimal scale, and
//! evaluation domain; admission validates all of those contracts before a run
//! can begin.
//!
//! The canonical representation is intentionally independent of authored node
//! order. It is used as part of scenario identity and as the version boundary
//! for replay.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use super::ContentHash;

mod adapter_runtime;
mod authoring;
mod binding;
mod binding_runtime;
mod canonical;
mod effect;
mod effect_implementation;
mod effect_parameters;
mod effect_registry;
mod error;
mod evaluator;
mod execution_runtime;
mod fallible_decode;
mod host_action_sink;
mod network_effect;
mod node_effect;
mod opportunity;
mod plan;
mod resource_limits;
mod runtime;
mod sampler;
mod search_materialization;
mod signal_id;
mod spatial;
mod storage_effect;
#[cfg(test)]
mod tests;
mod trace;
mod trace_import;
mod validation;
mod wire;

pub use adapter_runtime::*;
pub(crate) use authoring::*;
pub use binding::*;
pub use binding_runtime::*;
use canonical::program_material;
pub use effect::*;
pub use effect_implementation::*;
pub use effect_parameters::*;
pub use effect_registry::*;
pub use error::SignalProgramError;
pub use evaluator::*;
pub use execution_runtime::*;
pub use host_action_sink::*;
pub use network_effect::*;
pub use node_effect::*;
pub use opportunity::*;
pub use plan::*;
pub use resource_limits::*;
pub use runtime::*;
pub use sampler::*;
pub use search_materialization::*;
pub use signal_id::*;
pub use spatial::*;
pub use storage_effect::*;
pub use trace::*;
pub use trace_import::*;
use validation::*;
pub(crate) use wire::*;

/// Semantic version of the signal evaluator implemented by this crate.
pub const SIGNAL_EVALUATOR_VERSION: u16 = 1;

/// Hard maximum number of nodes in one signal program.
pub const HARD_SIGNAL_NODE_LIMIT: u32 = 65_536;

/// Hard maximum number of directed input edges in one signal program.
pub const HARD_SIGNAL_EDGE_LIMIT: u32 = 262_144;

/// Hard maximum number of inputs accepted by one signal node.
pub const HARD_SIGNAL_INPUTS_PER_NODE_LIMIT: u16 = 256;

/// Hard maximum depth of a signal graph.
pub const HARD_SIGNAL_GRAPH_DEPTH_LIMIT: u16 = 4_096;

/// Hard maximum bytes retained by all stateful signal nodes.
pub const HARD_SIGNAL_STATE_BYTES_LIMIT: u64 = 268_435_456;

/// Hard maximum encoded authored parameters retained by one signal program.
pub const HARD_SIGNAL_AUTHORED_PAYLOAD_BYTES_LIMIT: u64 = 16_777_216;

/// Hard maximum opaque bytes carried by one literal value.
pub const HARD_SIGNAL_LITERAL_BYTES_PER_VALUE: usize = 16_777_216;

/// Hard maximum state count in one finite state machine or Markov chain.
pub const HARD_SIGNAL_STATES_PER_NODE_LIMIT: u32 = 65_536;

/// Hard maximum transitions in one finite state machine.
pub const HARD_SIGNAL_TRANSITIONS_PER_NODE_LIMIT: u32 = 262_144;

/// Hard maximum lookup points in one source or operator node.
pub const HARD_SIGNAL_LOOKUP_POINTS_PER_NODE_LIMIT: u32 = 1_048_576;

/// Default admission limits for a signal program.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalResourceLimits {
    /// Maximum number of nodes.
    pub nodes: u32,
    /// Maximum number of directed input edges.
    pub edges: u32,
    /// Maximum inputs accepted by one node.
    pub inputs_per_node: u16,
    /// Maximum graph depth.
    pub graph_depth: u16,
    /// Maximum aggregate state retained by stateful nodes.
    pub state_bytes: u64,
    /// Maximum aggregate encoded authored node parameters.
    pub authored_payload_bytes: u64,
    /// Maximum states in one finite state machine or Markov chain.
    pub states_per_node: u32,
    /// Maximum transitions in one finite state machine.
    pub transitions_per_node: u32,
    /// Maximum explicit lookup or source points in one node.
    pub lookup_points_per_node: u32,
}

impl Default for SignalResourceLimits {
    fn default() -> Self {
        Self {
            nodes: 16_384,
            edges: 65_536,
            inputs_per_node: 64,
            graph_depth: HARD_SIGNAL_GRAPH_DEPTH_LIMIT,
            state_bytes: 67_108_864,
            authored_payload_bytes: 1_048_576,
            states_per_node: 4_096,
            transitions_per_node: 16_384,
            lookup_points_per_node: 65_536,
        }
    }
}

impl SignalResourceLimits {
    /// Validates configured limits against the compiled hard ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`SignalProgramError::LimitAboveHardCeiling`] when any configured
    /// limit exceeds its corresponding compiled ceiling, or
    /// [`SignalProgramError::ZeroLimit`] when a limit is zero.
    pub fn validate(self) -> Result<(), SignalProgramError> {
        check_limit(
            "signal_nodes",
            u64::from(self.nodes),
            u64::from(HARD_SIGNAL_NODE_LIMIT),
        )?;
        check_limit(
            "signal_edges",
            u64::from(self.edges),
            u64::from(HARD_SIGNAL_EDGE_LIMIT),
        )?;
        check_limit(
            "signal_inputs_per_node",
            u64::from(self.inputs_per_node),
            u64::from(HARD_SIGNAL_INPUTS_PER_NODE_LIMIT),
        )?;
        check_limit(
            "signal_graph_depth",
            u64::from(self.graph_depth),
            u64::from(HARD_SIGNAL_GRAPH_DEPTH_LIMIT),
        )?;
        check_limit(
            "signal_state_bytes",
            self.state_bytes,
            HARD_SIGNAL_STATE_BYTES_LIMIT,
        )?;
        check_limit(
            "signal_authored_payload_bytes",
            self.authored_payload_bytes,
            HARD_SIGNAL_AUTHORED_PAYLOAD_BYTES_LIMIT,
        )?;
        check_limit(
            "state_machine_states_per_node",
            u64::from(self.states_per_node),
            u64::from(HARD_SIGNAL_STATES_PER_NODE_LIMIT),
        )?;
        check_limit(
            "state_machine_transitions_per_node",
            u64::from(self.transitions_per_node),
            u64::from(HARD_SIGNAL_TRANSITIONS_PER_NODE_LIMIT),
        )?;
        check_limit(
            "lookup_points_per_node",
            u64::from(self.lookup_points_per_node),
            u64::from(HARD_SIGNAL_LOOKUP_POINTS_PER_NODE_LIMIT),
        )
    }
}

fn check_limit(field: &'static str, configured: u64, hard: u64) -> Result<(), SignalProgramError> {
    if configured == 0 {
        return Err(SignalProgramError::ZeroLimit { field });
    }
    if configured > hard {
        return Err(SignalProgramError::LimitAboveHardCeiling {
            field,
            configured,
            hard,
        });
    }
    Ok(())
}

/// An exact reduced rational number with a positive denominator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct ExactRatio {
    numerator: i64,
    denominator: u64,
}

impl<'de> serde::Deserialize<'de> for ExactRatio {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            numerator: i64,
            denominator: u64,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.numerator, wire.denominator).map_err(serde::de::Error::custom)
    }
}

impl ExactRatio {
    /// Builds an exact rational that is already in lowest terms.
    ///
    /// # Errors
    ///
    /// Returns [`SignalProgramError::InvalidRatio`] for a zero denominator or a
    /// fraction that is not reduced.
    pub fn new(numerator: i64, denominator: u64) -> Result<Self, SignalProgramError> {
        if denominator == 0 || gcd(numerator.unsigned_abs(), denominator) != 1 {
            return Err(SignalProgramError::InvalidRatio {
                numerator,
                denominator,
            });
        }
        Ok(Self {
            numerator,
            denominator,
        })
    }

    /// Returns the signed numerator.
    #[must_use]
    pub const fn numerator(self) -> i64 {
        self.numerator
    }

    /// Returns the positive denominator.
    #[must_use]
    pub const fn denominator(self) -> u64 {
        self.denominator
    }
}

fn gcd(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

/// Closed scalar and aggregate value types understood by signal programs.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum SignalValueType {
    /// Boolean state.
    Bool,
    /// Signed 64-bit integer.
    I64,
    /// Unsigned 64-bit integer.
    U64,
    /// Exact rational.
    Ratio,
    /// Unsigned duration in virtual nanoseconds.
    DurationNanos,
    /// Unsigned rate per second.
    RatePerSecond,
    /// Probability in millionths from zero through one million.
    ProbabilityMillionths,
    /// Variant from a named closed enum schema.
    Enum(SignalId),
    /// Event from a named closed event schema.
    Event(SignalId),
    /// Two scalar quantities of `element`.
    Vector2(Box<SignalValueType>),
    /// Three scalar quantities of `element`.
    Vector3(Box<SignalValueType>),
    /// Bounded opaque bytes used only by registered event and trace schemas.
    Bytes,
}

impl SignalValueType {
    fn material(&self) -> String {
        match self {
            Self::Bool => String::from("bool"),
            Self::I64 => String::from("i64"),
            Self::U64 => String::from("u64"),
            Self::Ratio => String::from("ratio"),
            Self::DurationNanos => String::from("duration_nanos"),
            Self::RatePerSecond => String::from("rate_per_second"),
            Self::ProbabilityMillionths => String::from("probability_millionths"),
            Self::Enum(schema) => format!("enum:{}", schema.as_str()),
            Self::Event(schema) => format!("event:{}", schema.as_str()),
            Self::Vector2(element) => format!("vector2:{}", element.material()),
            Self::Vector3(element) => format!("vector3:{}", element.material()),
            Self::Bytes => String::from("bytes"),
        }
    }

    /// Returns whether this type participates in registered exact arithmetic.
    #[must_use]
    pub const fn is_numeric(&self) -> bool {
        matches!(
            self,
            Self::I64
                | Self::U64
                | Self::Ratio
                | Self::DurationNanos
                | Self::RatePerSecond
                | Self::ProbabilityMillionths
        )
    }

    fn is_signed(&self) -> bool {
        matches!(self, Self::I64 | Self::Ratio)
    }
}

/// Closed physical units accepted by signal schema version 1.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum SignalUnit {
    /// Unitless quantity.
    Dimensionless,
    /// Virtual nanoseconds.
    VirtualNanoseconds,
    /// Millimetres.
    Millimetres,
    /// Squared millimetres.
    SquareMillimetres,
    /// Millimetres per second.
    MillimetresPerSecond,
    /// Millidegrees.
    Millidegrees,
    /// Millidegrees Celsius.
    Millicelsius,
    /// Microvolts.
    Microvolts,
    /// Microamps.
    Microamps,
    /// Microwatts.
    Microwatts,
    /// Femtowatts.
    Femtowatts,
    /// Microjoules.
    Microjoules,
    /// Millidecibels.
    Millidecibels,
    /// Millidecibel-milliwatts.
    MillidecibelMilliwatts,
    /// Kilohertz.
    Kilohertz,
    /// Bits per second.
    BitsPerSecond,
    /// Bytes per second.
    BytesPerSecond,
    /// Operations per second.
    OperationsPerSecond,
    /// Parts per million.
    PartsPerMillion,
    /// Probability millionths.
    ProbabilityMillionths,
    /// Micrometres per second squared.
    MicrometresPerSecondSquared,
    /// Micrometres per hour.
    MicrometresPerHour,
}

impl SignalUnit {
    fn material(self) -> &'static str {
        match self {
            Self::Dimensionless => "dimensionless",
            Self::VirtualNanoseconds => "virtual_nanoseconds",
            Self::Millimetres => "millimetres",
            Self::SquareMillimetres => "square_millimetres",
            Self::MillimetresPerSecond => "millimetres_per_second",
            Self::Millidegrees => "millidegrees",
            Self::Millicelsius => "millicelsius",
            Self::Microvolts => "microvolts",
            Self::Microamps => "microamps",
            Self::Microwatts => "microwatts",
            Self::Femtowatts => "femtowatts",
            Self::Microjoules => "microjoules",
            Self::Millidecibels => "millidecibels",
            Self::MillidecibelMilliwatts => "millidecibel_milliwatts",
            Self::Kilohertz => "kilohertz",
            Self::BitsPerSecond => "bits_per_second",
            Self::BytesPerSecond => "bytes_per_second",
            Self::OperationsPerSecond => "operations_per_second",
            Self::PartsPerMillion => "parts_per_million",
            Self::ProbabilityMillionths => "probability_millionths",
            Self::MicrometresPerSecondSquared => "micrometres_per_second_squared",
            Self::MicrometresPerHour => "micrometres_per_hour",
        }
    }
}

/// Complete static shape of one signal output.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct SignalShape {
    /// Value representation.
    pub value_type: SignalValueType,
    /// Physical unit.
    pub unit: SignalUnit,
    /// Base-ten exponent applied to the stored integer or rational.
    pub scale_decimal_exponent: i8,
}

impl<'de> serde::Deserialize<'de> for SignalShape {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            value_type: SignalValueType,
            unit: SignalUnit,
            scale_decimal_exponent: i8,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.value_type, wire.unit, wire.scale_decimal_exponent)
            .map_err(serde::de::Error::custom)
    }
}

impl SignalShape {
    /// Builds and validates a signal shape.
    ///
    /// # Errors
    ///
    /// Returns [`SignalProgramError::InvalidShape`] when the type, unit, or
    /// decimal scale combination is not legal in schema version 1.
    pub fn new(
        value_type: SignalValueType,
        unit: SignalUnit,
        scale_decimal_exponent: i8,
    ) -> Result<Self, SignalProgramError> {
        let shape = Self {
            value_type,
            unit,
            scale_decimal_exponent,
        };
        shape.validate()?;
        Ok(shape)
    }

    fn validate(&self) -> Result<(), SignalProgramError> {
        let scale_ok = (-18..=18).contains(&self.scale_decimal_exponent);
        let fixed_zero = matches!(self.unit, SignalUnit::VirtualNanoseconds);
        let unit_ok = match &self.value_type {
            SignalValueType::Bool | SignalValueType::Enum(_) | SignalValueType::Event(_) => {
                self.unit == SignalUnit::Dimensionless && self.scale_decimal_exponent == 0
            }
            SignalValueType::Bytes => {
                self.unit == SignalUnit::Dimensionless && self.scale_decimal_exponent == 0
            }
            SignalValueType::DurationNanos => {
                self.unit == SignalUnit::VirtualNanoseconds && self.scale_decimal_exponent == 0
            }
            SignalValueType::ProbabilityMillionths => {
                self.unit == SignalUnit::ProbabilityMillionths && self.scale_decimal_exponent == 0
            }
            SignalValueType::Vector2(element) | SignalValueType::Vector3(element) => {
                element.is_numeric() && !matches!(**element, SignalValueType::Ratio)
            }
            SignalValueType::I64
            | SignalValueType::U64
            | SignalValueType::Ratio
            | SignalValueType::RatePerSecond => !fixed_zero || self.scale_decimal_exponent == 0,
        };
        if !scale_ok || !unit_ok {
            return Err(SignalProgramError::InvalidShape {
                value_type: self.value_type.material(),
                unit: self.unit.material(),
                scale_decimal_exponent: self.scale_decimal_exponent,
            });
        }
        Ok(())
    }

    fn material(&self) -> String {
        format!(
            "{}|{}|{}",
            self.value_type.material(),
            self.unit.material(),
            self.scale_decimal_exponent
        )
    }
}

/// Canonical literal carried by a constant or analytic signal node.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum SignalValue {
    /// Boolean value.
    Bool(bool),
    /// Signed integer value.
    I64(i64),
    /// Unsigned integer value.
    U64(u64),
    /// Exact rational value.
    Ratio(ExactRatio),
    /// Duration in virtual nanoseconds.
    DurationNanos(u64),
    /// Rate per second.
    RatePerSecond(u64),
    /// Probability in millionths.
    ProbabilityMillionths(u32),
    /// Closed enum variant.
    Enum {
        /// Enum schema.
        schema: SignalId,
        /// Variant identifier.
        variant: SignalId,
    },
    /// Typed canonical event payload.
    Event {
        /// Event schema.
        schema: SignalId,
        /// Canonical bounded payload bytes.
        #[serde(deserialize_with = "fallible_decode::deserialize_vec")]
        payload: Vec<u8>,
    },
    /// Two numeric components.
    Vector2(#[serde(deserialize_with = "fallible_decode::deserialize_vec")] Vec<SignalValue>),
    /// Three numeric components.
    Vector3(#[serde(deserialize_with = "fallible_decode::deserialize_vec")] Vec<SignalValue>),
    /// Bounded opaque bytes.
    Bytes(#[serde(deserialize_with = "fallible_decode::deserialize_vec")] Vec<u8>),
}

impl SignalValue {
    /// Returns the closed value type when this literal is structurally valid.
    #[must_use]
    pub fn value_type(&self) -> Option<SignalValueType> {
        match self {
            Self::Bool(_) => Some(SignalValueType::Bool),
            Self::I64(_) => Some(SignalValueType::I64),
            Self::U64(_) => Some(SignalValueType::U64),
            Self::Ratio(_) => Some(SignalValueType::Ratio),
            Self::DurationNanos(_) => Some(SignalValueType::DurationNanos),
            Self::RatePerSecond(_) => Some(SignalValueType::RatePerSecond),
            Self::ProbabilityMillionths(value) if *value <= 1_000_000 => {
                Some(SignalValueType::ProbabilityMillionths)
            }
            Self::ProbabilityMillionths(_) => None,
            Self::Enum { schema, .. } => Some(SignalValueType::Enum(schema.clone())),
            Self::Event { schema, payload }
                if payload.len() <= HARD_SIGNAL_LITERAL_BYTES_PER_VALUE =>
            {
                Some(SignalValueType::Event(schema.clone()))
            }
            Self::Event { .. } => None,
            Self::Vector2(values) if values.len() == 2 => homogeneous_vector_type(values, true),
            Self::Vector3(values) if values.len() == 3 => homogeneous_vector_type(values, false),
            Self::Vector2(_) | Self::Vector3(_) => None,
            Self::Bytes(value) if value.len() <= HARD_SIGNAL_LITERAL_BYTES_PER_VALUE => {
                Some(SignalValueType::Bytes)
            }
            Self::Bytes(_) => None,
        }
    }

    fn material(&self) -> String {
        match self {
            Self::Bool(value) => format!("bool:{value}"),
            Self::I64(value) => format!("i64:{value}"),
            Self::U64(value) => format!("u64:{value}"),
            Self::Ratio(value) => {
                format!("ratio:{}/{}", value.numerator(), value.denominator())
            }
            Self::DurationNanos(value) => format!("duration_nanos:{value}"),
            Self::RatePerSecond(value) => format!("rate_per_second:{value}"),
            Self::ProbabilityMillionths(value) => format!("probability_millionths:{value}"),
            Self::Enum { schema, variant } => {
                format!("enum:{}:{}", schema.as_str(), variant.as_str())
            }
            Self::Event { schema, payload } => {
                format!("event:{}:{}", schema.as_str(), hex(payload))
            }
            Self::Vector2(values) => vector_material("vector2", values),
            Self::Vector3(values) => vector_material("vector3", values),
            Self::Bytes(value) => format!("bytes:{}", hex(value)),
        }
    }
}

fn homogeneous_vector_type(values: &[SignalValue], vector2: bool) -> Option<SignalValueType> {
    let first = values.first()?.value_type()?;
    if !first.is_numeric() || matches!(first, SignalValueType::Ratio) {
        return None;
    }
    if values
        .iter()
        .any(|value| value.value_type().as_ref() != Some(&first))
    {
        return None;
    }
    if vector2 {
        Some(SignalValueType::Vector2(Box::new(first)))
    } else {
        Some(SignalValueType::Vector3(Box::new(first)))
    }
}

fn vector_material(kind: &str, values: &[SignalValue]) -> String {
    let components = values
        .iter()
        .map(SignalValue::material)
        .collect::<Vec<_>>()
        .join(",");
    format!("{kind}:[{components}]")
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

/// Coordinate domain in which a signal node may be evaluated.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum SignalDomain {
    /// Global virtual nanoseconds.
    VirtualTime,
    /// Node and retired-instruction coordinate.
    NodeCounter,
    /// Stable hardware-operation opportunity.
    Operation,
    /// Position and optional orientation.
    Spatial,
    /// Typed event sequence.
    Event,
    /// Prior checkpointed model state.
    State,
}

impl SignalDomain {
    fn material(self) -> &'static str {
        match self {
            Self::VirtualTime => "virtual_time",
            Self::NodeCounter => "node_counter",
            Self::Operation => "operation",
            Self::Spatial => "spatial",
            Self::Event => "event",
            Self::State => "state",
        }
    }
}

/// Explicit behavior when fixed-width arithmetic would overflow.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum SignalOverflow {
    /// Stop evaluation with an error.
    Error,
    /// Clamp to the declared output type's boundary.
    Saturate,
}

/// Exact rounding rule for rational arithmetic.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum SignalRounding {
    /// Round toward negative infinity.
    Floor,
    /// Round toward positive infinity.
    Ceiling,
    /// Round toward zero.
    TowardZero,
    /// Round away from zero.
    AwayFromZero,
    /// Round to nearest, choosing the even result on a tie.
    NearestTiesToEven,
}

/// Closed pure operator vocabulary for evaluator version 1.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum PureSignalOperator {
    /// Adds equal-shaped inputs.
    Add,
    /// Subtracts the second input from the first.
    Subtract,
    /// Multiplies one input by an exact ratio.
    MultiplyRatio,
    /// Divides one input by an exact ratio.
    DivideRatio,
    /// Produces an absolute value.
    Absolute,
    /// Negates a signed value.
    Negate,
    /// Selects the minimum input.
    Min,
    /// Selects the maximum input.
    Max,
    /// Clamps one value to explicit bounds.
    Clamp,
    /// Tests equality.
    Equal,
    /// Tests inequality.
    NotEqual,
    /// Tests strict ordering.
    Less,
    /// Tests less-than-or-equal ordering.
    LessEqual,
    /// Tests greater-than ordering.
    Greater,
    /// Tests greater-than-or-equal ordering.
    GreaterEqual,
    /// Computes Boolean conjunction.
    All,
    /// Computes Boolean disjunction.
    Any,
    /// Computes Boolean negation.
    Not,
    /// Selects between equal-shaped branches using a Boolean condition.
    Select,
    /// Maps ordered breakpoints to piecewise-constant output.
    LookupStep,
    /// Maps ordered breakpoints by exact linear interpolation.
    PiecewiseLinear,
    /// Exhaustively maps enum variants.
    EnumMap,
    /// Performs an explicit compatible-unit conversion.
    UnitConvert,
    /// Delays a value in its declared domain.
    Delay,
    /// Samples and holds at a fixed cadence.
    SampleHold,
    /// Computes a bounded window minimum.
    WindowMin,
    /// Computes a bounded window maximum.
    WindowMax,
    /// Computes a bounded window mean.
    WindowMean,
    /// Computes distance in one coordinate frame.
    Distance,
    /// Tests membership in a declared zone.
    ZoneContains,
    /// Samples a spatial field.
    FieldSample,
    /// Computes an orientation delta.
    OrientationDelta,
    /// Emits an event on a Boolean rising edge.
    EdgeRising,
    /// Emits an event on a Boolean falling edge.
    EdgeFalling,
    /// Merges typed event streams.
    MergeEvents,
    /// Gates a typed event stream with a Boolean signal.
    GateEvents,
}

impl PureSignalOperator {
    /// Returns every accepted pure operator in canonical reference order.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Add,
            Self::Subtract,
            Self::MultiplyRatio,
            Self::DivideRatio,
            Self::Absolute,
            Self::Negate,
            Self::Min,
            Self::Max,
            Self::Clamp,
            Self::Equal,
            Self::NotEqual,
            Self::Less,
            Self::LessEqual,
            Self::Greater,
            Self::GreaterEqual,
            Self::All,
            Self::Any,
            Self::Not,
            Self::Select,
            Self::LookupStep,
            Self::PiecewiseLinear,
            Self::EnumMap,
            Self::UnitConvert,
            Self::Delay,
            Self::SampleHold,
            Self::WindowMin,
            Self::WindowMax,
            Self::WindowMean,
            Self::Distance,
            Self::ZoneContains,
            Self::FieldSample,
            Self::OrientationDelta,
            Self::EdgeRising,
            Self::EdgeFalling,
            Self::MergeEvents,
            Self::GateEvents,
        ]
    }

    /// Returns the exact spelling accepted by the scenario schema.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Subtract => "subtract",
            Self::MultiplyRatio => "multiply_ratio",
            Self::DivideRatio => "divide_ratio",
            Self::Absolute => "absolute",
            Self::Negate => "negate",
            Self::Min => "min",
            Self::Max => "max",
            Self::Clamp => "clamp",
            Self::Equal => "equal",
            Self::NotEqual => "not_equal",
            Self::Less => "less",
            Self::LessEqual => "less_equal",
            Self::Greater => "greater",
            Self::GreaterEqual => "greater_equal",
            Self::All => "all",
            Self::Any => "any",
            Self::Not => "not",
            Self::Select => "select",
            Self::LookupStep => "lookup_step",
            Self::PiecewiseLinear => "piecewise_linear",
            Self::EnumMap => "enum_map",
            Self::UnitConvert => "unit_convert",
            Self::Delay => "delay",
            Self::SampleHold => "sample_hold",
            Self::WindowMin => "window_min",
            Self::WindowMax => "window_max",
            Self::WindowMean => "window_mean",
            Self::Distance => "distance",
            Self::ZoneContains => "zone_contains",
            Self::FieldSample => "field_sample",
            Self::OrientationDelta => "orientation_delta",
            Self::EdgeRising => "edge_rising",
            Self::EdgeFalling => "edge_falling",
            Self::MergeEvents => "merge_events",
            Self::GateEvents => "gate_events",
        }
    }
}

/// Closed stateful operator vocabulary for evaluator version 1.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum StatefulSignalOperator {
    /// Boolean hysteresis with optional minimum residence.
    Hysteresis,
    /// Commits an input only after a residence interval.
    Debounce,
    /// Exact bounded integrator.
    Integrator,
    /// Fixed-cadence integrator with rational decay.
    LeakyIntegrator,
    /// Closed finite state machine.
    FiniteStateMachine,
    /// Exact-probability finite Markov chain.
    MarkovChain,
    /// Two-state good/bad burst process.
    BurstProcess,
    /// Bounded event counter.
    Counter,
    /// Bounded service and backlog model.
    QueueModel,
}

impl StatefulSignalOperator {
    /// Returns every accepted stateful operator in canonical reference order.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Hysteresis,
            Self::Debounce,
            Self::Integrator,
            Self::LeakyIntegrator,
            Self::FiniteStateMachine,
            Self::MarkovChain,
            Self::BurstProcess,
            Self::Counter,
            Self::QueueModel,
        ]
    }

    /// Returns the exact spelling accepted by the scenario schema.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hysteresis => "hysteresis",
            Self::Debounce => "debounce",
            Self::Integrator => "integrator",
            Self::LeakyIntegrator => "leaky_integrator",
            Self::FiniteStateMachine => "finite_state_machine",
            Self::MarkovChain => "markov_chain",
            Self::BurstProcess => "burst_process",
            Self::Counter => "counter",
            Self::QueueModel => "queue_model",
        }
    }
}

/// Closed source vocabulary for evaluator version 1.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum SignalSourceKind {
    /// One immutable literal.
    Constant,
    /// Piecewise-constant ordered points.
    Step,
    /// One exact active interval.
    Pulse,
    /// Repeating exact active intervals.
    PeriodicPulse,
    /// Exact linear ramp.
    Ramp,
    /// Periodic triangle wave.
    Triangle,
    /// Periodic sawtooth wave.
    Sawtooth,
    /// Ordered typed events.
    EventSequence,
    /// Content-addressed normalized trace channel.
    Trace,
    /// Read-only one-boundary-delayed adapter telemetry.
    Telemetry,
    /// Named spatial samples.
    PointSet,
    /// Dense regular spatial grid.
    RegularGrid,
    /// Content-addressed tiled spatial grid.
    TiledGrid,
    /// Polygon or polyhedron membership map.
    ZoneMap,
    /// Quantity indexed by distance along a path.
    PathProfile,
    /// Counter-keyed deterministic spatial field.
    SeededField,
    /// Transmitter path-loss and antenna contribution.
    TransmitterField,
    /// Keyed independent Boolean probability.
    Bernoulli,
    /// Keyed uniform integer range.
    UniformInteger,
    /// Versioned exact inverse-CDF exponential wait.
    ExponentialWait,
    /// Versioned exact inverse-CDF Weibull wait.
    WeibullWait,
}

impl SignalSourceKind {
    /// Returns every accepted source kind in canonical reference order.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Constant,
            Self::Step,
            Self::Pulse,
            Self::PeriodicPulse,
            Self::Ramp,
            Self::Triangle,
            Self::Sawtooth,
            Self::EventSequence,
            Self::Trace,
            Self::Telemetry,
            Self::PointSet,
            Self::RegularGrid,
            Self::TiledGrid,
            Self::ZoneMap,
            Self::PathProfile,
            Self::SeededField,
            Self::TransmitterField,
            Self::Bernoulli,
            Self::UniformInteger,
            Self::ExponentialWait,
            Self::WeibullWait,
        ]
    }

    /// Returns the exact spelling accepted by the scenario schema.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Constant => "constant",
            Self::Step => "step",
            Self::Pulse => "pulse",
            Self::PeriodicPulse => "periodic_pulse",
            Self::Ramp => "ramp",
            Self::Triangle => "triangle",
            Self::Sawtooth => "sawtooth",
            Self::EventSequence => "event_sequence",
            Self::Trace => "trace",
            Self::Telemetry => "telemetry",
            Self::PointSet => "point_set",
            Self::RegularGrid => "regular_grid",
            Self::TiledGrid => "tiled_grid",
            Self::ZoneMap => "zone_map",
            Self::PathProfile => "path_profile",
            Self::SeededField => "seeded_field",
            Self::TransmitterField => "transmitter_field",
            Self::Bernoulli => "bernoulli",
            Self::UniformInteger => "uniform_integer",
            Self::ExponentialWait => "exponential_wait",
            Self::WeibullWait => "weibull_wait",
        }
    }
}

/// Behavior before or after the defined extent of an ordered source.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum SignalBoundaryBehavior {
    /// Reject evaluation outside the source extent.
    Error,
    /// Hold the nearest defined value.
    Hold,
    /// Return an explicit constant value.
    Constant(SignalValue),
    /// Repeat the source extent periodically.
    Repeat,
    /// Return the binding's inactive value.
    Inactive,
}

/// Behavior when a normalized trace has no sample at a requested coordinate.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum MissingSampleBehavior {
    /// Reject evaluation.
    Error,
    /// Hold the preceding sample.
    Hold,
    /// Interpolate using the trace's declared interpolation rule.
    Interpolate,
    /// Return the binding's inactive value.
    Inactive,
}

/// Interpolation used by traces, spatial samples, and lookup tables.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum SignalInterpolation {
    /// Require an exact coordinate match.
    Exact,
    /// Hold the preceding sample.
    HoldPrevious,
    /// Select the nearest sample with deterministic tie-breaking.
    Nearest,
    /// Uses exact rational linear interpolation with explicit arithmetic policy.
    Linear {
        /// Rounding applied when the exact result is not integral.
        rounding: SignalRounding,
        /// Behavior when the interpolated result exceeds its output type.
        overflow: SignalOverflow,
    },
}

/// Stable coordinate for an analytic signal point.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum SignalCoordinate {
    /// Global virtual nanoseconds.
    VirtualTime {
        /// Global virtual nanoseconds.
        nanos: u64,
    },
    /// Retired-instruction coordinate for a node.
    NodeCounter {
        /// Node identifier.
        node: SignalId,
        /// Retired instruction count.
        retired_instructions: u64,
    },
    /// Stable hardware operation coordinate.
    Operation {
        /// Adapter identifier.
        adapter: SignalId,
        /// Target identifier.
        target: SignalId,
        /// Closed operation identifier.
        operation: SignalId,
        /// Adapter-owned producer sequence.
        producer_sequence: u64,
        /// Adapter-owned sub-operation ordinal.
        suboperation: u32,
    },
    /// Integer local Cartesian position and orientation.
    Spatial {
        /// Coordinate-frame identifier.
        frame: SignalId,
        /// X coordinate in millimetres.
        x_mm: i64,
        /// Y coordinate in millimetres.
        y_mm: i64,
        /// Z coordinate in millimetres.
        z_mm: i64,
        /// Yaw in millidegrees.
        yaw_mdeg: i64,
        /// Pitch in millidegrees.
        pitch_mdeg: i64,
        /// Roll in millidegrees.
        roll_mdeg: i64,
    },
    /// Typed event sequence coordinate in a parent domain.
    Event {
        /// Parent coordinate encoded by the registered event schema.
        parent: Box<SignalCoordinate>,
        /// Stable same-coordinate sequence.
        sequence: u64,
    },
    /// Delayed adapter-state boundary.
    State {
        /// Adapter identifier.
        adapter: SignalId,
        /// Target identifier.
        target: SignalId,
        /// Stable boundary sequence.
        boundary_sequence: u64,
    },
}

/// One ordered coordinate/value point.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct SignalPoint {
    /// Point coordinate.
    pub coordinate: SignalCoordinate,
    /// Stable same-coordinate order.
    pub sequence: u64,
    /// Point value.
    pub value: SignalValue,
}

/// Exact affine mapping from trace coordinates to virtual nanoseconds.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct TraceTimeMapping {
    /// Source coordinate corresponding to `virtual_epoch_nanos`.
    pub source_epoch: i64,
    /// Simulation coordinate corresponding to `source_epoch`.
    pub virtual_epoch_nanos: u64,
    /// Mapping scale.
    pub scale: ExactRatio,
    /// Mapping rounding rule.
    pub rounding: SignalRounding,
}

/// Closed source-node schemas for evaluator version 1.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum SignalSourceSpecification {
    /// Piecewise-constant ordered points.
    Step {
        /// Ordered points.
        points: Vec<SignalPoint>,
        /// Behavior before the first point.
        before: SignalBoundaryBehavior,
    },
    /// One exact active interval.
    Pulse {
        /// Inclusive start coordinate.
        start: SignalCoordinate,
        /// Positive duration in the domain's base coordinate.
        duration: u64,
        /// Value outside the interval.
        inactive: SignalValue,
        /// Value inside the interval.
        active: SignalValue,
    },
    /// Repeating exact active intervals.
    PeriodicPulse {
        /// Period epoch.
        epoch: SignalCoordinate,
        /// Positive period.
        period: u64,
        /// Active width no greater than `period`.
        width: u64,
        /// Offset from the epoch.
        phase: u64,
        /// Value outside each interval.
        inactive: SignalValue,
        /// Value inside each interval.
        active: SignalValue,
    },
    /// Exact linear ramp.
    Ramp {
        /// Inclusive ramp start.
        start: SignalCoordinate,
        /// Exclusive ramp end.
        end: SignalCoordinate,
        /// Value at `start`.
        start_value: SignalValue,
        /// Value at `end`.
        end_value: SignalValue,
        /// Exact division rounding.
        rounding: SignalRounding,
    },
    /// Periodic triangle wave.
    Triangle {
        /// Period epoch.
        epoch: SignalCoordinate,
        /// Positive period.
        period: u64,
        /// Offset from the epoch.
        phase: u64,
        /// Minimum value.
        minimum: SignalValue,
        /// Maximum value.
        maximum: SignalValue,
        /// Exact division rounding.
        rounding: SignalRounding,
    },
    /// Periodic sawtooth wave.
    Sawtooth {
        /// Period epoch.
        epoch: SignalCoordinate,
        /// Positive period.
        period: u64,
        /// Offset from the epoch.
        phase: u64,
        /// Minimum value.
        minimum: SignalValue,
        /// Maximum value.
        maximum: SignalValue,
        /// Exact division rounding.
        rounding: SignalRounding,
    },
    /// Ordered typed events.
    EventSequence {
        /// Ordered event points.
        events: Vec<SignalPoint>,
    },
    /// Content-addressed normalized trace channel.
    Trace {
        /// Normalized trace artifact.
        artifact: ContentHash,
        /// Retained raw provenance artifact.
        raw_provenance: ContentHash,
        /// Channel identifier.
        channel: SignalId,
        /// Optional validity or quality channel.
        quality_channel: Option<SignalId>,
        /// Inclusive minimum accepted quality.
        quality_accept: Option<i64>,
        /// Trace interpolation.
        interpolation: SignalInterpolation,
        /// Behavior before the first sample.
        before: SignalBoundaryBehavior,
        /// Behavior after the last sample.
        after: SignalBoundaryBehavior,
        /// Missing-sample behavior.
        missing: MissingSampleBehavior,
        /// Trace-to-simulation time mapping.
        time_mapping: Option<TraceTimeMapping>,
    },
    /// Read-only one-boundary-delayed adapter telemetry.
    Telemetry {
        /// Adapter identifier.
        adapter: SignalId,
        /// Target identifier.
        target: SignalId,
        /// Registered telemetry field.
        field: SignalId,
        /// Boundary delay; evaluator version 1 accepts only one.
        boundary_delay: u8,
    },
    /// Named spatial samples.
    PointSet {
        /// Normalized point artifact.
        artifact: ContentHash,
        /// Coordinate frame.
        coordinate_frame: SignalId,
        /// Interpolation rule.
        interpolation: SignalInterpolation,
        /// Outside-extent behavior.
        outside: SignalBoundaryBehavior,
    },
    /// Dense regular spatial grid.
    RegularGrid {
        /// Normalized grid artifact.
        artifact: ContentHash,
        /// Coordinate frame.
        coordinate_frame: SignalId,
        /// Integer origin.
        origin_mm: [i64; 3],
        /// Positive cell size for each axis.
        cell_size_mm: [u64; 3],
        /// Positive cell count for each axis.
        dimensions: [u32; 3],
        /// Interpolation rule.
        interpolation: SignalInterpolation,
        /// Outside-extent behavior.
        outside: SignalBoundaryBehavior,
    },
    /// Content-addressed tiled spatial grid.
    TiledGrid {
        /// Content-addressed tile manifest.
        manifest: ContentHash,
        /// Coordinate frame.
        coordinate_frame: SignalId,
        /// Positive tile size for each axis.
        tile_size_mm: [u64; 3],
        /// Interpolation rule.
        interpolation: SignalInterpolation,
        /// Outside-extent behavior.
        outside: SignalBoundaryBehavior,
    },
    /// Polygon or polyhedron membership map.
    ZoneMap {
        /// Normalized zone artifact.
        artifact: ContentHash,
        /// Coordinate frame.
        coordinate_frame: SignalId,
        /// Boundary inclusion rule identifier.
        boundary: SignalId,
        /// Overlap precedence rule identifier.
        overlap: SignalId,
    },
    /// Quantity indexed by distance along a path.
    PathProfile {
        /// Normalized profile artifact.
        artifact: ContentHash,
        /// Path identifier.
        path: SignalId,
        /// Interpolation rule.
        interpolation: SignalInterpolation,
        /// Behavior before the path starts.
        before: SignalBoundaryBehavior,
        /// Behavior after the path ends.
        after: SignalBoundaryBehavior,
    },
    /// Counter-keyed deterministic spatial field.
    SeededField {
        /// Seed domain separator.
        field_seed_domain: SignalId,
        /// Coordinate frame.
        coordinate_frame: SignalId,
        /// Quantization size for each axis.
        quantization_mm: [u64; 3],
        /// Correlation scale for each axis.
        correlation_mm: [u64; 3],
        /// Closed distribution identifier.
        distribution: SignalId,
        /// Distribution-specific exact integer parameters.
        distribution_parameters: Vec<i64>,
    },
    /// Transmitter path-loss and antenna contribution.
    TransmitterField {
        /// Transmitter identifier.
        transmitter: SignalId,
        /// Coordinate frame used by transmitter and receiver positions.
        coordinate_frame: SignalId,
        /// Input containing receiver position.
        position_signal: SignalId,
        /// Optional input containing receiver orientation.
        orientation_signal: Option<SignalId>,
        /// Closed propagation-model identifier.
        model: SignalId,
        /// Content-addressed calibrated model lookup.
        lookup: ContentHash,
        /// Additional environmental input signals.
        environment_signals: Vec<SignalId>,
    },
    /// Keyed independent Boolean probability.
    Bernoulli {
        /// Probability in millionths.
        probability_millionths: u32,
        /// Key domain.
        key_domain: StochasticKeyDomain,
        /// Optional registered opportunity filter.
        opportunity_filter: Option<SignalId>,
    },
    /// Keyed uniform integer range.
    UniformInteger {
        /// Inclusive minimum.
        minimum: i64,
        /// Inclusive maximum.
        maximum: i64,
        /// Key domain.
        key_domain: StochasticKeyDomain,
        /// Optional registered opportunity filter.
        opportunity_filter: Option<SignalId>,
    },
    /// Versioned exact inverse-CDF exponential wait.
    ExponentialWait {
        /// Exact event rate.
        rate: ExactRatio,
        /// Integer sampler semantic version.
        sampler_version: u16,
        /// Content-addressed normalized inverse-CDF table.
        sampler_table: ContentHash,
        /// Key domain.
        key_domain: StochasticKeyDomain,
        /// Optional maximum duration after rounding.
        maximum_nanos: Option<u64>,
    },
    /// Versioned exact inverse-CDF Weibull wait.
    WeibullWait {
        /// Exact shape parameter.
        shape: ExactRatio,
        /// Scale in virtual nanoseconds.
        scale_nanos: u64,
        /// Integer sampler semantic version.
        sampler_version: u16,
        /// Content-addressed normalized inverse-CDF table.
        sampler_table: ContentHash,
        /// Key domain.
        key_domain: StochasticKeyDomain,
        /// Optional maximum duration after rounding.
        maximum_nanos: Option<u64>,
    },
}

/// Stable identity domain for a stochastic keyed choice.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum StochasticKeyDomain {
    /// Stable hardware opportunity identity.
    Opportunity,
    /// Stateful-node transition identity.
    Transition,
    /// Explicit signal coordinate.
    Coordinate,
}

/// Closed pure-node schemas for evaluator version 1.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum PureSignalSpecification {
    /// Operator requiring no parameters beyond its inputs.
    Simple {
        /// Closed operator kind.
        operator: PureSignalOperator,
        /// Overflow policy.
        overflow: SignalOverflow,
    },
    /// Exact rational multiply or divide.
    RatioArithmetic {
        /// Multiply or divide operator.
        operator: PureSignalOperator,
        /// Exact ratio.
        ratio: ExactRatio,
        /// Rounding policy.
        rounding: SignalRounding,
        /// Overflow policy.
        overflow: SignalOverflow,
    },
    /// Explicit clamp bounds.
    Clamp {
        /// Inclusive minimum.
        minimum: SignalValue,
        /// Inclusive maximum.
        maximum: SignalValue,
        /// Overflow policy.
        overflow: SignalOverflow,
    },
    /// Piecewise-constant lookup.
    LookupStep {
        /// Ordered input/output points.
        points: Vec<(SignalValue, SignalValue)>,
        /// Behavior below the first key.
        before: SignalBoundaryBehavior,
        /// Behavior above the last key.
        after: SignalBoundaryBehavior,
    },
    /// Piecewise-linear lookup.
    PiecewiseLinear {
        /// Ordered input/output points.
        points: Vec<(SignalValue, SignalValue)>,
        /// Rounding policy.
        rounding: SignalRounding,
        /// Overflow policy.
        overflow: SignalOverflow,
    },
    /// Exhaustive enum mapping.
    EnumMap {
        /// Input-variant/output entries.
        entries: Vec<(SignalId, SignalValue)>,
    },
    /// Explicit compatible-unit conversion.
    UnitConvert {
        /// Declared source unit.
        from_unit: SignalUnit,
        /// Declared destination unit.
        to_unit: SignalUnit,
        /// Exact conversion scale.
        ratio: ExactRatio,
        /// Exact additive offset after scaling.
        offset: ExactRatio,
        /// Rounding policy.
        rounding: SignalRounding,
        /// Overflow policy.
        overflow: SignalOverflow,
    },
    /// Domain delay.
    Delay {
        /// Positive delay in the domain's base coordinate.
        delay: u64,
        /// Hard maximum retained source samples.
        retained_samples: u32,
    },
    /// Fixed-cadence sample and hold.
    SampleHold {
        /// Positive cadence.
        cadence: u64,
        /// Cadence epoch.
        epoch: SignalCoordinate,
        /// Hard maximum retained source samples.
        retained_samples: u32,
    },
    /// Bounded window aggregation.
    Window {
        /// Minimum, maximum, or mean operator.
        operator: PureSignalOperator,
        /// Positive window width.
        window: u64,
        /// Explicit sampling cadence, or zero for source change points.
        sampling_cadence: u64,
        /// Hard retained-sample bound.
        retained_samples: u32,
        /// Rounding policy used by means.
        rounding: SignalRounding,
        /// Overflow policy.
        overflow: SignalOverflow,
    },
    /// Spatial distance.
    Distance {
        /// Closed metric identifier.
        metric: SignalId,
        /// Rounding policy.
        rounding: SignalRounding,
    },
    /// Zone membership test.
    ZoneContains {
        /// Zone identifier.
        zone: SignalId,
    },
    /// Spatial field sample.
    FieldSample,
    /// Orientation delta.
    OrientationDelta {
        /// Closed orientation convention.
        convention: SignalId,
    },
    /// Event merge with fixed same-coordinate source-then-sequence ordering.
    MergeEvents {
        /// Exclusive upper bound for each source's local same-coordinate sequence.
        source_sequence_limit: u64,
    },
    /// Event gate.
    GateEvents,
}

/// Closed stateful-node schemas for evaluator version 1.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum StatefulSignalSpecification {
    /// Boolean hysteresis.
    Hysteresis {
        /// Initial Boolean state.
        initial: bool,
        /// Inclusive set threshold.
        set_when: SignalValue,
        /// Inclusive clear threshold.
        clear_when: SignalValue,
        /// Minimum residence after a transition.
        minimum_residence_nanos: u64,
    },
    /// Residence-based debounce.
    Debounce {
        /// Initial committed value.
        initial: SignalValue,
        /// Required residence.
        residence_nanos: u64,
    },
    /// Exact bounded integrator.
    Integrator {
        /// Initial accumulator.
        initial: SignalValue,
        /// Zero selects source change points; otherwise this is a cadence.
        cadence_nanos: u64,
        /// Number of virtual nanoseconds represented by one input-rate unit.
        time_unit_nanos: u64,
        /// Rounding policy.
        rounding: SignalRounding,
        /// Overflow policy.
        overflow: SignalOverflow,
    },
    /// Fixed-cadence leaky integrator.
    LeakyIntegrator {
        /// Initial accumulator.
        initial: SignalValue,
        /// Positive cadence.
        cadence_nanos: u64,
        /// Number of virtual nanoseconds represented by one input-rate unit.
        time_unit_nanos: u64,
        /// Exact decay per cadence.
        decay_ratio: ExactRatio,
        /// Maximum number of cadence transitions processed by one evaluation.
        maximum_catch_up_steps: u32,
        /// Rounding policy.
        rounding: SignalRounding,
        /// Overflow policy.
        overflow: SignalOverflow,
    },
    /// Closed finite state machine.
    FiniteStateMachine {
        /// Closed state identifiers.
        states: Vec<SignalId>,
        /// Initial state.
        initial: SignalId,
        /// Exhaustive transition table.
        transitions: Vec<StateMachineTransition>,
        /// Closed unmatched-event policy.
        unmatched_event: SignalId,
    },
    /// Exact-probability finite Markov chain.
    MarkovChain {
        /// Closed state identifiers.
        states: Vec<SignalId>,
        /// Initial state.
        initial: SignalId,
        /// Transition opportunity identifier.
        opportunity: SignalId,
        /// Row-major exact probabilities in millionths.
        probability_rows: Vec<Vec<u32>>,
    },
    /// Good/bad burst process.
    BurstProcess {
        /// Whether the initial state is bad.
        initial_bad: bool,
        /// Good-to-bad probability in millionths.
        good_to_bad_millionths: u32,
        /// Bad-to-good probability in millionths.
        bad_to_good_millionths: u32,
        /// Transition opportunity identifier.
        opportunity: SignalId,
    },
    /// Bounded event counter.
    Counter {
        /// Initial count.
        initial: u64,
        /// Inclusive maximum count.
        maximum: u64,
        /// Overflow policy.
        overflow: SignalOverflow,
        /// Optional reset-event schema.
        reset_event: Option<SignalId>,
    },
    /// Bounded service and backlog model.
    QueueModel {
        /// Maximum queued entries.
        capacity: u32,
        /// Closed queue discipline.
        discipline: SignalId,
        /// Closed queue-overflow policy.
        overflow: SignalId,
    },
}

/// One finite-state-machine transition.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct StateMachineTransition {
    /// Source state.
    pub from: SignalId,
    /// Input event variant.
    pub event: SignalId,
    /// Optional Boolean guard signal.
    pub guard: Option<SignalId>,
    /// Destination state.
    pub to: SignalId,
    /// Optional emitted event variant.
    pub emit: Option<SignalId>,
    /// Bounded timer operations in stable order.
    pub timer_operations: Vec<StateMachineTimerOperation>,
}

/// One closed finite-state-machine timer operation.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum StateMachineTimerOperation {
    /// Starts or replaces a named timer.
    Start {
        /// Timer identifier.
        timer: SignalId,
        /// Positive duration.
        duration_nanos: u64,
    },
    /// Cancels a named timer.
    Cancel {
        /// Timer identifier.
        timer: SignalId,
    },
}

/// Parameters shared by source, pure, and stateful node variants.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum SignalNodeKind {
    /// Literal constant source.
    Constant {
        /// Immutable literal.
        value: SignalValue,
    },
    /// Registered analytic, trace, spatial, telemetry, or stochastic source.
    Source(SignalSourceSpecification),
    /// Registered pure operator.
    Pure(PureSignalSpecification),
    /// Registered bounded stateful operator.
    Stateful {
        /// Closed stateful-node schema.
        specification: StatefulSignalSpecification,
        /// Maximum serialized state bytes reserved by this node.
        state_bytes: u64,
    },
}

/// One node in a typed signal program.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalNode {
    /// Stable node identifier.
    pub id: SignalId,
    /// Evaluation domain.
    pub domain: SignalDomain,
    /// Static output shape.
    pub output: SignalShape,
    /// Input node identifiers in semantic order.
    pub inputs: Vec<SignalId>,
    /// Closed node behavior and parameters.
    pub kind: SignalNodeKind,
}

/// A validated, canonical, content-addressed signal graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignalProgram {
    nodes: Vec<SignalNode>,
    exported_outputs: Vec<SignalId>,
    limits: SignalResourceLimits,
    canonical_material: String,
    id: ContentHash,
}

impl SignalProgram {
    /// Validates and canonicalizes an authored signal graph.
    ///
    /// Presentation order does not affect the returned node order or identity.
    /// Every node must contribute to an explicitly exported output.
    ///
    /// # Errors
    ///
    /// Returns [`SignalProgramError`] when identifiers, types, units, limits,
    /// parameter tables, graph edges, cycles, depth, or reachability violate the
    /// closed evaluator contract.
    pub fn new(
        nodes: Vec<SignalNode>,
        exported_outputs: Vec<SignalId>,
        limits: SignalResourceLimits,
    ) -> Result<Self, SignalProgramError> {
        limits.validate()?;
        let canonical = validate_and_order(nodes, &exported_outputs, limits)?;
        let mut exports = exported_outputs;
        exports.sort();
        if let Some(pair) = exports.windows(2).find(|pair| pair[0] == pair[1]) {
            return Err(SignalProgramError::DuplicateExport {
                id: pair[0].clone(),
            });
        }
        let material = program_material(&canonical, &exports, limits);
        let id = ContentHash::from_canonical_material("crucible.signal-program.v1", &material);
        Ok(Self {
            nodes: canonical,
            exported_outputs: exports,
            limits,
            canonical_material: material,
            id,
        })
    }

    /// Returns nodes in canonical topological order with stable ID tie-breaking.
    #[must_use]
    pub fn nodes(&self) -> &[SignalNode] {
        &self.nodes
    }

    /// Returns exported outputs in canonical identifier order.
    #[must_use]
    pub fn exported_outputs(&self) -> &[SignalId] {
        &self.exported_outputs
    }

    /// Returns the scenario-declared resource limits.
    #[must_use]
    pub const fn limits(&self) -> SignalResourceLimits {
        self.limits
    }

    /// Returns the content identity of this evaluator-versioned program.
    #[must_use]
    pub const fn id(&self) -> ContentHash {
        self.id
    }

    /// Returns the exact material used to compute [`Self::id`].
    #[must_use]
    pub fn canonical_material(&self) -> &str {
        &self.canonical_material
    }

    /// Returns the static shape of an exported output.
    #[must_use]
    pub fn exported_shape(&self, id: &SignalId) -> Option<&SignalShape> {
        if self.exported_outputs.binary_search(id).is_err() {
            return None;
        }
        self.nodes
            .iter()
            .find(|node| &node.id == id)
            .map(|node| &node.output)
    }

    /// Returns an exported node's complete validated declaration.
    #[must_use]
    pub fn exported_node(&self, id: &SignalId) -> Option<&SignalNode> {
        if self.exported_outputs.binary_search(id).is_err() {
            return None;
        }
        self.nodes.iter().find(|node| &node.id == id)
    }
}
