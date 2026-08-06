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
use std::fmt;

use super::ContentHash;

mod adapter_runtime;
mod authoring;
mod binding;
mod binding_runtime;
mod canonical;
mod effect;
mod effect_parameters;
mod effect_registry;
mod error;
mod evaluator;
mod execution_runtime;
mod host_action_sink;
mod network_effect;
mod node_effect;
mod opportunity;
mod plan;
mod runtime;
mod sampler;
mod search_materialization;
mod spatial;
mod storage_effect;
#[cfg(test)]
mod tests;
mod trace;
mod trace_import;
mod wire;

pub use adapter_runtime::*;
pub(crate) use authoring::*;
pub use binding::*;
pub use binding_runtime::*;
use canonical::program_material;
pub use effect::*;
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
pub use runtime::*;
pub use sampler::*;
pub use search_materialization::*;
pub use spatial::*;
pub use storage_effect::*;
pub use trace::*;
pub use trace_import::*;
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
pub const HARD_SIGNAL_AUTHORED_PAYLOAD_BYTES_LIMIT: u64 = 67_108_864;

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
            authored_payload_bytes: 16_777_216,
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

/// Stable author-supplied identifier used by signal nodes and exported outputs.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct SignalId(String);

impl SignalId {
    /// Parses a canonical signal identifier.
    ///
    /// Identifiers contain 1 through 96 ASCII bytes. They begin with a lower
    /// case letter and otherwise contain lower case letters, digits, or single
    /// hyphens separating non-empty components.
    ///
    /// # Errors
    ///
    /// Returns [`SignalProgramError::InvalidId`] when `value` is not canonical.
    pub fn parse(value: impl Into<String>) -> Result<Self, SignalProgramError> {
        let value = value.into();
        if !valid_signal_id(&value) {
            return Err(SignalProgramError::InvalidId { value });
        }
        Ok(Self(value))
    }

    /// Returns the canonical identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> serde::Deserialize<'de> for SignalId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for SignalId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

fn valid_signal_id(value: &str) -> bool {
    if value.is_empty() || value.len() > 96 || !value.is_ascii() {
        return false;
    }
    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_lowercase() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return false;
    }
    let mut previous_hyphen = false;
    for byte in bytes {
        let hyphen = *byte == b'-';
        if !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || hyphen)
            || (hyphen && previous_hyphen)
        {
            return false;
        }
        previous_hyphen = hyphen;
    }
    true
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
        payload: Vec<u8>,
    },
    /// Two numeric components.
    Vector2(Vec<SignalValue>),
    /// Three numeric components.
    Vector3(Vec<SignalValue>),
    /// Bounded opaque bytes.
    Bytes(Vec<u8>),
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

fn validate_and_order(
    nodes: Vec<SignalNode>,
    exports: &[SignalId],
    limits: SignalResourceLimits,
) -> Result<Vec<SignalNode>, SignalProgramError> {
    let node_count = u64::try_from(nodes.len()).map_err(|_| SignalProgramError::CountOverflow {
        field: "signal_nodes",
    })?;
    if node_count > u64::from(limits.nodes) {
        return Err(SignalProgramError::ResourceExceeded {
            field: "signal_nodes",
            current: node_count,
            requested: node_count,
            configured: u64::from(limits.nodes),
            hard: u64::from(HARD_SIGNAL_NODE_LIMIT),
        });
    }
    if exports.is_empty() {
        return Err(SignalProgramError::NoExportedOutputs);
    }

    let mut by_id = BTreeMap::new();
    let mut edge_count = 0_u64;
    let mut state_bytes = 0_u64;
    let mut authored_payload_bytes = 0_u64;
    for mut node in nodes {
        canonicalize_node_inputs(&mut node);
        node.output.validate()?;
        let input_count =
            u64::try_from(node.inputs.len()).map_err(|_| SignalProgramError::CountOverflow {
                field: "signal_inputs_per_node",
            })?;
        if input_count > u64::from(limits.inputs_per_node) {
            return Err(SignalProgramError::NodeInputLimit {
                id: node.id.clone(),
                current: input_count,
                configured: u64::from(limits.inputs_per_node),
                hard: u64::from(HARD_SIGNAL_INPUTS_PER_NODE_LIMIT),
            });
        }
        edge_count =
            edge_count
                .checked_add(input_count)
                .ok_or(SignalProgramError::CountOverflow {
                    field: "signal_edges",
                })?;
        validate_node_contract(&node, limits)?;
        let node_payload_bytes = encoded_node_parameter_bytes(&node)?;
        authored_payload_bytes = authored_payload_bytes
            .checked_add(node_payload_bytes)
            .ok_or(SignalProgramError::CountOverflow {
                field: "signal_authored_payload_bytes",
            })?;
        if let SignalNodeKind::Stateful {
            state_bytes: node_state_bytes,
            ..
        } = &node.kind
        {
            state_bytes = state_bytes.checked_add(*node_state_bytes).ok_or(
                SignalProgramError::CountOverflow {
                    field: "signal_state_bytes",
                },
            )?;
        }
        let id = node.id.clone();
        if by_id.insert(id.clone(), node).is_some() {
            return Err(SignalProgramError::DuplicateNode { id });
        }
    }
    check_resource(
        "signal_edges",
        edge_count,
        u64::from(limits.edges),
        u64::from(HARD_SIGNAL_EDGE_LIMIT),
    )?;
    check_resource(
        "signal_state_bytes",
        state_bytes,
        limits.state_bytes,
        HARD_SIGNAL_STATE_BYTES_LIMIT,
    )?;
    check_resource(
        "signal_authored_payload_bytes",
        authored_payload_bytes,
        limits.authored_payload_bytes,
        HARD_SIGNAL_AUTHORED_PAYLOAD_BYTES_LIMIT,
    )?;

    for export in exports {
        if !by_id.contains_key(export) {
            return Err(SignalProgramError::MissingExport { id: export.clone() });
        }
    }
    for node in by_id.values() {
        for (index, input) in node.inputs.iter().enumerate() {
            let source = by_id
                .get(input)
                .ok_or_else(|| SignalProgramError::MissingInput {
                    node: node.id.clone(),
                    input: input.clone(),
                })?;
            validate_edge_contract(node, source, index)?;
        }
        validate_input_group(node, &by_id)?;
    }

    let reachable = reachable_nodes(&by_id, exports)?;
    if let Some(id) = by_id.keys().find(|id| !reachable.contains(*id)) {
        return Err(SignalProgramError::UnreferencedNode { id: (*id).clone() });
    }
    topological_order(by_id, limits.graph_depth)
}

fn encoded_node_parameter_bytes(node: &SignalNode) -> Result<u64, SignalProgramError> {
    struct Counter {
        bytes: u64,
    }

    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let length = u64::try_from(bytes.len()).map_err(|_| {
                std::io::Error::other("signal authored payload byte count overflowed")
            })?;
            self.bytes = self.bytes.checked_add(length).ok_or_else(|| {
                std::io::Error::other("signal authored payload byte count overflowed")
            })?;
            if self.bytes > HARD_SIGNAL_AUTHORED_PAYLOAD_BYTES_LIMIT {
                return Err(std::io::Error::other(
                    "signal authored payload exceeds compiled hard ceiling",
                ));
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut counter = Counter { bytes: 0 };
    serde_json::to_writer(&mut counter, &node.kind).map_err(|_| {
        SignalProgramError::ResourceExceeded {
            field: "signal_authored_payload_bytes",
            current: counter.bytes,
            requested: counter.bytes,
            configured: HARD_SIGNAL_AUTHORED_PAYLOAD_BYTES_LIMIT,
            hard: HARD_SIGNAL_AUTHORED_PAYLOAD_BYTES_LIMIT,
        }
    })?;
    Ok(counter.bytes)
}

fn canonicalize_node_inputs(node: &mut SignalNode) {
    let commutative = matches!(
        &node.kind,
        SignalNodeKind::Pure(PureSignalSpecification::Simple {
            operator: PureSignalOperator::Add
                | PureSignalOperator::Min
                | PureSignalOperator::Max
                | PureSignalOperator::Equal
                | PureSignalOperator::NotEqual
                | PureSignalOperator::All
                | PureSignalOperator::Any,
            ..
        }) | SignalNodeKind::Pure(PureSignalSpecification::MergeEvents { .. })
    );
    if commutative {
        node.inputs.sort();
    }
}

fn check_resource(
    field: &'static str,
    current: u64,
    configured: u64,
    hard: u64,
) -> Result<(), SignalProgramError> {
    if current > configured {
        return Err(SignalProgramError::ResourceExceeded {
            field,
            current,
            requested: current,
            configured,
            hard,
        });
    }
    Ok(())
}

fn validate_node_contract(
    node: &SignalNode,
    limits: SignalResourceLimits,
) -> Result<(), SignalProgramError> {
    match &node.kind {
        SignalNodeKind::Constant { value } => {
            if !node.inputs.is_empty() {
                return Err(SignalProgramError::InvalidInputCount {
                    node: node.id.clone(),
                    expected: "zero",
                    actual: node.inputs.len(),
                });
            }
            let actual = value
                .value_type()
                .ok_or_else(|| SignalProgramError::InvalidValue {
                    node: node.id.clone(),
                })?;
            if actual != node.output.value_type {
                return Err(SignalProgramError::LiteralTypeMismatch {
                    node: node.id.clone(),
                    declared: node.output.value_type.material(),
                    actual: actual.material(),
                });
            }
            return Ok(());
        }
        SignalNodeKind::Source(specification) => {
            let expected_inputs = match specification {
                SignalSourceSpecification::TransmitterField {
                    position_signal,
                    orientation_signal,
                    environment_signals,
                    ..
                } => {
                    let mut expected = vec![position_signal.clone()];
                    expected.extend(orientation_signal.iter().cloned());
                    expected.extend(environment_signals.iter().cloned());
                    expected
                }
                _ => Vec::new(),
            };
            if node.inputs != expected_inputs {
                return Err(SignalProgramError::InvalidInputCount {
                    node: node.id.clone(),
                    expected: "the source schema's referenced signals in field order",
                    actual: node.inputs.len(),
                });
            }
            validate_source(node, specification, limits)?;
        }
        SignalNodeKind::Pure(specification) => validate_pure(node, specification, limits)?,
        SignalNodeKind::Stateful {
            specification,
            state_bytes,
        } => {
            if *state_bytes == 0 {
                return Err(SignalProgramError::ZeroStateBound {
                    node: node.id.clone(),
                });
            }
            validate_stateful(node, specification, limits)?;
        }
    }
    validate_operator_arity(node)
}

fn validate_source(
    node: &SignalNode,
    specification: &SignalSourceSpecification,
    limits: SignalResourceLimits,
) -> Result<(), SignalProgramError> {
    let valid_value =
        |value: &SignalValue| value.value_type().as_ref() == Some(&node.output.value_type);
    let valid_point = |point: &SignalPoint| {
        coordinate_domain(&point.coordinate) == node.domain && valid_value(&point.value)
    };
    let valid = match specification {
        SignalSourceSpecification::Step { points, before } => {
            point_count_valid(points.len(), limits.lookup_points_per_node)
                && points.iter().all(valid_point)
                && ordered_points(points)
                && boundary_valid(before, &node.output.value_type)
        }
        SignalSourceSpecification::Pulse {
            start,
            duration,
            inactive,
            active,
        } => {
            coordinate_domain(start) == node.domain
                && *duration > 0
                && valid_value(inactive)
                && valid_value(active)
        }
        SignalSourceSpecification::PeriodicPulse {
            epoch,
            period,
            width,
            phase,
            inactive,
            active,
        } => {
            coordinate_domain(epoch) == node.domain
                && *period > 0
                && *width <= *period
                && *phase < *period
                && valid_value(inactive)
                && valid_value(active)
        }
        SignalSourceSpecification::Ramp {
            start,
            end,
            start_value,
            end_value,
            ..
        } => {
            coordinate_domain(start) == node.domain
                && coordinate_domain(end) == node.domain
                && start < end
                && valid_value(start_value)
                && valid_value(end_value)
                && node.output.value_type.is_numeric()
        }
        SignalSourceSpecification::Triangle {
            epoch,
            period,
            phase,
            minimum,
            maximum,
            ..
        }
        | SignalSourceSpecification::Sawtooth {
            epoch,
            period,
            phase,
            minimum,
            maximum,
            ..
        } => {
            coordinate_domain(epoch) == node.domain
                && *period > 0
                && *phase < *period
                && valid_value(minimum)
                && valid_value(maximum)
                && minimum < maximum
                && node.output.value_type.is_numeric()
        }
        SignalSourceSpecification::EventSequence { events } => {
            matches!(node.output.value_type, SignalValueType::Event(_))
                && point_count_valid(events.len(), limits.lookup_points_per_node)
                && events.iter().all(valid_point)
                && ordered_points(events)
        }
        SignalSourceSpecification::Trace {
            quality_channel,
            quality_accept,
            time_mapping,
            interpolation,
            missing,
            before,
            after,
            ..
        } => {
            quality_channel.is_some() == quality_accept.is_some()
                && time_mapping_valid(time_mapping)
                && (*missing != MissingSampleBehavior::Interpolate
                    || !matches!(interpolation, SignalInterpolation::Exact))
                && boundary_valid(before, &node.output.value_type)
                && boundary_valid(after, &node.output.value_type)
        }
        SignalSourceSpecification::Telemetry { boundary_delay, .. } => *boundary_delay == 1,
        SignalSourceSpecification::PointSet {
            interpolation,
            outside,
            ..
        } => {
            node.domain == SignalDomain::Spatial
                && spatial_interpolation_valid(*interpolation, &node.output.value_type)
                && spatial_boundary_valid(outside, &node.output.value_type)
        }
        SignalSourceSpecification::ZoneMap {
            boundary, overlap, ..
        } => {
            node.domain == SignalDomain::Spatial
                && matches!(boundary.as_str(), "inclusive" | "exclusive")
                && overlap.as_str() == "priority-then-id"
        }
        SignalSourceSpecification::PathProfile {
            interpolation,
            before,
            after,
            ..
        } => {
            node.domain == SignalDomain::Spatial
                && spatial_interpolation_valid(*interpolation, &node.output.value_type)
                && spatial_boundary_valid(before, &node.output.value_type)
                && spatial_boundary_valid(after, &node.output.value_type)
        }
        SignalSourceSpecification::RegularGrid {
            cell_size_mm,
            dimensions,
            interpolation,
            outside,
            ..
        } => {
            node.domain == SignalDomain::Spatial
                && cell_size_mm.iter().all(|value| *value > 0)
                && dimensions.iter().all(|value| *value > 0)
                && spatial_interpolation_valid(*interpolation, &node.output.value_type)
                && spatial_boundary_valid(outside, &node.output.value_type)
        }
        SignalSourceSpecification::TiledGrid {
            tile_size_mm,
            interpolation,
            outside,
            ..
        } => {
            node.domain == SignalDomain::Spatial
                && tile_size_mm.iter().all(|value| *value > 0)
                && spatial_interpolation_valid(*interpolation, &node.output.value_type)
                && spatial_boundary_valid(outside, &node.output.value_type)
        }
        SignalSourceSpecification::SeededField {
            quantization_mm,
            correlation_mm,
            distribution,
            distribution_parameters,
            ..
        } => {
            node.domain == SignalDomain::Spatial
                && quantization_mm.iter().all(|value| *value > 0)
                && correlation_mm.iter().all(|value| *value > 0)
                && seeded_distribution_valid(
                    distribution,
                    distribution_parameters,
                    &node.output.value_type,
                )
        }
        SignalSourceSpecification::TransmitterField { model, .. } => matches!(
            model.as_str(),
            "free-space" | "log-distance" | "two-ray" | "calibrated-lookup"
        ),
        SignalSourceSpecification::Bernoulli {
            probability_millionths,
            ..
        } => {
            *probability_millionths <= 1_000_000 && node.output.value_type == SignalValueType::Bool
        }
        SignalSourceSpecification::UniformInteger {
            minimum, maximum, ..
        } => minimum <= maximum && node.output.value_type == SignalValueType::I64,
        SignalSourceSpecification::ExponentialWait {
            rate,
            sampler_version,
            ..
        } => {
            *sampler_version == SIGNAL_EVALUATOR_VERSION
                && rate.numerator() > 0
                && node.output.value_type == SignalValueType::DurationNanos
        }
        SignalSourceSpecification::WeibullWait {
            shape,
            scale_nanos,
            sampler_version,
            ..
        } => {
            *sampler_version == SIGNAL_EVALUATOR_VERSION
                && shape.numerator() > 0
                && *scale_nanos > 0
                && node.output.value_type == SignalValueType::DurationNanos
        }
    };
    if !valid {
        return Err(SignalProgramError::InvalidSource {
            node: node.id.clone(),
        });
    }
    Ok(())
}

fn boundary_valid(boundary: &SignalBoundaryBehavior, value_type: &SignalValueType) -> bool {
    match boundary {
        SignalBoundaryBehavior::Constant(value) => value.value_type().as_ref() == Some(value_type),
        SignalBoundaryBehavior::Error
        | SignalBoundaryBehavior::Hold
        | SignalBoundaryBehavior::Repeat
        | SignalBoundaryBehavior::Inactive => true,
    }
}

fn spatial_boundary_valid(boundary: &SignalBoundaryBehavior, value_type: &SignalValueType) -> bool {
    !matches!(boundary, SignalBoundaryBehavior::Repeat) && boundary_valid(boundary, value_type)
}

fn spatial_interpolation_valid(
    interpolation: SignalInterpolation,
    value_type: &SignalValueType,
) -> bool {
    !matches!(interpolation, SignalInterpolation::Linear { .. }) || value_type.is_numeric()
}

fn seeded_distribution_valid(
    distribution: &SignalId,
    parameters: &[i64],
    value_type: &SignalValueType,
) -> bool {
    match distribution.as_str() {
        "uniform-integer" => {
            value_type == &SignalValueType::I64
                && parameters.len() == 2
                && parameters[0] <= parameters[1]
        }
        "probability-millionths" => {
            value_type == &SignalValueType::ProbabilityMillionths
                && parameters.len() == 1
                && (0..=1_000_000).contains(&parameters[0])
        }
        "signed-hash" => value_type == &SignalValueType::I64 && parameters.is_empty(),
        _ => false,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SignalDimension {
    Dimensionless,
    Time,
    Length,
    SquareLength,
    Velocity,
    Angle,
    Temperature,
    Voltage,
    Current,
    Power,
    Energy,
    LogRatio,
    AbsoluteRadioPower,
    Frequency,
    DataRate,
    OperationRate,
    Concentration,
    Probability,
    Acceleration,
    Precipitation,
}

fn compatible_units(from: SignalUnit, to: SignalUnit) -> bool {
    unit_dimension(from) == unit_dimension(to)
}

fn unit_dimension(unit: SignalUnit) -> SignalDimension {
    match unit {
        SignalUnit::Dimensionless => SignalDimension::Dimensionless,
        SignalUnit::VirtualNanoseconds => SignalDimension::Time,
        SignalUnit::Millimetres => SignalDimension::Length,
        SignalUnit::SquareMillimetres => SignalDimension::SquareLength,
        SignalUnit::MillimetresPerSecond => SignalDimension::Velocity,
        SignalUnit::Millidegrees => SignalDimension::Angle,
        SignalUnit::Millicelsius => SignalDimension::Temperature,
        SignalUnit::Microvolts => SignalDimension::Voltage,
        SignalUnit::Microamps => SignalDimension::Current,
        SignalUnit::Microwatts | SignalUnit::Femtowatts => SignalDimension::Power,
        SignalUnit::Microjoules => SignalDimension::Energy,
        SignalUnit::Millidecibels => SignalDimension::LogRatio,
        SignalUnit::MillidecibelMilliwatts => SignalDimension::AbsoluteRadioPower,
        SignalUnit::Kilohertz => SignalDimension::Frequency,
        SignalUnit::BitsPerSecond | SignalUnit::BytesPerSecond => SignalDimension::DataRate,
        SignalUnit::OperationsPerSecond => SignalDimension::OperationRate,
        SignalUnit::PartsPerMillion => SignalDimension::Concentration,
        SignalUnit::ProbabilityMillionths => SignalDimension::Probability,
        SignalUnit::MicrometresPerSecondSquared => SignalDimension::Acceleration,
        SignalUnit::MicrometresPerHour => SignalDimension::Precipitation,
    }
}

fn coordinate_domain(coordinate: &SignalCoordinate) -> SignalDomain {
    match coordinate {
        SignalCoordinate::VirtualTime { .. } => SignalDomain::VirtualTime,
        SignalCoordinate::NodeCounter { .. } => SignalDomain::NodeCounter,
        SignalCoordinate::Operation { .. } => SignalDomain::Operation,
        SignalCoordinate::Spatial { .. } => SignalDomain::Spatial,
        SignalCoordinate::Event { .. } => SignalDomain::Event,
        SignalCoordinate::State { .. } => SignalDomain::State,
    }
}

fn ordered_points(points: &[SignalPoint]) -> bool {
    points.windows(2).all(|pair| {
        pair[0].coordinate < pair[1].coordinate
            || (pair[0].coordinate == pair[1].coordinate && pair[0].sequence < pair[1].sequence)
    })
}

fn time_mapping_valid(mapping: &Option<TraceTimeMapping>) -> bool {
    mapping
        .as_ref()
        .is_none_or(|mapping| mapping.scale.numerator() > 0)
}

fn validate_pure(
    node: &SignalNode,
    specification: &PureSignalSpecification,
    limits: SignalResourceLimits,
) -> Result<(), SignalProgramError> {
    let valid = match specification {
        PureSignalSpecification::Simple { operator, .. } => matches!(
            operator,
            PureSignalOperator::Add
                | PureSignalOperator::Subtract
                | PureSignalOperator::Absolute
                | PureSignalOperator::Negate
                | PureSignalOperator::Min
                | PureSignalOperator::Max
                | PureSignalOperator::Equal
                | PureSignalOperator::NotEqual
                | PureSignalOperator::Less
                | PureSignalOperator::LessEqual
                | PureSignalOperator::Greater
                | PureSignalOperator::GreaterEqual
                | PureSignalOperator::All
                | PureSignalOperator::Any
                | PureSignalOperator::Not
                | PureSignalOperator::Select
                | PureSignalOperator::EdgeRising
                | PureSignalOperator::EdgeFalling
        ),
        PureSignalSpecification::RatioArithmetic {
            operator, ratio, ..
        } => {
            matches!(
                operator,
                PureSignalOperator::MultiplyRatio | PureSignalOperator::DivideRatio
            ) && !(*operator == PureSignalOperator::DivideRatio && ratio.numerator() == 0)
        }
        PureSignalSpecification::Clamp {
            minimum, maximum, ..
        } => {
            minimum.value_type().as_ref() == Some(&node.output.value_type)
                && maximum.value_type().as_ref() == Some(&node.output.value_type)
                && minimum <= maximum
        }
        PureSignalSpecification::LookupStep {
            points,
            before,
            after,
        } => {
            point_count_valid(points.len(), limits.lookup_points_per_node)
                && points.windows(2).all(|pair| pair[0].0 < pair[1].0)
                && points.iter().all(|(_, output)| {
                    output.value_type().as_ref() == Some(&node.output.value_type)
                })
                && boundary_valid(before, &node.output.value_type)
                && boundary_valid(after, &node.output.value_type)
        }
        PureSignalSpecification::PiecewiseLinear { points, .. } => {
            point_count_valid(points.len(), limits.lookup_points_per_node)
                && points.windows(2).all(|pair| pair[0].0 < pair[1].0)
                && node.output.value_type.is_numeric()
                && points.iter().all(|(_, output)| {
                    output.value_type().as_ref() == Some(&node.output.value_type)
                })
        }
        PureSignalSpecification::EnumMap { entries } => {
            point_count_valid(entries.len(), limits.lookup_points_per_node)
                && entries.windows(2).all(|pair| pair[0].0 < pair[1].0)
                && entries.iter().all(|(_, output)| {
                    output.value_type().as_ref() == Some(&node.output.value_type)
                })
        }
        PureSignalSpecification::UnitConvert {
            from_unit, to_unit, ..
        } => compatible_units(*from_unit, *to_unit) && *to_unit == node.output.unit,
        PureSignalSpecification::Delay {
            delay,
            retained_samples,
        } => *delay > 0 && *retained_samples > 0,
        PureSignalSpecification::SampleHold {
            cadence,
            epoch,
            retained_samples,
        } => *cadence > 0 && *retained_samples > 0 && coordinate_domain(epoch) == node.domain,
        PureSignalSpecification::Window {
            operator,
            window,
            retained_samples,
            ..
        } => {
            matches!(
                operator,
                PureSignalOperator::WindowMin
                    | PureSignalOperator::WindowMax
                    | PureSignalOperator::WindowMean
            ) && *window > 0
                && *retained_samples > 0
        }
        PureSignalSpecification::Distance { metric, .. } => {
            matches!(
                metric.as_str(),
                "manhattan" | "euclidean" | "euclidean-squared"
            )
        }
        PureSignalSpecification::OrientationDelta { convention } => {
            convention.as_str() == "yaw-pitch-roll-millidegrees"
        }
        PureSignalSpecification::ZoneContains { .. } | PureSignalSpecification::FieldSample => true,
        PureSignalSpecification::MergeEvents {
            source_sequence_limit,
        } => {
            *source_sequence_limit > 0
                && matches!(node.output.value_type, SignalValueType::Event(_))
                && u64::try_from(node.inputs.len())
                    .is_ok_and(|count| count.checked_mul(*source_sequence_limit).is_some())
        }
        PureSignalSpecification::GateEvents => {
            matches!(node.output.value_type, SignalValueType::Event(_))
        }
    };
    if !valid {
        return Err(SignalProgramError::InvalidOperator {
            node: node.id.clone(),
        });
    }
    Ok(())
}

fn validate_stateful(
    node: &SignalNode,
    specification: &StatefulSignalSpecification,
    limits: SignalResourceLimits,
) -> Result<(), SignalProgramError> {
    let expected_inputs = match specification {
        StatefulSignalSpecification::MarkovChain { .. }
        | StatefulSignalSpecification::BurstProcess { .. } => 0,
        StatefulSignalSpecification::QueueModel { .. } => 2,
        StatefulSignalSpecification::FiniteStateMachine { transitions, .. } => {
            let guards = transitions
                .iter()
                .filter_map(|transition| transition.guard.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            if node.inputs.get(1..) != Some(guards.as_slice()) {
                return Err(SignalProgramError::InvalidStatefulOperator {
                    node: node.id.clone(),
                });
            }
            node.inputs.len()
        }
        _ => 1,
    };
    if node.inputs.len() != expected_inputs {
        return Err(SignalProgramError::InvalidInputCount {
            node: node.id.clone(),
            expected: match expected_inputs {
                0 => "zero",
                1 => "one",
                2 => "two",
                _ => "the registered number of",
            },
            actual: node.inputs.len(),
        });
    }
    let valid = match specification {
        StatefulSignalSpecification::Hysteresis {
            set_when,
            clear_when,
            ..
        } => {
            node.output.value_type == SignalValueType::Bool
                && set_when.value_type() == clear_when.value_type()
                && clear_when < set_when
        }
        StatefulSignalSpecification::Debounce {
            initial,
            residence_nanos,
        } => initial.value_type().as_ref() == Some(&node.output.value_type) && *residence_nanos > 0,
        StatefulSignalSpecification::Integrator {
            initial,
            time_unit_nanos,
            ..
        } => {
            initial.value_type().as_ref() == Some(&node.output.value_type)
                && node.output.value_type.is_numeric()
                && *time_unit_nanos > 0
        }
        StatefulSignalSpecification::LeakyIntegrator {
            initial,
            cadence_nanos,
            time_unit_nanos,
            maximum_catch_up_steps,
            ..
        } => {
            initial.value_type().as_ref() == Some(&node.output.value_type)
                && node.output.value_type.is_numeric()
                && *cadence_nanos > 0
                && *time_unit_nanos > 0
                && *maximum_catch_up_steps > 0
        }
        StatefulSignalSpecification::FiniteStateMachine {
            states,
            initial,
            transitions,
            ..
        } => {
            matches!(node.output.value_type, SignalValueType::Enum(_))
                && point_count_valid(states.len(), limits.states_per_node)
                && sorted_unique(states)
                && states.contains(initial)
                && point_count_valid(transitions.len(), limits.transitions_per_node)
                && transitions.iter().all(|transition| {
                    states.contains(&transition.from)
                        && states.contains(&transition.to)
                        && transition
                            .timer_operations
                            .iter()
                            .all(|operation| match operation {
                                StateMachineTimerOperation::Start { duration_nanos, .. } => {
                                    *duration_nanos > 0
                                }
                                StateMachineTimerOperation::Cancel { .. } => true,
                            })
                })
                && transitions.windows(2).all(|pair| {
                    (&pair[0].from, &pair[0].event, &pair[0].guard)
                        < (&pair[1].from, &pair[1].event, &pair[1].guard)
                })
        }
        StatefulSignalSpecification::MarkovChain {
            states,
            initial,
            probability_rows,
            ..
        } => {
            matches!(node.output.value_type, SignalValueType::Enum(_))
                && point_count_valid(states.len(), limits.states_per_node)
                && sorted_unique(states)
                && states.contains(initial)
                && probability_rows.len() == states.len()
                && probability_rows.iter().all(|row| {
                    row.len() == states.len()
                        && row.iter().all(|value| *value <= 1_000_000)
                        && row.iter().map(|value| u64::from(*value)).sum::<u64>() == 1_000_000
                })
        }
        StatefulSignalSpecification::BurstProcess {
            good_to_bad_millionths,
            bad_to_good_millionths,
            ..
        } => {
            node.output.value_type == SignalValueType::Bool
                && *good_to_bad_millionths <= 1_000_000
                && *bad_to_good_millionths <= 1_000_000
        }
        StatefulSignalSpecification::Counter {
            initial, maximum, ..
        } => {
            initial <= maximum
                && node.output.value_type == SignalValueType::U64
                && node.output.unit == SignalUnit::Dimensionless
                && node.output.scale_decimal_exponent == 0
        }
        StatefulSignalSpecification::QueueModel { capacity, .. } => {
            *capacity > 0
                && node.output.value_type == SignalValueType::U64
                && node.output.unit == SignalUnit::Dimensionless
                && node.output.scale_decimal_exponent == 0
        }
    };
    if !valid {
        return Err(SignalProgramError::InvalidStatefulOperator {
            node: node.id.clone(),
        });
    }
    Ok(())
}

fn sorted_unique(values: &[SignalId]) -> bool {
    !values.is_empty() && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn point_count_valid(count: usize, configured: u32) -> bool {
    count > 0 && u32::try_from(count).is_ok_and(|count| count <= configured)
}

impl PureSignalSpecification {
    fn operator(&self) -> PureSignalOperator {
        match self {
            Self::Simple { operator, .. }
            | Self::RatioArithmetic { operator, .. }
            | Self::Window { operator, .. } => *operator,
            Self::Clamp { .. } => PureSignalOperator::Clamp,
            Self::LookupStep { .. } => PureSignalOperator::LookupStep,
            Self::PiecewiseLinear { .. } => PureSignalOperator::PiecewiseLinear,
            Self::EnumMap { .. } => PureSignalOperator::EnumMap,
            Self::UnitConvert { .. } => PureSignalOperator::UnitConvert,
            Self::Delay { .. } => PureSignalOperator::Delay,
            Self::SampleHold { .. } => PureSignalOperator::SampleHold,
            Self::Distance { .. } => PureSignalOperator::Distance,
            Self::ZoneContains { .. } => PureSignalOperator::ZoneContains,
            Self::FieldSample => PureSignalOperator::FieldSample,
            Self::OrientationDelta { .. } => PureSignalOperator::OrientationDelta,
            Self::MergeEvents { .. } => PureSignalOperator::MergeEvents,
            Self::GateEvents => PureSignalOperator::GateEvents,
        }
    }
}

fn validate_operator_arity(node: &SignalNode) -> Result<(), SignalProgramError> {
    let SignalNodeKind::Pure(specification) = &node.kind else {
        return Ok(());
    };
    let operator = specification.operator();
    let (minimum, maximum, expected) = match operator {
        PureSignalOperator::Add
        | PureSignalOperator::Min
        | PureSignalOperator::Max
        | PureSignalOperator::All
        | PureSignalOperator::Any
        | PureSignalOperator::MergeEvents => (1, usize::MAX, "one or more"),
        PureSignalOperator::Subtract
        | PureSignalOperator::Equal
        | PureSignalOperator::NotEqual
        | PureSignalOperator::Less
        | PureSignalOperator::LessEqual
        | PureSignalOperator::Greater
        | PureSignalOperator::GreaterEqual
        | PureSignalOperator::Distance
        | PureSignalOperator::ZoneContains
        | PureSignalOperator::FieldSample
        | PureSignalOperator::OrientationDelta
        | PureSignalOperator::GateEvents => (2, 2, "two"),
        PureSignalOperator::Select => (3, 3, "three"),
        _ => (1, 1, "one"),
    };
    if node.inputs.len() < minimum || node.inputs.len() > maximum {
        return Err(SignalProgramError::InvalidInputCount {
            node: node.id.clone(),
            expected,
            actual: node.inputs.len(),
        });
    }
    Ok(())
}

fn validate_edge_contract(
    node: &SignalNode,
    source: &SignalNode,
    index: usize,
) -> Result<(), SignalProgramError> {
    if node.domain != source.domain && !cross_domain_operator(&node.kind) {
        return Err(SignalProgramError::ImplicitDomainCrossing {
            node: node.id.clone(),
            input: source.id.clone(),
            node_domain: node.domain,
            input_domain: source.domain,
        });
    }
    let SignalNodeKind::Pure(specification) = &node.kind else {
        return Ok(());
    };
    let operator = specification.operator();
    let same_shape = source.output == node.output;
    let boolean = SignalValueType::Bool;
    let shape_ok = match operator {
        PureSignalOperator::Add
        | PureSignalOperator::Subtract
        | PureSignalOperator::Min
        | PureSignalOperator::Max
        | PureSignalOperator::Clamp
        | PureSignalOperator::Absolute
        | PureSignalOperator::Negate
        | PureSignalOperator::MultiplyRatio
        | PureSignalOperator::DivideRatio
        | PureSignalOperator::Delay
        | PureSignalOperator::SampleHold
        | PureSignalOperator::WindowMin
        | PureSignalOperator::WindowMax
        | PureSignalOperator::WindowMean => same_shape && source.output.value_type.is_numeric(),
        PureSignalOperator::Equal
        | PureSignalOperator::NotEqual
        | PureSignalOperator::Less
        | PureSignalOperator::LessEqual
        | PureSignalOperator::Greater
        | PureSignalOperator::GreaterEqual => {
            node.output.value_type == boolean && node.output.unit == SignalUnit::Dimensionless
        }
        PureSignalOperator::All | PureSignalOperator::Any | PureSignalOperator::Not => {
            source.output.value_type == boolean
                && node.output.value_type == boolean
                && source.output.unit == SignalUnit::Dimensionless
                && node.output.unit == SignalUnit::Dimensionless
        }
        PureSignalOperator::Select => {
            if index == 0 {
                source.output.value_type == boolean
            } else {
                source.output == node.output
            }
        }
        PureSignalOperator::EdgeRising | PureSignalOperator::EdgeFalling => {
            source.output.value_type == boolean
                && matches!(node.output.value_type, SignalValueType::Event(_))
        }
        PureSignalOperator::GateEvents => {
            if index == 0 {
                matches!(source.output.value_type, SignalValueType::Event(_))
                    && source.output == node.output
            } else {
                source.output.value_type == boolean
            }
        }
        PureSignalOperator::MergeEvents => source.output == node.output,
        PureSignalOperator::UnitConvert
        | PureSignalOperator::LookupStep
        | PureSignalOperator::PiecewiseLinear
        | PureSignalOperator::EnumMap
        | PureSignalOperator::Distance
        | PureSignalOperator::ZoneContains
        | PureSignalOperator::FieldSample
        | PureSignalOperator::OrientationDelta => true,
    };
    if !shape_ok {
        return Err(SignalProgramError::InputShapeMismatch {
            node: node.id.clone(),
            input: source.id.clone(),
            input_shape: source.output.material(),
            output_shape: node.output.material(),
        });
    }
    if matches!(
        operator,
        PureSignalOperator::Absolute | PureSignalOperator::Negate
    ) && !source.output.value_type.is_signed()
    {
        return Err(SignalProgramError::SignedInputRequired {
            node: node.id.clone(),
        });
    }
    Ok(())
}

fn validate_input_group(
    node: &SignalNode,
    nodes: &BTreeMap<SignalId, SignalNode>,
) -> Result<(), SignalProgramError> {
    let inputs = node
        .inputs
        .iter()
        .map(|id| {
            nodes
                .get(id)
                .ok_or_else(|| SignalProgramError::MissingInput {
                    node: node.id.clone(),
                    input: id.clone(),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if let SignalNodeKind::Stateful { specification, .. } = &node.kind {
        let valid = match specification {
            StatefulSignalSpecification::Hysteresis {
                set_when,
                clear_when,
                ..
            } => inputs.first().is_some_and(|input| {
                input.output.value_type.is_numeric()
                    && set_when.value_type().as_ref() == Some(&input.output.value_type)
                    && clear_when.value_type().as_ref() == Some(&input.output.value_type)
            }),
            StatefulSignalSpecification::Debounce { .. } => inputs
                .first()
                .is_some_and(|input| input.output == node.output),
            StatefulSignalSpecification::Integrator { .. }
            | StatefulSignalSpecification::LeakyIntegrator { .. } => inputs
                .first()
                .is_some_and(|input| input.output.value_type.is_numeric()),
            StatefulSignalSpecification::FiniteStateMachine { .. } => {
                inputs.first().is_some_and(|input| {
                    matches!(input.output.value_type, SignalValueType::Event(_))
                }) && inputs.iter().skip(1).all(|input| {
                    input.output.value_type == SignalValueType::Bool
                        && input.output.unit == SignalUnit::Dimensionless
                })
            }
            StatefulSignalSpecification::MarkovChain { .. }
            | StatefulSignalSpecification::BurstProcess { .. } => inputs.is_empty(),
            StatefulSignalSpecification::Counter { .. } => inputs
                .first()
                .is_some_and(|input| matches!(input.output.value_type, SignalValueType::Event(_))),
            StatefulSignalSpecification::QueueModel { .. } => {
                inputs.first().is_some_and(|input| {
                    matches!(input.output.value_type, SignalValueType::Event(_))
                }) && inputs.get(1).is_some_and(|input| {
                    matches!(
                        input.output.value_type,
                        SignalValueType::RatePerSecond | SignalValueType::U64
                    )
                })
            }
        };
        if !valid {
            return Err(SignalProgramError::InputGroupMismatch {
                node: node.id.clone(),
            });
        }
        return Ok(());
    }
    if let SignalNodeKind::Source(SignalSourceSpecification::TransmitterField { .. }) = &node.kind {
        let position_valid = inputs.first().is_some_and(|input| {
            matches!(input.output.value_type, SignalValueType::Vector3(_))
                && input.output.unit == SignalUnit::Millimetres
        });
        let orientation_valid = match &node.kind {
            SignalNodeKind::Source(SignalSourceSpecification::TransmitterField {
                orientation_signal,
                ..
            }) if orientation_signal.is_some() => inputs.get(1).is_some_and(|input| {
                matches!(input.output.value_type, SignalValueType::Vector3(_))
                    && input.output.unit == SignalUnit::Millidegrees
            }),
            _ => true,
        };
        let environment_start = match &node.kind {
            SignalNodeKind::Source(SignalSourceSpecification::TransmitterField {
                orientation_signal,
                ..
            }) => 1 + usize::from(orientation_signal.is_some()),
            _ => 1,
        };
        let environments_valid = inputs[environment_start..]
            .iter()
            .all(|input| input.output == node.output);
        if !position_valid || !orientation_valid || !environments_valid {
            return Err(SignalProgramError::InputGroupMismatch {
                node: node.id.clone(),
            });
        }
        return Ok(());
    }
    let SignalNodeKind::Pure(specification) = &node.kind else {
        return Ok(());
    };
    let operator = specification.operator();
    let pair_equal = inputs
        .first()
        .is_none_or(|first| inputs.iter().all(|input| input.output == first.output));
    let valid = match operator {
        PureSignalOperator::Equal
        | PureSignalOperator::NotEqual
        | PureSignalOperator::Less
        | PureSignalOperator::LessEqual
        | PureSignalOperator::Greater
        | PureSignalOperator::GreaterEqual => {
            pair_equal
                && inputs
                    .first()
                    .is_some_and(|input| input.output.value_type.is_numeric())
        }
        PureSignalOperator::Select => {
            inputs
                .get(1)
                .zip(inputs.get(2))
                .is_some_and(|(when_true, when_false)| {
                    when_true.output == when_false.output && when_true.output == node.output
                })
        }
        PureSignalOperator::MergeEvents => pair_equal,
        PureSignalOperator::UnitConvert => {
            let PureSignalSpecification::UnitConvert {
                from_unit, to_unit, ..
            } = specification
            else {
                return Err(SignalProgramError::InvalidOperator {
                    node: node.id.clone(),
                });
            };
            inputs.first().is_some_and(|input| {
                input.output.unit == *from_unit
                    && node.output.unit == *to_unit
                    && input.output.value_type == node.output.value_type
                    && input.output.value_type.is_numeric()
            })
        }
        PureSignalOperator::EnumMap => inputs
            .first()
            .is_some_and(|input| matches!(input.output.value_type, SignalValueType::Enum(_))),
        PureSignalOperator::LookupStep | PureSignalOperator::PiecewiseLinear => {
            let points = match specification {
                PureSignalSpecification::LookupStep { points, .. }
                | PureSignalSpecification::PiecewiseLinear { points, .. } => points,
                _ => {
                    return Err(SignalProgramError::InvalidOperator {
                        node: node.id.clone(),
                    });
                }
            };
            inputs.first().is_some_and(|input| {
                input.output.value_type.is_numeric()
                    && points
                        .iter()
                        .all(|(key, _)| key.value_type().as_ref() == Some(&input.output.value_type))
            })
        }
        PureSignalOperator::FieldSample => {
            inputs
                .first()
                .zip(inputs.get(1))
                .is_some_and(|(field, position)| {
                    field.domain == SignalDomain::Spatial
                        && field.output == node.output
                        && is_position_shape(&position.output)
                        && position.output.unit == SignalUnit::Millimetres
                })
        }
        PureSignalOperator::ZoneContains => {
            inputs
                .first()
                .zip(inputs.get(1))
                .is_some_and(|(position, zones)| {
                    zones.domain == SignalDomain::Spatial
                        && matches!(zones.output.value_type, SignalValueType::Enum(_))
                        && is_position_shape(&position.output)
                        && position.output.unit == SignalUnit::Millimetres
                        && node.output.value_type == SignalValueType::Bool
                })
        }
        PureSignalOperator::Distance => {
            let PureSignalSpecification::Distance { metric, .. } = specification else {
                return Err(SignalProgramError::InvalidOperator {
                    node: node.id.clone(),
                });
            };
            inputs
                .first()
                .zip(inputs.get(1))
                .is_some_and(|(left, right)| {
                    left.output == right.output
                        && is_position_shape(&left.output)
                        && left.output.unit == SignalUnit::Millimetres
                        && node.output.value_type == SignalValueType::I64
                        && node.output.scale_decimal_exponent == left.output.scale_decimal_exponent
                        && node.output.unit
                            == if metric.as_str() == "euclidean-squared" {
                                SignalUnit::SquareMillimetres
                            } else {
                                SignalUnit::Millimetres
                            }
                })
        }
        PureSignalOperator::OrientationDelta => {
            inputs
                .first()
                .zip(inputs.get(1))
                .is_some_and(|(left, right)| {
                    left.output == right.output
                        && matches!(
                            left.output.value_type,
                            SignalValueType::Vector3(ref element)
                                if element.as_ref() == &SignalValueType::I64
                        )
                        && left.output.unit == SignalUnit::Millidegrees
                        && node.output == left.output
                })
        }
        _ => true,
    };
    if !valid {
        return Err(SignalProgramError::InputGroupMismatch {
            node: node.id.clone(),
        });
    }
    Ok(())
}

fn is_position_shape(shape: &SignalShape) -> bool {
    matches!(
        &shape.value_type,
        SignalValueType::Vector2(element) | SignalValueType::Vector3(element)
            if element.as_ref() == &SignalValueType::I64
    )
}

fn cross_domain_operator(kind: &SignalNodeKind) -> bool {
    matches!(
        kind,
        SignalNodeKind::Pure(PureSignalSpecification::FieldSample)
            | SignalNodeKind::Pure(PureSignalSpecification::SampleHold { .. })
    )
}

fn reachable_nodes(
    nodes: &BTreeMap<SignalId, SignalNode>,
    exports: &[SignalId],
) -> Result<BTreeSet<SignalId>, SignalProgramError> {
    let mut reachable = BTreeSet::new();
    let mut pending = exports.to_vec();
    while let Some(id) = pending.pop() {
        if !reachable.insert(id.clone()) {
            continue;
        }
        let node = nodes
            .get(&id)
            .ok_or_else(|| SignalProgramError::MissingExport { id: id.clone() })?;
        pending.extend(node.inputs.iter().cloned());
    }
    Ok(reachable)
}

fn topological_order(
    mut nodes: BTreeMap<SignalId, SignalNode>,
    configured_depth: u16,
) -> Result<Vec<SignalNode>, SignalProgramError> {
    let mut dependants: BTreeMap<SignalId, Vec<SignalId>> = BTreeMap::new();
    let mut indegree = BTreeMap::new();
    let mut depth = BTreeMap::new();
    for node in nodes.values() {
        indegree.insert(node.id.clone(), node.inputs.len());
        for input in &node.inputs {
            dependants
                .entry(input.clone())
                .or_default()
                .push(node.id.clone());
        }
    }
    for values in dependants.values_mut() {
        values.sort();
    }
    let mut ready = indegree
        .iter()
        .filter_map(|(id, count)| (*count == 0).then_some(id.clone()))
        .collect::<VecDeque<_>>();
    let mut ordered_ids = Vec::with_capacity(nodes.len());
    while let Some(id) = ready.pop_front() {
        let node_depth = *depth.entry(id.clone()).or_insert(1_u16);
        if node_depth > configured_depth {
            return Err(SignalProgramError::GraphDepthExceeded {
                node: id,
                current: u64::from(node_depth),
                configured: u64::from(configured_depth),
                hard: u64::from(HARD_SIGNAL_GRAPH_DEPTH_LIMIT),
            });
        }
        ordered_ids.push(id.clone());
        if let Some(children) = dependants.get(&id) {
            for child in children {
                let child_depth =
                    node_depth
                        .checked_add(1)
                        .ok_or(SignalProgramError::CountOverflow {
                            field: "signal_graph_depth",
                        })?;
                depth
                    .entry(child.clone())
                    .and_modify(|current| *current = (*current).max(child_depth))
                    .or_insert(child_depth);
                let count =
                    indegree
                        .get_mut(child)
                        .ok_or_else(|| SignalProgramError::MissingInput {
                            node: child.clone(),
                            input: id.clone(),
                        })?;
                *count = count
                    .checked_sub(1)
                    .ok_or(SignalProgramError::CountOverflow {
                        field: "signal_edges",
                    })?;
                if *count == 0 {
                    let position = ready.partition_point(|candidate| candidate < child);
                    ready.insert(position, child.clone());
                }
            }
        }
    }
    if ordered_ids.len() != nodes.len() {
        let id = indegree
            .into_iter()
            .find_map(|(id, count)| (count != 0).then_some(id))
            .ok_or(SignalProgramError::CountOverflow {
                field: "signal_nodes",
            })?;
        return Err(SignalProgramError::Cycle { node: id });
    }
    ordered_ids
        .into_iter()
        .map(|id| {
            nodes.remove(&id).ok_or(SignalProgramError::CountOverflow {
                field: "signal_nodes",
            })
        })
        .collect()
}
