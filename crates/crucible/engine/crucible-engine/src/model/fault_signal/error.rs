//! Typed signal-program admission failures.

use std::error::Error;
use std::fmt;

use super::{SignalDomain, SignalId};

/// Admission error for a typed signal program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignalProgramError {
    /// An author-supplied identifier is not canonical.
    InvalidId {
        /// Rejected text.
        value: String,
    },
    /// An exact rational is zero-denominator or not reduced.
    InvalidRatio {
        /// Rejected numerator.
        numerator: i64,
        /// Rejected denominator.
        denominator: u64,
    },
    /// A type, unit, and decimal-scale combination is invalid.
    InvalidShape {
        /// Declared value type.
        value_type: String,
        /// Declared unit.
        unit: &'static str,
        /// Declared decimal exponent.
        scale_decimal_exponent: i8,
    },
    /// A configured resource limit is zero.
    ZeroLimit {
        /// Limit field.
        field: &'static str,
    },
    /// A configured limit exceeds its compiled hard ceiling.
    LimitAboveHardCeiling {
        /// Limit field.
        field: &'static str,
        /// Configured value.
        configured: u64,
        /// Compiled hard ceiling.
        hard: u64,
    },
    /// A runtime-sized count could not fit its canonical counter.
    CountOverflow {
        /// Counter field.
        field: &'static str,
    },
    /// A resource requirement exceeds the scenario limit.
    ResourceExceeded {
        /// Resource field.
        field: &'static str,
        /// Current usage.
        current: u64,
        /// Usage requested by the operation.
        requested: u64,
        /// Scenario-configured limit.
        configured: u64,
        /// Compiled hard ceiling.
        hard: u64,
    },
    /// One node exceeds the per-node input limit.
    NodeInputLimit {
        /// Node identifier.
        id: SignalId,
        /// Current input count.
        current: u64,
        /// Configured limit.
        configured: u64,
        /// Compiled hard ceiling.
        hard: u64,
    },
    /// No output was explicitly exported.
    NoExportedOutputs,
    /// One node identifier occurs more than once.
    DuplicateNode {
        /// Duplicate identifier.
        id: SignalId,
    },
    /// One exported output occurs more than once.
    DuplicateExport {
        /// Duplicate identifier.
        id: SignalId,
    },
    /// An exported output does not name a node.
    MissingExport {
        /// Missing identifier.
        id: SignalId,
    },
    /// An input edge does not name a node.
    MissingInput {
        /// Consumer node.
        node: SignalId,
        /// Missing input.
        input: SignalId,
    },
    /// A node is not reachable from an exported output.
    UnreferencedNode {
        /// Unreferenced node.
        id: SignalId,
    },
    /// The graph contains a directed cycle.
    Cycle {
        /// One node in the cycle.
        node: SignalId,
    },
    /// The graph exceeds its configured depth.
    GraphDepthExceeded {
        /// Node whose computed depth exceeds the limit.
        node: SignalId,
        /// Computed depth.
        current: u64,
        /// Scenario-configured limit.
        configured: u64,
        /// Compiled hard ceiling.
        hard: u64,
    },
    /// A node has the wrong number of inputs for its registered kind.
    InvalidInputCount {
        /// Node identifier.
        node: SignalId,
        /// Human-readable registered arity.
        expected: &'static str,
        /// Authored arity.
        actual: usize,
    },
    /// A constant or parameter contains a malformed bounded value.
    InvalidValue {
        /// Node containing the value.
        node: SignalId,
    },
    /// A literal does not match its declared static type.
    LiteralTypeMismatch {
        /// Node identifier.
        node: SignalId,
        /// Declared type.
        declared: String,
        /// Literal type.
        actual: String,
    },
    /// A stateful node declares no serialized-state capacity.
    ZeroStateBound {
        /// Node identifier.
        node: SignalId,
    },
    /// A source specification violates its registered schema.
    InvalidSource {
        /// Node identifier.
        node: SignalId,
    },
    /// A pure operator specification violates its registered schema.
    InvalidOperator {
        /// Node identifier.
        node: SignalId,
    },
    /// A stateful operator specification violates its registered schema.
    InvalidStatefulOperator {
        /// Node identifier.
        node: SignalId,
    },
    /// An edge crosses domains without an explicit sampling operator.
    ImplicitDomainCrossing {
        /// Consumer node.
        node: SignalId,
        /// Input node.
        input: SignalId,
        /// Consumer domain.
        node_domain: SignalDomain,
        /// Input domain.
        input_domain: SignalDomain,
    },
    /// An operator input does not satisfy the registered type and unit contract.
    InputShapeMismatch {
        /// Consumer node.
        node: SignalId,
        /// Input node.
        input: SignalId,
        /// Input shape.
        input_shape: String,
        /// Consumer output shape.
        output_shape: String,
    },
    /// An operator requires a signed input.
    SignedInputRequired {
        /// Consumer node.
        node: SignalId,
    },
    /// Inputs are individually legal but mutually incompatible.
    InputGroupMismatch {
        /// Consumer node.
        node: SignalId,
    },
}

impl fmt::Display for SignalProgramError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidId { value } => write!(formatter, "invalid signal identifier {value:?}"),
            Self::InvalidRatio {
                numerator,
                denominator,
            } => write!(
                formatter,
                "ratio {numerator}/{denominator} is not canonical"
            ),
            Self::InvalidShape {
                value_type,
                unit,
                scale_decimal_exponent,
            } => write!(
                formatter,
                "signal shape {value_type}/{unit}/10^{scale_decimal_exponent} is invalid",
            ),
            Self::ZeroLimit { field } => write!(formatter, "resource limit {field} is zero"),
            Self::LimitAboveHardCeiling {
                field,
                configured,
                hard,
            } => write!(
                formatter,
                "resource limit {field}={configured} exceeds hard ceiling {hard}",
            ),
            Self::CountOverflow { field } => write!(formatter, "resource count {field} overflowed"),
            Self::ResourceExceeded {
                field,
                current,
                requested,
                configured,
                hard,
            } => write!(
                formatter,
                "resource {field} exceeded: current={current}, requested={requested}, configured={configured}, hard={hard}",
            ),
            Self::NodeInputLimit {
                id,
                current,
                configured,
                hard,
            } => write!(
                formatter,
                "node {id} input limit exceeded: current={current}, configured={configured}, hard={hard}",
            ),
            Self::NoExportedOutputs => formatter.write_str("signal program exports no outputs"),
            Self::DuplicateNode { id } => write!(formatter, "duplicate signal node {id}"),
            Self::DuplicateExport { id } => write!(formatter, "duplicate signal export {id}"),
            Self::MissingExport { id } => write!(formatter, "signal export {id} does not exist"),
            Self::MissingInput { node, input } => {
                write!(formatter, "signal node {node} input {input} does not exist")
            }
            Self::UnreferencedNode { id } => write!(formatter, "signal node {id} is unreferenced"),
            Self::Cycle { node } => write!(formatter, "signal graph contains a cycle at {node}"),
            Self::GraphDepthExceeded {
                node,
                current,
                configured,
                hard,
            } => write!(
                formatter,
                "signal graph depth at {node} exceeded: current={current}, configured={configured}, hard={hard}",
            ),
            Self::InvalidInputCount {
                node,
                expected,
                actual,
            } => write!(
                formatter,
                "signal node {node} expects {expected} inputs but has {actual}",
            ),
            Self::InvalidValue { node } => {
                write!(formatter, "signal node {node} has invalid value")
            }
            Self::LiteralTypeMismatch {
                node,
                declared,
                actual,
            } => write!(
                formatter,
                "signal node {node} declares {declared} but literal is {actual}",
            ),
            Self::ZeroStateBound { node } => {
                write!(
                    formatter,
                    "stateful signal node {node} has zero state bound"
                )
            }
            Self::InvalidSource { node } => {
                write!(
                    formatter,
                    "signal node {node} has an invalid source specification"
                )
            }
            Self::InvalidOperator { node } => {
                write!(
                    formatter,
                    "signal node {node} has an invalid pure operator specification"
                )
            }
            Self::InvalidStatefulOperator { node } => write!(
                formatter,
                "signal node {node} has an invalid stateful operator specification",
            ),
            Self::ImplicitDomainCrossing {
                node,
                input,
                node_domain,
                input_domain,
            } => write!(
                formatter,
                "signal node {node} in {node_domain:?} implicitly samples {input} in {input_domain:?}",
            ),
            Self::InputShapeMismatch {
                node,
                input,
                input_shape,
                output_shape,
            } => write!(
                formatter,
                "signal node {node} input {input} shape {input_shape} is incompatible with output {output_shape}",
            ),
            Self::SignedInputRequired { node } => {
                write!(formatter, "signal node {node} requires a signed input")
            }
            Self::InputGroupMismatch { node } => {
                write!(
                    formatter,
                    "signal node {node} has mutually incompatible inputs"
                )
            }
        }
    }
}

impl Error for SignalProgramError {}
