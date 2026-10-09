//! Finite search mutations, cases, and materialized plans.

use super::*;

/// One exact replacement in a normalized trace channel.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct TraceSampleMutation {
    /// Mapped virtual coordinate of the existing sample.
    pub coordinate: u64,
    /// Existing event sequence, or `None` for a scalar channel.
    pub event_sequence: Option<u64>,
    /// Replacement value with the channel's exact admitted type.
    pub value: SignalValue,
}

/// Concrete trace-window mutation selected by an explorer.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct TraceWindowMaterialization {
    /// Trace source node whose manifest is replaced.
    pub trace_node: SignalId,
    /// Nonempty canonical set of exact sample replacements.
    pub samples: Vec<TraceSampleMutation>,
}

/// One exact replacement of an authored piecewise transfer-function point.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct MappingPointMutation {
    /// Zero-based point index admitted by the binding search policy.
    pub index: u32,
    /// Complete replacement point.
    pub point: BindingMapPoint,
}

/// Concrete transfer-function mutation selected by an explorer.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct MappingMaterialization {
    /// Nonempty canonical set of point replacements.
    pub points: Vec<MappingPointMutation>,
}

/// Canonical description of the mutation applied to an executable case.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterializedSearchMutation {
    /// A normalized trace interval was replaced.
    TraceWindow(TraceWindowMaterialization),
    /// Piecewise mapping points were replaced.
    Mapping(MappingMaterialization),
}

/// An ordinary fixed-policy executable produced by one finite mutation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaterializedSearchCase {
    /// Original signal-program identity.
    pub original_program: ContentHash,
    /// Binding identity retained across materialization.
    pub binding_id: FaultObjectId,
    /// Concrete fixed-policy signal program.
    pub program: SignalProgram,
    /// Concrete fixed-policy binding admitted against `program`.
    pub binding: FaultBinding,
    /// Exact mutation schedule.
    pub mutation: MaterializedSearchMutation,
    /// Content identity of the complete transformation.
    pub provenance: ContentHash,
    /// Newly created content-addressed artifacts in dependency order.
    pub artifacts: Vec<ContentHash>,
}

/// One complete fixed-policy fault plan from the Cartesian mutation space.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaterializedSearchPlan {
    /// Concrete fault plan containing no mutation search policies.
    pub plan: FaultSignalPlan,
    /// Ordered concrete mutation choices applied to build the plan.
    pub cases: Vec<MaterializedSearchCase>,
    /// Content identity of the complete ordered materialization.
    pub provenance: ContentHash,
    /// Newly created content-addressed artifacts in dependency order.
    pub artifacts: Vec<ContentHash>,
}
