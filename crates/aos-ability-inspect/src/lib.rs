//! Portable inspection, query, comparison, and rendering for checked abilities.
//!
//! [`bundle`] carries the complete pure inputs needed to reconstruct a checked
//! effect plan without evaluating Nix or acquiring live resources. [`view`]
//! projects that checked plan into stable heterogeneous nodes and typed edges.
//! [`query`] performs bounded graph traversal, [`compare`] computes stable
//! structural changes, [`projection`] selects one semantic edge family, and
//! [`render()`] presents a view, projection, or slice as text, canonical JSON,
//! DOT, or Mermaid.
//!
//! This crate deliberately has no dependency on the native runtime, filesystem,
//! CLI parsing, registry transport, or privileged provider adapters. Native
//! frontends may translate execution records into separate portable inspection
//! DTOs without importing those capabilities here.

#![forbid(unsafe_code)]

pub mod artifact_consumption;
pub mod bundle;
pub mod compare;
pub mod diagnostic_bundle;
pub mod explanation;
pub mod operator_view;
pub mod projection;
pub mod query;
pub mod reference;
pub mod render;
pub mod view;

pub use artifact_consumption::{
    ARTIFACT_CONSUMPTION_EVIDENCE_MAX_BYTES, ArtifactConsumptionEvidenceError,
    ArtifactConsumptionExplanation, ArtifactConsumptionGraphBinding, ArtifactConsumptionLimitation,
    ArtifactConsumptionPhase, ArtifactConsumptionProvenance, ArtifactConsumptionQuery,
    CheckedArtifactConsumptionEvidence,
};
pub use bundle::{
    CheckedInspectionBundle, INSPECTION_BUNDLE_MAX_BYTES, INSPECTION_BUNDLE_SCHEMA,
    InspectionBundle, InspectionBundleError,
};
pub use compare::{ChangedNode, INSPECTION_DIFF_SCHEMA, InspectionDiff};
pub use diagnostic_bundle::{
    DIAGNOSTIC_BUNDLE_MAX_BYTES, DIAGNOSTIC_BUNDLE_SCHEMA, DiagnosticArtifact, DiagnosticBundle,
    DiagnosticBundleAudience, DiagnosticBundleError, DiagnosticLimitation, ExecutionTimeline,
    PendingOperationInput, PendingOperationView, PendingStateAvailability, ReplayAvailability,
    TimelineEvent, TimelineEventInput, TimelineEventKind, TimelineProvenance, TimelineTiming,
};
pub use explanation::{
    BINDING_EXPLANATION_MAX_BYTES, BINDING_EXPLANATION_SCHEMA, BindingExplanation,
    BindingExplanationAudience, BindingExplanationError, BindingExplanationOutcome,
    ExplainedObligation, ExplanationLimitation, ProtectedValue, RejectedCandidateHistory,
};
pub use operator_view::{
    ExpansionHint, GenerationAxis, GenerationConvergence, GenerationObservation, NodeObservation,
    OPERATOR_OBSERVATION_MAX_BYTES, OPERATOR_OBSERVATION_SCHEMA, OPERATOR_QUERY_MAX_BYTES,
    OPERATOR_QUERY_SCHEMA, OPERATOR_VIEW_MAX_BYTES, OPERATOR_VIEW_SCHEMA, ObservedNodeState,
    OperatorFocus, OperatorGroup, OperatorGroupKey, OperatorNodeState, OperatorNodeStatus,
    OperatorObservation, OperatorObservationError, OperatorObservationProvenance,
    OperatorObservationSummary, OperatorQuery, OperatorQueryError, OperatorView, OperatorViewError,
    TransactionObservation,
};
pub use projection::{
    INSPECTION_PROJECTION_SCHEMA, InspectionProjection, InspectionProjectionError, ProjectionKind,
};
pub use query::{
    Direction, GraphQuery, GraphQueryError, GraphSlice, INSPECTION_QUERY_MAX_BYTES,
    INSPECTION_QUERY_MAX_DEPTH, INSPECTION_QUERY_MAX_NODES, INSPECTION_QUERY_MAX_ROOTS,
    INSPECTION_QUERY_SCHEMA, INSPECTION_SLICE_SCHEMA,
};
pub use reference::{
    CheckedReferenceInspection, REFERENCE_GRAPH_SLICE_SCHEMA, REFERENCE_INSPECTION_INPUT_MAX_BYTES,
    REFERENCE_INSPECTION_INPUT_SCHEMA, REFERENCE_INSPECTION_VIEW_MAX_BYTES,
    REFERENCE_INSPECTION_VIEW_SCHEMA, ReferenceGraphSlice, ReferenceInspectionAnchor,
    ReferenceInspectionDiagnostic, ReferenceInspectionDiagnosticCode,
    ReferenceInspectionDisclosure, ReferenceInspectionError, ReferenceInspectionInput,
    ReferenceInspectionView,
};
pub use render::{
    RenderError, RenderFormat, render, render_projection, render_reference, render_reference_slice,
    render_slice,
};
pub use view::{
    INSPECTION_VIEW_MAX_BYTES, INSPECTION_VIEW_MAX_ITEMS, INSPECTION_VIEW_SCHEMA, InspectionEdge,
    InspectionNode, InspectionRelation, InspectionView, InspectionViewError, NodeKey, ViewAnchor,
};

#[cfg(test)]
mod tests;
