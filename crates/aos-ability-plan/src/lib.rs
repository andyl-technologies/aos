//! Deterministic provider resolution and pure recursive ability composition.
//!
//! [`resolution`] validates authenticated candidate policy, preserves explicit
//! selections and exact pins, and returns checked bindings with a replayable
//! decision trace. [`composition`] repeatedly invokes exact pure provider entry
//! points until the request and binding state reaches a bounded fixed point.
//! [`transition`] invokes selected provider transition constructors and returns
//! a completely validated finite effect graph.
//! This crate performs no downloads, resource acquisition, or runtime effects.

pub mod composition;
pub mod resolution;
pub mod snapshot;
pub mod transition;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

pub use composition::{
    CompositionContext, CompositionError, CompositionEvaluation, CompositionEvaluationResult,
    CompositionEvaluator, CompositionFragment, CompositionLimits, CompositionOutcome,
    CompositionPass, EvaluationError, RecursiveComposer, child_request_id,
};
pub use resolution::{
    BindingCandidate, CandidateOrder, CandidateRejection, CandidateSelection,
    EnabledProviderSelection, ExistingProviderPin, ResolutionDecision, ResolutionError,
    ResolutionLimits, ResolutionOutcome, ResolutionPolicyDocument, Resolver,
};
pub use snapshot::{
    PLANNING_SNAPSHOT_MAX_BYTES, PLANNING_SNAPSHOT_SCHEMA, PlanningReplayInputs, PlanningSnapshot,
    PlanningSnapshotError, ResolutionSnapshot, VerifiedPlanningSnapshot,
};
pub use transition::{
    ResourceChange, ResourceChangeKind, ScopedDesiredState, ScopedObservations,
    TRANSITION_CONTEXT_SCHEMA, TRANSITION_FRAGMENT_SCHEMA, TRANSITION_SNAPSHOT_MAX_BYTES,
    TRANSITION_SNAPSHOT_SCHEMA, TransitionContext, TransitionError, TransitionEvaluation,
    TransitionEvaluationResult, TransitionExport, TransitionExportKind, TransitionFragment,
    TransitionImport, TransitionImportDirection, TransitionInputs, TransitionLimits,
    TransitionLink, TransitionPlanner, TransitionReplayInputs, TransitionSnapshot,
    TransitionSnapshotError, VerifiedTransitionPlan,
};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod transition_tests;
