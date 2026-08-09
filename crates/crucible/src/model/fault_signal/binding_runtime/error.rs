//! Errors raised while evaluating signal-to-effect bindings.

use std::error::Error;
use std::fmt;

use super::super::*;

/// Signal-to-effect runtime failure.
#[derive(Debug)]
pub enum BindingRuntimeError {
    /// Binding IDs are not unique.
    DuplicateBinding,
    /// A host collection or encoded length did not fit its public counter.
    CountOverflow(&'static str),
    /// Search mutation was not materialized into a concrete program/artifact.
    UnmaterializedSearchMutation,
    /// A binding was admitted against a different signal program.
    BindingProgramMismatch,
    /// Runtime state omitted one admitted binding.
    MissingState(FaultObjectId),
    /// Dynamic membership named no admitted binding.
    MissingBinding(FaultObjectId),
    /// Program no longer exposes one admitted signal.
    MissingSignal(SignalId),
    /// Active dynamic membership had no retained mapped value state.
    MissingMappedValues(FaultObjectId),
    /// A dynamic membership update named a static binding.
    NotDynamic(FaultObjectId),
    /// Dynamic path membership contained a non-network target.
    DynamicTargetAdapter,
    /// Dynamic path membership contained a target kind illegal for its effect.
    DynamicTargetKind,
    /// Dynamic membership became empty when the authored selector forbids it.
    DynamicTargetEmpty,
    /// Dynamic membership path, version, sequence, or evidence is invalid.
    DynamicTransitionIdentity,
    /// A required signal evaluated inactive.
    InactiveSignal(SignalId),
    /// An adapter delivered an older opportunity sequence for the same scope.
    NonMonotoneOpportunity,
    /// An adapter opportunity arrived before its same-time boundary completed.
    OpportunityBeforeBoundary,
    /// One scope reused an opportunity sequence for different immutable input.
    OpportunitySequenceCollision,
    /// Mapping received a value that contradicted its admitted type.
    MappingType,
    /// Runtime omitted an admitted named mapping declaration.
    MappingDeclaration,
    /// An opportunity-domain signal was sampled without an opportunity.
    OpportunityRequired,
    /// A node-counter signal lacked a retired-instruction coordinate.
    CounterCoordinateRequired,
    /// A spatial output was not projected through an explicit field-sample node.
    UnprojectedSpatialSignal,
    /// Event-domain evaluation omitted explicit parent provenance.
    EventParentRequired,
    /// Canonical mapped-value framing exceeded its integer count.
    MappedValueLimit,
    /// Keyed hazard rejection sampling exhausted its bounded counter space.
    HazardKeyExhausted,
    /// A per-binding observation counter exhausted `u64`.
    ObservationSequenceOverflow,
    /// Search candidate identity, bound, or override is inconsistent.
    SearchChoice,
    /// Locked replay ended before consuming every supplied override.
    UnusedSearchOverride,
    /// A required cadence or residence wakeup exceeded virtual time.
    WakeupOverflow,
    /// Scheduler boundary moved backward.
    NonMonotoneBoundary,
    /// Runtime is terminally poisoned after an impossible rollback failure.
    Poisoned,
    /// Checkpoint version, program, or binding identity differs.
    CheckpointIdentity,
    /// Checkpoint mutable state is incomplete or internally inconsistent.
    CheckpointState,
    /// Nested program validation failed while deriving runtime coordinates.
    Program(SignalProgramError),
    /// Nested signal evaluation failed.
    Evaluation(SignalEvaluationError),
    /// Evaluator rollback failed after a rejected atomic boundary.
    Rollback(SignalEvaluationError),
    /// Nested trace value codec failed.
    Trace(TraceError),
    /// A plan-owned resource reservation was rejected.
    ResourceLimit(FaultResourceLimitError),
    /// Nested active-table or transition state failed.
    Runtime(FaultRuntimeError),
    /// The production adapter rejected an atomic action batch.
    AdapterRejected(Box<RejectedActionBatch>),
    /// Production adapter returned an incomplete or mismatched result batch.
    AdapterResult,
    /// Production adapter could not discard a prepared transaction.
    AdapterAbort(FaultRuntimeError),
    /// Production adapter commit visibility became ambiguous or partial.
    AdapterCommit(FaultRuntimeError),
}

impl fmt::Display for BindingRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "fault binding evaluation failed: {self:?}")
    }
}

impl Error for BindingRuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Program(error) => Some(error),
            Self::Evaluation(error) | Self::Rollback(error) => Some(error),
            Self::Trace(error) => Some(error),
            Self::ResourceLimit(error) => Some(error),
            Self::Runtime(error) => Some(error),
            Self::AdapterAbort(error) => Some(error),
            Self::AdapterCommit(error) => Some(error),
            Self::AdapterRejected(error) => Some(&error.error),
            _ => None,
        }
    }
}
