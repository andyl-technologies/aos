//! Portable runtime-backend and durable execution contracts.
//!
//! Runtime backends realize already-authorized, fully resolved plans. They do
//! not parse public requests, evaluate policy, select host paths, or own the
//! journal. The [`RuntimeBackend`] trait uses move-only typestate values so a
//! caller cannot start an unprepared runtime, execute against a frozen target,
//! or destroy a live target through the portable API.
//!
//! Execution admission is deliberately separate from backend realization.
//! [`ExecutionAdmissionStore`] owns the atomic admission boundary, while
//! [`ExecutionEffectStore`] owns effect issuance and completion. Recovery
//! consumes authenticated durable snapshots and backend observations; it never
//! treats an in-memory handle or a scalar "not found" result as proof.

mod backend;
mod capability;
mod codec;
mod execution_admission;
mod execution_effect;
mod execution_recovery;
mod gateway;
mod model;

mod sealed {
    pub trait BackendLifecycleRecoveryLoaderV1 {}
    pub trait BackendRuntimeInspectionLoaderV1 {}
    pub trait BackendExecutionInspectionLoaderV1 {}
    pub trait BackendExecutionInventoryLoaderV1 {}
}

pub use backend::{
    BackendEffectOutcome, BackendExecutionOutcome, BackendRecoveryOutcome, RuntimeBackend,
    RuntimeBackendError,
};
pub use capability::{
    BackendCapabilitiesV1, BackendCapabilityV1, BackendCapabilityViolation,
    BackendProbeCurrentnessV1, BackendProbeReportV1, RequiredBackendCapabilitiesV1,
};
pub use codec::{
    DurableExecutionCodecError, decode_durable_execution_admission_v1,
    decode_durable_execution_effect_v1, encode_durable_execution_admission_v1,
    encode_durable_execution_effect_v1,
};
pub use execution_admission::{
    AdmissionCommitDispositionV1, AdmissionCommitError, AdmissionCurrentnessV1,
    AdmissionIdempotencyV1, AdmissionStoreCommitV1, AdmittedExecutionV1, DurableAdmissionCommitV1,
    ExecutionAdmissionDraftV1, ExecutionAdmissionOutcomeV1, ExecutionAdmissionStore,
    admit_execution, recover_execution_admission,
};
pub use execution_effect::{
    DurableExecutionEffectV1, EffectCommitDispositionV1, EffectCommitError,
    EffectCompletionStatusV1, EffectCompletionV1, EffectIdempotencyV1, EffectIssueV1,
    EffectOperationV1, EffectPhaseV1, EffectStoreCommitV1, EffectStoreTransitionV1,
    ExecutionEffectStore, ExecutionEffectTransitionV1, complete_effect, mark_effect_indeterminate,
    prepare_effect, recover_effect_completion, recover_effect_indeterminate, recover_effect_issue,
    recover_pending_effect, reserve_effect_issue,
};
pub use execution_recovery::{
    BackendExecutionInventoryInputV1, BackendExecutionInventoryLoaderV1,
    BackendExecutionInventoryV1, BackendExecutionPresenceV1, ExecutionRecoveryActionV1,
    ExecutionRecoveryError, ExecutionRecoveryPreflightV1, load_backend_execution_inventory_v1,
    preflight_execution_recovery, reconcile_execution_effect,
};
pub use gateway::{
    BackendEvidenceVerificationError, BackendEvidenceVerifierV1,
    SignedBackendExecutionInspectionV1, SignedBackendExecutionInventoryV1,
    SignedBackendLifecycleRecoveryV1, SignedBackendRuntimeInspectionV1,
    backend_agent_outcome_commitment_v1, backend_agent_outcome_signing_message_v1,
    backend_evidence_authority_binding_v1, backend_execution_inspection_binding_v1,
};
pub use model::{
    BackendExecutionHandle, BackendExecutionInspectionInputV1, BackendExecutionInspectionLoaderV1,
    BackendExecutionInspectionRequestV1, BackendExecutionInspectionV1, BackendExecutionPhaseV1,
    BackendExecutionRequestV1, BackendFreezeObservationV1, BackendLifecycleOperationV1,
    BackendLifecycleRecoveryInputV1, BackendLifecycleRecoveryLoaderV1,
    BackendLifecycleRecoveryRecordV1, BackendOperationIdV1, BackendOperationSequenceV1,
    BackendRetryClassV1, BackendRuntimeInspectionInputV1, BackendRuntimeInspectionLoaderV1,
    BackendRuntimeInspectionV1, BackendRuntimePhaseV1, BackendStartObservationV1,
    BackendStopDeadlineV1, BackendStopObservationV1, DestroyableRuntime, DestroyedRuntime,
    FrozenRuntime, PreparedRuntime, ResolvedRuntimePlanV1, RunningRuntime, RuntimeCurrentnessV1,
    RuntimeHandleCommitmentV1, RuntimeModelError, RuntimeRecoveryToken, StoppableRuntime,
    StoppedRuntime, load_backend_execution_inspection_v1, load_backend_lifecycle_recovery_v1,
    load_backend_runtime_inspection_v1,
};
