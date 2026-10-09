//! Non-production runtime-backend handoff and fixed-root composition contracts.
//!
//! Backend staging retains typed recovery and verifies authenticated observations.
//! Fixed-root composition retains its protected owner claim and probe evidence.
//! Composition evidence does not authorize service readiness.
//! These contracts remain separate from production Host service dispatch.

mod backend;
mod composition;
pub use backend::{
    DormantAgentExecutionHandoffV1, DormantBackendHandoffErrorV1, DormantControlCompletionErrorV1,
    DormantControlCompletionOutcomeV1, DormantControlCompletionRecoveryV1,
    DormantExecutionHandleV1, DormantExecutionRecoveryHandleV1, DormantForcedKillHandoffV1,
    DormantKillEscalationErrorV1, DormantKillStopOutcomeV1, DormantLifecycleRecoveryHandleV1,
    DormantPendingKillV1, DormantPreparedHandleV1, DormantProtectedRuntimeBackendV1,
    DormantRuntimeBackendReadinessEvidenceV1, DormantRuntimeHandleV1, SignedAgentOutcomeV1,
    SignedDormantKillDeadlineObservationV1, dormant_kill_deadline_signing_message_v1,
};
pub use composition::{
    DormantComposedRuntimeBackendV1, DormantRuntimeBackendCompositionErrorV1,
    DormantRuntimeBackendCompositionV1,
};
