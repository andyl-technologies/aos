//! Protected journal ownership for runtime execution admission and effects.
//!
//! This module is source-only and is not called by controller dispatch. It
//! binds the portable runtime-backend records to one dedicated protected
//! journal, resolves exact replay before any fresh observation, and exposes
//! move-only recovery, dispatch, and completion evidence.

mod agent_checkpoint;
mod agent_execution_adapter;
mod agent_process_effect;
mod agent_reducer;
mod agent_store;
mod evidence;
mod guest_authority;
mod outcome_record;
mod owner;
mod recovery;
mod route_record;
mod store;

#[cfg(unix)]
pub use agent_execution_adapter::DormantGuestProvisioningOwnerV1;
pub use agent_execution_adapter::{
    DormantGuestExecutionAdapterV1, DormantGuestExecutionPreparationV1,
    GuestExecutableCredentialV1, GuestExecutionAdapterErrorV1, GuestForcedCommandCredentialV1,
    GuestLocalExecutionHandoffV1, GuestLocalExecutionRequestV1, ObservedGuestLocalExecutionV1,
};
pub use agent_process_effect::{
    DormantGuestCredentialEffectV1, DormantGuestProcessEffectErrorV1, DormantGuestProcessEffectV1,
    DormantGuestProcessEffectsV1, DormantGuestProcessSupervisorErrorV1,
    DormantGuestProcessSupervisorV1, DormantObservedProcessStateV1,
};
pub use agent_reducer::{
    AgentHandshakeSigner, AgentOperationCasError, AgentOutcomeRecoveryTokenV1, AgentOutcomeSigner,
    AgentProvisioningV1, AgentReducerError, agent_handshake_signing_message_v1,
    agent_outcome_signing_message_v1,
};
pub use agent_store::JournalAgentStoreError;
pub use evidence::{
    JournalExecutionCompletionV1, RuntimeExecutionEvidenceError,
    completion_from_backend_observation_v1, decode_authorize_completion_running_v1,
    decode_cancel_completion_phase_v1, decode_control_completion_phase_v1,
};
pub use guest_authority::{
    DormantGuestCheckpointRecoveryTokenV1, DormantGuestProcessExecutionFailureV1,
    DormantGuestProcessOutcomeUnknownV1, DormantGuestProcessPreparationErrorV1,
    DormantGuestReservedReadbackDispositionV1, DormantGuestReservedReadbackEvidenceV1,
    DormantGuestReservedReadbackReconciliationErrorV1, DormantGuestReservedReconciliationV1,
    DormantProtectedGuestCompletionErrorV1, DormantProtectedGuestExecutionControllerV1,
    DormantProtectedGuestExecutionErrorV1, ProtectedDormantGuestProcessEffectV1,
    dormant_guest_reserved_outcome_signing_message_v1,
    dormant_guest_reserved_readback_signing_message_v1,
};
pub use owner::{
    AuthenticatedRecoveredHostAgentOutcomeV1, CommittedHostAgentOutcomeV1,
    DormantRuntimeExecutionClaimV1, DormantRuntimeExecutionOwnerErrorV1,
    DormantRuntimeExecutionOwnerV1, ProtectedLifecycleIssueV1, ProtectedRuntimeAgentPeerV1,
    ProtectedRuntimeHostVerifierV1, RecoveredHostAgentRouteV1,
};
pub use recovery::AppliedExecutionRecoveryV1;
pub use store::{
    AuthenticatedJournalExecutionRecoveryV1, ExecutionJournalRecoveryTokenV1,
    JournalRuntimeExecutionError,
};
