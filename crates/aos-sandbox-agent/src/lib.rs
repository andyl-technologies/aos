#![deny(missing_docs)]

//! Defines the portable, node-internal AOS sandbox guest-agent contract.
//!
//! The agent authenticates one exact incarnation handshake, accepts a bounded
//! stop-and-wait operation stream, and reduces execution/quiesce requests into
//! move-only decisions for a future guest-local effect adapter. It is not a
//! public execution data plane and exposes no host mount, systemd, storage, or
//! network authority.
//!
//! [`protocol`] owns the exact `AOSAGE01` framing and allocation bounds.
//! [`reducer`] owns session fencing, sequence CAS, exact replay, and closed
//! execution state transitions. [`checkpoint`] owns canonical protected reopen
//! state and bounded replay history. [`broker_adapter`] contains only a
//! dormant, nonauthorizing projection for existing local protobuf messages.

pub mod broker_adapter;
pub mod checkpoint;
pub mod model;
pub mod protocol;
pub mod reducer;

pub use checkpoint::{
    AgentCheckpointCandidateV1, AgentCheckpointError, AgentDurableCheckpointV1,
    decode_checkpoint_v1,
};
pub use model::{
    AgentExecutionOperationV1, AgentExecutionOutcomeV1, AgentExecutionPhaseV1, AgentFeatureSetV1,
    AgentFeatureV1, AgentHandshakeRequestV1, AgentHandshakeResponseV1, AgentNonceV1,
    AgentOperationIdV1, AgentOperationRequestV1, AgentOperationSequenceV1, AgentProtocolVersionV1,
    AgentRuntimeBindingV1, AgentSessionBindingV1, AgentSessionIdV1, InvalidAgentModel,
};
pub use protocol::{AgentFrameV1, AgentProtocolError, decode_frame_v1, encode_frame_v1};
pub use reducer::{
    AgentDecisionV1, AgentDurableHistoryRecordV1, AgentHandshakeSigner, AgentOperationCas,
    AgentOperationCasError, AgentOperationRecoveryCas, AgentOperationReservationV1,
    AgentProvisioningV1, AgentRecoveredOperationV1, AgentRecoveredReservationV1, AgentReducerError,
    AgentReplayDispositionV1, AgentReservationDispositionV1, AgentReservationRecoveryTokenV1,
    AgentReservationStoreTransitionV1, AuthenticatedRecoveredAgentOutcomeV1, GuestAgentReducerV1,
    PreparedAgentOperationV1, SignedRecoveredAgentOutcomeV1, agent_handshake_signing_message_v1,
    agent_outcome_signing_message_v1, agent_recovery_authority_binding_v1,
    recovered_agent_outcome_signing_message_v1, validate_agent_checkpoint_history_v1,
    verify_signed_recovered_agent_outcome_v1,
};
