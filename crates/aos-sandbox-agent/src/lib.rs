#![deny(missing_docs)]

//! Portable wire contracts for the AOS sandbox Guest agent.
//!
//! [`model`] and [`protocol`] own bounded incarnation handshakes and operation
//! framing. [`launch`] encodes runtime-bound launch proposals without acquiring
//! descriptors or authenticating their protected provenance. The OpenSSH modules
//! validate signed gate, ticket, monitor and control messages; parsing those
//! values never establishes physical process custody or effect authority.
//! [`guest_root_publication`] describes assignment-bound root evidence, while
//! [`runtime_argument_observation`] verifies signed argument-limit packets.
//!
//! This crate owns no Linux entry point, filesystem population, process effects,
//! gate installer or executable builder. Those owners live in `aos-sandbox-guest`.
//! Durable execution admission and semantic commit remain with their respective
//! protected runtime owners.

pub mod guest_attach_trust;
pub mod guest_root_publication;
pub mod launch;
pub mod model;
pub mod openssh_attach_certificate;
pub mod openssh_consume;
pub mod openssh_control;
pub mod openssh_control_channel;
pub mod openssh_gate;
pub mod openssh_monitor;
pub mod openssh_session;
pub mod openssh_ticket;
pub mod protocol;
pub mod runtime_argument_observation;
pub mod signed_outcome_packet;

pub use model::{
    AgentExecutionOperationV1, AgentExecutionOutcomeV1, AgentExecutionPhaseV1, AgentFeatureSetV1,
    AgentFeatureV1, AgentHandshakeRequestV1, AgentHandshakeResponseV1, AgentNonceV1,
    AgentOperationIdV1, AgentOperationRequestV1, AgentOperationSequenceV1, AgentProtocolVersionV1,
    AgentRuntimeBindingV1, AgentSessionBindingV1, AgentSessionIdV1, InvalidAgentModel,
};
pub use protocol::{
    AgentFrameV1, AgentProtocolError, AgentSealedAuthorizeReferenceV1,
    MAX_AGENT_SEALED_SPEC_BYTES_V1, decode_frame_v1, encode_frame_v1,
};
pub use runtime_argument_observation::{
    GuestRuntimeArgumentObservationErrorV1, GuestRuntimeArgumentObserveRequestV1,
    GuestRuntimeArgumentReadbackV1, verify_guest_runtime_argument_readback_v1,
};
pub use signed_outcome_packet::{
    SignedAgentOutcomePacketErrorV1, SignedAgentOutcomePacketV1,
    decode_signed_agent_outcome_packet_v1, encode_signed_agent_outcome_packet_v1,
};
