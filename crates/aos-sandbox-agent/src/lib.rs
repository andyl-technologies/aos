#![deny(missing_docs)]

//! Defines the portable, node-internal AOS sandbox guest-agent contract.
//!
//! The agent authenticates one exact incarnation handshake, accepts a bounded
//! stop-and-wait operation stream, and provides independently buildable dormant
//! guest artifacts. Durable reservation, reduction, and terminal commit
//! authority live only in `aos-sandbox::runtime_execution`; this crate exports
//! no generic persistence or reducer-completion hook.
//!
//! [`protocol`] owns the exact `AOSAGE01` framing and allocation bounds;
//! [`signed_outcome_packet`] carries its detached outcome signature on the
//! Host/guest wire without changing the checkpoint frame.
//! [`openssh_gate`] defines signed attach readback and the fixed bridge claim;
//! Linux physical measurement and the forced-command binary own its guest
//! enforcement path.
//! [`guest_root_publication`], [`guest_root_tree`], and [`guest_root_marker`]
//! define assignment-bound population evidence and physical tree readback.
//! [`dormant_guest_agent`], [`dormant_root_builder`], and
//! [`dormant_package`] provide independent, executable normal-source seams
//! with an independently packaged but uninstalled binary. [`broker_adapter`]
//! contains only a dormant, nonauthorizing projection for existing local
//! protobuf messages.

pub mod broker_adapter;
pub mod dormant_guest_agent;
pub mod dormant_package;
#[cfg(target_os = "linux")]
pub mod guest_attach_trust;
#[cfg(unix)]
pub mod dormant_root_builder;
pub mod guest_root_publication;
#[cfg(target_os = "linux")]
pub mod guest_root_marker;
#[cfg(unix)]
pub mod guest_root_tree;
pub mod model;
pub mod openssh_gate;
#[cfg(target_os = "linux")]
pub mod openssh_gate_linux;
#[cfg(target_os = "linux")]
pub mod protected_entry;
pub mod protocol;
pub mod signed_outcome_packet;
pub use dormant_guest_agent::{
    DormantGuestAgentMainErrorV1, DormantGuestAgentServiceV1, dormant_guest_agent_main_v1,
};
pub use dormant_package::{DormantGuestAgentPackageErrorV1, DormantGuestAgentPackageV1};
#[cfg(unix)]
pub use dormant_root_builder::{
    DormantGuestRootBuildErrorV1, DormantGuestRootBuildPlanV1, build_dormant_guest_root_v1,
};
pub use model::{
    AgentExecutionOperationV1, AgentExecutionOutcomeV1, AgentExecutionPhaseV1, AgentFeatureSetV1,
    AgentFeatureV1, AgentHandshakeRequestV1, AgentHandshakeResponseV1, AgentNonceV1,
    AgentOperationIdV1, AgentOperationRequestV1, AgentOperationSequenceV1, AgentProtocolVersionV1,
    AgentRuntimeBindingV1, AgentSessionBindingV1, AgentSessionIdV1, InvalidAgentModel,
};
pub use protocol::{AgentFrameV1, AgentProtocolError, decode_frame_v1, encode_frame_v1};
pub use signed_outcome_packet::{
    SignedAgentOutcomePacketErrorV1, SignedAgentOutcomePacketV1,
    decode_signed_agent_outcome_packet_v1, encode_signed_agent_outcome_packet_v1,
};
