//! Protected local foundation for Broker Session Authentication 1.0.
//!
//! This production-inert crate decodes one fixed protected manifest, retains
//! role-local signing seeds behind protected file descriptors, detects local
//! configuration replacement, pins the custody process through a retained
//! self pidfd, and obtains process identifiers and hello nonces directly from
//! the Linux kernel. It does not sign protocol messages, construct verification
//! contexts or session bindings, advertise the authentication feature,
//! authorize peers, dispatch effects, or persist state.
//!
//! [`manifest`] owns the fixed `AOSBSC01` format. The private protected-files
//! module pins the endpoint directory and its three role-local files. The
//! private self-execution module pins and revalidates the loading process, the
//! private entropy module implements bounded kernel acquisition, and the
//! endpoint module exposes the deliberately narrow client and broker custody
//! APIs.

#![cfg(target_os = "linux")]

mod endpoint;
mod entropy;
mod error;
pub mod manifest;
mod protected_files;
mod self_execution;

pub use endpoint::{
    BrokerSessionProcessExecutionIdV1, FreshBrokerHelloNonceV1, FreshClientHelloNonceV1,
    ProtectedBrokerSessionBrokerV1, ProtectedBrokerSessionClientV1,
};
pub use error::BrokerSessionSecurityError;
pub use manifest::{
    BROKER_SESSION_SECURITY_MANIFEST_BYTES, BrokerSessionManifestBindingV1,
    BrokerSessionSecurityAudienceV1, BrokerSessionSecurityKeyPinV1,
    BrokerSessionSecurityManifestV1,
};
