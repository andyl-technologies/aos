//! Protected local foundation for Broker Session Authentication 1.0.
//!
//! This production-inert crate decodes one fixed protected manifest, retains
//! role-local signing seeds behind protected file descriptors, detects local
//! configuration replacement, pins the custody process through a retained
//! self pidfd, and obtains process identifiers and hello nonces directly from
//! the Linux kernel. A sealed private composition finalizes the two hello
//! signatures and carries their three bootstrap flights over one socket, but
//! it has no production entry point. A further private typestate composes the
//! protected controller and Network catalog journals around the mandatory
//! sequence-one exchange. This crate does not expose signing,
//! verification-context, session-binding, journal-owner, or channel APIs,
//! advertise the authentication feature, authorize peers, or dispatch effects.
//!
//! [`manifest`] owns the fixed `AOSBSC01` format. The private protected-files
//! module pins the endpoint directory and its three role-local files. The
//! private self-execution module pins and revalidates the loading process, the
//! private entropy module implements bounded kernel acquisition, the endpoint
//! module exposes deliberately narrow client and broker custody APIs, and the
//! private handshake module owns the unreachable same-channel hello and
//! mandatory Network sequence-one traffic-proof typestates.

#![cfg(target_os = "linux")]

#[allow(
    dead_code,
    reason = "sealed handshake finalizers stay unreachable until protected peer policy exists"
)]
mod endpoint;
mod entropy;
mod error;
#[allow(
    dead_code,
    reason = "P0-10 keeps the sealed authenticated handshake production-unreachable"
)]
mod handshake;
pub mod manifest;
#[allow(
    dead_code,
    reason = "sealed handshake context access stays unreachable until P0-10"
)]
mod protected_files;
#[allow(
    dead_code,
    reason = "sealed handshake boot access stays unreachable until P0-10"
)]
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
