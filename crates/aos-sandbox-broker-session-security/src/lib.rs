//! Protected local foundation for Broker Session Authentication 1.0.
//!
//! This production-inert crate decodes one fixed protected manifest, retains
//! role-local signing seeds behind protected file descriptors, detects local
//! configuration replacement, pins the custody process through a retained
//! self pidfd, and obtains process identifiers and hello nonces directly from
//! the Linux kernel. A sealed private composition finalizes the two hello
//! signatures and carries their three bootstrap flights over one adopted socket,
//! but it has no production entry point. A further private typestate composes
//! the protected controller and Network catalog journals around the mandatory
//! sequence-one exchange. The public dormant Mount-session owner selects only
//! fixed endpoint roots, journal basename, ownership policy, and replay limits;
//! raw endpoint loaders and journal openers remain crate-private. The crate does
//! not expose signing, verification-context, session-binding, or channel APIs,
//! advertise the authentication feature, create listeners, or dispatch effects.
//!
//! [`manifest`] owns the fixed `AOSBSC01` format. The private protected-files
//! module pins the endpoint directory and its three role-local files. The
//! private self-execution module pins and revalidates the loading process, the
//! private entropy module implements bounded kernel acquisition, the endpoint
//! module owns deliberately narrow client and broker custody APIs, and the
//! private handshake module owns the unreachable same-channel hello and
//! mandatory Network sequence-one traffic-proof typestates. The private
//! recovery module owns the fixed-root `AOSBSJ01` namespace-47 journal,
//! protected full-history currentness sandwiches, and the only paths able to
//! mint recovered resend or outstanding-outcome state.

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
    reason = "durable recovery remains sealed until authenticated dispatch activation"
)]
mod recovery;
#[allow(
    dead_code,
    reason = "sealed handshake boot access stays unreachable until P0-10"
)]
mod self_execution;

pub use endpoint::{
    BrokerSessionProcessExecutionIdV1, FreshBrokerHelloNonceV1, FreshClientHelloNonceV1,
};
pub(crate) use endpoint::{ProtectedBrokerSessionBrokerV1, ProtectedBrokerSessionClientV1};
pub use error::BrokerSessionSecurityError;
pub use manifest::{
    BROKER_SESSION_SECURITY_MANIFEST_BYTES, BrokerSessionManifestBindingV1,
    BrokerSessionSecurityAudienceV1, BrokerSessionSecurityKeyPinV1,
    BrokerSessionSecurityManifestV1,
};
pub use recovery::{
    ProtectedBrokerOutcomeAdmissionGateV1, ProtectedBrokerOutcomeAdmissionV1,
    ProtectedBrokerOutcomeCommitReadbackV1, ProtectedBrokerOutcomeCommitRecoveryV1,
    ProtectedBrokerOutcomeCommitResultV1, ProtectedBrokerOutcomeCommittedAdvancementV1,
    ProtectedBrokerOutcomeCurrentV1, ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ProtectedBrokerOutcomeDurableCasV1, ProtectedBrokerOutcomePendingAdvancementV1,
    ProtectedBrokerOutcomeReplayV1, ProtectedBrokerRequestCommitRecoveryV1,
    ProtectedBrokerRequestCommitResultV1, ProtectedBrokerSessionInitializationRecoveryV1,
    ProtectedBrokerSessionInitializationResultV1, ProtectedMountBrokerSessionOwnerV1,
    ProtectedMountBrokerSessionRoleV1,
};
