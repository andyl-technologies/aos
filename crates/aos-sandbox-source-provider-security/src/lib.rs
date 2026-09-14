//! Protected, production-inert SourceProvider custody foundation.
//!
//! This crate decodes the fixed `AOSPSEC1`, `AOSPTRS1`, and `AOSPRTE1`
//! protected records, retains role-local signing keys and kernel process
//! identity, derives process-exclusive hello nonces, and defines sealed
//! handshake, descriptor, boot, and death-evidence states. None of those
//! states is reachable from a public authority-producing constructor.
//!
//! Traffic signing and durable send permission deliberately do not live here
//! yet. They require concrete opaque plans and receipts from the future
//! standalone AOSSPL ledger. This crate has no service, listener, socket path,
//! backend dispatch, feature advertisement, or descriptor-release API.
//!
//! Linux descriptor-subject records identify a privileged sender-nominated
//! process, which is not necessarily the process that executed the socket
//! syscall. Production activation therefore remains gated on a concrete MAC
//! and capability policy that prevents socket-file-description delegation and
//! unauthorized subject nomination. The retained pidfd, credential, cgroup,
//! and socket evidence here does not by itself discharge that system policy.

#![cfg(target_os = "linux")]
#![allow(
    dead_code,
    reason = "the security foundation stays sealed until concrete AOSSPL receipts exist"
)]

mod carrier;
mod custody;
mod descriptor;
mod entropy;
mod error;
mod execution;
mod handshake;
pub mod manifest;
mod protected_files;
pub mod route_file;
pub mod trust_file;

pub use custody::{ProtectedProviderCustodyV1, ProtectedRootMountCustodyV1};
pub use descriptor::{CommittedSourceRootV1, ObservedSourceRootV1};
pub use error::SourceProviderSecurityError;
pub use execution::{CurrentKernelBootV1, DeadProviderExecutionV1};
pub use handshake::{
    AuthenticatedProviderOutcomeV1, CommittedProviderOutcomeV1, CurrentProviderIngressSessionV1,
    CurrentProviderRequestV1, CurrentRootMountSourceProviderSessionV1,
};
