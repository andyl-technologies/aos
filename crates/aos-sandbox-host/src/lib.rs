//! Root-only fixed-function host broker for AOS sandbox runtimes.
//!
//! The broker accepts only semantically validated local runtime requests,
//! durably fences assignment generations and request replays, resolves opaque
//! workspace/network/attachment handles through a trusted node catalog, and
//! invokes one short-lived typed systemd worker transaction. It never accepts
//! a caller-selected path, command, unit name, D-Bus property, or signal.
//!
//! Modules divide the privilege boundary as follows:
//!
//! - [`activation`] adopts the sole systemd-owned broker socket;
//! - [`authorization`] exposes the shared CTRL-03/host semantic compiler and
//!   owns host-audience admission;
//! - [`plan`] resolves catalog handles and compiles the fixed nspawn launch;
//! - [`catalog`] resolves launch resources from one atomic root-owned snapshot;
//! - [`peer`] pins the controller process to its exact service cgroup;
//! - [`service`] serves one bounded request per verified connection;
//! - [`state`] persists fences, pending effects, and replay receipts;
//! - [`transport`] validates systemd-activated local packet sockets;
//! - [`worker`] performs idempotent typed systemd and pidfd operations;
//! - [`broker`] orders validation, durability, effects, and replies.

pub mod activation;
pub mod authorization;
pub mod broker;
pub mod catalog;
pub mod peer;
pub mod plan;
pub mod service;
pub mod state;
pub mod transport;
pub mod worker;

pub(crate) const KERNEL_CLOCK_PROVENANCE: [u8; 16] = *b"aos-kernel-clock";

/// Errors returned by the fixed host broker.
#[derive(Debug, thiserror::Error)]
pub enum HostError {
    /// Hostile or unauthorized local protocol input was rejected.
    #[error("host protocol rejected request: {0}")]
    Protocol(#[from] aos_sandbox_protocol::ProtocolValidationError),
    /// The trusted catalog could not resolve an exact opaque handle tuple.
    #[error("host catalog rejected launch: {0}")]
    Catalog(String),
    /// A resolved launch plan violates the fixed backend profile.
    #[error("invalid resolved host launch plan: {0}")]
    InvalidPlan(String),
    /// Durable host fence or replay state is corrupt or unavailable.
    #[error("host durable state failure: {0}")]
    State(String),
    /// A request is stale or contradicts durable host state.
    #[error("host request fence conflict: {0}")]
    Fence(&'static str),
    /// Signed plan, ownership lease, or authenticated local authority failed.
    #[error("host authority rejected request: {0}")]
    Authority(#[from] aos_sandbox_broker::BrokerAdmissionError),
    /// The fixed systemd worker could not complete or verify an effect.
    #[error("host worker failure: {0}")]
    Worker(String),
}

/// Convenience result type for host broker operations.
pub type Result<T> = std::result::Result<T, HostError>;
