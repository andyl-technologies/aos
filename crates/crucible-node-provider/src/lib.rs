//! Bounded process transport and request custody for Crucible node providers.
//!
//! Module map: [`transport`] owns CNP/1 stream framing, [`envelope`] defines correlation
//! and request identity, and [`session`] checks connection sequence and scope.
//! These components do not authenticate native state or qualify a provider.
//! The host verifies implementation identity, referenced schemas and receipts
//! before a decoded request can authorize any model effect.
//!
//! Spec index: RFC-0025 files 06, 07, 08.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod blob;
pub mod bodies;
pub mod client;
pub mod conformance;
pub mod connection;
pub mod envelope;
pub mod gem5;
pub mod handshake;
pub mod journal;
pub mod native_journal;
pub mod reference_device;
pub mod reference_lineage;
pub mod reference_service;
pub mod session;
pub mod transport;

/// Reports transport, portable schema, or correlation failure.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    /// The stream could not complete an I/O operation.
    #[error("provider stream I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Portable data failed its canonical representation or bounds.
    #[error("invalid provider data: {0}")]
    Contract(#[from] crucible_node_contract::ContractError),
    /// A frame cannot be interpreted under the admitted transport.
    #[error("invalid provider frame: {0}")]
    Frame(&'static str),
    /// A message disagrees with retained connection or request custody.
    #[error("provider correlation failure: {0}")]
    Correlation(&'static str),
    /// A finite storage or sequence allowance is exhausted.
    #[error("provider resource exhausted: {0}")]
    ResourceExhausted(&'static str),
    /// A request identity is reused with different material.
    #[error("provider request conflict: {0}")]
    Conflict(&'static str),
}

// Operational host clocks remain private to audited process/transport paths.
mod operational_time;
