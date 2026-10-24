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
mod hello_frames;
pub mod input_commit;
pub mod journal;
pub mod native_hello;
pub mod native_journal;
pub mod reference_device;

pub mod protocol_snapshot;
pub mod reference_lineage;
/// Exposes a finite source-owned packet provider over the public protocol.
pub mod reference_packet;
pub mod reference_service;
pub mod retained_metadata;
pub mod session;
pub mod transport;

// Operational host clocks remain private to audited process/transport paths.
mod operational_time;

pub use crucible_source_birth_data::errors::ProviderError;
