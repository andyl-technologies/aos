//! Defines portable source-profile records and their static validation.
//!
//! These values describe a selection; no record is a live native owner or an
//! authenticated process/connection/source capability.

pub use crate::errors::ProviderError;
pub mod bodies;
pub mod handshake;
pub mod reference_service;

pub mod client;

pub mod connection;

pub mod reference_packet;

/// Defines the original inert operation vocabulary.
pub mod envelope;
/// Shares actual requested tree-layout arithmetic.
pub mod requested_storage;
/// Shares the actual serializer projection without metadata custody.
pub mod serialization_storage;

pub(crate) mod launch_projection;
