//! Produces and verifies per-object attributes through injected storage APIs.
//!
//! Side-table lookups use a verified authoritative metadata catalog and never
//! read plaintext on a hit. Unsupported function versions remain retained but
//! untrusted. Quarantined records are removed from serving independently of
//! immutable pack bytes. Backfill execution belongs to the later tree-job layer.
//! Producer verification binds detached terminal-key signatures to checked
//! producing tree/object witnesses, or uses verified inline attribute origins
//! for legacy unsigned records. Missing evidence leaves provenance untrusted.

mod dictionary;
mod object;
mod produce;
#[cfg(feature = "std")]
mod storage;
mod table;

pub use dictionary::{DictionarySet, StoreDictionaries};
pub use object::{DictionaryResolver, NoDictionaries, PlaintextObject, StoreObject};
pub use produce::{
    Requirements, SignedProducer, compute, produce_required, produce_required_signed,
};
pub use table::{
    AttributeCatalog, AttributeQuarantine, ProducerEvidence, ProducerVerifier, Quarantine,
    SideTable, Trust,
};

use crate::{codec::FrameError, store::StoreFailure};
use std::fmt;
use terrane_core::derived;

/// A production, storage, or provenance failure.
#[derive(Debug)]
pub enum Error {
    /// The pure attribute format or producer rejected input.
    Derived(derived::Error),
    /// Immutable content retrieval or admission failed.
    Store(StoreFailure),
    /// Object manifest validation failed.
    Manifest(terrane_core::manifest::Error),
    /// A chunk's plaintext could not be verified.
    Frame(FrameError),
    /// Producer evidence is absent or contradicts the record.
    InvalidProducer,
    /// A plaintext reader returned an unexpected byte count.
    InvalidRead,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Derived(e) => write!(f, "derived attribute: {e}"),
            Self::Store(e) => write!(f, "attribute storage: {e}"),
            Self::Manifest(e) => write!(f, "attribute object manifest: {e}"),
            Self::Frame(e) => write!(f, "attribute chunk: {e}"),
            Self::InvalidProducer => f.write_str("unverified attribute producer evidence"),
            Self::InvalidRead => f.write_str("plaintext read length mismatch"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Derived(e) => Some(e),
            Self::Store(e) => Some(e),
            Self::Manifest(e) => Some(e),
            Self::Frame(e) => Some(e),
            _ => None,
        }
    }
}

impl From<derived::Error> for Error {
    fn from(e: derived::Error) -> Self {
        Self::Derived(e)
    }
}

impl From<StoreFailure> for Error {
    fn from(e: StoreFailure) -> Self {
        Self::Store(e)
    }
}

impl From<terrane_core::manifest::Error> for Error {
    fn from(e: terrane_core::manifest::Error) -> Self {
        Self::Manifest(e)
    }
}

impl From<FrameError> for Error {
    fn from(e: FrameError) -> Self {
        Self::Frame(e)
    }
}

impl From<terrane_core::identity::IdentityError> for Error {
    fn from(e: terrane_core::identity::IdentityError) -> Self {
        Self::Derived(e.into())
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "Failed test setup and assertions intentionally panic."
)]
mod tests;

#[cfg(all(test, feature = "tokio"))]
#[allow(
    clippy::expect_used,
    reason = "Failed durable fixture setup and assertions intentionally panic."
)]
mod storage_tests;
