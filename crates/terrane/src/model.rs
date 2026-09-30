//! Exposes canonical models used by the repository's public API.
//!
//! Consumers configure local authority, name commit sources, and inspect
//! algebra results through these shared types. The definitions remain in
//! `terrane-core`. Repository I/O and authorization use this crate's verbs.

/// Exposes canonical algebra result types and their pure representations.
pub use terrane_core::algebra;

/// Exposes authority and grant types used to configure local repositories.
pub use terrane_core::auth::{Authority, Grant, PrincipalKind, Verbs};

/// Exposes the source and locality models carried by repository requests.
pub use terrane_core::refs::{CommitSource, Locality};
