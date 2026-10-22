//! Seals the service DTOs whose JSON diagnostic paths have finite source bounds.
//!
//! These are the existing policy, bootstrap and workflow schemas. Their runtime
//! validation remains in the consuming service; this module grants no service,
//! IO parser or arbitrary custom visitor admission.

use serde::Deserialize;

/// Owns the authenticated asset and campaign-creation projection wire types.
pub mod assets;
/// Owns the pinned SQLite bootstrap projection wire types.
pub mod bootstrap;
/// Owns the campaign policy projection wire types.
pub mod policy;
/// Owns the original service workflow projection wire types.
pub mod workflow;

pub(super) mod sealed {
    pub trait Sealed {}
}

/// Identifies a concrete service DTO with a reviewed slice diagnostic profile.
///
/// Implementations are sealed to this crate. External deserializers cannot
/// supply a numeric allowance or use a service profile for another type.
pub trait ClosedJsonProfile<'input>: sealed::Sealed + Deserialize<'input> {
    /// Lists the actual Serde field, variant and generated type labels.
    #[doc(hidden)]
    const DIAGNOSTIC_LABELS: &'static [&'static str];
}
