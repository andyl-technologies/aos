//! Portable assignment planning with inspectable policies and scoped execution.
//!
//! The model types and pure [`validate`], [`evaluate`], and [`verify`] operations
//! are re-exported from [`dispatch_model`]. [`ProblemBuilder`] constructs models
//! without hiding their constraints or objectives. [`recipes`] provides explicit
//! policy expansions; [`analysis`] compares assignments and explains evaluations.
//!
//! With the `runtime` feature, the `runtime` module supplies bounded sessions and execution
//! providers. Pure operations execute in the caller's resource context. Session
//! execution moves substantive materialization and verification into the selected
//! worker boundary. A verified plan describes the submitted snapshot; callers
//! retain responsibility for freshness, reservations, and applying changes.

pub mod analysis;
mod builder;
pub mod recipes;

pub use builder::ProblemBuilder;
pub use dispatch_model::*;

/// Exposes session execution without coupling portable models to a supervisor.
#[cfg(feature = "runtime")]
pub use dispatch_runtime as runtime;

/// Exposes the primary session types at the public facade boundary.
#[cfg(feature = "runtime")]
pub use dispatch_runtime::{Session, SessionBuilder, SolveOptions};

/// Exposes portable solve documents without putting execution paths in models.
#[cfg(feature = "protocol")]
pub use dispatch_protocol::request::{SearchRequestOptions, SolveRequest};
