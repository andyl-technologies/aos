//! Package-scoped module evaluation and durable deployment transactions.
//!
//! Packages publish payload and module artifact envelopes. Resolution supplies
//! exact envelopes and module dependencies before evaluation. A single module
//! fixed point emits a bound transaction; this layer retains it and executes it
//! through package-provided ability handlers. Profiles and system deployments
//! are callers of the same scope-neutral API.
//!
//! [`model`] owns the envelope and transaction formats, [`evaluation`] renders
//! the pure Nix entry point, and [`transaction`] commits journaled generations.
//! [`handler`] interprets terminal operations through the bounded process transport.

pub mod evaluation;
pub mod handler;
pub mod model;
pub mod nix;
pub(crate) mod process;
pub mod retention;
mod source_views;
pub mod transaction;

#[cfg(test)]
mod tests;
