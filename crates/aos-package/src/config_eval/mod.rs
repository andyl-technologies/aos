//! Native domain evaluator integration for storage provisioning.
//!
//! Generic package resolution, evaluation, and activation belong to
//! [`crate::deployment`]. This module retains only the package-owned evaluator
//! transport and its bounded immutable source import boundary.

pub(crate) mod provisioning_evaluator;
pub mod provisioning_evaluator_provider;
pub(crate) mod provisioning_sources;
