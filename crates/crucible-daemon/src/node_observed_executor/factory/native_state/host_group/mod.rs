//! Source-selected independent Script/Block composition before native enrollment.
//!
//! The old clock-only mixed qualifier remains separate. These source helpers
//! supply complete regenerated metadata, not native admission or readiness.
//! Actual resource enrollment and the common all-owner barrier remain required.

pub(super) mod archive_credit;
pub(super) mod artifacts;
mod capability_metadata;
pub(super) mod continuation_policy;
pub(super) mod evidence;
pub(super) mod factory;
pub(super) mod failure_retirement;
pub(super) mod immutable;
pub(super) mod metadata;
pub(super) mod profile;
pub(super) mod reservation;
pub(in crate::node_observed_executor::factory) mod selection;
pub(super) mod source;
