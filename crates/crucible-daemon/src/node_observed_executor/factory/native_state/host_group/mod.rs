//! Source-selected independent Script/Block composition before native enrollment.
//!
//! The old clock-only mixed qualifier remains separate. These source helpers
//! supply complete regenerated metadata, not native admission or readiness.
//! Actual resource enrollment and the common all-owner barrier remain required.

pub(super) mod evidence;
pub(super) mod profile;
pub(in crate::node_observed_executor::factory) mod selection;
