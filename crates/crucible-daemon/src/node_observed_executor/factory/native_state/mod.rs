//! Installed mixed-native world qualification and owning restoration custody.
//!
//! Native preservation dispatches through each immutable backend/profile/schema
//! key. Original complete runtime and coordinator state remains common; native
//! images, actual live certificates and fresh owner binding remain backend-owned.

pub(super) mod archive;
mod control;
mod custody;
mod evidence;
mod execution;
mod factory;
pub(super) mod host;
pub(in crate::node_observed_executor::factory) mod host_clocks;
pub(in crate::node_observed_executor::factory) mod host_group;
mod installed;
mod ledger;
pub(super) mod profile;
pub(super) mod public_catalog;
mod publication;
mod scheduling_epochs;
mod service;
mod staging;

pub use control::{
    InstalledGem5Isa, NativeCapturePoint, NativeWorldOutcome, NativeWorldRecord, NativeWorldRequest,
};
pub use service::{NativeWorldRetention, NativeWorldService};

#[cfg(test)]
mod ledger_tests;

#[cfg(test)]
mod service_tests;

#[cfg(test)]
mod tests;
