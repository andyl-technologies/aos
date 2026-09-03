//! Pure contracts and policy for local AOS package maintenance.
//!
//! This crate models package-update inventory, workflow state, journal events,
//! and presentation-neutral command results. Callers supply observations and
//! perform effects; this crate performs no filesystem, network, Git, Nix,
//! process, clock, model, terminal, or credential I/O.
//!
//! # Module map
//!
//! - [`identity`] defines validated stable identifiers.
//! - [`inventory`] defines the closed package-maintenance inventory.
//! - [`envelope`] binds evaluated inventory to an exact local repository.
//! - [`workflow`] defines legal run transitions and event contracts.
//! - [`presentation`] defines renderer-independent command completion.

#![forbid(unsafe_code)]

pub mod envelope;
pub mod identity;
pub mod inventory;
pub mod presentation;
pub mod workflow;

/// Schema identifier for the first maintenance inventory contract.
pub const MAINTENANCE_INVENTORY_V1: &str = "aos.maintenance-inventory/v1";

/// Schema identifier for the first repository-bound inventory envelope.
pub const MAINTENANCE_INVENTORY_ENVELOPE_V1: &str = "aos.maintenance-inventory-envelope/v1";

/// Schema identifier for the first durable maintenance journal event.
pub const MAINTENANCE_JOURNAL_EVENT_V1: &str = "aos.maintain.journal-event/v1";

/// Schema identifier for the first transient maintenance progress event.
pub const MAINTENANCE_PROGRESS_EVENT_V1: &str = "aos.maintain.progress-event/v1";

/// Schema identifier for the first maintenance command result.
pub const MAINTENANCE_CLI_V1: &str = "aos.maintain.cli/v1";
