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
//! - [`discovery`] models bounded provider evidence and candidate selection.
//! - [`plan`] freezes selected updates and their permitted semantic mutations.
//! - [`workflow`] defines legal run transitions and event contracts.
//! - [`presentation`] defines renderer-independent command completion.

#![forbid(unsafe_code)]

pub mod discovery;
pub mod envelope;
pub mod identity;
pub mod inventory;
pub mod plan;
pub mod presentation;
pub mod run;
pub mod workflow;

/// Schema identifier for the first maintenance inventory contract.
pub const MAINTENANCE_INVENTORY_V1: &str = "aos.maintenance-inventory/v1";

/// Schema identifier for the first repository-bound inventory envelope.
pub const MAINTENANCE_INVENTORY_ENVELOPE_V1: &str = "aos.maintenance-inventory-envelope/v1";

/// Schema identifier for one immutable upstream-provider observation.
pub const UPSTREAM_OBSERVATION_V1: &str = "aos.upstream-observation/v1";

/// Schema identifier for one repository-bound discovery snapshot.
pub const DISCOVERY_SNAPSHOT_V1: &str = "aos.discovery-snapshot/v1";

/// Schema identifier for one immutable package-update plan.
pub const PACKAGE_UPDATE_PLAN_V1: &str = "aos.package-update-plan/v1";
/// Schema identity for durable local execution records.
pub const PACKAGE_UPDATE_RUN_V1: &str = "aos.package-update-run/v1";
/// Schema identity for deterministic attempt-zero materialization evidence.
pub const PACKAGE_UPDATE_MATERIALIZATION_V1: &str = "aos.package-update-materialization/v1";
/// Schema identity for one tree-bound gate execution set.
pub const PACKAGE_UPDATE_GATE_RESULTS_V1: &str = "aos.package-update-gate-results/v1";
/// Schema identity for the complete local candidate evidence dossier.
pub const PACKAGE_UPDATE_EVIDENCE_V1: &str = "aos.package-update-evidence/v1";

/// Schema identifier for the first durable maintenance journal event.
pub const MAINTENANCE_JOURNAL_EVENT_V1: &str = "aos.maintain.journal-event/v1";

/// Schema identifier for the first transient maintenance progress event.
pub const MAINTENANCE_PROGRESS_EVENT_V1: &str = "aos.maintain.progress-event/v1";

/// Schema identifier for the first maintenance command result.
pub const MAINTENANCE_CLI_V1: &str = "aos.maintain.cli/v1";
