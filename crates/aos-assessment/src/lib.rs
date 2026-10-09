//! Shared pure package inventory and assessment policy for AOS.
//!
//! This crate owns portable contracts and deterministic evaluation used by
//! local maintenance and every Hub runtime. Callers supply observations and
//! explicit time; the crate performs no filesystem, network, database, Git,
//! process, clock, or credential I/O.
//!
//! # Module map
//!
//! - [`identity`] defines validated component and update-unit identifiers.
//! - [`inventory`] validates the existing package-maintenance declarations.
//! - [`discovery`] evaluates bounded observations against version policy.
//! - [`decision`] defines the shared interpretation of discovery evidence.
//! - [`time`] validates explicit portable evaluation and observation timestamps.
//! - [`security`] declares product identities, advisory profiles and coverage.
//! - [`definition`] binds reusable package-authored scan semantics.
//! - [`scan_inventory`] binds source/artifact subjects and dependency graphs.
//! - [`observation`] binds immutable provider evidence, completeness and freshness.
//! - [`advisory`] binds normalized advisory revisions and query snapshots.
//! - [`ranges`] interprets admitted version intervals without lexical fallback.
//! - [`nvd`] evaluates complete configuration expressions and environment facts.
//! - [`input`] freezes policy, candidate history and complete evidence references.
//! - [`disposition`] binds reviewed claims to exact components and source revisions.
//! - [`evaluator`] and [`findings`] construct deterministic scoped assessments.
//! - [`result`] defines shared version, finding, diagnostic and coverage records.
//! - [`bundle`] verifies portable exports and offline reproduction without granting authority.
//!
//! Existing `aos-maintain` paths reexport these contracts for compatibility.

#![forbid(unsafe_code)]

pub mod advisory;
mod aliases;
pub mod bundle;
pub mod decision;
pub mod definition;
pub mod discovery;
pub mod disposition;
pub mod evaluator;
pub mod findings;
pub mod identity;
pub mod input;
pub mod inventory;
pub mod nvd;
pub mod observation;
pub mod ranges;
pub mod result;
pub mod scan_inventory;
pub mod security;
pub mod time;
mod validation;
mod version;

/// Schema identifier for the first maintenance inventory contract.
pub const MAINTENANCE_INVENTORY_V1: &str = "aos.maintenance-inventory/v1";

/// Schema identifier for one immutable upstream-provider observation.
pub const UPSTREAM_OBSERVATION_V1: &str = "aos.upstream-observation/v1";

/// Schema identifier for one repository-bound discovery snapshot.
pub const DISCOVERY_SNAPSHOT_V1: &str = "aos.discovery-snapshot/v1";
