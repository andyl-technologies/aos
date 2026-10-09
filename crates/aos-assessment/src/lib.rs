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
//!
//! Existing `aos-maintain` paths reexport these contracts for compatibility.

#![forbid(unsafe_code)]

pub mod decision;
pub mod discovery;
pub mod identity;
pub mod inventory;

/// Schema identifier for the first maintenance inventory contract.
pub const MAINTENANCE_INVENTORY_V1: &str = "aos.maintenance-inventory/v1";

/// Schema identifier for one immutable upstream-provider observation.
pub const UPSTREAM_OBSERVATION_V1: &str = "aos.upstream-observation/v1";

/// Schema identifier for one repository-bound discovery snapshot.
pub const DISCOVERY_SNAPSHOT_V1: &str = "aos.discovery-snapshot/v1";
