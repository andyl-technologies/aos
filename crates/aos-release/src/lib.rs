//! Pure contracts and offline verification for canonical AOS releases.
//!
//! This crate defines the signed data that crosses the release pipeline's
//! trust boundaries. It performs no filesystem, process, network, clock, or
//! key-provider I/O, so producers, the Hub, native clients, Workers, and
//! offline verifiers can share the same fail-closed interpretation.
//!
//! # Module map
//!
//! - [`canonical`] parses strict JSON and produces canonical bytes.
//! - [`digest`] defines typed, domain-separated SHA-256 identities.
//! - [`platform`] defines the closed package and image matrix.
//! - [`artifact`] defines immutable bundle members and relationships.
//! - [`plan`] freezes release intent before build effects begin.
//! - [`manifest`] binds finalized artifacts to the frozen plan.
//! - [`evidence`] records public gate and qualification results.
//! - [`inventory`] validates the Nix-derived four-target package inventory.
//! - [`signing`] defines role-bound signing requests and responses.
//! - [`state`] defines the append-only release journal state machine.
//! - [`receipt`] binds staging, production, and channel operations.
//! - [`verify`] verifies complete release values and captured bundle bytes.

#![forbid(unsafe_code)]

pub mod artifact;
pub mod build;
pub mod canonical;
pub mod digest;
pub mod evidence;
pub mod inventory;
pub mod manifest;
pub mod plan;
pub mod platform;
pub mod receipt;
pub mod registry;
pub mod sbom;
pub mod signing;
pub mod state;
pub mod tuf;
pub mod verify;

pub use digest::Sha256Digest;

/// Schema identifier for the first frozen release-plan contract.
pub const RELEASE_PLAN_V1: &str = "aos.release.plan/v1";

/// Schema identifier for the first finalized release-manifest contract.
pub const RELEASE_MANIFEST_V1: &str = "aos.release.manifest/v1";

/// Schema identifier for the first hash-chained journal-entry contract.
pub const RELEASE_JOURNAL_ENTRY_V1: &str = "aos.release.journal-entry/v1";
