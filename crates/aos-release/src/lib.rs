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
//! - [`registry`] classifies registry identities, tiers, and channel kinds.
//! - [`plan`] freezes release intent, publication surfaces, and destinations
//!   before build effects begin.
//! - [`artifact_profile`] binds baked client settings to the release registry.
//! - [`manifest`] binds finalized artifacts to the frozen plan.
//! - [`evidence`] records public gate and qualification results.
//! - [`qualification`] defines the shared contract: typed scopes, assurance
//!   claims, destination profiles, change scope, and fixed admission limits.
//! - [`qualification_evidence`] expands per-destination cases and derives
//!   assurance from observations.
//! - [`qualification_admission`] binds rollout and completion decisions and
//!   independent reviews to one destination.
//! - [`fitness`] validates signed environment-exercise attestations.
//! - [`profile_override`] validates threshold-signed soak and ring relaxations.
//! - [`inventory`] validates the Nix-derived four-target package inventory.
//! - [`signing`] defines role-bound signing requests and responses.
//! - [`state`] defines the append-only, per-destination release journal.
//! - [`receipt`] binds publication, qualification, and channel operations on
//!   Hub and static surfaces.
//! - [`verify`] verifies complete release values, captured bundle bytes, and
//!   journals.
//!
//! # How the pieces fit
//!
//! A release starts from a [`plan::ReleasePlan`] that embeds the
//! [`qualification::QualificationContract`]. The contract's destination table
//! selects a profile for each `<surface>/<channel>` destination; the plan
//! freezes each destination's gates, soak, and rollout rings. The build
//! produces a [`manifest::ReleaseManifestV1`]; publication, qualification, and
//! channel operations append [`state::JournalEntry`] records whose
//! per-destination state [`verify::verify_journal`] recomputes. Fitness
//! attestations and profile overrides are separately signed inputs checked
//! against the destination's profile at publication time.

#![forbid(unsafe_code)]

#[cfg(test)]
extern crate self as aos_release;

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod assurance_tests;

#[cfg(test)]
mod native_adapter_matrix_tests;

pub mod artifact;
pub mod artifact_profile;
pub mod build;
pub mod canonical;
pub mod digest;
pub mod evidence;
pub mod fitness;
pub mod inventory;
pub mod manifest;
pub mod plan;
pub mod platform;
pub mod profile_override;
pub mod qualification;
pub mod qualification_document;
pub mod qualification_admission;
pub mod qualification_evidence;
pub mod receipt;
pub mod record;
pub mod registry;
pub mod sbom;
pub mod signing;
pub mod state;
pub mod tuf;
pub mod verify;

pub use digest::Sha256Digest;

/// Schema for release plans with surfaces, destinations, and profiles.
pub const RELEASE_PLAN: &str = "aos.release.plan/v1";

/// Schema identifier for the first finalized release-manifest contract.
pub const RELEASE_MANIFEST_V1: &str = "aos.release.manifest/v1";

/// Schema identifier for per-destination journal entries.
pub const RELEASE_JOURNAL_ENTRY: &str = "aos.release.journal-entry/v1";
