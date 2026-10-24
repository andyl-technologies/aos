//! Native acquisition and verified consumption of AOS package registries.
//!
//! Portable records are defined in `aos-registry-format`. This crate owns
//! configuration discovery, transport, trusted-key storage, and provenance
//! verification; installation and activation policy live in their own projects.

// Native registry I/O uses host time, entropy for signing keys and temporary
// names, and process-local lookup tables. It is outside Crucible state paths.
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

pub mod cleanup;
pub mod config;
pub mod dry_run;
#[cfg(test)]
mod gitcmd;
pub mod hub_auth;
pub mod provenance;
pub mod registry;
pub mod security;
/// Creates authenticated reader fixtures when test support is enabled.
#[cfg(any(test, feature = "test-support"))]
pub mod sshkey;
pub mod sync;
#[cfg(test)]
mod testutil;
pub mod types;

fn canonical_json_digest(value: &serde_json::Value) -> anyhow::Result<String> {
    let canonical = aos_core::json::canonical_json(value)?;
    Ok(aos_core::Sha256Digest::of_bytes(canonical).to_string())
}
