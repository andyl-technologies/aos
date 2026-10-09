//! Native acquisition and verified consumption of AOS package registries.
//!
//! Portable records are defined in `aos-registry-format`. This crate owns
//! configuration discovery, transport, trusted-key storage, and provenance
//! verification; installation and activation policy live in their own projects.

pub mod config;
pub mod dry_run;
pub mod hub_auth;
pub mod provenance;
pub mod registry;
pub mod security;
pub mod sshkey;
pub mod types;
#[cfg(test)] mod gitcmd;
#[cfg(test)] mod testutil;

fn canonical_json_digest(value: &serde_json::Value) -> anyhow::Result<String> {
 let canonical = aos_core::json::canonical_json(value)?;
 Ok(aos_core::Sha256Digest::of_bytes(canonical).to_string())
}
