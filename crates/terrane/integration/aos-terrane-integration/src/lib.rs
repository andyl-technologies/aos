//! Owns AOS adapters for the standalone Terrane SDK.
//!
//! Host integration belongs here; standalone Terrane crates never depend on
//! this crate. The host module supplies the integration boundary for privileged
//! host services without granting privilege to Terrane roles. Service-manager,
//! mount-broker and sandbox adapters are added by their implementation tasks.

#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
pub mod host;
