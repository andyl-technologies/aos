//! Owns AOS adapters for the standalone Terrane SDK.
//!
//! This foundation establishes the glue boundary in CRATE-18 and integration
//! PKG-1. Service-manager, mount-broker, identity, and sandbox adapters belong
//! here as their integration tasks land. The standalone Terrane crates never
//! depend on this crate. There are no adapters or public modules in T0.

#![forbid(unsafe_code)]
