//! Generic native journal framing, durability, geometry, and map mechanics.
//!
//! [`framing`] owns native frame bytes, checksums, retained partial reads, and
//! write/flush/sync mechanics. [`geometry`] owns record and transaction widths
//! and generic native configuration bounds. [`materialized`] owns ordered
//! DATA-map projection and mutation without domain-specific indexes or admission.
//! [`record`] owns raw namespace bytes and borrowed native record payloads;
//! domain owners retain closed namespace decoding and semantic validation.
//! Controller, Storage, and session-security owners use these same mechanics
//! without sharing authority.
//!
//! This crate does not open protected storage, decode domain namespaces, issue
//! authority, sign records, apply semantic transitions, or own replay visibility.
//! Transaction assembly, locking, compaction, and semantic replay remain with
//! their existing owners; this is not a complete journal ownership migration.

pub mod framing;
pub mod geometry;
pub mod materialized;
pub mod record;
