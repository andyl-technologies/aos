//! Generic native journal framing, durability, geometry, and map mechanics.
//!
//! [`framing`] owns native frame bytes, checksums, retained partial reads, and
//! write/flush/sync mechanics. [`geometry`] owns record and transaction widths
//! and generic native configuration bounds. [`materialized`] owns ordered
//! DATA-map projection and mutation without domain-specific indexes or admission.
//! [`record`] owns raw namespace bytes and borrowed native record payloads;
//! domain owners retain closed namespace decoding and semantic validation.
//! [`transaction`] owns ordered native transaction construction and incremental
//! ID/count/digest state without decoding records or publishing committed state.
//! [`recovery`] finalizes the already replayed tail on the same borrowed file;
//! actual semantic replay and selected native-result custody remain upper.
//! [`replay`] retains incremental coordinates, counts, and the original ID set;
//! domain owners still decide when semantic application permits each update.
//! [`storage`] retains supplied data and lock files, append uncertainty, and
//! bounded physical readers without admitting the files or issuing receipts.
//! [`owner`] now retains a concrete native journal's files, configuration,
//! coordinates, identity/provenance sets, and materialized DATA map together.
//! Domain wrappers still own semantic replay, protected opening, and authority.
//! Controller, Storage, and session-security owners use these same mechanics
//! without sharing authority.
//!
//! This crate does not open protected storage, decode domain namespaces, issue
//! authority, sign records, apply semantic transitions, or own replay visibility.
//! Lock acquisition, compaction, and semantic replay remain with
//! their existing owners; this is not a complete journal ownership migration.

pub mod framing;
pub mod geometry;
pub mod materialized;
pub mod owner;
pub mod record;
pub mod recovery;
pub mod replay;
pub mod storage;
pub mod transaction;
