//! Generic native journal framing, durability, geometry, and map mechanics.
//!
//! [`framing`] owns native frame bytes, checksums, retained partial reads, and
//! write/flush/sync mechanics. [`geometry`] owns record and transaction widths
//! and generic native configuration bounds. [`materialized`] owns ordered
//! DATA-map projection and mutation without domain-specific indexes or admission.
//! [`native_suffix`] owns borrowed before/after accounting and raw suffix widths;
//! domain owners retain actual mutation graphs and final headroom admission.
//! [`record`] owns raw namespace bytes and borrowed native record payloads;
//! domain owners retain closed namespace decoding and semantic validation.
//! [`transaction`] owns ordered native transaction construction and incremental
//! ID/count/digest state without decoding records or publishing committed state.
//! Its bounded record owner shares extent accounting and a borrowed duplicate
//! index; domain schema checks remain between those two mechanical stages.
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
//! The opt-in Unix physical owner opens protected paths and retains the
//! actual directory and replacement-cleanup loan. Default generic selection
//! remains portable. Domain owners still acquire locks, replay domain schemas,
//! admit authority, and perform final crossings while retaining original causes.
//! This physical prerequisite is not a complete protected Journal migration.

/// Owns opt-in Unix physical custody without semantic replay or authority.
#[cfg(all(unix, feature = "protected-unix"))]
pub mod protected_storage;

pub mod framing;
pub mod geometry;
pub mod materialized;
pub mod native_suffix;
pub mod owner;
pub mod record;
pub mod recovery;
pub mod replay;
pub mod storage;
pub mod transaction;
