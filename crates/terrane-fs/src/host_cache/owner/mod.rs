//! Owns native cache configuration and the physical command-owner boundary.
//!
//! Configuration validation performs no filesystem mutation. Writable readiness
//! additionally requires actual confinement, authenticated quota custody, a
//! measured publisher probe and completed recovery; configuration grants none
//! of those authorities.

mod admission;
mod config;
mod index_io;
mod preparation;
mod publication;
mod recovery;
mod recovery_accounting;
mod recovery_candidates;
mod recovery_inline;
mod recovery_manifest_state;
mod recovery_manifests;
mod recovery_namespace;
mod recovery_residences;
mod recovery_state;
mod recovery_state_parent;
mod resume_error;
mod retention;
mod snapshot;

/// Selects the latest Unix deadline encodable by existing TOML policy snapshots.
///
/// TOML integers are signed. Using `u64::MAX` makes even the first retained pin
/// fail preflight serialization. Native operation custody and reservations remain
/// retained through actual retirement; this value grants no release authority.
pub(super) const RETAINED_LEASE_DEADLINE: u64 = i64::MAX as u64;

pub(super) use index_io::open_regular_at;

pub use admission::{
    NativeChunkAdmission, NativeChunkAdmissionError, NativeMetadataAdmission,
    NativeMetadataAdmissionError,
};
pub use config::{IndexRepairPolicy, NativeCacheOwnerConfig};
pub use preparation::NativeCachePreparation;
pub use publication::{
    NativeInlinePublication, NativeManifestPublication, NativeResidentChunkRead,
};
pub use recovery::CompletedRecovery;
pub use resume_error::NativeResumeError;
pub(crate) use retention::{
    AcceptedRecoveryManifestEffect, PublisherResumeTurn, PublisherRunningTurn,
    RecoveryManifestBodyFailure, RecoveryManifestBodyRetention, RecoveryManifestEffect,
    RecoveryManifestEffectFailure, RecoveryRetainedManifest,
};
pub use retention::{NativeIndexRepairReport, NativeMetadataOwner, RetainedManifest};
