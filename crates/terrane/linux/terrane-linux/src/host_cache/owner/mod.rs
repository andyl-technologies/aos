//! Owns native cache configuration and the physical command-owner boundary.
//!
//! Configuration validation performs no filesystem mutation. Writable readiness
//! additionally requires actual confinement, authenticated quota custody, a
//! measured publisher probe and completed recovery; configuration grants none
//! of those authorities.

mod admission;
mod config;
mod consumer;
mod corruption;
mod fetch;
mod index_io;
#[cfg(feature = "native-test-fixtures")]
mod policy_stall_fixture;
mod preparation;
mod publication;
mod read_through;
mod recovery;
mod recovery_accounting;
mod recovery_candidates;
mod recovery_cold;
mod recovery_encoded;
mod recovery_indexes;
mod recovery_inline;
mod recovery_manifest_state;
mod recovery_manifests;
mod recovery_metadata;
mod recovery_namespace;
mod recovery_pending;
mod recovery_portable;
mod recovery_residences;
mod recovery_restore;
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

pub(crate) use admission::eviction::turn::PublisherEncodedCacheTurn;
pub(crate) use admission::read_custody::PublisherEncodedReadTurn;
pub use admission::{
    NativeAdmissionHandoffError, NativeAdmissionHandoffReport, NativeChunkAdmission,
    NativeChunkAdmissionError, NativeChunkAdmissionTicket, NativeMetadataAdmission,
    NativeMetadataAdmissionError,
};
pub use config::{IndexRepairPolicy, NativeCacheOwnerConfig};
pub use consumer::{
    NativeConsumerLease, NativeLeaseAccounting, NativeSealedBacking, NativeSealedObjectLease,
};
pub use fetch::{NativeChunkFetchRequest, NativeFetchedChunk};
#[cfg(feature = "native-test-fixtures")]
pub use policy_stall_fixture::NativePolicyStall;
pub use preparation::NativeCachePreparation;
pub use publication::{
    NativeCacheEvictionReport, NativeCacheHandoffError, NativeCacheHandoffReport,
    NativeInlinePublication, NativeManifestPublication, NativeProducerReadClosure,
    NativeResidentChunkSource, NativeSourceCleanupReport,
};
pub use read_through::NativeReadChunk;
pub use recovery::CompletedRecovery;
pub(crate) use recovery::RunningRecovery;
pub(crate) use recovery_pending::PublisherRecoveryRetirementTurn;
pub(crate) use recovery_restore::PublisherRecoveryRestoreTurn;
pub use resume_error::NativeResumeError;
pub(crate) use retention::{
    AcceptedRecoveryManifestEffect, PublisherCacheRetirementTurn, PublisherCleanupTurn,
    PublisherCorruptionTurn, PublisherResumeTurn, PublisherRunningTurn,
    RecoveryManifestBodyFailure, RecoveryManifestBodyRetention, RecoveryManifestEffect,
    RecoveryManifestEffectFailure, RecoveryRetainedManifest,
};
pub use retention::{NativeIndexRepairReport, NativeMetadataOwner, RetainedManifest};
