//! Owns native cache configuration and the physical command-owner boundary.
//!
//! Configuration validation performs no filesystem mutation. Writable readiness
//! additionally requires actual confinement, authenticated quota custody, a
//! measured publisher probe and completed recovery; configuration grants none
//! of those authorities.

mod config;
mod index_io;
mod preparation;
mod recovery;
mod recovery_accounting;
mod recovery_inline;
mod recovery_namespace;
mod recovery_residences;
mod recovery_state;
mod recovery_state_parent;
mod resume_error;
mod retention;

pub(super) use index_io::open_regular_at;

pub use config::{IndexRepairPolicy, NativeCacheOwnerConfig};
pub use preparation::NativeCachePreparation;
pub use recovery::CompletedRecovery;
pub use resume_error::NativeResumeError;
pub(crate) use retention::{
    AcceptedRecoveryManifestEffect, LiveManifestRecoveryContext, PublisherResumeTurn,
    PublisherRunningTurn, RecoveryManifestBackingRetention, RecoveryManifestBodyFailure,
    RecoveryManifestBodyRetention, RecoveryManifestEffect, RecoveryManifestEffectFailure,
    RecoveryRetainedManifest,
};
pub use retention::{NativeIndexRepairReport, NativeMetadataOwner, RetainedManifest};
