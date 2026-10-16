//! Owns native cache configuration and the physical command-owner boundary.
//!
//! Configuration validation performs no filesystem mutation. Writable readiness
//! additionally requires actual confinement, authenticated quota custody, a
//! measured publisher probe and completed recovery; configuration grants none
//! of those authorities.

mod config;
mod index_io;
mod preparation;
mod retention;

pub use config::{IndexRepairPolicy, NativeCacheOwnerConfig};
pub use preparation::NativeCachePreparation;
pub use retention::{NativeIndexRepairReport, NativeMetadataOwner, RetainedManifest};
