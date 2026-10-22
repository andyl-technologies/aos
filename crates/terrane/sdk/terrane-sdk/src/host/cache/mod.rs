//! Owns domain-scoped encoded cache reads, admission and bounded eviction.
//!
//! Encoded content and plaintext sealed handles remain separate interfaces.
//! Persistent policy state contains no chunk index or sealed-read lock.

mod fetch;
mod kernel;
mod layout;
mod metadata;
mod policy;
mod readonly;
mod reassembly;
mod recovery;
mod residence;
mod state;
mod verification;

pub use fetch::{FetchRequirement, fetch_verified};
pub use kernel::{HostInspection, HostKernel, SealInspection};
pub use layout::{DomainHostLayout, HostDomainLocation, HostReadLocation};
pub use metadata::{HostMetadataEntry, HostMetadataReader};
pub use policy::{CacheEntry, CachePolicy, CircuitBreaker, PolicyConfig};
pub use readonly::{HostReadLimits, HostReadOnlyContent};
pub use reassembly::ReassemblyMode;
pub use recovery::{ReconstructedPackIndex, reconstruct_pack_index};
pub use residence::{HostResidenceReader, HostResidentContent, ResidenceChunk};
pub use state::{
    CacheState, ExposurePhase, ExposureRecord, LeaseRecord, PinRecord, ReservationRecord,
    ResidenceRecord, StateLimits,
};
pub use verification::{inspect_standalone_length, maximum_encoded_chunk_bytes};

#[cfg(test)]
mod policy_tests;

#[cfg(all(test, feature = "tokio", unix))]
mod native_tests;

#[cfg(all(test, feature = "tokio", unix))]
mod fetch_tests;
