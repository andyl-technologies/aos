//! Owns domain-scoped encoded cache reads, admission and bounded eviction.
//!
//! Encoded content and plaintext sealed handles remain separate interfaces.
//! Persistent policy state contains no chunk index or sealed-read lock.

mod fetch;
mod kernel;
mod layout;
mod policy;
mod readonly;
mod reassembly;
mod state;
mod verification;

pub use fetch::{FetchRequirement, fetch_verified};
pub use kernel::{HostInspection, HostKernel, SealInspection};
pub use layout::DomainHostLayout;
pub use policy::{CacheEntry, CachePolicy, CircuitBreaker, PolicyConfig};
pub use readonly::HostReadOnlyContent;
pub use reassembly::ReassemblyMode;
pub use state::{
    CacheState, LeaseRecord, PinRecord, ReservationRecord, ResidenceRecord, StateLimits,
};
pub use verification::{inspect_standalone_length, maximum_encoded_chunk_bytes};

#[cfg(test)]
mod policy_tests;

#[cfg(all(test, feature = "tokio", unix))]
mod native_tests;

#[cfg(all(test, feature = "tokio", unix))]
mod fetch_tests;
