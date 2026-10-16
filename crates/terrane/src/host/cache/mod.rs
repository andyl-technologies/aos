//! Owns domain-scoped encoded cache reads, admission and bounded eviction.
//!
//! Encoded content and plaintext sealed handles remain separate interfaces.
//! Persistent policy state contains no chunk index or sealed-read lock.

mod kernel;
mod layout;
mod policy;
mod readonly;
mod state;

pub use kernel::{HostInspection, HostKernel, SealInspection};
pub use layout::DomainHostLayout;
pub use policy::{CacheEntry, CachePolicy, CircuitBreaker, PolicyConfig};
pub use readonly::HostReadOnlyContent;
pub use state::{
    CacheState, LeaseRecord, PinRecord, ReservationRecord, ResidenceRecord, StateLimits,
};

#[cfg(test)]
mod policy_tests;
