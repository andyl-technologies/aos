//! Publishes singleton collector leases under explicitly configured maintenance authority.
//!
//! Each operation acquires the actual namespace exclusion and observes the complete
//! selected publication chain. The lease is selected with one consecutive revision;
//! the physical `gc/lease` file is only a recoverable cache. This API grants no
//! object deletion, collection-root, or actor Commit authority.

use crate::bucket::{BucketBinding, FileBucket};
use crate::guard::{Guard, OriginalAuthority};
use crate::store::{Clock, ContentValidator, LocalFs, StoreFailure};
use terrane_core::gc::{GcError, GcLease};

/// Reports a refused lease proposal or failed native publication.
#[derive(Debug)]
pub enum LeaseError {
    /// The whole lease or its arithmetic cannot authorize the requested successor.
    Lease(GcError),
    /// Fresh selected authority, clock retention, or native storage failed.
    Store(StoreFailure),
}

impl core::fmt::Display for LeaseError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Lease(error) => error.fmt(formatter),
            Self::Store(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for LeaseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Lease(error) => Some(error),
            Self::Store(error) => Some(error),
        }
    }
}

impl From<GcError> for LeaseError {
    fn from(error: GcError) -> Self {
        Self::Lease(error)
    }
}

impl From<StoreFailure> for LeaseError {
    fn from(error: StoreFailure) -> Self {
        Self::Store(error)
    }
}

/// Acknowledges a whole lease and the consecutive revision selecting it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseReceipt {
    /// The complete canonical lease selected by the acknowledged transaction.
    pub lease: GcLease,
    /// The durable selected publication revision.
    pub revision: u64,
}

/// Borrows explicit maintenance configuration and its genuinely bound registration.
///
/// Construction selects trusted host configuration, rather than authenticating an
/// actor token. Every operation independently checks that this exact Guard and
/// registration remain selected for this physical backend. The borrowed values
/// alone cannot construct native effects or authorize collection or deletion.
pub struct Collector<'configuration, F, B, V, C> {
    guard: &'configuration Guard<FileBucket<F, B, V>, C>,
    authority: &'configuration OriginalAuthority,
}

impl<'configuration, F, B, V, C> Collector<'configuration, F, B, V, C> {
    /// Selects the trusted Guard and checked registration for maintenance operations.
    pub fn new(
        guard: &'configuration Guard<FileBucket<F, B, V>, C>,
        authority: &'configuration OriginalAuthority,
    ) -> Self {
        Self { guard, authority }
    }
}

impl<F, B, V, C> Collector<'_, F, B, V, C>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    /// Acquires an absent lease or takes over an expired lease at a higher epoch.
    ///
    /// A live lease, including one with the same holder, refuses acquisition.
    /// Durations are seconds in the configured clock's Unix time domain.
    ///
    /// # Errors
    /// Rejects a live selected lease, invalid arithmetic, stale configured Guard
    /// or registration, unsafe native paths, unsupported clock/exclusion retention,
    /// clock discontinuity, expiry, or failed durable publication. Storage failure
    /// after slot dispatch may leave the lease selected; callers must reopen and
    /// observe the actual selected whole value before retrying.
    pub async fn acquire(&self, holder: String, duration: u64) -> Result<LeaseReceipt, LeaseError> {
        crate::selected_bridge::native_collection::publish(
            self.guard,
            self.authority,
            Proposal::Acquire { holder, duration },
        )
        .await
    }

    /// Renews exactly the supplied selected whole lease without changing its epoch.
    ///
    /// The current lease must still match holder, epoch and expiry together.
    /// The proposed expiry must strictly increase while the old lease remains live.
    ///
    /// # Errors
    /// Rejects a stale whole value, expiry, invalid arithmetic, stale configured
    /// Guard or registration, unsafe paths, unsupported native retention, clock
    /// discontinuity, or failed durability. A failure after slot dispatch can be
    /// indeterminate and requires a fresh selected observation before retrying.
    pub async fn renew(
        &self,
        current: &GcLease,
        duration: u64,
    ) -> Result<LeaseReceipt, LeaseError> {
        crate::selected_bridge::native_collection::publish(
            self.guard,
            self.authority,
            Proposal::Renew {
                current: current.clone(),
                duration,
            },
        )
        .await
    }
}

/// Carries a request whose selected whole preimage is resolved by the genuine producer.
pub(crate) enum Proposal {
    /// Acquires absence or an expired selected whole lease.
    Acquire { holder: String, duration: u64 },
    /// Extends exactly the supplied whole selected value.
    Renew { current: GcLease, duration: u64 },
}

#[cfg(all(test, feature = "tokio", unix))]
#[path = "lease/tests.rs"]
/// Qualifies genuine native collector acquisition and retained dispatch.
pub(crate) mod tests;

#[cfg(all(test, unix, any(feature = "tokio", not(feature = "send"))))]
#[path = "lease/fixture.rs"]
mod fixture;

#[cfg(all(test, unix, not(feature = "send")))]
#[path = "lease/local_tests.rs"]
mod local_tests;
