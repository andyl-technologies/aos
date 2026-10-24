//! Connects shared directory views to acknowledged native sealed consumer grants.
//!
//! The fixed inventory contains only genuine consumer leases. It creates no
//! pins, copies, reservations or native descriptors; cloning a lease preserves
//! the original grant's expiry and revocation. Reads retain the ordinary active
//! read guard so final consumer cleanup waits for actual backing closure.

use super::NativeConsumerLease;
use terrane_format::identity::Identity;
use terrane_sdk::{
    host::cache::{DomainHostLayout, HostResidenceReader, ResidenceChunk},
    store::{InvalidReason, StoreErrorKind, StoreFailure},
};

/// Supplies sealed residences through existing live consumer leases in one domain.
///
/// This binding supplies residence fallback for [`terrane_sdk::store::shared_dir::SharedDir`].
/// It neither opens caller-selected files nor extends a consumer lease. Encoded
/// bodies remain the ordinary directory reader's responsibility. Private-domain
/// grants and differing physical roots or chunk profiles are refused.
pub struct NativeSharedResidences {
    leases: Vec<NativeConsumerLease>,
}

impl NativeSharedResidences {
    /// Checks a finite inventory against its configured shared domain directory.
    ///
    /// `max_entries` is an explicit operator resource bound. Each lease must
    /// already have been acknowledged by its original native physical owner.
    /// This constructor performs no mutation and supplies no new read authority.
    ///
    /// # Errors
    /// Returns capacity for a zero/exceeded inventory limit, invalid for duplicate
    /// identities, unsupported for encoded backing, and denies foreign/private
    /// layouts. Expired, revoked or unavailable grants return their actual error.
    pub fn new(
        layout: &DomainHostLayout,
        leases: Vec<NativeConsumerLease>,
        max_entries: usize,
    ) -> Result<Self, StoreFailure> {
        if max_entries == 0 || leases.len() > max_entries || leases.capacity() > max_entries {
            return Err(StoreFailure::new(StoreErrorKind::Capacity));
        }
        for (index, lease) in leases.iter().enumerate() {
            lease.check_shared_layout(layout)?;
            if leases[..index]
                .iter()
                .any(|previous| previous.identity() == lease.identity())
            {
                return Err(StoreFailure::new(StoreErrorKind::Invalid(
                    InvalidReason::MalformedRequest,
                )));
            }
        }
        Ok(Self { leases })
    }
}

#[async_trait::async_trait]
impl HostResidenceReader for NativeSharedResidences {
    async fn read_chunk(
        &self,
        layout: &DomainHostLayout,
        identity: &Identity,
        max_plaintext_bytes: usize,
    ) -> Result<Option<ResidenceChunk>, StoreFailure> {
        // A matching original grant checks the complete layout before native
        // IO. An absent identity consults no other directory or host owner.
        self.leases
            .iter()
            .find(|lease| lease.identity() == identity)
            .map(|lease| lease.read_shared_chunk(layout, max_plaintext_bytes))
            .transpose()
    }

    async fn chunk_identities(
        &self,
        layout: &DomainHostLayout,
        max_entries: usize,
    ) -> Result<Vec<Identity>, StoreFailure> {
        if self.leases.len() > max_entries {
            return Err(StoreFailure::new(StoreErrorKind::Capacity));
        }
        let mut identities = Vec::new();
        identities
            .try_reserve_exact(self.leases.len())
            .map_err(|error| StoreFailure::with_source(StoreErrorKind::Capacity, error))?;
        if identities.capacity() > max_entries {
            return Err(StoreFailure::new(StoreErrorKind::Capacity));
        }
        for lease in &self.leases {
            lease.check_shared_layout(layout)?;
            identities.push(lease.identity().clone());
        }
        Ok(identities)
    }
}
