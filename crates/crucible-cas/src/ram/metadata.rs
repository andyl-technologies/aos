//! Original namespace admission retained by decoded RAM metadata borrowers.

use std::sync::Arc;

use crucible_ram::RootRecord;

use crate::content_store::{ContentId, StorePhysicalQuotaGuard};

use super::{
    LeasedRamRoot, RamRootLease, RamStore, RamStoreError, maximum_ram_root_decoding_bytes,
};

/// Authenticated discovery metadata retaining its predecode resource credit.
///
/// This object grants no storage retention or native launch authority. The
/// record can be borrowed while its original namespace credit remains live.
pub struct AdmittedRamRootMetadata {
    record: RootRecord,
    _resources: Arc<RootMetadataResources>,
}

impl AdmittedRamRootMetadata {
    /// Returns the record covered by the original predecode resource loan.
    #[must_use]
    pub fn record(&self) -> &RootRecord {
        &self.record
    }
}

pub(super) struct RootMetadataResources {
    _authority: Arc<dyn StorePhysicalQuotaGuard>,
    _credit: crate::owned_decode::ResourceLoan,
}

struct AdmittedRootLease {
    lease: Arc<dyn RamRootLease>,
    _resources: Arc<RootMetadataResources>,
}

impl RamRootLease for AdmittedRootLease {
    fn root(&self) -> ContentId {
        self.lease.root()
    }
}

pub(super) fn retain_resources(
    lease: Arc<dyn RamRootLease>,
    resources: Arc<RootMetadataResources>,
) -> Arc<dyn RamRootLease> {
    Arc::new(AdmittedRootLease {
        lease,
        _resources: resources,
    })
}

impl RamStore {
    /// Opens RAM under both live storage retention and original metadata credit.
    ///
    /// The backend must project its authentic namespace resource authority.
    /// Admission precedes every root read and allocation. Root clones and
    /// transferred shared metadata retain that credit until their final close.
    /// Callers already holding an explicit predecode loan use [`Self::open`].
    ///
    /// # Errors
    /// Refuses absent or exhausted original resources, invalid retention,
    /// corrupt root metadata, cancellation, and configured storage bounds.
    pub fn open_with_metadata_resources(
        &self,
        lease: Arc<dyn RamRootLease>,
        original: &crate::owned_decode::DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
    ) -> Result<LeasedRamRoot, RamStoreError> {
        boundary()?;
        let resources = self.reserve_root_metadata(1)?;
        self.open(retain_resources(lease, resources), original, boundary)
    }

    /// Inspects root metadata while retaining original predecode admission.
    ///
    /// GC discovery still requires the caller's existing namespace fence.
    /// This method obtains no shared GC fence and grants no page-read lease.
    ///
    /// # Errors
    /// Refuses absent or exhausted original resources, corrupt metadata,
    /// cancellation, and configured storage bounds.
    pub fn inspect_root_with_metadata_resources(
        &self,
        id: ContentId,
        original: &crate::owned_decode::DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
    ) -> Result<AdmittedRamRootMetadata, RamStoreError> {
        boundary()?;
        let resources = self.reserve_root_metadata(1)?;
        let record = self.inspect_root(id, original, boundary)?;
        Ok(AdmittedRamRootMetadata {
            record,
            _resources: resources,
        })
    }

    pub(super) fn reserve_root_metadata(
        &self,
        simultaneous_roots: u64,
    ) -> Result<Arc<RootMetadataResources>, RamStoreError> {
        let authority = self.backend.metadata_resources()?;
        authority.verify()?;
        let bytes = maximum_ram_root_decoding_bytes()?
            .checked_mul(simultaneous_roots)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<AdmittedRootLease>() as u64))
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<RootMetadataResources>() as u64)
            })
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<AdmittedRamRootMetadata>() as u64)
            })
            .ok_or(RamStoreError::Limit("root metadata admission"))?;
        let credit = authority.reserve_resources(0, bytes)?;
        Ok(Arc::new(RootMetadataResources {
            _authority: authority,
            _credit: credit,
        }))
    }
}
