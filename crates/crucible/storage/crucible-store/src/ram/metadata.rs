//! Original namespace admission retained by decoded RAM metadata borrowers.

use std::sync::Arc;

use crucible_ram::RootRecord;

use crate::content_store::{ContentId, StorePhysicalQuotaGuard};
use crate::owned_decode::ResourceLoan;

use super::{LeasedRamRoot, RamRootLease, RamStore, RamStoreError, maximum_ram_root_decoding_bytes};

/// Authenticated discovery metadata retaining its predecode resource credit.
///
/// This object grants no storage retention or native launch authority. The
/// record can be borrowed while its original namespace credit remains live.
pub struct AdmittedRamRootMetadata {
    record: RootRecord,
    _resources: ResourceLoan,
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
        let mut root = self.open(lease, original, boundary)?;
        root.metadata_resources = resources.into();
        Ok(root)
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
    ) -> Result<ResourceLoan, RamStoreError> {
        let authority = self.backend.metadata_resources()?;
        authority.verify()?;
        let bytes = allocation_bytes(simultaneous_roots)?;
        let credit = authority.reserve_resources(0, bytes)?;
        // ResourceLoan frees its own shared control before dropping this
        // concrete credit. Storage retention supplies no financial custody.
        Ok(ResourceLoan::new(RootMetadataResources {
            _authority: authority,
            _credit: credit,
        }))
    }
}

pub(super) fn allocation_bytes(simultaneous_roots: u64) -> Result<u64, RamStoreError> {
    // The decoder's bound covers the temporary reference Vec. Conversion
    // to the shared slice overlaps that Vec, so admit the complete second
    // allocation, including its counters and alignment, before decoding.
    let references = std::alloc::Layout::array::<super::codec::TreeRef>(
        crucible_ram::Limits::default().max_regions,
    )
    .map_err(|_| RamStoreError::Limit("root metadata admission"))?;
    let (references, _) = std::alloc::Layout::new::<[usize; 2]>()
        .extend(references)
        .map_err(|_| RamStoreError::Limit("root metadata admission"))?;
    let record = super::record_account::shared_extent::<RootRecord>()?;
    maximum_ram_root_decoding_bytes()?
        .checked_add(references.pad_to_align().size() as u64)
        .and_then(|bytes| bytes.checked_add(record))
        .and_then(|bytes| bytes.checked_mul(simultaneous_roots))
        .and_then(|bytes| {
            bytes.checked_add(ResourceLoan::allocation_bytes::<RootMetadataResources>())
        })
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<LeasedRamRoot>() as u64))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<AdmittedRamRootMetadata>() as u64))
        .ok_or(RamStoreError::Limit("root metadata admission"))
}
