//! Quota-bound object and reference stores for the guarded campaign owner.
//!
//! Namespace preparation authenticates inherited physical quotas before either
//! backend opens a file. Each backend and its deferred sources retain actual
//! catalog resource loans independently of the calling campaign owner.

use super::*;
use crucible_cas::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, ImmutableBlobBackend, MutableRefBackend,
};

pub(in crate::packaged_qemu_executor) struct GuardedCampaignStorage {
    pub(in crate::packaged_qemu_executor) backend: Arc<dyn ImmutableBlobBackend>,
    pub(in crate::packaged_qemu_executor) refs: Arc<dyn MutableRefBackend>,
    #[cfg(test)]
    pub(in crate::packaged_qemu_executor) blob_admin:
        Arc<dyn crucible_cas::content_store::BlobStoreAdmin>,
    #[cfg(test)]
    pub(in crate::packaged_qemu_executor) ref_admin:
        Arc<dyn crucible_cas::content_store::RefStoreAdmin>,
    pub(in crate::packaged_qemu_executor) quota: Arc<dyn StorePhysicalQuotaGuard>,
    _resources: Arc<dyn Send + Sync>,
}

impl CatalogService {
    pub(in crate::packaged_qemu_executor::ram_catalog) fn open_guarded_storage(
        &self,
        directory: &Path,
    ) -> Result<GuardedCampaignStorage, StoreError> {
        let quota = self.prepare_directory(directory)?;
        let resources =
            quota.reserve_resources(0, std::mem::size_of::<GuardedCampaignStorage>() as u64)?;
        let objects = directory.join("objects");
        let authority = directory.join("authority");
        let object_quota = self.prepare_directory(&objects)?;
        let reference_quota = self.prepare_directory(&authority)?;

        let (backend, _blob_admin) = DirectoryBlobBackend::new_with_physical_quota_and_admin(
            "guarded-campaign",
            objects,
            object_quota,
        )?;
        let (refs, _ref_admin) =
            DirectoryRefBackend::new_with_physical_quota_and_admin(authority, reference_quota)?;
        quota.verify()?;
        Ok(GuardedCampaignStorage {
            backend,
            refs,
            #[cfg(test)]
            blob_admin: _blob_admin,
            #[cfg(test)]
            ref_admin: _ref_admin,
            quota,
            _resources: resources,
        })
    }
}
