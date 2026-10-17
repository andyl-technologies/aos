//! Saved archive metadata authority and descriptor-bound project descendants.
//!
//! The independently authored archive service owns the project before its first
//! RAM operation. Child directories retain that same guard and original account;
//! a source repository cannot donate its namespace permission to a destination.

use std::path::Path;
use std::sync::Arc;

use crucible_campaign::{CampaignRamAdmission, CampaignRepository};
use crucible_cas::content_store::{
    DirectoryBlobBackend, DirectoryRefBackend, StoreError, StorePhysicalQuotaGuard,
};
use crucible_cas::owned_decode::{DecodeBudget, ResourceLoan};

use super::{BoundLinuxProjectQuota, LinuxProjectQuotaBinder};

/// Retains one independently admitted archive namespace and its saved account.
pub struct CampaignArchiveNamespace {
    original: DecodeBudget,
    guard: Arc<BoundLinuxProjectQuota>,
    _resources: ResourceLoan,
}

impl CampaignArchiveNamespace {
    /// Returns the exact pinned namespace root admitted for this archive.
    pub fn root(&self) -> &Path {
        &self.guard.authority.root
    }

    /// Borrows the original namespace account captured before archive access.
    pub fn original(&self) -> &DecodeBudget {
        &self.original
    }

    /// Checks original metadata, quota and supervision without renewing them.
    ///
    /// # Errors
    /// Returns the first original account or physical namespace refusal.
    pub fn verify(&self) -> Result<(), StoreError> {
        self.original
            .verify_live()
            .map_err(|source| StoreError::DecodeAdmission {
                source,
                custody: Some(self.original.custody()),
            })?;
        self.guard.verify()
    }

    /// Authenticates or prepares a bounded child directory below the pinned root.
    ///
    /// Components use authenticated descriptors and inherit the installed project.
    /// Symlinks, mount crossings, parent escapes and excessive depth are refused.
    ///
    /// # Errors
    /// Preserves original admission, quota, path validation and filesystem failures.
    pub fn prepare_directory(&self, path: &Path) -> Result<(), StoreError> {
        self.original
            .verify_live()
            .map_err(|source| StoreError::DecodeAdmission {
                source,
                custody: Some(self.original.custody()),
            })?;
        super::check_provider_error_path(path)?;
        let bytes = path
            .as_os_str()
            .len()
            .checked_mul(4)
            .ok_or(StoreError::Quota)?;
        let _scratch = self.guard.reserve_resources(0, bytes as u64)?;
        let permit = self.guard.clone().begin_provider_diagnostic()?;
        let _serial = self
            .guard
            .authority
            .service
            .serial
            .try_lock()
            .map_err(|_| StoreError::Unauthorized)?;
        if let Err(source) = self
            .guard
            .authority
            .binding
            .prepare_descendant_directory(path)
        {
            return Err(super::retain_provider_cause(permit, source.into()));
        }
        drop(_serial);
        self.original
            .verify_live()
            .map_err(|source| StoreError::DecodeAdmission {
                source,
                custody: Some(self.original.custody()),
            })
    }

    /// Opens a repository only in an authenticated child of this archive project.
    ///
    /// Both durable object and reference stores retain the same quota authority.
    /// RAM access uses the saved namespace account explicitly.
    ///
    /// # Errors
    /// Refuses escaped paths, original admission or physical quota changes,
    /// unsafe descendants, or insufficient facade resources.
    pub fn open_repository(&self, root: &Path) -> Result<CampaignRepository, StoreError> {
        self.prepare_directory(root)?;
        let path_bytes = root
            .as_os_str()
            .len()
            .checked_add(8)
            .and_then(|bytes| bytes.checked_mul(4))
            .ok_or(StoreError::Quota)?;
        let _paths = self.guard.reserve_resources(0, path_bytes as u64)?;
        let objects = root.join("objects");
        let refs = root.join("refs");
        self.prepare_directory(&objects)?;
        self.prepare_directory(&refs)?;
        let guard: Arc<dyn StorePhysicalQuotaGuard> = self.guard.clone();
        let blobs = DirectoryBlobBackend::new_with_physical_quota(
            "finding-bundle",
            objects,
            guard.clone(),
        )?;
        let refs = DirectoryRefBackend::new_with_physical_quota(refs, guard)?;
        self.verify()?;
        Ok(CampaignRepository::new(
            blobs,
            refs,
            CampaignRamAdmission::Available(self.original.clone()),
        ))
    }
}

impl LinuxProjectQuotaBinder {
    pub(crate) fn archive_namespace(
        &self,
        root: &Path,
        project_id: u32,
        maximum_physical_bytes: u64,
        maximum_inodes: u64,
    ) -> Result<CampaignArchiveNamespace, StoreError> {
        let guard = self.bind_guard(root, project_id, maximum_physical_bytes, maximum_inodes)?;
        let resources =
            guard.reserve_resources(0, std::mem::size_of::<CampaignArchiveNamespace>() as u64)?;
        let original = DecodeBudget::for_store(guard.clone()).map_err(|source| {
            StoreError::DecodeAdmission {
                source,
                custody: None,
            }
        })?;
        Ok(CampaignArchiveNamespace {
            original,
            guard,
            _resources: resources,
        })
    }
}
