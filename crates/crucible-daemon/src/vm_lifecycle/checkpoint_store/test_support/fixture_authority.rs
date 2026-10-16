//! Explicitly modeled directory and reader custody for codec fixtures.
//!
//! These fixture capabilities never authenticate a kernel quota or native
//! deployment. They pin directory incarnations and exercise the production
//! guarded SQLite handles, cached ownership and retirement handshake.

use super::{
    ProductionRamCatalogProvider, ProductionRamCatalogRetirement, ProductionRamCatalogStorage,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct FixtureResourceBudget(Mutex<(u64, u64)>);

struct FixtureResourceCredit {
    budget: Arc<FixtureResourceBudget>,
    descriptors: u64,
    resident_bytes: u64,
}

impl FixtureResourceBudget {
    const MAXIMUM_RESIDENT_BYTES: u64 = 2 * 1024 * 1024 * 1024;

    fn reserve(
        self: &Arc<Self>,
        descriptors: u64,
        resident_bytes: u64,
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, crucible_cas::content_store::StoreError>
    {
        use crucible_cas::content_store::StoreError;

        let mut used = self.0.lock().map_err(|_| StoreError::Unauthorized)?;
        let next_descriptors = used.0.checked_add(descriptors).ok_or(StoreError::Quota)?;
        let next_resident = used
            .1
            .checked_add(resident_bytes)
            .ok_or(StoreError::Quota)?;
        // Codec fixtures author finite modeled capacity independently from
        // the production kernel quota and native Service qualification.
        if next_descriptors > 4096 || next_resident > Self::MAXIMUM_RESIDENT_BYTES {
            return Err(StoreError::Quota);
        }
        *used = (next_descriptors, next_resident);
        Ok(crucible_cas::owned_decode::ResourceLoan::new(
            FixtureResourceCredit {
                budget: self.clone(),
                descriptors,
                resident_bytes,
            },
        ))
    }
}

impl Drop for FixtureResourceCredit {
    fn drop(&mut self) {
        if let Ok(mut used) = self.budget.0.lock() {
            used.0 -= self.descriptors;
            used.1 -= self.resident_bytes;
        }
    }
}

struct FixtureCatalogSupervisor(Arc<FixtureResourceBudget>);
struct FixtureCatalogOperation;

impl crucible_cas::content_store::SqliteCatalogSupervisor for FixtureCatalogSupervisor {
    fn reserve_resident_bytes(
        &self,
        bytes: u64,
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, crucible_cas::content_store::StoreError>
    {
        self.0.reserve(0, bytes)
    }

    fn begin(
        &self,
        _kind: crucible_cas::content_store::SqliteCatalogOperationKind,
    ) -> Result<
        Box<dyn crucible_cas::content_store::SqliteCatalogOperation>,
        crucible_cas::content_store::StoreError,
    > {
        Ok(Box::new(FixtureCatalogOperation))
    }
}

impl crucible_cas::content_store::SqliteCatalogOperation for FixtureCatalogOperation {
    fn check(&self) -> Result<(), crucible_cas::content_store::StoreError> {
        Ok(())
    }

    fn complete(self: Box<Self>) -> Result<(), crucible_cas::content_store::StoreError> {
        Ok(())
    }
}

/// Creates explicitly modeled authority for codec fixtures without a VM process.
///
/// This authority pins the fixture directory incarnation. It does not certify
/// filesystem quotas, native paging, or deployment admission.
pub(in crate::vm_lifecycle) fn test_ram_catalog_provider() -> Arc<dyn ProductionRamCatalogProvider>
{
    Arc::new(FixtureRamCatalogProvider::default())
}

#[derive(Default)]
struct FixtureRamCatalogProvider {
    catalogs: Mutex<BTreeMap<PathBuf, FixtureCatalogState>>,
    root_loans: Arc<std::sync::atomic::AtomicUsize>,
}

/// Creates modeled authority with observable decoded-root loan lifetime.
#[cfg(test)]
pub(in crate::vm_lifecycle) fn tracked_ram_catalog_provider() -> (
    Arc<dyn ProductionRamCatalogProvider>,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    let provider = FixtureRamCatalogProvider::default();
    let loans = provider.root_loans.clone();
    (Arc::new(provider), loans)
}

struct FixtureRootCredit(Arc<std::sync::atomic::AtomicUsize>);

impl Drop for FixtureRootCredit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

enum FixtureCatalogState {
    Open(ProductionRamCatalogStorage),
    Retiring(Arc<FixtureCatalogRetirement>),
}

struct FixtureCatalogRetirement {
    active: PathBuf,
    retired: PathBuf,
    _quota: Arc<dyn crucible_cas::content_store::StorePhysicalQuotaGuard>,
}

impl ProductionRamCatalogRetirement for FixtureCatalogRetirement {
    fn finish_deleted(&self) -> Result<(), crucible_cas::content_store::StoreError> {
        use crucible_cas::content_store::StoreError;

        for path in [&self.active, &self.retired] {
            match fs::symlink_metadata(path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(StoreError::Io {
                        operation: "authenticate modeled catalog deletion",
                        path: path.clone(),
                        source,
                    });
                }
                Ok(_) => return Err(StoreError::Quota),
            }
        }
        Ok(())
    }
}

struct FixtureRamCatalogGuard {
    directory: PathBuf,
    device: u64,
    inode: u64,
    resources: Arc<FixtureResourceBudget>,
}

impl ProductionRamCatalogProvider for FixtureRamCatalogProvider {
    fn reserve_root_metadata(
        &self,
        _directory: &Path,
        _bytes: u64,
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, crucible_cas::content_store::StoreError>
    {
        self.root_loans
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(crucible_cas::owned_decode::ResourceLoan::new(
            FixtureRootCredit(self.root_loans.clone()),
        ))
    }

    fn prepare_directory(
        &self,
        directory: &Path,
    ) -> Result<
        Arc<dyn crucible_cas::content_store::StorePhysicalQuotaGuard>,
        crucible_cas::content_store::StoreError,
    > {
        use std::os::unix::fs::MetadataExt;

        fs::create_dir_all(directory).map_err(|source| {
            crucible_cas::content_store::StoreError::Io {
                operation: "create modeled fixture catalog",
                path: directory.to_path_buf(),
                source,
            }
        })?;
        let metadata = fs::symlink_metadata(directory).map_err(|source| {
            crucible_cas::content_store::StoreError::Io {
                operation: "pin modeled fixture catalog",
                path: directory.to_path_buf(),
                source,
            }
        })?;
        if !metadata.is_dir() {
            return Err(crucible_cas::content_store::StoreError::Unauthorized);
        }
        Ok(Arc::new(FixtureRamCatalogGuard {
            directory: directory.to_path_buf(),
            device: metadata.dev(),
            inode: metadata.ino(),
            resources: Arc::new(FixtureResourceBudget::default()),
        }))
    }

    fn open_catalog(
        &self,
        directory: &Path,
    ) -> Result<ProductionRamCatalogStorage, crucible_cas::content_store::StoreError> {
        use crucible_cas::content_store::{SqliteBlobBackend, StoreError};
        use rustix::fs::{FlockOperation, flock};

        let mut catalogs = self.catalogs.lock().map_err(|_| StoreError::Unauthorized)?;
        if let Some(state) = catalogs.get(directory) {
            return match state {
                FixtureCatalogState::Open(storage) => {
                    storage.quota.verify()?;
                    Ok(storage.clone())
                }
                FixtureCatalogState::Retiring(_) => Err(StoreError::Unauthorized),
            };
        }

        let quota = self.prepare_directory(directory)?;
        let original = crucible_cas::owned_decode::DecodeBudget::for_store(quota.clone()).map_err(
            |source| StoreError::DecodeAdmission {
                source,
                custody: None,
            },
        )?;
        let path = directory.join("retention.lock");
        let fence = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|source| StoreError::Io {
                operation: "open modeled fixture retention fence",
                path,
                source,
            })?;
        flock(&fence, FlockOperation::LockShared).map_err(|error| StoreError::StreamIo {
            operation: "retain modeled fixture catalog",
            source: error.into(),
        })?;
        let heap = match crucible_cas::content_store::fixture_sqlite_heap() {
            Ok(heap) => heap,
            Err(error) => panic!("authored SQLite fixture process: {error}"),
        };
        let backend = SqliteBlobBackend::open_with_physical_quota(
            "fixture-checkpoint-ram",
            directory,
            quota.clone(),
            self.maximum_sqlite_heap_bytes(),
            Arc::new(FixtureCatalogSupervisor(Arc::new(
                FixtureResourceBudget::default(),
            ))),
            &heap,
        )?;
        let storage = ProductionRamCatalogStorage {
            backend,
            quota,
            retention_fence: Arc::new(fence),
            original,
        };
        catalogs.insert(
            directory.to_path_buf(),
            FixtureCatalogState::Open(storage.clone()),
        );
        Ok(storage)
    }

    fn begin_catalog_retirement(
        &self,
        directory: &Path,
    ) -> Result<Arc<dyn ProductionRamCatalogRetirement>, crucible_cas::content_store::StoreError>
    {
        use crucible_cas::content_store::StoreError;

        let mut catalogs = self.catalogs.lock().map_err(|_| StoreError::Unauthorized)?;
        match catalogs.get(directory) {
            Some(FixtureCatalogState::Retiring(receipt)) => return Ok(receipt.clone()),
            Some(FixtureCatalogState::Open(storage)) => {
                // The private StoreAuthority retains one intrinsic quota alias;
                // exclusivity excludes all operation accounts and decoded readers.
                if !storage.original.is_exclusive()
                    || Arc::strong_count(&storage.backend) != 1
                    || Arc::strong_count(&storage.retention_fence) != 1
                    || Arc::strong_count(&storage.quota) != 3
                {
                    return Err(StoreError::Quota);
                }
            }
            None => return Err(StoreError::Unauthorized),
        }

        let active = directory
            .parent()
            .ok_or(StoreError::Unauthorized)?
            .to_path_buf();
        let parent = active.parent().ok_or(StoreError::Unauthorized)?;
        let scenario = active
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(StoreError::Unauthorized)?;
        let retired = parent.join(format!(".retired-checkpoint-catalog-{scenario}"));
        let Some(FixtureCatalogState::Open(storage)) = catalogs.remove(directory) else {
            return Err(StoreError::Unauthorized);
        };
        drop(storage.original);
        let receipt = Arc::new(FixtureCatalogRetirement {
            active,
            retired,
            _quota: storage.quota,
        });
        drop(storage.backend);
        drop(storage.retention_fence);
        catalogs.insert(
            directory.to_path_buf(),
            FixtureCatalogState::Retiring(receipt.clone()),
        );
        Ok(receipt)
    }

    fn maximum_sqlite_heap_bytes(&self) -> u64 {
        // Checked error copies need a finite native bound. This authored heap
        // preserves the existing 2 GiB component admission bank. Exhaustion
        // tests isolate lower process-wide hard limits in a child process.
        8 * 1024 * 1024
    }
}

impl crucible_cas::content_store::StorePhysicalQuotaGuard for FixtureRamCatalogGuard {
    fn decoded_metadata_limit(&self) -> Result<u64, crucible_cas::content_store::StoreError> {
        self.verify()?;
        Ok(FixtureResourceBudget::MAXIMUM_RESIDENT_BYTES)
    }

    fn reserve_resources(
        &self,
        descriptors: u64,
        resident_bytes: u64,
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, crucible_cas::content_store::StoreError>
    {
        self.verify()?;
        self.resources.reserve(descriptors, resident_bytes)
    }

    fn verify(&self) -> Result<(), crucible_cas::content_store::StoreError> {
        use std::os::unix::fs::MetadataExt;

        let metadata = fs::symlink_metadata(&self.directory).map_err(|source| {
            crucible_cas::content_store::StoreError::Io {
                operation: "verify modeled fixture catalog",
                path: self.directory.clone(),
                source,
            }
        })?;
        if metadata.is_dir() && metadata.dev() == self.device && metadata.ino() == self.inode {
            Ok(())
        } else {
            Err(crucible_cas::content_store::StoreError::Unauthorized)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modeled_resource_credit_releases_only_after_last_borrower() {
        let budget = Arc::new(FixtureResourceBudget::default());
        let credit = budget
            .reserve(4096, 2 * 1024 * 1024 * 1024)
            .unwrap_or_else(|error| panic!("reserve modeled fixture capacity: {error}"));
        let reader = credit.clone();
        assert!(budget.reserve(1, 0).is_err());
        assert!(budget.reserve(0, 1).is_err());

        drop(credit);
        assert!(budget.reserve(1, 1).is_err());
        drop(reader);
        assert!(budget.reserve(4096, 2 * 1024 * 1024 * 1024).is_ok());
    }
}
