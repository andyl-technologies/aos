//! Retained physical catalog authority, cached SQL descriptors, and deletion receipts.
//!
//! One cache mutex closes admission before checking loans. Each returned blob
//! source retains its per-catalog quota guard, so backend, fence, and guard counts
//! together prove that SQL descriptors can close before exclusive retirement.

use super::PackagedRamCatalogConfig;
use crate::provider_error_custody::{
    ProviderServiceAdmissionError, arc_allocation_bytes, check_provider_error_path,
    lease_control_bytes, provider_diagnostic_bytes, retain_provider_cause,
};
use crucible_api::vm_lifecycle::{
    ProductionRamCatalogProvider, ProductionRamCatalogRetirement, ProductionRamCatalogStorage,
};
use crucible_cas::content_store::{
    DirectoryBlobBackend, ImmutableBlobBackend, SqliteBlobBackend, SqliteCatalogOperation,
    SqliteCatalogOperationKind, SqliteCatalogSupervisor, StoreError, StorePhysicalQuotaGuard,
};
use crucible_linux_resource::host_services::{HostServiceAllocator, HostServiceLease};
use crucible_linux_resource::host_supervision::{
    HostOperationClass, HostOperationGuard, HostOperationSupervisor, HostSupervisionError,
};
use crucible_linux_resource::{LinuxProjectQuotaBinding, LinuxProjectQuotaError};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError, Weak};

mod directory_storage;
#[cfg(test)]
mod retirement_tests;
#[cfg(test)]
mod spool;
mod sqlite_heap;

pub(in crate::packaged_qemu_executor) use directory_storage::GuardedCampaignStorage;
#[cfg(test)]
pub(crate) use spool::CatalogEvidenceSpool;

// The two SQL connections and rollback-journal work fit six descriptors. The
// shared fence and serialized inventory/fsync work need three more slots.
const CATALOG_DESCRIPTORS: u64 = 9;

/// Returns the admitted namespace peak plus one complete SQL catalog peak.
pub(super) const fn minimum_file_descriptors() -> u64 {
    LinuxProjectQuotaBinding::maximum_audit_file_descriptors() + CATALOG_DESCRIPTORS
}

// This namespace contains no deferred provider, avoiding a policy/provider cycle.
struct CatalogNamespace {
    root: PathBuf,
    project_id: u32,
    maximum_inodes: u64,
    resources: crucible_api::host_operational::HostResourceVector,
    maximum_sqlite_heap_bytes: u64,
}

impl CatalogNamespace {
    fn root(&self) -> &Path {
        &self.root
    }
    fn project_id(&self) -> u32 {
        self.project_id
    }
    fn maximum_inodes(&self) -> u64 {
        self.maximum_inodes
    }
    fn resources(&self) -> crucible_api::host_operational::HostResourceVector {
        self.resources
    }
}

// Fixed slots make the cache's retained container allocation explicit. A catalog
// consumes its descriptor and path/guard credit before occupying any slot.
struct CatalogCache {
    entries: Box<[Option<(PathBuf, CatalogEntry)>]>,
}

impl CatalogCache {
    fn get(&self, path: &Path) -> Option<&CatalogEntry> {
        self.entries
            .iter()
            .flatten()
            .find(|(key, _)| key == path)
            .map(|(_, value)| value)
    }

    fn cached_open(&self, path: &Path) -> Result<Option<ProductionRamCatalogStorage>, StoreError> {
        match self.get(path) {
            Some(CatalogEntry::Open { storage, closed }) if !closed.load(Ordering::Acquire) => {
                storage.quota.verify()?;
                Ok(Some(storage.clone()))
            }
            Some(_) => Err(StoreError::Unauthorized),
            None => Ok(None),
        }
    }

    fn take(&mut self, path: &Path) -> Option<(PathBuf, CatalogEntry)> {
        self.entries
            .iter_mut()
            .find(|entry| entry.as_ref().is_some_and(|(key, _)| key == path))
            .and_then(Option::take)
    }

    fn remove(&mut self, path: &Path) -> Option<CatalogEntry> {
        self.take(path).map(|(_, value)| value)
    }

    fn close_for_retirement(
        &mut self,
        directory: &Path,
    ) -> Result<Option<ClosedCatalog>, StoreError> {
        let Some((path, entry)) = self.take(directory) else {
            return Ok(None);
        };
        let (mut storage, closed) = match entry {
            CatalogEntry::Open { storage, closed } => {
                // Closed admission prevents new children while cleanup proves
                // that all existing operation and reader custody has ended.
                closed.store(true, Ordering::Release);
                if !storage.original.is_exclusive() {
                    self.insert(path, CatalogEntry::Open { storage, closed })?;
                    return Err(StoreError::Quota);
                }
                let ProductionRamCatalogStorage {
                    backend,
                    quota,
                    retention_fence,
                    original,
                } = storage;
                drop(original);
                (
                    ClosedCatalog {
                        backend: Some(backend),
                        quota,
                        retention_fence,
                    },
                    closed,
                )
            }
            CatalogEntry::Closed { storage, closed } => (storage, closed),
            CatalogEntry::Retiring(receipt) => {
                self.insert(path, CatalogEntry::Retiring(receipt))?;
                return Err(StoreError::Unauthorized);
            }
        };

        if let Some(backend) = storage.backend.as_ref() {
            if Arc::strong_count(backend) != 1
                || Arc::strong_count(&storage.retention_fence) != 1
                || Arc::strong_count(&storage.quota) != 2
            {
                self.insert(path, CatalogEntry::Closed { storage, closed })?;
                return Err(StoreError::Quota);
            }
            // The physical facade retains its own resource loan. Closing its
            // unique backend removes that intrinsic closed-namespace alias.
            drop(storage.backend.take());
        }

        if Arc::strong_count(&storage.retention_fence) != 1
            || Arc::strong_count(&storage.quota) != 1
            || Arc::strong_count(&closed) != 2
        {
            self.insert(path, CatalogEntry::Closed { storage, closed })?;
            return Err(StoreError::Quota);
        }
        Ok(Some(storage))
    }

    fn insert(&mut self, path: PathBuf, entry: CatalogEntry) -> Result<(), StoreError> {
        let slot = self
            .entries
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(StoreError::Quota)?;
        *slot = Some((path, entry));
        Ok(())
    }
}

struct CatalogAuthority {
    policy: CatalogNamespace,
    allocator: HostServiceAllocator,
    metadata_allocator: HostServiceAllocator,
    binding: Mutex<Option<LinuxProjectQuotaBinding>>,
    supervisor: HostOperationSupervisor,
    diagnostic_occupied: AtomicBool,
    _root_resources: HostServiceLease,
    _sql_staging_resources: HostServiceLease,
    sqlite_heap: crucible_cas::content_store::SqliteProcessHeap,
    _metadata_resources: crucible_cas::owned_decode::ResourceLoan,
    // The original actor remains pinned through final constructor credit release.
    _custody: Arc<dyn Send + Sync>,
}

/// Keeps actual actor and quota custody independently of transient readers.
pub(super) struct CatalogService {
    // Cached material closes while its original authority credit is retained.
    catalogs: Arc<Mutex<CatalogCache>>,
    authority: Arc<CatalogAuthority>,
}

enum CatalogEntry {
    Open {
        storage: ProductionRamCatalogStorage,
        closed: Arc<AtomicBool>,
    },
    Closed {
        storage: ClosedCatalog,
        closed: Arc<AtomicBool>,
    },
    Retiring(Arc<CatalogRetirement>),
}

// Closing the saved account does not release endpoint custody or reopen admission.
struct ClosedCatalog {
    backend: Option<Arc<dyn ImmutableBlobBackend>>,
    quota: Arc<dyn StorePhysicalQuotaGuard>,
    retention_fence: Arc<File>,
}

impl CatalogService {
    /// Retains explicit actor custody and reserves the secure namespace peak.
    ///
    /// # Errors
    /// Refuses insufficient independently authored descriptor or staging capacity.
    #[cfg(test)]
    pub(super) fn new(
        policy: PackagedRamCatalogConfig,
        custody: Arc<dyn Send + Sync>,
        supervisor: HostOperationSupervisor,
    ) -> Result<Self, ProviderServiceAdmissionError> {
        Self::new_with_heap(policy, custody, supervisor, None)
    }

    pub(super) fn new_with_heap(
        policy: PackagedRamCatalogConfig,
        custody: Arc<dyn Send + Sync>,
        supervisor: HostOperationSupervisor,
        borrowed_heap: Option<&crucible_cas::content_store::SqliteProcessHeap>,
    ) -> Result<Self, ProviderServiceAdmissionError> {
        supervisor
            .verify_original_live()
            .map_err(sqlite_supervision_error)?;
        if let Some(heap) = borrowed_heap {
            heap.verify_live()?;
            if heap.maximum_heap_bytes() > policy.maximum_sqlite_heap_bytes() {
                return Err(StoreError::Quota.into());
            }
        }
        let resources = policy.resources();
        let audit = LinuxProjectQuotaBinding::maximum_audit_file_descriptors();
        if resources.file_descriptors < minimum_file_descriptors()
            || resources.staging_bytes < minimum_staging_bytes()
        {
            return Err(StoreError::Quota.into());
        }
        let allocator = HostServiceAllocator::new(
            resources.task_slots,
            resources.file_descriptors,
            resources.resident_peak_bytes,
        )
        .map_err(ProviderServiceAdmissionError::from)?;
        let metadata_allocator = HostServiceAllocator::new(
            1,
            1,
            resources
                .metadata_bytes
                .checked_sub(policy.maximum_sqlite_heap_bytes())
                .ok_or(StoreError::Quota)?,
        )
        .map_err(ProviderServiceAdmissionError::from)?;
        let slots = usize::try_from((resources.file_descriptors - audit) / CATALOG_DESCRIPTORS)
            .map_err(|_| StoreError::Quota)?;
        let constructor_bytes = catalog_constructor_bytes(&policy, slots)?;
        // One raw pair pays all covered bodies and controls before either shared
        // lease exists. Earlier supervisor/allocator bootstrap is a separate prerequisite.
        let (metadata, resident) =
            metadata_allocator.reserve_paired_bytes(&allocator, constructor_bytes)?;
        let metadata_resources =
            crucible_cas::owned_decode::ResourceLoan::new(CatalogMetadataCredit {
                _leases: crucible_linux_resource::host_services::HostServiceLeasePair::new(
                    resident, metadata,
                ),
            });
        let root_resources = allocator
            .reserve_resources(
                0,
                audit,
                LinuxProjectQuotaBinding::maximum_audit_scratch_bytes(),
            )
            .map_err(ProviderServiceAdmissionError::from)?;
        let sql_staging_resources = allocator
            .reserve_resources(
                0,
                0,
                crucible_cas::content_store::minimum_sqlite_catalog_staging_bytes(),
            )
            .map_err(ProviderServiceAdmissionError::from)?;
        let sqlite_heap = match borrowed_heap {
            Some(heap) => heap.clone(),
            None => sqlite_heap::install(
                &allocator,
                &metadata_allocator,
                &supervisor,
                custody.clone(),
                policy.maximum_sqlite_heap_bytes(),
                slots.checked_mul(2).ok_or(StoreError::Quota)?,
            )?,
        };
        let entries = std::iter::repeat_with(|| None)
            .take(slots)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let policy = CatalogNamespace {
            root: policy.root().to_owned(),
            project_id: policy.project_id(),
            maximum_inodes: policy.maximum_inodes(),
            maximum_sqlite_heap_bytes: policy.maximum_sqlite_heap_bytes(),
            resources,
        };
        Ok(Self {
            authority: Arc::new(CatalogAuthority {
                policy,
                allocator,
                metadata_allocator,
                binding: Mutex::new(None),
                supervisor,
                diagnostic_occupied: AtomicBool::new(false),
                _root_resources: root_resources,
                _sql_staging_resources: sql_staging_resources,
                sqlite_heap,
                _custody: custody,
                _metadata_resources: metadata_resources,
            }),
            catalogs: Arc::new(Mutex::new(CatalogCache { entries })),
        })
    }

    /// Authenticates existing quota geometry before any catalog backend opens.
    ///
    /// # Errors
    /// Refuses repeated binding, unsafe existing contents, and quota changes.
    pub(super) fn bind(&self) -> Result<(), StoreError> {
        let authority = &self.authority;
        let mut binding = authority
            .binding
            .lock()
            .map_err(|_| StoreError::Unauthorized)?;
        if binding.is_some() {
            return Err(StoreError::Unauthorized);
        }
        let policy = &authority.policy;
        *binding = Some(
            LinuxProjectQuotaBinding::bind_existing_supervised(
                policy.root(),
                policy.project_id(),
                policy.resources().backing_peak_bytes,
                policy.maximum_inodes(),
                authority.supervisor.clone(),
            )
            .map_err(quota_error)?,
        );
        Ok(())
    }
}

// Existing covered allocations only: fixed table, root clone, all four Arc
// bodies/headers, five lease controls and one exclusive diagnostic peak.
fn catalog_constructor_bytes(
    policy: &PackagedRamCatalogConfig,
    slots: usize,
) -> Result<u64, StoreError> {
    let mut bytes = slots
        .checked_mul(std::mem::size_of::<Option<(PathBuf, CatalogEntry)>>())
        .and_then(|bytes| bytes.checked_add(policy.root().as_os_str().len()))
        .ok_or(StoreError::Quota)?;
    for extent in [
        arc_allocation_bytes::<CatalogAuthority>()?,
        arc_allocation_bytes::<Mutex<CatalogCache>>()?,
        arc_allocation_bytes::<CatalogService>()?,
        arc_allocation_bytes::<CatalogMetadataCredit>()?,
        lease_control_bytes()?
            .checked_mul(5)
            .ok_or(StoreError::Quota)?,
        usize::try_from(provider_diagnostic_bytes()).map_err(|_| StoreError::Quota)?,
    ] {
        bytes = bytes.checked_add(extent).ok_or(StoreError::Quota)?;
    }
    u64::try_from(bytes).map_err(|_| StoreError::Quota)
}

/// Returns the secure namespace scratch plus actual shared SQL staging layouts.
pub(super) const fn minimum_staging_bytes() -> u64 {
    LinuxProjectQuotaBinding::maximum_audit_scratch_bytes()
        + crucible_cas::content_store::minimum_sqlite_catalog_staging_bytes()
}

impl CatalogAuthority {
    fn validate_path(&self, directory: &Path) -> Result<(), StoreError> {
        let relative = directory
            .strip_prefix(self.policy.root())
            .map_err(|_| StoreError::Unauthorized)?;
        if relative.components().count() > 16
            || relative
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(StoreError::Unauthorized);
        }
        Ok(())
    }

    fn prepare(&self, directory: &Path) -> Result<(), StoreError> {
        self.validate_path(directory)?;
        let operation = self
            .supervisor
            .begin(HostOperationClass::Preparation)
            .map_err(sqlite_supervision_error)?;
        // Verification and descriptor walks share one lock across all guards;
        // concurrent SQL callers cannot create an unbounded transient FD peak.
        let binding = supervised_lock(&self.binding, &operation)?;
        binding
            .as_ref()
            .ok_or(StoreError::Quota)?
            .prepare_descendant_directory(directory)
            .map_err(quota_error)?;
        operation
            .complete()
            .map(|_| ())
            .map_err(sqlite_supervision_error)
    }

    fn verify(&self) -> Result<(), StoreError> {
        let operation = self
            .supervisor
            .begin(HostOperationClass::Writeback)
            .map_err(sqlite_supervision_error)?;
        let binding = supervised_lock(&self.binding, &operation)?;
        binding
            .as_ref()
            .ok_or(StoreError::Quota)?
            .verify()
            .map_err(quota_error)?;
        operation
            .complete()
            .map(|_| ())
            .map_err(sqlite_supervision_error)
    }

    fn verify_funded(
        &self,
        permit: crucible_cas::content_store::ProviderDiagnosticPermit,
    ) -> Result<crucible_cas::content_store::ProviderDiagnosticPermit, StoreError> {
        let operation = match self.supervisor.begin(HostOperationClass::Writeback) {
            Ok(operation) => operation,
            Err(source) => return Err(retain_provider_cause(permit, source.into())),
        };
        let binding = loop {
            if let Err(source) = operation.wait_slice() {
                return Err(retain_provider_cause(permit, source.into()));
            }
            match self.binding.try_lock() {
                Ok(binding) => break binding,
                Err(TryLockError::WouldBlock) => std::thread::yield_now(),
                Err(TryLockError::Poisoned(_)) => return Err(StoreError::Unauthorized),
            }
        };
        let binding = binding.as_ref().ok_or(StoreError::Quota)?;
        if let Err(source) = binding.verify() {
            return Err(retain_provider_cause(permit, source.into()));
        }
        if let Err(source) = operation.complete() {
            return Err(retain_provider_cause(permit, source.into()));
        }
        Ok(permit)
    }
}

fn catalog_metadata_bytes(directory: &Path) -> Result<u64, StoreError> {
    // The guard retains this credit through the entire open or pending phase.
    // Four path copies cover the cache key, receipt key, active and retired names.
    let paths = directory
        .as_os_str()
        .len()
        .checked_add(".retired-checkpoint-catalog-".len())
        .and_then(|bytes| bytes.checked_mul(4))
        .ok_or(StoreError::Quota)?;
    let bytes = paths
        .checked_add(std::mem::size_of::<CatalogGuard>())
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<CatalogRetirement>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<File>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<HostServiceLease>()))
        .and_then(|bytes| bytes.checked_add(8 * std::mem::size_of::<usize>()))
        .ok_or(StoreError::Quota)?;
    u64::try_from(bytes).map_err(|_| StoreError::Quota)
}

struct CatalogGuard {
    authority: Arc<CatalogAuthority>,
    closed: Arc<AtomicBool>,
    _resources: HostServiceLease,
    _metadata: crucible_cas::owned_decode::ResourceLoan,
}

impl StorePhysicalQuotaGuard for CatalogGuard {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        self.verify()?;
        Ok(self.authority.metadata_allocator.maximum_resident_bytes())
    }

    fn verify(&self) -> Result<(), StoreError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(StoreError::Unauthorized);
        }
        self.authority.verify()
    }

    fn reserve_resources(
        &self,
        descriptors: u64,
        resident_bytes: u64,
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, StoreError> {
        self.verify()?;
        let resources = reserve_catalog_resources(
            &self.authority,
            Some(self.closed.clone()),
            descriptors,
            resident_bytes,
        )?;
        self.verify()?;
        Ok(resources)
    }
}

impl ProductionRamCatalogProvider for CatalogService {
    fn prepare_directory(
        &self,
        directory: &Path,
    ) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        let resources = CatalogSqliteSupervisor(self.authority.clone()).reserve_resident_bytes(
            std::mem::size_of::<NamespaceGuard>() as u64
                + u64::try_from(directory.as_os_str().len()).map_err(|_| StoreError::Quota)?,
        )?;
        self.authority.prepare(directory)?;
        Ok(Arc::new(NamespaceGuard {
            authority: self.authority.clone(),
            directory: directory.to_path_buf(),
            _resources: resources,
        }))
    }

    fn open_catalog(&self, directory: &Path) -> Result<ProductionRamCatalogStorage, StoreError> {
        self.authority.validate_path(directory)?;
        let operation = self
            .authority
            .supervisor
            .begin(HostOperationClass::Preparation)
            .map_err(sqlite_supervision_error)?;
        let mut catalogs = supervised_lock(&self.catalogs, &operation)?;
        if let Some(storage) = catalogs.cached_open(directory)? {
            operation.complete().map_err(sqlite_supervision_error)?;
            return Ok(storage);
        }

        let resources = self
            .authority
            .allocator
            .reserve_resources(0, CATALOG_DESCRIPTORS, 0)
            .map_err(|_| StoreError::Quota)?;
        let metadata_credit = CatalogSqliteSupervisor(self.authority.clone())
            .reserve_resident_bytes(catalog_metadata_bytes(directory)?)?;
        let closed = Arc::new(AtomicBool::new(false));
        let quota: Arc<dyn StorePhysicalQuotaGuard> = Arc::new(CatalogGuard {
            authority: self.authority.clone(),
            closed: closed.clone(),
            _resources: resources,
            _metadata: metadata_credit,
        });
        let original = crucible_cas::owned_decode::DecodeBudget::for_store(quota.clone()).map_err(
            |source| StoreError::DecodeAdmission {
                source,
                custody: None,
            },
        )?;
        self.authority.prepare(directory)?;
        let path = directory.join("retention.lock");
        let fence: File = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&path)
            .map_err(|source| StoreError::Io {
                operation: "retain quota-bound RAM catalog",
                path: path.clone(),
                source,
            })?;
        let metadata = fence.metadata().map_err(|source| StoreError::Io {
            operation: "authenticate RAM catalog fence",
            path,
            source,
        })?;
        if !metadata.is_file() {
            return Err(StoreError::Unauthorized);
        }
        rustix::fs::flock(&fence, rustix::fs::FlockOperation::NonBlockingLockShared).map_err(
            |source| StoreError::StreamIo {
                operation: "retain RAM catalog deletion exclusion",
                source: source.into(),
            },
        )?;
        let backend = SqliteBlobBackend::open_with_physical_quota(
            "native-checkpoint-ram",
            directory,
            quota.clone(),
            self.maximum_sqlite_heap_bytes(),
            Arc::new(CatalogSqliteSupervisor(self.authority.clone())),
            &self.authority.sqlite_heap,
        )?;
        let storage = ProductionRamCatalogStorage {
            backend,
            quota,
            retention_fence: Arc::new(fence),
            original,
        };
        catalogs.insert(
            directory.to_path_buf(),
            CatalogEntry::Open {
                storage: storage.clone(),
                closed,
            },
        )?;
        operation.complete().map_err(sqlite_supervision_error)?;
        Ok(storage)
    }

    fn begin_catalog_retirement(
        &self,
        directory: &Path,
    ) -> Result<Arc<dyn ProductionRamCatalogRetirement>, StoreError> {
        self.authority.validate_path(directory)?;
        if directory.file_name().and_then(|name| name.to_str()) != Some("checkpoint-ram-objects") {
            return Err(StoreError::Unauthorized);
        }
        let active = directory
            .parent()
            .ok_or(StoreError::Unauthorized)?
            .to_path_buf();
        let name = active
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(StoreError::Unauthorized)?;
        let retired = active
            .parent()
            .ok_or(StoreError::Unauthorized)?
            .join(format!(".retired-checkpoint-catalog-{name}"));
        let operation = self
            .authority
            .supervisor
            .begin(HostOperationClass::Cleanup)
            .map_err(sqlite_supervision_error)?;
        let mut catalogs = supervised_lock(&self.catalogs, &operation)?;
        if let Some(CatalogEntry::Retiring(receipt)) = catalogs.get(directory) {
            operation.complete().map_err(sqlite_supervision_error)?;
            return Ok(receipt.clone());
        }
        let quota = match catalogs.close_for_retirement(directory)? {
            Some(storage) => {
                drop(storage.retention_fence);
                storage.quota
            }
            None => {
                // Restart reconciliation may retire a persisted catalog that
                // this process has never opened. The physical namespace lease
                // excludes a competing provider; the caller takes its exclusive
                // retention fence before deleting any bytes.
                self.authority.verify()?;
                let resources = self
                    .authority
                    .allocator
                    .reserve_resources(0, CATALOG_DESCRIPTORS, 0)
                    .map_err(|_| StoreError::Quota)?;
                let metadata_credit = CatalogSqliteSupervisor(self.authority.clone())
                    .reserve_resident_bytes(catalog_metadata_bytes(directory)?)?;
                Arc::new(CatalogGuard {
                    authority: self.authority.clone(),
                    closed: Arc::new(AtomicBool::new(true)),
                    _resources: resources,
                    _metadata: metadata_credit,
                }) as Arc<dyn StorePhysicalQuotaGuard>
            }
        };
        let receipt = Arc::new(CatalogRetirement {
            directory: directory.to_path_buf(),
            active,
            retired,
            authority: self.authority.clone(),
            catalogs: Arc::downgrade(&self.catalogs),
            quota: Mutex::new(Some(quota)),
            finished: AtomicBool::new(false),
        });
        catalogs.insert(
            directory.to_path_buf(),
            CatalogEntry::Retiring(receipt.clone()),
        )?;
        operation.complete().map_err(sqlite_supervision_error)?;
        Ok(receipt)
    }

    fn reserve_root_metadata(
        &self,
        directory: &Path,
        bytes: u64,
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, StoreError> {
        if bytes == 0 {
            return Err(StoreError::Quota);
        }
        self.authority.validate_path(directory)?;
        let operation = self
            .authority
            .supervisor
            .begin(HostOperationClass::PageIn)
            .map_err(sqlite_supervision_error)?;
        let catalogs = supervised_lock(&self.catalogs, &operation)?;
        if !matches!(catalogs.get(directory), Some(CatalogEntry::Open {closed, ..}) if !closed.load(Ordering::Acquire))
        {
            return Err(StoreError::Unauthorized);
        }
        let credit =
            CatalogSqliteSupervisor(self.authority.clone()).reserve_resident_bytes(bytes)?;
        operation.complete().map_err(sqlite_supervision_error)?;
        Ok(credit)
    }

    fn maximum_sqlite_heap_bytes(&self) -> u64 {
        self.authority.policy.maximum_sqlite_heap_bytes
    }
}

struct CatalogMetadataCredit {
    _leases: crucible_linux_resource::host_services::HostServiceLeasePair,
}

struct CatalogResourceCredit {
    _descriptors: Option<HostServiceLease>,
    _metadata: crucible_cas::owned_decode::ResourceLoan,
    _authority: Arc<CatalogAuthority>,
    _closed: Option<Arc<AtomicBool>>,
}

fn reserve_catalog_resources(
    authority: &Arc<CatalogAuthority>,
    closed: Option<Arc<AtomicBool>>,
    descriptors: u64,
    bytes: u64,
) -> Result<crucible_cas::owned_decode::ResourceLoan, StoreError> {
    authority.verify()?;
    let descriptors = reserve_catalog_descriptors(&authority.allocator, descriptors)?;
    let charged = bytes
        .checked_add(std::mem::size_of::<CatalogResourceCredit>() as u64)
        .and_then(|bytes| bytes.checked_add((2 * std::mem::size_of::<usize>()) as u64))
        .ok_or(StoreError::Quota)?;
    let metadata =
        reserve_metadata_credit(&authority.allocator, &authority.metadata_allocator, charged)?;
    authority.verify()?;
    Ok(crucible_cas::owned_decode::ResourceLoan::new(
        CatalogResourceCredit {
            _descriptors: descriptors,
            _metadata: metadata,
            _authority: authority.clone(),
            _closed: closed,
        },
    ))
}

fn reserve_catalog_descriptors(
    allocator: &HostServiceAllocator,
    descriptors: u64,
) -> Result<Option<HostServiceLease>, StoreError> {
    // Metadata-only loans retain the original authority without requesting an
    // empty allocator contract. Actual descriptors still require a live lease.
    if descriptors == 0 {
        return Ok(None);
    }
    allocator
        .reserve_resources(0, descriptors, 0)
        .map(Some)
        .map_err(|_| StoreError::Quota)
}

fn reserve_metadata_credit(
    resident: &HostServiceAllocator,
    metadata: &HostServiceAllocator,
    bytes: u64,
) -> Result<crucible_cas::owned_decode::ResourceLoan, StoreError> {
    reserve_metadata_credit_raw(resident, metadata, bytes).map_err(|_| StoreError::Quota)
}

fn reserve_metadata_credit_raw(
    resident: &HostServiceAllocator,
    metadata: &HostServiceAllocator,
    bytes: u64,
) -> Result<
    crucible_cas::owned_decode::ResourceLoan,
    crucible_linux_resource::host_services::HostServiceError,
> {
    use crucible_linux_resource::host_services::HostServiceError;

    let charged = bytes
        .checked_add(std::mem::size_of::<CatalogMetadataCredit>() as u64)
        .and_then(|bytes| bytes.checked_add((2 * std::mem::size_of::<usize>()) as u64))
        .ok_or(HostServiceError::CapacityExhausted)?;
    let (metadata, resident) = metadata.reserve_paired_bytes(resident, charged)?;
    Ok(crucible_cas::owned_decode::ResourceLoan::new(
        CatalogMetadataCredit {
            _leases: crucible_linux_resource::host_services::HostServiceLeasePair::new(
                resident, metadata,
            ),
        },
    ))
}

struct CatalogSqliteSupervisor(Arc<CatalogAuthority>);

impl SqliteCatalogSupervisor for CatalogSqliteSupervisor {
    fn reserve_resident_bytes(
        &self,
        bytes: u64,
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, StoreError> {
        reserve_metadata_credit(&self.0.allocator, &self.0.metadata_allocator, bytes)
    }

    fn begin(
        &self,
        kind: SqliteCatalogOperationKind,
    ) -> Result<Box<dyn SqliteCatalogOperation>, StoreError> {
        let class = match kind {
            SqliteCatalogOperationKind::Read => HostOperationClass::PageIn,
            SqliteCatalogOperationKind::Write => HostOperationClass::Writeback,
        };
        Ok(Box::new(CatalogSqliteOperation(
            self.0
                .supervisor
                .begin(class)
                .map_err(sqlite_supervision_error)?,
        )))
    }
}

struct CatalogSqliteOperation(HostOperationGuard);

impl SqliteCatalogOperation for CatalogSqliteOperation {
    fn check(&self) -> Result<(), StoreError> {
        self.0
            .wait_slice()
            .map(|_| ())
            .map_err(sqlite_supervision_error)
    }

    fn complete(self: Box<Self>) -> Result<(), StoreError> {
        self.0
            .complete()
            .map(|_| ())
            .map_err(sqlite_supervision_error)
    }
}

fn sqlite_supervision_error(source: HostSupervisionError) -> StoreError {
    StoreError::Supervision {
        source: Box::new(source),
    }
}

struct NamespaceGuard {
    authority: Arc<CatalogAuthority>,
    directory: PathBuf,
    _resources: crucible_cas::owned_decode::ResourceLoan,
}

impl crucible_cas::content_store::ProviderDiagnosticStorage for NamespaceGuard {
    fn try_occupy(&self) -> Result<(), StoreError> {
        self.authority
            .diagnostic_occupied
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| StoreError::Unavailable)
    }

    fn release(&self) {
        self.authority
            .diagnostic_occupied
            .store(false, Ordering::Release);
    }
}

impl StorePhysicalQuotaGuard for NamespaceGuard {
    fn begin_provider_diagnostic(
        self: Arc<Self>,
    ) -> Result<crucible_cas::content_store::ProviderDiagnosticPermit, StoreError> {
        // Checkout has no lower callback: this bound is checked before a quota
        // verifier can clone either diagnostic path into its first refusal.
        check_provider_error_path(self.authority.policy.root())?;
        check_provider_error_path(&self.directory)?;
        let permit = crucible_cas::content_store::ProviderDiagnosticPermit::checkout(self.clone())?;
        self.authority.verify_funded(permit)
    }

    fn gc_mark_backend(
        self: Arc<Self>,
        scope: &str,
    ) -> Result<Arc<dyn ImmutableBlobBackend>, StoreError> {
        if scope.is_empty() || scope.len() > 256 || scope.chars().any(char::is_control) {
            return Err(StoreError::InvalidComposition {
                reason: "GC mark scope must be bounded nonempty text",
            });
        }
        self.verify()?;
        let path_bytes = self
            .directory
            .as_os_str()
            .len()
            .checked_add(80)
            .ok_or(StoreError::Quota)?;
        let _paths = self.reserve_resources(
            0,
            u64::try_from(path_bytes.checked_mul(3).ok_or(StoreError::Quota)?)
                .map_err(|_| StoreError::Quota)?,
        )?;
        let digest = blake3::hash(scope.as_bytes()).to_hex();
        let directory = self.directory.join(".gc-marks").join(digest.as_str());
        self.authority.prepare(&directory)?;
        DirectoryBlobBackend::new_with_physical_quota("campaign-gc-marks", directory, self)
    }

    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        self.verify()?;
        Ok(self.authority.metadata_allocator.maximum_resident_bytes())
    }

    fn verify(&self) -> Result<(), StoreError> {
        self.authority.verify()
    }

    fn reserve_resources(
        &self,
        descriptors: u64,
        resident_bytes: u64,
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, StoreError> {
        reserve_catalog_resources(&self.authority, None, descriptors, resident_bytes)
    }
}

struct CatalogRetirement {
    directory: PathBuf,
    active: PathBuf,
    retired: PathBuf,
    catalogs: Weak<Mutex<CatalogCache>>,
    quota: Mutex<Option<Arc<dyn StorePhysicalQuotaGuard>>>,
    finished: AtomicBool,
    // The cache's final weak reference and quota material close while original
    // constructor credit is still retained by this authority.
    authority: Arc<CatalogAuthority>,
}

impl ProductionRamCatalogRetirement for CatalogRetirement {
    fn finish_deleted(&self) -> Result<(), StoreError> {
        if self.finished.load(Ordering::Acquire) {
            return Ok(());
        }
        let cache = self.catalogs.upgrade().ok_or(StoreError::Unauthorized)?;
        let operation = self
            .authority
            .supervisor
            .begin(HostOperationClass::Cleanup)
            .map_err(sqlite_supervision_error)?;
        let mut catalogs = supervised_lock(&cache, &operation)?;
        self.authority.verify()?;
        for path in [&self.active, &self.retired] {
            match std::fs::symlink_metadata(path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(StoreError::Io {
                        operation: "authenticate complete RAM catalog deletion",
                        path: path.clone(),
                        source,
                    });
                }
                Ok(_) => return Err(StoreError::Quota),
            }
        }
        let mut quota = supervised_lock(&self.quota, &operation)?;
        if quota
            .as_ref()
            .is_none_or(|guard| Arc::strong_count(guard) != 1)
        {
            return Err(StoreError::Unauthorized);
        }
        if !matches!(catalogs.get(&self.directory), Some(CatalogEntry::Retiring(receipt)) if std::ptr::eq(receipt.as_ref(), self))
        {
            return Err(StoreError::Unauthorized);
        }
        operation.complete().map_err(sqlite_supervision_error)?;
        quota.take();
        catalogs.remove(&self.directory);
        self.finished.store(true, Ordering::Release);
        Ok(())
    }
}

fn supervised_lock<'a, T>(
    mutex: &'a Mutex<T>,
    operation: &HostOperationGuard,
) -> Result<MutexGuard<'a, T>, StoreError> {
    loop {
        operation.wait_slice().map_err(sqlite_supervision_error)?;
        match mutex.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(TryLockError::WouldBlock) => std::thread::yield_now(),
            Err(TryLockError::Poisoned(_)) => return Err(StoreError::Unauthorized),
        }
    }
}

fn quota_error(source: LinuxProjectQuotaError) -> StoreError {
    match source {
        LinuxProjectQuotaError::Supervision(source) => sqlite_supervision_error(source),
        source => StoreError::StreamIo {
            operation: "authenticate retained RAM catalog physical quota",
            source: std::io::Error::other(source),
        },
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- resource fixtures panic only on invalid setup.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn metadata_only_loans_do_not_request_empty_descriptor_contracts() {
        let allocator =
            HostServiceAllocator::new(1, 1, 4096).expect("one independently authored descriptor");
        let descriptor =
            reserve_catalog_descriptors(&allocator, 1).expect("retained actual descriptor loan");

        assert!(
            reserve_catalog_descriptors(&allocator, 0)
                .expect("metadata-only reservation needs no descriptor")
                .is_none()
        );
        assert!(reserve_catalog_descriptors(&allocator, 1).is_err());

        drop(descriptor);
        assert!(reserve_catalog_descriptors(&allocator, 1).is_ok());
    }

    #[test]
    fn issuing_catalog_funds_original_cancellation_before_lower_binding_verification() {
        use crucible_linux_resource::host_supervision::{
            HostOperationBudget, HostOperationBudgets,
        };

        let resources = crucible_api::host_operational::HostResourceVector {
            resident_peak_bytes: 128 << 20,
            backing_peak_bytes: 512 << 20,
            metadata_bytes: 64 << 20,
            staging_bytes: 8 << 20,
            paging_io_slots: 1,
            cpu_slots: 1,
            task_slots: 1,
            file_descriptors: 128,
        };
        let policy =
            PackagedRamCatalogConfig::new("/component/catalog", 30000, 1000, resources, 8 << 20)
                .expect("explicit complete component catalog contract");
        let slots = usize::try_from(
            (resources.file_descriptors
                - LinuxProjectQuotaBinding::maximum_audit_file_descriptors())
                / CATALOG_DESCRIPTORS,
        )
        .expect("bounded catalog count");
        let constructor_bytes =
            catalog_constructor_bytes(&policy, slots).expect("complete constructor geometry");
        eprintln!(
            "catalog constructor: authority={} authority_arc={} cache_arc={} service_arc={} credit_arc={} entry={} table={} root={} controls={} diagnostic={} paired={constructor_bytes}",
            std::mem::size_of::<CatalogAuthority>(),
            arc_allocation_bytes::<CatalogAuthority>().expect("authority Arc"),
            arc_allocation_bytes::<Mutex<CatalogCache>>().expect("cache Arc"),
            arc_allocation_bytes::<CatalogService>().expect("service Arc"),
            arc_allocation_bytes::<CatalogMetadataCredit>().expect("credit Arc"),
            std::mem::size_of::<Option<(PathBuf, CatalogEntry)>>(),
            slots * std::mem::size_of::<Option<(PathBuf, CatalogEntry)>>(),
            policy.root().as_os_str().len(),
            5 * lease_control_bytes().expect("control geometry"),
            provider_diagnostic_bytes()
        );
        let supervisor = HostOperationSupervisor::new(
            HostOperationBudgets {
                classes: [HostOperationBudget::finite(std::time::Duration::from_secs(60));
                    crucible_linux_resource::host_supervision::HOST_OPERATION_CLASS_COUNT],
            },
            Some(std::time::Duration::from_secs(60)),
        )
        .expect("same original finite roster");
        let service = CatalogService::new_with_heap(
            policy,
            Arc::new(()),
            supervisor.clone(),
            Some(
                &crucible_cas::content_store::fixture_sqlite_heap()
                    .expect("authored SQLite fixture process"),
            ),
        )
        .expect("actual service diagnostic preadmission");
        let namespace_credit = reserve_metadata_credit_raw(
            &service.authority.allocator,
            &service.authority.metadata_allocator,
            (std::mem::size_of::<NamespaceGuard>()
                + 2 * std::mem::size_of::<usize>()
                + "/component/catalog/marks".len()) as u64,
        )
        .expect("actual original namespace handle metadata before allocation");
        let guard = Arc::new(NamespaceGuard {
            authority: service.authority.clone(),
            directory: PathBuf::from("/component/catalog/marks"),
            // This test performs no namespace I/O. Existing service admission
            // owns its actual audit resources; no project-quota proof is claimed.
            _resources: namespace_credit,
        });
        let retained = Arc::downgrade(&guard);
        supervisor
            .cancel()
            .expect("cancel original service before first lower check");

        let error = guard
            .clone()
            .begin_provider_diagnostic()
            .expect_err("original cancellation");
        let StoreError::ProviderDiagnostic { source } = &error else {
            panic!("lost originally paid cancellation cause");
        };
        assert_eq!(
            source.kind(),
            crucible_cas::content_store::ProviderFailureKind::Supervision
        );
        let cause = std::error::Error::source(source)
            .and_then(std::error::Error::source)
            .and_then(|cause| cause.downcast_ref::<HostSupervisionError>());
        assert!(matches!(cause, Some(HostSupervisionError::Terminal { .. })));
        assert!(matches!(
            guard.clone().begin_provider_diagnostic(),
            Err(StoreError::Unavailable)
        ));

        drop(guard);
        drop(service);
        assert!(retained.upgrade().is_some());
        drop(error);
        assert!(retained.upgrade().is_none());
    }

    #[test]
    fn initial_catalog_slot_refusal_is_inline_before_any_binding() {
        use crucible_linux_resource::host_supervision::{
            HostOperationBudget, HostOperationBudgets,
        };
        let resources = crucible_api::host_operational::HostResourceVector {
            resident_peak_bytes: 128 << 20,
            backing_peak_bytes: 512 << 20,
            metadata_bytes: (8 << 20) + crate::provider_error_custody::provider_diagnostic_bytes()
                - 1,
            staging_bytes: 8 << 20,
            paging_io_slots: 1,
            cpu_slots: 1,
            task_slots: 1,
            file_descriptors: 128,
        };
        let policy =
            PackagedRamCatalogConfig::new("/component/catalog", 30000, 1000, resources, 8 << 20)
                .expect("explicit contract with insufficient initial diagnostic headroom");
        let supervisor = HostOperationSupervisor::new(
            HostOperationBudgets {
                classes: [HostOperationBudget::finite(std::time::Duration::from_secs(60));
                    crucible_linux_resource::host_supervision::HOST_OPERATION_CLASS_COUNT],
            },
            Some(std::time::Duration::from_secs(60)),
        )
        .expect("original finite roster");

        let slots = usize::try_from(
            (resources.file_descriptors
                - LinuxProjectQuotaBinding::maximum_audit_file_descriptors())
                / CATALOG_DESCRIPTORS,
        )
        .expect("bounded catalog count");
        let exact =
            catalog_constructor_bytes(&policy, slots).expect("complete constructor geometry");
        let mut resources = resources;
        resources.metadata_bytes = (8 << 20) + exact - 1;
        let policy =
            PackagedRamCatalogConfig::new("/component/catalog", 30000, 1000, resources, 8 << 20)
                .expect("one byte below complete constructor geometry");
        assert!(matches!(
            CatalogService::new(policy, Arc::new(()), supervisor),
            Err(ProviderServiceAdmissionError::Resources(
                crucible_linux_resource::host_services::HostServiceError::CapacityExhausted
            ))
        ));
    }

    #[test]
    fn metadata_loans_preserve_the_heap_subset_and_release_at_last_reader() {
        let resident = HostServiceAllocator::new(1, 1, 1024 * 1024)
            .expect("authored complete resident fixture");
        let metadata =
            HostServiceAllocator::new(1, 1, 4096).expect("authored residual metadata fixture");
        let credit = reserve_metadata_credit(&resident, &metadata, 3000)
            .expect("bounded root metadata loan");
        let reader = credit.clone();

        assert!(reserve_metadata_credit(&resident, &metadata, 1500).is_err());
        drop(credit);
        assert!(reserve_metadata_credit(&resident, &metadata, 1500).is_err());
        drop(reader);
        assert!(reserve_metadata_credit(&resident, &metadata, 3000).is_ok());
    }
}
