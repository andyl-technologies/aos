//! Authored physical containment for the retained native RAM catalog service.
//!
//! Catalog backing persists independently of assignment process lifetimes.
//! The operator installs the project's inherited physical byte and inode quota
//! before the provider authenticates and opens its backend.

use crucible_api::vm_lifecycle::ProductionRamCatalogProvider;
use crucible_cas::content_store::{StoreError, StorePhysicalQuotaGuard};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use crucible_api::host_operational::HostResourceVector;

mod provider;

#[cfg(test)]
pub(crate) use provider::CatalogEvidenceSpool;
pub(super) use provider::GuardedCampaignStorage;

/// Charges and authenticates the durable catalog namespace before startup writes.
///
/// Admission survives both provider drops and partial quota binding failures:
/// existing bytes are never treated as deleted merely because startup failed.
///
/// # Errors
/// Refuses missing authored bounds, combined service and assignment exhaustion,
/// unavailable actor custody, unsafe existing quotas, or reused provider admission.
pub(super) fn admit_catalog_service(
    config: &super::PackagedQemuExecutorConfig,
    registry: &crate::HostOperationalRegistry,
) -> Result<(), super::PackagedQemuExecutorError> {
    use crucible_api::host_operational::HostOperationalError;
    use crucible_linux_resource::host_supervision::HostOperationSupervisor;

    let catalog = config.ram_catalog().ok_or(StoreError::Quota)?;
    let mut identity = blake3::Hasher::new();
    identity.update(b"crucible.host.ram-catalog-service.v1\0");
    identity.update(&config.daemon_epoch.as_bytes());
    identity.update(catalog.root().as_os_str().as_encoded_bytes());
    identity.update(&catalog.project_id().to_be_bytes());
    let owner = *identity.finalize().as_bytes();
    let budgets = config.host_operation_budgets().ok_or(StoreError::Quota)?;
    #[cfg(feature = "private-measurement-domain")]
    let supervisor = if let Some(original) = &config.original_preparation {
        original.derive_supervisor(budgets)?
    } else {
        HostOperationSupervisor::new(budgets, None)
            .map_err(crate::ProviderServiceAdmissionError::from)?
    };
    #[cfg(not(feature = "private-measurement-domain"))]
    let supervisor = HostOperationSupervisor::new(budgets, None)
        .map_err(crate::ProviderServiceAdmissionError::from)?;
    let custody = registry.capacity_custody()?;
    registry.reserve_service_with_assignment_headroom(
        owner,
        catalog.resources(),
        config
            .assignment_resources()
            .ok_or(HostOperationalError::Unavailable)?,
    )?;
    let service = match provider::CatalogService::new_with_heap(
        catalog.clone(),
        custody,
        supervisor,
        catalog.process_heap.as_ref(),
    ) {
        Ok(service) => Arc::new(service),
        Err(error) => {
            // The provider has not opened any namespace descriptor or backend.
            registry.release_service_after_cleanup(owner)?;
            return Err(error.into());
        }
    };
    if let Err(error) = registry.retain_catalog_service(owner, service.clone()) {
        // No namespace descriptor has been opened yet. The exact empty service
        // reservation can roll back without claiming persisted bytes deleted.
        registry.release_service_after_cleanup(owner)?;
        return Err(error.into());
    }
    service.bind()?;
    catalog.install_provider(service)?;
    Ok(())
}

/// Immutable physical quota and complete service entitlement for native RAM catalogs.
#[derive(Clone)]
pub struct PackagedRamCatalogConfig {
    root: PathBuf,
    project_id: u32,
    maximum_inodes: u64,
    resources: HostResourceVector,
    maximum_sqlite_heap_bytes: u64,
    provider: Arc<AdmittedCatalogProvider>,
    process_heap: Option<crucible_cas::content_store::SqliteProcessHeap>,
}

/// Refusal of an invalid catalog resource or physical containment contract.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error(
    "RAM catalog requires an absolute quota root, nonzero project identity and finite service bounds"
)]
pub struct PackagedRamCatalogConfigError;

impl PackagedRamCatalogConfig {
    /// Retains an independently authored physical catalog quota and service ceiling.
    ///
    /// This constructor validates the contract. Actual backend admission must
    /// authenticate the installed project quota before opening any catalog file.
    ///
    /// # Errors
    /// Refuses a relative root, zero project identity, empty inode allowance,
    /// zero resource dimensions, an empty or exhausted SQLite heap subset,
    /// overflowing subsets, subsets above peaks, or
    /// resources that cannot retain the bounded namespace walk and one backend.
    pub fn new(
        root: impl Into<PathBuf>,
        project_id: u32,
        maximum_inodes: u64,
        resources: HostResourceVector,
        maximum_sqlite_heap_bytes: u64,
    ) -> Result<Self, PackagedRamCatalogConfigError> {
        let root = root.into();
        if !root.is_absolute()
            || root.components().any(|part| {
                !matches!(
                    part,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
            || project_id == 0
            || maximum_inodes == 0
            || maximum_sqlite_heap_bytes == 0
            || maximum_sqlite_heap_bytes >= resources.metadata_bytes
            || [
                resources.resident_peak_bytes,
                resources.backing_peak_bytes,
                resources.metadata_bytes,
                resources.staging_bytes,
                resources.paging_io_slots,
                resources.cpu_slots,
                resources.task_slots,
                resources.file_descriptors,
            ]
            .contains(&0)
            || resources
                .metadata_bytes
                .checked_add(resources.staging_bytes)
                .is_none_or(|bytes| bytes > resources.resident_peak_bytes)
            || resources.staging_bytes > resources.backing_peak_bytes
            || resources.file_descriptors < provider::minimum_file_descriptors()
            || resources.staging_bytes < provider::minimum_staging_bytes()
        {
            return Err(PackagedRamCatalogConfigError);
        }
        Ok(Self {
            root,
            project_id,
            maximum_inodes,
            resources,
            maximum_sqlite_heap_bytes,
            process_heap: None,
            provider: Arc::new(AdmittedCatalogProvider {
                maximum_sqlite_heap_bytes,
                admitted: OnceLock::new(),
            }),
        })
    }

    /// Borrows the original process heap without issuing another native allowance.
    ///
    /// # Errors
    /// Refuses closed ownership, an already admitted provider or a process heap
    /// exceeding this catalog's existing native maximum.
    pub fn with_sqlite_process_heap(
        mut self,
        heap: &crucible_cas::content_store::SqliteProcessHeap,
    ) -> Result<Self, StoreError> {
        heap.verify_live()?;
        if self.provider.admitted.get().is_some()
            || heap.maximum_heap_bytes() > self.maximum_sqlite_heap_bytes
        {
            return Err(StoreError::Quota);
        }
        self.process_heap = Some(heap.clone());
        Ok(self)
    }

    /// Returns the operator-installed inherited project-quota root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the stable physical project identity retained across daemon restarts.
    #[must_use]
    pub const fn project_id(&self) -> u32 {
        self.project_id
    }

    /// Returns the hard inode ceiling covering every catalog descendant.
    #[must_use]
    pub const fn maximum_inodes(&self) -> u64 {
        self.maximum_inodes
    }

    /// Returns the independently authored SQLite heap subset of metadata.
    #[must_use]
    pub const fn maximum_sqlite_heap_bytes(&self) -> u64 {
        self.maximum_sqlite_heap_bytes
    }

    /// Returns the complete independently admitted catalog service vector.
    #[must_use]
    pub const fn resources(&self) -> HostResourceVector {
        self.resources
    }
}

impl std::fmt::Debug for PackagedRamCatalogConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PackagedRamCatalogConfig")
            .field("root", &self.root)
            .field("project_id", &self.project_id)
            .field("maximum_inodes", &self.maximum_inodes)
            .field("resources", &self.resources)
            .field("maximum_sqlite_heap_bytes", &self.maximum_sqlite_heap_bytes)
            .field("admitted", &self.provider.admitted.get().is_some())
            .finish()
    }
}

impl PackagedRamCatalogConfig {
    /// Opens the guarded repository inside genuine admitted catalog custody.
    ///
    /// # Errors
    /// Refuses missing admission, escaped directories, exhausted resource loans,
    /// unsafe physical quotas, expired supervision, and backend failures.
    pub(super) fn open_guarded_storage(
        &self,
        directory: &Path,
    ) -> Result<GuardedCampaignStorage, StoreError> {
        self.provider
            .admitted
            .get()
            .ok_or(StoreError::Quota)?
            .open_guarded_storage(directory)
    }

    /// Creates a bounded anonymous spool under already admitted catalog custody.
    ///
    /// # Errors
    /// Refuses missing admission, an escaped directory, exhausted descriptor or
    /// metadata credit, invalid byte bounds, expired original supervision, and
    /// failed kernel quota authentication or filesystem operations.
    #[cfg(test)]
    pub(crate) fn create_evidence_spool(
        &self,
        directory: &Path,
        maximum_bytes: u64,
        supervisor: &crucible_linux_resource::host_supervision::HostOperationSupervisor,
    ) -> Result<CatalogEvidenceSpool, StoreError> {
        self.provider
            .admitted
            .get()
            .ok_or(StoreError::Quota)?
            .create_evidence_spool(directory, maximum_bytes, supervisor)
    }

    /// Retains diagnostic buffers within the admitted catalog's Rust metadata.
    ///
    /// The credit keeps original actor and physical-quota custody alive across
    /// node retirement. The caller reserves it before allocating the buffers.
    ///
    /// # Errors
    /// Refuses missing admission, empty or exhausted credit, failed quota
    /// authentication, or expired original supervision.
    #[cfg(test)]
    pub(crate) fn reserve_evidence_resident(
        &self,
        bytes: u64,
        supervisor: &crucible_linux_resource::host_supervision::HostOperationSupervisor,
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, StoreError> {
        self.provider
            .admitted
            .get()
            .ok_or(StoreError::Quota)?
            .reserve_evidence_resident(bytes, supervisor)
    }

    pub(super) fn provider(&self) -> Arc<dyn ProductionRamCatalogProvider> {
        self.provider.clone()
    }

    fn install_provider(&self, provider: Arc<provider::CatalogService>) -> Result<(), StoreError> {
        self.provider
            .admitted
            .set(provider)
            .map_err(|_| StoreError::Quota)
    }
}

struct AdmittedCatalogProvider {
    maximum_sqlite_heap_bytes: u64,
    admitted: OnceLock<Arc<provider::CatalogService>>,
}

impl ProductionRamCatalogProvider for AdmittedCatalogProvider {
    fn prepare_directory(
        &self,
        directory: &Path,
    ) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        self.admitted
            .get()
            .ok_or(StoreError::Quota)?
            .prepare_directory(directory)
    }

    fn open_catalog(
        &self,
        directory: &Path,
    ) -> Result<crucible_api::vm_lifecycle::ProductionRamCatalogStorage, StoreError> {
        self.admitted
            .get()
            .ok_or(StoreError::Quota)?
            .open_catalog(directory)
    }

    fn begin_catalog_retirement(
        &self,
        directory: &Path,
    ) -> Result<Arc<dyn crucible_api::vm_lifecycle::ProductionRamCatalogRetirement>, StoreError>
    {
        self.admitted
            .get()
            .ok_or(StoreError::Quota)?
            .begin_catalog_retirement(directory)
    }

    fn reserve_root_metadata(
        &self,
        directory: &Path,
        bytes: u64,
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, StoreError> {
        self.admitted
            .get()
            .ok_or(StoreError::Quota)?
            .reserve_root_metadata(directory, bytes)
    }

    fn maximum_sqlite_heap_bytes(&self) -> u64 {
        self.maximum_sqlite_heap_bytes
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- contract fixtures panic only to localize setup failures.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn resources() -> HostResourceVector {
        HostResourceVector {
            resident_peak_bytes: 128 * 1024 * 1024,
            backing_peak_bytes: 512 * 1024 * 1024,
            metadata_bytes: 64 * 1024 * 1024,
            staging_bytes: 8 * 1024 * 1024,
            paging_io_slots: 1,
            cpu_slots: 1,
            task_slots: 1,
            file_descriptors: 128,
        }
    }

    #[test]
    fn catalog_contract_preserves_secure_walk_and_backend_peak() {
        let mut insufficient = resources();
        insufficient.file_descriptors = provider::minimum_file_descriptors() - 1;
        assert!(
            PackagedRamCatalogConfig::new("/catalogs", 30000, 1000, insufficient, 8 << 20).is_err()
        );

        insufficient = resources();
        insufficient.staging_bytes = provider::minimum_staging_bytes() - 1;
        assert!(
            PackagedRamCatalogConfig::new("/catalogs", 30000, 1000, insufficient, 8 << 20).is_err()
        );
        assert!(
            PackagedRamCatalogConfig::new("/catalogs/../other", 30000, 1000, resources(), 8 << 20)
                .is_err()
        );
        assert!(
            PackagedRamCatalogConfig::new("/catalogs", 30000, 1000, resources(), 8 << 20).is_ok()
        );
    }

    #[test]
    fn sqlite_heap_is_an_explicit_strict_subset_of_metadata() {
        for heap in [0, resources().metadata_bytes, u64::MAX] {
            assert!(
                PackagedRamCatalogConfig::new("/catalogs", 30000, 1000, resources(), heap).is_err()
            );
        }
    }

    #[test]
    fn deferred_catalog_authority_refuses_before_admission() {
        let directory = tempfile::tempdir().expect("catalog contract fixture");
        let root = directory.path().join("catalogs");
        let contract = PackagedRamCatalogConfig::new(&root, 30000, 1000, resources(), 8 << 20)
            .expect("explicit finite catalog contract");
        let provider = contract.provider();

        assert!(provider.prepare_directory(&root.join("worlds")).is_err());
        assert!(
            provider
                .open_catalog(&root.join("worlds/test/checkpoint-ram-objects"))
                .is_err()
        );
        let supervisor = crucible_linux_resource::host_supervision::HostOperationSupervisor::new(
            crucible_linux_resource::host_supervision::HostOperationBudgets {
                classes: [crucible_linux_resource::host_supervision::HostOperationBudget::finite(
                    std::time::Duration::from_secs(1),
                );
                    crucible_linux_resource::host_supervision::HOST_OPERATION_CLASS_COUNT],
            },
            None,
        )
        .expect("finite diagnostic fixture supervision");

        assert!(
            contract
                .reserve_evidence_resident(4096, &supervisor)
                .is_err()
        );
        assert!(
            contract
                .create_evidence_spool(&root.join("evidence"), 4096, &supervisor)
                .is_err()
        );
        assert!(!root.exists());
    }
}
