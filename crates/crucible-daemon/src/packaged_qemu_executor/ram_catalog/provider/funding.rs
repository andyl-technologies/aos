//! Selects existing catalog funding and supervision for the shared provider.
//!
//! Ordinary deployments retain their original service allocators. The closed
//! actor deployment instead borrows its published catalog binding, while its
//! external owner keeps constructor credit through actual Arc/cache closure.

use super::*;

/// Retains the already issued funding for one deployment mode.
pub(super) enum CatalogFunding {
    /// Retains the independently admitted ordinary deployment.
    Ordinary {
        allocator: HostServiceAllocator,
        metadata_allocator: HostServiceAllocator,
        _root_resources: HostServiceLease,
        _sql_staging_resources: HostServiceLease,
        _metadata_resources: crucible_cas::owned_decode::ResourceLoan,
        _custody: Arc<dyn Send + Sync>,
    },
    #[cfg(feature = "private-measurement-domain")]
    /// Retains loans under the already published original catalog.
    Original {
        binding: crate::private_measurement_runtime::catalog::OriginalCatalogBinding,
        _sql_staging_resources: crucible_cas::owned_decode::ResourceLoan,
    },
}

/// Dispatches fixed provider operations to their actual retained supervisor.
#[derive(Clone)]
pub(super) enum CatalogSupervision {
    /// Uses the ordinary deployment supervisor.
    Ordinary(HostOperationSupervisor),
    #[cfg(feature = "private-measurement-domain")]
    /// Uses the same retained original catalog roster.
    Original(crate::private_measurement_runtime::catalog::OriginalCatalogBinding),
}

impl CatalogSupervision {
    /// Starts an operation in the retained deployment supervisor.
    ///
    /// # Errors
    /// Refuses invalid geometry, wrong deployment, original funding or the retained boundary.
    pub(super) fn begin(
        &self,
        class: HostOperationClass,
    ) -> Result<HostOperationGuard, StoreError> {
        match self {
            Self::Ordinary(supervisor) => supervisor.begin(class).map_err(sqlite_supervision_error),
            #[cfg(feature = "private-measurement-domain")]
            Self::Original(binding) => binding.begin(class),
        }
    }

    /// Borrows the ordinary supervisor for its own quota installation route.
    ///
    /// # Errors
    /// Refuses invalid geometry, wrong deployment, original funding or the retained boundary.
    pub(super) fn ordinary(&self) -> Result<HostOperationSupervisor, StoreError> {
        match self {
            Self::Ordinary(supervisor) => Ok(supervisor.clone()),
            #[cfg(feature = "private-measurement-domain")]
            Self::Original(_) => Err(StoreError::Unauthorized),
        }
    }
}

impl CatalogService {
    #[cfg(feature = "private-measurement-domain")]
    /// Computes the actual fixed provider bodies and control layout before birth.
    ///
    /// # Errors
    /// Refuses invalid geometry, wrong deployment, original funding or the retained boundary.
    pub(crate) fn original_constructor_bytes() -> Result<u64, StoreError> {
        let slots = original_catalog_slots()?;
        let mut bytes = slots
            .checked_mul(std::mem::size_of::<Option<(PathBuf, CatalogEntry)>>())
            .and_then(|bytes| bytes.checked_add("/var/lib/crucible/measurement/catalog".len()))
            .ok_or(StoreError::Quota)?;
        for extent in [
            arc_allocation_bytes::<CatalogAuthority>()?,
            arc_allocation_bytes::<Mutex<CatalogCache>>()?,
            arc_allocation_bytes::<CatalogService>()?,
            usize::try_from(provider_diagnostic_bytes()).map_err(|_| StoreError::Quota)?,
        ] {
            bytes = bytes.checked_add(extent).ok_or(StoreError::Quota)?;
        }
        u64::try_from(bytes).map_err(|_| StoreError::Quota)
    }

    #[cfg(feature = "private-measurement-domain")]
    /// Builds a provider using externally prepaid original constructor custody.
    ///
    /// # Errors
    /// Refuses invalid geometry, wrong deployment, original funding or the retained boundary.
    pub(crate) fn new_original(
        binding: crate::private_measurement_runtime::catalog::OriginalCatalogBinding,
        heap: &crucible_cas::content_store::SqliteProcessHeap,
    ) -> Result<Self, StoreError> {
        binding.verify()?;
        heap.verify_live()?;
        let slots = original_catalog_slots()?;
        let staging = binding.reserve_metadata(
            crucible_cas::content_store::minimum_sqlite_catalog_staging_bytes(),
        )?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(slots)
            .map_err(|source| binding.retain_allocation_error(source))?;
        entries.resize_with(slots, || None);
        let service = Self {
            catalogs: Arc::new(Mutex::new(CatalogCache {
                entries: entries.into_boxed_slice(),
            })),
            authority: Arc::new(CatalogAuthority {
                policy: CatalogNamespace {
                    root: PathBuf::from("/var/lib/crucible/measurement/catalog"),
                    // Original binding verifies its authenticated project directly;
                    // these ordinary-only quota-install fields are never consumed.
                    project_id: None,
                    maximum_inodes: 1_048_576,
                    resources: crucible_api::host_operational::HostResourceVector {
                        resident_peak_bytes: 512 << 20,
                        backing_peak_bytes: 8 << 30,
                        metadata_bytes: 256 << 20,
                        staging_bytes: 32 << 20,
                        paging_io_slots: 1,
                        cpu_slots: 1,
                        task_slots: 1,
                        file_descriptors: 128,
                    },
                    maximum_sqlite_heap_bytes: heap.maximum_heap_bytes(),
                },
                funding: CatalogFunding::Original {
                    binding: binding.clone(),
                    _sql_staging_resources: staging,
                },
                binding: Mutex::new(None),
                supervisor: CatalogSupervision::Original(binding),
                diagnostic_occupied: AtomicBool::new(false),
                sqlite_heap: heap.clone(),
            }),
        };
        service.verify_original_binding()?;
        Ok(service)
    }

    #[cfg(feature = "private-measurement-domain")]
    /// Checks the original provider binding and its installed quota.
    ///
    /// # Errors
    /// Refuses invalid geometry, wrong deployment, original funding or the retained boundary.
    pub(crate) fn verify_original_binding(&self) -> Result<(), StoreError> {
        match &self.authority.funding {
            CatalogFunding::Original { binding, .. } => binding.verify(),
            CatalogFunding::Ordinary { .. } => Err(StoreError::Unauthorized),
        }
    }

    #[cfg(feature = "private-measurement-domain")]
    /// Checks the exact retained original used by factory preparation.
    ///
    /// # Errors
    /// Refuses invalid geometry, wrong deployment, original funding or the retained boundary.
    pub(crate) fn verify_original_preparation(
        &self,
        preparation: &crate::private_original_capture::OriginalPreparation,
    ) -> Result<(), StoreError> {
        match &self.authority.funding {
            CatalogFunding::Original { binding, .. } => binding.verify_preparation(preparation),
            CatalogFunding::Ordinary { .. } => Err(StoreError::Unauthorized),
        }
    }

    #[cfg(feature = "private-measurement-domain")]
    /// Checks exclusive authority and an empty physically retired cache.
    pub(crate) fn can_close(&mut self) -> bool {
        if Arc::get_mut(&mut self.authority).is_none() {
            return false;
        }
        let Some(cache) = Arc::get_mut(&mut self.catalogs) else {
            return false;
        };
        match cache.get_mut() {
            Ok(cache) => cache.entries.iter().all(Option::is_none),
            Err(_) => false,
        }
    }
}

#[cfg(feature = "private-measurement-domain")]
fn original_catalog_slots() -> Result<usize, StoreError> {
    usize::try_from(
        (128 - LinuxProjectQuotaBinding::maximum_audit_file_descriptors()) / CATALOG_DESCRIPTORS,
    )
    .map_err(|_| StoreError::Quota)
}

/// Keeps actual descriptor credit through its physical users.
pub(super) enum CatalogDescriptors {
    /// Retains the independently admitted ordinary deployment.
    Ordinary { _lease: HostServiceLease },
    #[cfg(feature = "private-measurement-domain")]
    /// Retains loans under the already published original catalog.
    Original {
        _loan: crucible_cas::owned_decode::ResourceLoan,
    },
}

impl CatalogAuthority {
    #[cfg(test)]
    /// Borrows only the ordinary mode allocators for component controls.
    ///
    /// # Errors
    /// Refuses invalid geometry, wrong deployment, original funding or the retained boundary.
    pub(super) fn ordinary_allocators(
        &self,
    ) -> Result<(&HostServiceAllocator, &HostServiceAllocator), StoreError> {
        match &self.funding {
            CatalogFunding::Ordinary {
                allocator,
                metadata_allocator,
                ..
            } => Ok((allocator, metadata_allocator)),
            #[cfg(feature = "private-measurement-domain")]
            CatalogFunding::Original { .. } => Err(StoreError::Unauthorized),
        }
    }

    /// Reserves actual descriptors from the retained deployment funding.
    ///
    /// # Errors
    /// Refuses invalid geometry, wrong deployment, original funding or the retained boundary.
    pub(super) fn reserve_descriptors(
        &self,
        descriptors: u64,
    ) -> Result<Option<CatalogDescriptors>, StoreError> {
        if descriptors == 0 {
            return Ok(None);
        }
        match &self.funding {
            CatalogFunding::Ordinary { allocator, .. } => {
                reserve_catalog_descriptors(allocator, descriptors)
                    .map(|lease| lease.map(|lease| CatalogDescriptors::Ordinary { _lease: lease }))
            }
            #[cfg(feature = "private-measurement-domain")]
            CatalogFunding::Original { binding, .. } => binding
                .reserve_descriptors(descriptors)
                .map(|loan| Some(CatalogDescriptors::Original { _loan: loan })),
        }
    }

    /// Reserves actual metadata from the retained deployment funding.
    ///
    /// # Errors
    /// Refuses invalid geometry, wrong deployment, original funding or the retained boundary.
    pub(super) fn reserve_metadata(
        &self,
        bytes: u64,
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, StoreError> {
        match &self.funding {
            CatalogFunding::Ordinary {
                allocator,
                metadata_allocator,
                ..
            } => reserve_metadata_credit(allocator, metadata_allocator, bytes),
            #[cfg(feature = "private-measurement-domain")]
            CatalogFunding::Original { binding, .. } => binding.reserve_metadata(bytes),
        }
    }

    /// Checks and returns the supported metadata extent for this deployment.
    ///
    /// # Errors
    /// Refuses invalid geometry, wrong deployment, original funding or the retained boundary.
    pub(super) fn metadata_limit(&self) -> Result<u64, StoreError> {
        match &self.funding {
            CatalogFunding::Ordinary {
                metadata_allocator, ..
            } => Ok(metadata_allocator.maximum_resident_bytes()),
            #[cfg(feature = "private-measurement-domain")]
            CatalogFunding::Original { binding, .. } => binding.metadata_limit(),
        }
    }
}
