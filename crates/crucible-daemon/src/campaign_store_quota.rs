//! Admits persistent physical quota authority for a standalone campaign store.
//!
//! Operator-authored service capacity and one finite original lifetime cover
//! binding and later verification. Namespace guards retain their descriptor
//! leases, while one audit lock bounds temporary scan resources across callers.
//! Retained store handles and readers borrow the remaining descriptor capacity
//! and paired metadata/resident credits without releasing the pinned quota.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crucible_cas::content_store::{StoreError, StorePhysicalQuotaBinder, StorePhysicalQuotaGuard};
use crucible_linux_resource::host_services::{HostServiceAllocator, HostServiceLease};
use crucible_linux_resource::host_supervision::{
    HostOperationBudget, HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
};
use crucible_linux_resource::ram_policy::HostResourceVector;
use crucible_linux_resource::{LinuxProjectQuotaBinding, LinuxProjectQuotaError};

/// Operator-authored standalone service admission, independent of VM resources.
#[derive(Clone, Copy, Debug)]
pub struct CampaignQuotaServiceConfig {
    /// Original finite lifetime covering binding and every later quota check.
    pub lifetime: Duration,
    /// Complete service entitlement, including audit scratch and caller overhead.
    ///
    /// CPU slots are nominal admission capacity; this adapter does not install
    /// a whole-host CPU bandwidth limit. The backing entitlement excludes the
    /// separately operator-installed persistent quota being authenticated.
    pub resources: HostResourceVector,
}

#[derive(Debug)]
struct QuotaService {
    supervisor: HostOperationSupervisor,
    resources: HostServiceAllocator,
    metadata: HostServiceAllocator,
    serial: Mutex<()>,
    _caller: HostServiceLease,
}

/// Binds operator-installed quotas under one admitted standalone service.
#[derive(Clone, Debug)]
pub struct LinuxProjectQuotaBinder {
    service: Arc<QuotaService>,
}

#[derive(Debug)]
struct BoundLinuxProjectQuota {
    authority: Arc<QuotaAuthority>,
}

#[derive(Debug)]
struct QuotaAuthority {
    binding: LinuxProjectQuotaBinding,
    service: Arc<QuotaService>,
    _descriptors: HostServiceLease,
    _metadata: QuotaMetadataCredit,
}

#[derive(Debug)]
struct QuotaMetadataCredit {
    _resident: HostServiceLease,
    _metadata: HostServiceLease,
}

struct QuotaResourceCredit {
    // Authority closes the real root descriptors before these credits expire.
    _authority: Arc<QuotaAuthority>,
    _descriptors: Option<HostServiceLease>,
    _metadata: QuotaMetadataCredit,
}

impl LinuxProjectQuotaBinder {
    /// Starts a bounded standalone quota service before any namespace opens.
    ///
    /// The existing caller reserves one task and the authored nonmetadata
    /// resident allowance; no worker is created. Retained metadata loans draw
    /// from the remaining resident capacity and the metadata subset together.
    /// Each bound namespace reserves its complete descriptor audit peak,
    /// including two persistent descriptors. Store handle and reader loans
    /// require additional authored descriptor and metadata capacity.
    /// Clones share capacity and original lifetime. Serialized audit scratch
    /// comes from the independently authored staging subset.
    ///
    /// # Errors
    /// Refuses invalid lifetime, insufficient complete resource entitlement,
    /// audit capacity, or unavailable resource/supervision authority.
    pub fn new(config: CampaignQuotaServiceConfig) -> Result<Self, StoreError> {
        let admitted = config.resources;
        let subsets = admitted
            .metadata_bytes
            .checked_add(admitted.staging_bytes)
            .ok_or(StoreError::Quota)?;
        if admitted.cpu_slots == 0
            || admitted.task_slots == 0
            || admitted.paging_io_slots == 0
            || admitted.file_descriptors
                < LinuxProjectQuotaBinding::maximum_audit_file_descriptors()
            || admitted.staging_bytes < LinuxProjectQuotaBinding::maximum_audit_scratch_bytes()
            || subsets >= admitted.resident_peak_bytes
            || subsets > admitted.backing_peak_bytes
        {
            return Err(StoreError::Quota);
        }
        let resources = HostServiceAllocator::new(
            admitted.task_slots,
            admitted.file_descriptors,
            admitted.resident_peak_bytes,
        )
        .map_err(supervision_error)?;
        let caller = resources
            .reserve_resources(1, 0, admitted.resident_peak_bytes - admitted.metadata_bytes)
            .map_err(supervision_error)?;
        let metadata =
            HostServiceAllocator::new(1, 1, admitted.metadata_bytes).map_err(supervision_error)?;
        let budgets = HostOperationBudgets {
            classes: [HostOperationBudget::finite(config.lifetime);
                crucible_linux_resource::host_supervision::HOST_OPERATION_CLASS_COUNT],
        };
        let supervisor = HostOperationSupervisor::new(budgets, Some(config.lifetime))
            .map_err(supervision_error)?;
        Ok(Self {
            service: Arc::new(QuotaService {
                supervisor,
                resources,
                metadata,
                serial: Mutex::new(()),
                _caller: caller,
            }),
        })
    }
}

impl StorePhysicalQuotaBinder for LinuxProjectQuotaBinder {
    fn bind(
        &self,
        root: &Path,
        project_id: u32,
        maximum_physical_bytes: u64,
        maximum_inodes: u64,
    ) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        let _serial = self
            .service
            .serial
            .try_lock()
            .map_err(|_| StoreError::Unauthorized)?;
        let descriptors = self
            .service
            .resources
            .reserve_resources(
                0,
                LinuxProjectQuotaBinding::maximum_audit_file_descriptors(),
                0,
            )
            .map_err(supervision_error)?;
        let metadata_bytes = root
            .as_os_str()
            .len()
            .checked_add(std::mem::size_of::<QuotaAuthority>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<BoundLinuxProjectQuota>()))
            .and_then(|bytes| bytes.checked_add(4 * std::mem::size_of::<usize>()))
            .ok_or(StoreError::Quota)?;
        let metadata = self.service.reserve_metadata(
            u64::try_from(metadata_bytes)
                .map_err(|_| StoreError::Quota)?
                .checked_add(HostServiceLease::metadata_bytes())
                .ok_or(StoreError::Quota)?,
        )?;
        let binding = LinuxProjectQuotaBinding::bind_existing_supervised(
            root,
            project_id,
            maximum_physical_bytes,
            maximum_inodes,
            self.service.supervisor.clone(),
        )
        .map_err(store_error)?;
        Ok(Arc::new(BoundLinuxProjectQuota {
            authority: Arc::new(QuotaAuthority {
                binding,
                service: self.service.clone(),
                _descriptors: descriptors,
                _metadata: metadata,
            }),
        }))
    }
}

impl StorePhysicalQuotaGuard for BoundLinuxProjectQuota {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        self.verify()?;
        Ok(self.authority.service.metadata.maximum_resident_bytes())
    }

    fn verify(&self) -> Result<(), StoreError> {
        let _serial = self
            .authority
            .service
            .serial
            .try_lock()
            .map_err(|_| StoreError::Unauthorized)?;
        self.authority.binding.verify().map_err(store_error)
    }

    fn reserve_resources(
        &self,
        descriptors: u64,
        resident_bytes: u64,
    ) -> Result<Arc<dyn Send + Sync>, StoreError> {
        let service = &self.authority.service;
        let operation = service
            .supervisor
            .begin(HostOperationClass::Preparation)
            .map_err(supervision_error)?;
        self.verify()?;
        let charged = resident_bytes
            .checked_add(std::mem::size_of::<QuotaResourceCredit>() as u64)
            .and_then(|bytes| bytes.checked_add((2 * std::mem::size_of::<usize>()) as u64))
            .and_then(|bytes| {
                bytes.checked_add(if descriptors == 0 {
                    0
                } else {
                    HostServiceLease::metadata_bytes()
                })
            })
            .ok_or(StoreError::Quota)?;
        let descriptors = if descriptors == 0 {
            None
        } else {
            Some(
                service
                    .resources
                    .reserve_resources(0, descriptors, 0)
                    .map_err(supervision_error)?,
            )
        };
        let metadata = service.reserve_metadata(charged)?;
        self.verify()?;
        operation.complete().map_err(supervision_error)?;
        Ok(Arc::new(QuotaResourceCredit {
            _authority: self.authority.clone(),
            _descriptors: descriptors,
            _metadata: metadata,
        }))
    }
}

impl QuotaService {
    fn reserve_metadata(&self, bytes: u64) -> Result<QuotaMetadataCredit, StoreError> {
        let operation = self
            .supervisor
            .begin(HostOperationClass::Preparation)
            .map_err(supervision_error)?;
        let charged = bytes
            .checked_add(2 * HostServiceLease::metadata_bytes())
            .ok_or(StoreError::Quota)?;
        let metadata = self
            .metadata
            .reserve_resources(0, 0, charged)
            .map_err(supervision_error)?;
        let resident = self
            .resources
            .reserve_resources(0, 0, charged)
            .map_err(supervision_error)?;
        operation.complete().map_err(supervision_error)?;
        Ok(QuotaMetadataCredit {
            _resident: resident,
            _metadata: metadata,
        })
    }
}

fn supervision_error(error: impl std::error::Error + Send + Sync + 'static) -> StoreError {
    StoreError::Supervision {
        source: Box::new(error),
    }
}

fn store_error(error: LinuxProjectQuotaError) -> StoreError {
    match error {
        LinuxProjectQuotaError::Io {
            operation,
            path,
            source,
        } => StoreError::Io {
            operation,
            path,
            source,
        },
        LinuxProjectQuotaError::Supervision(error) => supervision_error(error),
        _ => StoreError::Quota,
    }
}

#[cfg(test)]
mod tests {
    //! Checks admission and shared original cancellation before namespace I/O.

    use super::*;
    use crucible_linux_resource::host_services::HostServiceError;
    use crucible_linux_resource::host_supervision::HostSupervisionError;

    fn config() -> CampaignQuotaServiceConfig {
        CampaignQuotaServiceConfig {
            lifetime: Duration::from_secs(60),
            resources: HostResourceVector {
                resident_peak_bytes: 1024 * 1024,
                backing_peak_bytes: 1024 * 1024,
                metadata_bytes: 4096,
                staging_bytes: 128 * 1024,
                paging_io_slots: 1,
                cpu_slots: 1,
                task_slots: 1,
                file_descriptors: 36,
            },
        }
    }

    #[test]
    fn incomplete_service_capacity_refuses_before_namespace_io() {
        for field in 0..3 {
            let mut contract = config();
            match field {
                0 => contract.resources.file_descriptors = 35,
                1 => contract.resources.staging_bytes = 68 * 1024 - 1,
                _ => contract.resources.cpu_slots = 0,
            }
            assert!(matches!(
                LinuxProjectQuotaBinder::new(contract),
                Err(StoreError::Quota)
            ));
        }
    }

    #[test]
    fn cloned_binder_retains_original_cancellation_before_opening_a_root() {
        let binder = LinuxProjectQuotaBinder::new(config())
            .unwrap_or_else(|error| panic!("construct standalone admission: {error}"));
        let cloned = binder.clone();
        binder
            .service
            .supervisor
            .cancel()
            .unwrap_or_else(|error| panic!("cancel original service: {error}"));
        let error = cloned
            .bind(Path::new("/aos-quota-test-no-such-root"), 1, 4096, 16)
            .err()
            .unwrap_or_else(|| panic!("canceled service unexpectedly bound"));
        assert!(matches!(error, StoreError::Supervision { source }
            if source.downcast_ref::<HostSupervisionError>().is_some()));
    }

    #[test]
    fn descriptor_capacity_is_shared_and_reserved_before_quota_io() {
        let binder = LinuxProjectQuotaBinder::new(config())
            .unwrap_or_else(|error| panic!("construct standalone admission: {error}"));
        let held = binder
            .service
            .resources
            .reserve_resources(0, 36, 0)
            .unwrap_or_else(|error| panic!("retain namespace descriptor peak: {error}"));
        let error = binder
            .clone()
            .bind(Path::new("/aos-quota-test-no-such-root"), 1, 4096, 16)
            .err()
            .unwrap_or_else(|| panic!("exhausted service unexpectedly bound"));
        assert!(matches!(error, StoreError::Supervision { source }
            if source.downcast_ref::<HostServiceError>() == Some(&HostServiceError::CapacityExhausted)));
        drop(held);
        assert!(binder.service.resources.reserve_resources(0, 36, 0).is_ok());
    }

    #[test]
    fn metadata_loans_share_the_authored_subset_and_release_after_last_owner() {
        let binder = LinuxProjectQuotaBinder::new(config())
            .unwrap_or_else(|error| panic!("construct standalone admission: {error}"));
        let cloned = binder.clone();
        let held = Arc::new(
            binder
                .service
                .reserve_metadata(3000)
                .unwrap_or_else(|error| panic!("reserve retained metadata: {error}")),
        );
        let last_owner = held.clone();

        assert!(cloned.service.reserve_metadata(3000).is_err());
        drop(held);
        assert!(cloned.service.reserve_metadata(3000).is_err());
        drop(last_owner);
        assert!(cloned.service.reserve_metadata(3000).is_ok());
    }

    #[test]
    fn cancellation_refuses_retained_metadata_before_credit_creation() {
        let binder = LinuxProjectQuotaBinder::new(config())
            .unwrap_or_else(|error| panic!("construct standalone admission: {error}"));
        let original_cap = binder
            .service
            .supervisor
            .outer_cap_binding()
            .unwrap_or_else(|error| panic!("read original cap: {error}"));
        binder
            .service
            .supervisor
            .cancel()
            .unwrap_or_else(|error| panic!("cancel original service: {error}"));

        assert!(matches!(binder.service.reserve_metadata(1),
            Err(StoreError::Supervision { source })
                if source.downcast_ref::<HostSupervisionError>().is_some()));
        let final_cap = binder
            .service
            .supervisor
            .outer_cap_binding()
            .unwrap_or_else(|error| panic!("read canceled original cap: {error}"));
        assert_eq!(original_cap.cap_id, final_cap.cap_id);
        assert_eq!(
            original_cap.original_monotonic_ns,
            final_cap.original_monotonic_ns
        );
    }
}
