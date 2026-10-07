//! Admits persistent physical quota authority for a standalone campaign store.
//!
//! Operator-authored service capacity and one original supervisor cover
//! binding and later verification. Namespace guards retain their descriptor
//! leases, while one audit lock bounds temporary scan resources across callers.
//! Retained store handles and readers borrow the remaining descriptor capacity
//! and paired metadata/resident credits without releasing the pinned quota.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::provider_error_custody::{
    ProviderServiceAdmissionError, arc_allocation_bytes, check_provider_error_path,
    lease_control_bytes, provider_diagnostic_bytes, retain_provider_cause,
};
use crucible_cas::content_store::{StoreError, StorePhysicalQuotaBinder, StorePhysicalQuotaGuard};
use crucible_linux_resource::host_services::{HostServiceAllocator, HostServiceLease};
use crucible_linux_resource::host_supervision::{
    HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
};
use crucible_linux_resource::ram_policy::HostResourceVector;
use crucible_linux_resource::{LinuxProjectQuotaBinding, LinuxProjectQuotaError};

/// Operator-authored standalone service admission, independent of VM resources.
#[derive(Clone, Debug)]
pub struct CampaignQuotaServiceConfig {
    /// Original supervisor with the independently authored operation roster.
    ///
    /// Binding and every later check retain this exact cap, start and terminal
    /// state. Construction does not create or renew any class or outer deadline.
    pub supervisor: HostOperationSupervisor,
    /// Complete service entitlement, including audit scratch and caller overhead.
    ///
    /// CPU slots are nominal admission capacity; this adapter does not install
    /// a whole-host CPU bandwidth limit. The backing entitlement includes all
    /// distinct operator-installed physical project quotas being authenticated.
    pub resources: HostResourceVector,
}

impl CampaignQuotaServiceConfig {
    /// Starts the first original supervisor from an explicitly authored roster.
    ///
    /// This constructor is for storage-only callers that do not already own a
    /// supervisor. A caller with active original work supplies that existing
    /// supervisor directly instead of renewing its cap through this method.
    ///
    /// # Errors
    /// Refuses invalid or unbounded infrastructure budgets and invalid outer
    /// allowances. Complete resource capacity is checked by the binder before IO.
    pub fn from_authored_budgets(
        budgets: HostOperationBudgets,
        outer: Option<Duration>,
        resources: HostResourceVector,
    ) -> Result<Self, ProviderServiceAdmissionError> {
        budgets
            .validate(false)
            .map_err(ProviderServiceAdmissionError::from)?;
        Ok(Self {
            supervisor: HostOperationSupervisor::new(budgets, outer)
                .map_err(ProviderServiceAdmissionError::from)?,
            resources,
        })
    }
}

#[derive(Debug)]
struct QuotaService {
    supervisor: HostOperationSupervisor,
    resources: HostServiceAllocator,
    metadata: HostServiceAllocator,
    serial: Mutex<()>,
    projects: Mutex<ProjectAccounting>,
    diagnostic_occupied: AtomicBool,
    _caller: HostServiceLease,
    // The table, caller and service-owned material close before this paired credit.
    _project_metadata: QuotaMetadataCredit,
}

#[derive(Clone, Copy, Debug)]
struct ProjectCharge {
    identity: (u64, u32),
    bytes: u64,
    inodes: u64,
}

#[derive(Debug)]
struct ProjectAccounting {
    charges: Vec<ProjectCharge>,
    maximum_projects: usize,
    maximum_bytes: u64,
    used_bytes: u64,
}

impl ProjectAccounting {
    fn admit(&mut self, charge: ProjectCharge) -> Result<(), StoreError> {
        if let Some(existing) = self
            .charges
            .iter()
            .find(|existing| existing.identity == charge.identity)
        {
            return if existing.bytes == charge.bytes && existing.inodes == charge.inodes {
                Ok(())
            } else {
                Err(StoreError::Quota)
            };
        }
        let used = self
            .used_bytes
            .checked_add(charge.bytes)
            .ok_or(StoreError::Quota)?;
        if used > self.maximum_bytes || self.charges.len() >= self.maximum_projects {
            return Err(StoreError::Quota);
        }
        self.charges.push(charge);
        self.used_bytes = used;
        Ok(())
    }
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
    root: std::path::PathBuf,
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
    /// Clones share capacity, the authored roster and original outer cap.
    /// Serialized audit scratch comes from the authored staging subset.
    ///
    /// # Errors
    /// Refuses an invalid original roster, insufficient complete resource
    /// entitlement, audit capacity, or unavailable supervision authority.
    pub fn new(config: CampaignQuotaServiceConfig) -> Result<Self, ProviderServiceAdmissionError> {
        config
            .supervisor
            .budgets()
            .map_err(ProviderServiceAdmissionError::from)?
            .1
            .validate(false)
            .map_err(ProviderServiceAdmissionError::from)?;
        let preparation = config
            .supervisor
            .begin(HostOperationClass::Preparation)
            .map_err(ProviderServiceAdmissionError::from)?;
        preparation
            .wait_slice()
            .map_err(ProviderServiceAdmissionError::from)?;
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
            return Err(StoreError::Quota.into());
        }
        let resources = HostServiceAllocator::new(
            admitted.task_slots,
            admitted.file_descriptors,
            admitted.resident_peak_bytes,
        )
        .map_err(ProviderServiceAdmissionError::from)?;
        let metadata = HostServiceAllocator::new(1, 1, admitted.metadata_bytes)
            .map_err(ProviderServiceAdmissionError::from)?;
        let maximum_projects =
            usize::try_from(admitted.file_descriptors / 2).map_err(|_| StoreError::Quota)?;
        let constructor_bytes = quota_constructor_bytes(maximum_projects)?;
        // Prepay covered allocations in the two original accounts; the first
        // allocator/supervisor bootstrap controls remain a separate prerequisite.
        let (metadata_credit, resident_credit) =
            metadata.reserve_paired_bytes(&resources, constructor_bytes)?;
        let project_metadata = QuotaMetadataCredit {
            _resident: resident_credit,
            _metadata: metadata_credit,
        };
        let caller = resources
            .reserve_resources(1, 0, admitted.resident_peak_bytes - admitted.metadata_bytes)
            .map_err(ProviderServiceAdmissionError::from)?;
        let mut charges = Vec::new();
        charges
            .try_reserve_exact(maximum_projects)
            .map_err(|_| StoreError::Quota)?;
        preparation
            .complete()
            .map_err(ProviderServiceAdmissionError::from)?;
        Ok(Self {
            service: Arc::new(QuotaService {
                supervisor: config.supervisor,
                resources,
                metadata,
                serial: Mutex::new(()),
                projects: Mutex::new(ProjectAccounting {
                    charges,
                    maximum_projects,
                    maximum_bytes: admitted.backing_peak_bytes,
                    used_bytes: 0,
                }),
                diagnostic_occupied: AtomicBool::new(false),
                _project_metadata: project_metadata,
                _caller: caller,
            }),
        })
    }
}

fn quota_constructor_bytes(maximum_projects: usize) -> Result<u64, StoreError> {
    let mut bytes = maximum_projects
        .checked_mul(std::mem::size_of::<ProjectCharge>())
        .ok_or(StoreError::Quota)?;
    for extent in [
        arc_allocation_bytes::<QuotaService>()?,
        std::mem::size_of::<LinuxProjectQuotaBinder>(),
        lease_control_bytes()?
            .checked_mul(3)
            .ok_or(StoreError::Quota)?,
        usize::try_from(provider_diagnostic_bytes()).map_err(|_| StoreError::Quota)?,
    ] {
        bytes = bytes.checked_add(extent).ok_or(StoreError::Quota)?;
    }
    u64::try_from(bytes).map_err(|_| StoreError::Quota)
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
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<std::path::PathBuf>()))
            .ok_or(StoreError::Quota)?
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
        let mut admitted = false;
        let binding = LinuxProjectQuotaBinding::bind_existing_admitted(
            root,
            project_id,
            maximum_physical_bytes,
            maximum_inodes,
            self.service.supervisor.clone(),
            &mut |identity| {
                self.service
                    .projects
                    .lock()
                    .map_err(|_| LinuxProjectQuotaError::InvalidLimits)?
                    .admit(ProjectCharge {
                        identity,
                        bytes: maximum_physical_bytes,
                        inodes: maximum_inodes,
                    })
                    .map_err(|_| LinuxProjectQuotaError::InvalidLimits)?;
                admitted = true;
                Ok(())
            },
        );
        let binding = match binding {
            Ok(binding) => binding,
            Err(error) => {
                if admitted {
                    // The lower binder may have created a lease or retained a
                    // pin. Preserve exactly the receipts admitted before that
                    // effect; a failed return is not namespace deletion proof.
                    std::mem::forget((descriptors, metadata, self.service.clone()));
                }
                return Err(store_error(error));
            }
        };
        let authority = Arc::new(QuotaAuthority {
            binding,
            root: root.to_path_buf(),
            service: self.service.clone(),
            _descriptors: descriptors,
            _metadata: metadata,
        });
        // Closing local handles proves no deletion of an existing namespace.
        // Retain the original pins and complete account until authenticated
        // operator retirement exists; never recycle a project by integer ID.
        std::mem::forget(Arc::clone(&authority));
        Ok(Arc::new(BoundLinuxProjectQuota { authority }))
    }
}

impl crucible_cas::content_store::ProviderDiagnosticStorage for BoundLinuxProjectQuota {
    fn try_occupy(&self) -> Result<(), StoreError> {
        self.authority
            .service
            .diagnostic_occupied
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| StoreError::Unavailable)
    }

    fn release(&self) {
        self.authority
            .service
            .diagnostic_occupied
            .store(false, Ordering::Release);
    }
}

impl StorePhysicalQuotaGuard for BoundLinuxProjectQuota {
    fn begin_provider_diagnostic(
        self: Arc<Self>,
    ) -> Result<crucible_cas::content_store::ProviderDiagnosticPermit, StoreError> {
        check_provider_error_path(&self.authority.root)?;
        let permit = crucible_cas::content_store::ProviderDiagnosticPermit::checkout(self.clone())?;
        let _serial = self
            .authority
            .service
            .serial
            .try_lock()
            .map_err(|_| StoreError::Unauthorized)?;
        if let Err(source) = self.authority.binding.verify() {
            return Err(retain_provider_cause(permit, source.into()));
        }
        Ok(permit)
    }

    fn gc_mark_backend(
        self: Arc<Self>,
        scope: &str,
    ) -> Result<Arc<dyn crucible_cas::content_store::ImmutableBlobBackend>, StoreError> {
        if scope.is_empty() || scope.len() > 256 || scope.chars().any(char::is_control) {
            return Err(StoreError::InvalidComposition {
                reason: "GC mark scope is empty, unbounded or contains control characters",
            });
        }
        let operation = self
            .authority
            .service
            .supervisor
            .begin(HostOperationClass::Writeback)
            .map_err(supervision_error)?;
        self.verify()?;
        // A digest names one isolated mark namespace without accepting caller
        // path components. All durable bytes inherit this same physical quota.
        let path_bytes = self
            .authority
            .root
            .as_os_str()
            .len()
            .checked_add(96)
            .and_then(|bytes| bytes.checked_mul(4))
            .ok_or(StoreError::Quota)?;
        let _scratch = self.reserve_resources(0, path_bytes as u64)?;
        let mut digest = blake3::Hasher::new();
        digest.update(b"crucible.campaign-gc.mark-namespace.v1\0");
        digest.update(scope.as_bytes());
        let directory = self
            .authority
            .root
            .join(".gc-marks")
            .join(digest.finalize().to_hex().as_str());
        {
            // Descendant creation borrows the same bounded audit descriptor
            // roster as quota verification, so it cannot overlap another scan.
            let _serial = self
                .authority
                .service
                .serial
                .try_lock()
                .map_err(|_| StoreError::Unauthorized)?;
            self.authority
                .binding
                .prepare_descendant_directory(&directory)
                .map_err(store_error)?;
        }
        let guard: Arc<dyn StorePhysicalQuotaGuard> = self.clone();
        let marks = crucible_cas::content_store::DirectoryBlobBackend::new_with_physical_quota(
            "campaign-gc-marks",
            directory,
            guard,
        )?;
        operation.complete().map_err(supervision_error)?;
        Ok(marks)
    }

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
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, StoreError> {
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
        Ok(crucible_cas::owned_decode::ResourceLoan::new(
            QuotaResourceCredit {
                _authority: self.authority.clone(),
                _descriptors: descriptors,
                _metadata: metadata,
            },
        ))
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
    use crate::provider_error_custody::provider_diagnostic_bytes;
    use crucible_linux_resource::host_services::HostServiceError;
    use crucible_linux_resource::host_supervision::HostSupervisionError;
    use crucible_linux_resource::host_supervision::{HostOperationBudget, HostOperationBudgets};
    use std::time::Duration;

    fn config() -> CampaignQuotaServiceConfig {
        CampaignQuotaServiceConfig {
            supervisor: HostOperationSupervisor::new(
                HostOperationBudgets {
                    classes: [HostOperationBudget::finite(Duration::from_secs(60));
                        crucible_linux_resource::host_supervision::HOST_OPERATION_CLASS_COUNT],
                },
                Some(Duration::from_secs(60)),
            )
            .unwrap_or_else(|error| panic!("authored finite fixture roster: {error}")),
            resources: HostResourceVector {
                resident_peak_bytes: 1024 * 1024,
                backing_peak_bytes: 1024 * 1024,
                // The original component account also funds its one exclusive
                // diagnostic slot before admitting the project roster.
                metadata_bytes: 4096 + provider_diagnostic_bytes(),
                staging_bytes: 128 * 1024,
                paging_io_slots: 1,
                cpu_slots: 1,
                task_slots: 1,
                file_descriptors: 36,
            },
        }
    }

    #[test]
    fn constructor_funds_complete_inline_geometry_until_last_service_owner() {
        let mut contract = config();
        let maximum_projects = usize::try_from(contract.resources.file_descriptors / 2)
            .unwrap_or_else(|error| panic!("fixture project count: {error}"));
        let bytes = quota_constructor_bytes(maximum_projects)
            .unwrap_or_else(|error| panic!("complete constructor geometry: {error}"));
        contract.resources.metadata_bytes = bytes;
        let binder = LinuxProjectQuotaBinder::new(contract)
            .unwrap_or_else(|error| panic!("exact constructor capacity: {error}"));
        let last_owner = binder.clone();
        let weak = Arc::downgrade(&binder.service);

        let capacity = binder
            .service
            .projects
            .lock()
            .map(|table| table.charges.capacity())
            .unwrap_or_else(|error| panic!("original project table: {error}"));
        assert_eq!(capacity, maximum_projects);
        assert!(binder.service.metadata.reserve_resources(0, 0, 1).is_err());
        eprintln!(
            "quota constructor: service={} arc={} binder={} project={} table={} controls={} diagnostic={} paired={bytes}",
            std::mem::size_of::<QuotaService>(),
            arc_allocation_bytes::<QuotaService>()
                .unwrap_or_else(|error| panic!("Arc geometry: {error}")),
            std::mem::size_of::<LinuxProjectQuotaBinder>(),
            std::mem::size_of::<ProjectCharge>(),
            maximum_projects * std::mem::size_of::<ProjectCharge>(),
            3 * lease_control_bytes().unwrap_or_else(|error| panic!("control geometry: {error}")),
            provider_diagnostic_bytes()
        );

        drop(binder);
        assert!(weak.upgrade().is_some());
        drop(last_owner);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn distinct_project_limits_share_only_an_exact_pinned_quota_identity() {
        let mut accounting = ProjectAccounting {
            charges: Vec::with_capacity(2),
            maximum_projects: 2,
            maximum_bytes: 512,
            used_bytes: 0,
        };
        let first = ProjectCharge {
            identity: (1, 10),
            bytes: 256,
            inodes: 16,
        };
        assert!(accounting.admit(first).is_ok());
        assert!(accounting.admit(first).is_ok());
        assert_eq!(accounting.used_bytes, 256);
        assert_eq!(accounting.charges.len(), 1);

        assert!(
            accounting
                .admit(ProjectCharge {
                    inodes: 17,
                    ..first
                })
                .is_err()
        );
        assert!(
            accounting
                .admit(ProjectCharge {
                    bytes: 257,
                    ..first
                })
                .is_err()
        );
        assert_eq!(accounting.used_bytes, 256);

        // Identical project integers on another pinned filesystem are distinct.
        assert!(
            accounting
                .admit(ProjectCharge {
                    identity: (2, 10),
                    ..first
                })
                .is_ok()
        );
        assert_eq!(accounting.used_bytes, 512);
        assert!(
            accounting
                .admit(ProjectCharge {
                    identity: (1, 11),
                    ..first
                })
                .is_err()
        );
        assert_eq!(accounting.used_bytes, 512);
        assert_eq!(accounting.charges.len(), 2);
    }

    #[test]
    fn supplied_supervisor_keeps_its_original_outer_anchor() {
        let contract = config();
        let original = contract
            .supervisor
            .outer_cap_binding()
            .unwrap_or_else(|error| panic!("fixture original cap: {error}"));
        let binder = LinuxProjectQuotaBinder::new(contract)
            .unwrap_or_else(|error| panic!("standalone original admission: {error}"));
        let retained = binder
            .service
            .supervisor
            .outer_cap_binding()
            .unwrap_or_else(|error| panic!("retained original cap: {error}"));
        assert_eq!(retained.cap_id, original.cap_id);
        assert_eq!(
            retained.original_monotonic_ns,
            original.original_monotonic_ns
        );
        assert_eq!(retained.allowance, original.allowance);
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
                Err(ProviderServiceAdmissionError::Store(StoreError::Quota))
            ));
        }
    }

    #[test]
    fn canceled_bootstrap_returns_inline_original_supervision_before_slot_allocation() {
        let contract = config();
        contract
            .supervisor
            .cancel()
            .unwrap_or_else(|error| panic!("cancel original roster: {error}"));

        let error = LinuxProjectQuotaBinder::new(contract)
            .err()
            .unwrap_or_else(|| panic!("canceled original service admitted"));

        assert!(matches!(
            error,
            ProviderServiceAdmissionError::Supervision(HostSupervisionError::Terminal { .. })
        ));
    }

    #[test]
    fn initial_slot_refusal_keeps_original_allocator_failure_inline() {
        let mut contract = config();
        contract.resources.metadata_bytes = provider_diagnostic_bytes() - 1;

        assert!(matches!(
            LinuxProjectQuotaBinder::new(contract),
            Err(ProviderServiceAdmissionError::Resources(
                HostServiceError::CapacityExhausted
            ))
        ));
    }

    #[test]
    fn original_supervisor_constructor_refusals_remain_inline_before_service_creation() {
        for (duration, outer) in [
            (Duration::ZERO, None),
            (Duration::from_secs(60), Some(Duration::ZERO)),
        ] {
            let budgets = HostOperationBudgets {
                classes: [HostOperationBudget::finite(duration);
                    crucible_linux_resource::host_supervision::HOST_OPERATION_CLASS_COUNT],
            };

            assert!(matches!(
                CampaignQuotaServiceConfig::from_authored_budgets(
                    budgets,
                    outer,
                    config().resources
                ),
                Err(ProviderServiceAdmissionError::Supervision(
                    HostSupervisionError::InvalidBudget
                ))
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
