//! Admits persistent physical quota authority for a standalone campaign store.
//!
//! Operator-authored service capacity and one original supervisor cover
//! binding and later verification. Namespace guards retain their descriptor
//! leases, while one audit lock bounds temporary scan resources across callers.
//! Retained store handles and readers borrow the remaining descriptor capacity
//! and paired metadata/resident credits without releasing the pinned quota.

mod archive;
pub use archive::CampaignArchiveNamespace;

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::provider_error_custody::{
    ProviderCause, ProviderServiceAdmissionError, arc_allocation_bytes, check_provider_error_path,
    lease_control_bytes, provider_diagnostic_bytes, retain_provider_cause,
};
use crucible_cas::content_store::{
    StoreError, StorePhysicalQuotaBinder, StorePhysicalQuotaBinderHandle, StorePhysicalQuotaGuard,
};
use crucible_linux_resource::host_services::{
    HostServiceAllocator, HostServiceBootstrap, HostServiceLease,
};
use crucible_linux_resource::host_supervision::{
    HostOperationBudgets, HostOperationClass, HostOperationGuard, HostOperationSupervisor,
    HostSupervisionBootstrap,
};
use crucible_linux_resource::ram_policy::HostResourceVector;
use crucible_linux_resource::{LinuxProjectQuotaBinding, LinuxProjectQuotaError};

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

/// Consumes every private service alias before releasing its original accounts.
#[derive(Debug)]
struct QuotaServiceOwner {
    value: Option<Arc<QuotaService>>,
}

impl QuotaServiceOwner {
    fn new(value: QuotaService) -> Self {
        Self {
            value: Some(Arc::new(value)),
        }
    }
}

impl Clone for QuotaServiceOwner {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
        }
    }
}

impl std::ops::Deref for QuotaServiceOwner {
    type Target = QuotaService;

    fn deref(&self) -> &Self::Target {
        match &self.value {
            Some(value) => value,
            None => unreachable!("a live service owner retains its original value"),
        }
    }
}

impl Drop for QuotaServiceOwner {
    fn drop(&mut self) {
        if let Some(value) = self.value.take() {
            // All aliases are private and use this terminal close. The final
            // control closes before its value releases supervision or credit.
            drop(Arc::into_inner(value));
        }
    }
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
    service: QuotaServiceOwner,
}

#[derive(Debug)]
struct BoundLinuxProjectQuota {
    authority: Arc<QuotaAuthority>,
}

#[derive(Debug)]
struct QuotaAuthority {
    binding: LinuxProjectQuotaBinding,
    root: std::path::PathBuf,
    service: QuotaServiceOwner,
    _descriptors: HostServiceLease,
    _metadata: QuotaMetadataCredit,
}

#[derive(Debug)]
struct QuotaMetadataCredit {
    // Neither half is exposed or cloned; only complete enclosing owners share
    // this custody. Their two controls close before either bank can refund.
    pair: Option<(HostServiceLease, HostServiceLease)>,
}

impl QuotaMetadataCredit {
    fn new(resident: HostServiceLease, metadata: HostServiceLease) -> Self {
        Self {
            pair: Some((resident, metadata)),
        }
    }
}

impl Drop for QuotaMetadataCredit {
    fn drop(&mut self) {
        if let Some((resident, metadata)) = self.pair.take() {
            HostServiceLease::close_pair(resident, metadata);
        }
    }
}

struct QuotaResourceCredit {
    // Authority closes the real root descriptors before these credits expire.
    _authority: Arc<QuotaAuthority>,
    _descriptors: Option<HostServiceLease>,
    _metadata: QuotaMetadataCredit,
}

struct MemoryNamespaceCredit {
    // ResourceLoan consumes its shared control before this original service
    // and private paired grants close. No disk authority is manufactured.
    _service: QuotaServiceOwner,
    _credit: QuotaMetadataCredit,
}

// This storage is constructed only on failure after stack checkout of the
// original slot. Its Arc has one alias owned by one diagnostic permit. Neither
// the concrete storage nor an Arc/Weak to it is exposed or cloned.
struct MemoryDiagnosticStorage {
    service: QuotaServiceOwner,
}

impl crucible_cas::content_store::ProviderDiagnosticStorage for MemoryDiagnosticStorage {
    fn try_occupy(&self) -> Result<(), StoreError> {
        // Occupancy moved here from the private stack owner; checkout adds no
        // second grant and cannot race another checkout of this same service.
        Ok(())
    }

    fn release(&self) {
        self.service
            .diagnostic_occupied
            .store(false, Ordering::Release);
    }

    fn close(self: Arc<Self>) {
        drop(Arc::into_inner(self));
    }
}

impl Drop for MemoryDiagnosticStorage {
    fn drop(&mut self) {
        // The consuming close has already freed this exclusive Arc control.
        // Retain the original service during slot release, then close it.
        crucible_cas::content_store::ProviderDiagnosticStorage::release(self);
    }
}

struct MemoryDiagnosticCheckout<'a> {
    service: &'a QuotaServiceOwner,
    occupied: bool,
}

impl<'a> MemoryDiagnosticCheckout<'a> {
    fn new(service: &'a QuotaServiceOwner) -> Result<Self, StoreError> {
        service
            .diagnostic_occupied
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| StoreError::Unavailable)?;
        Ok(Self {
            service,
            occupied: true,
        })
    }

    fn retain(mut self, cause: ProviderCause) -> StoreError {
        let storage = Arc::new(MemoryDiagnosticStorage {
            service: self.service.clone(),
        });
        self.occupied = false;
        match crucible_cas::content_store::ProviderDiagnosticPermit::checkout(storage) {
            Ok(permit) => retain_provider_cause(permit, cause),
            // The private storage above always accepts its transferred slot.
            // Fail closed if that contract changes; never fabricate a permit.
            Err(error) => error,
        }
    }
}

impl Drop for MemoryDiagnosticCheckout<'_> {
    fn drop(&mut self) {
        if self.occupied {
            self.service
                .diagnostic_occupied
                .store(false, Ordering::Release);
        }
    }
}

#[derive(Clone, Copy)]
enum BinderPublication {
    Value,
    Graph,
}

// The preparation and all supervisor aliases close before either original
// capacity on every fallible constructor return and valid unwind.
struct QuotaServiceConstruction {
    archive_operation: Option<HostOperationGuard>,
    preparation: HostOperationGuard,
    supervisor: HostOperationSupervisor,
    resources: HostServiceAllocator,
    metadata: HostServiceAllocator,
}

// The guard closes before the prepaid original service on early return.
struct QuotaServiceAdmission {
    archive_operation: Option<HostOperationGuard>,
    binder: LinuxProjectQuotaBinder,
}

impl LinuxProjectQuotaBinder {
    /// Starts the first original standalone quota service before namespace I/O.
    ///
    /// The finite authored roster starts once. Both original resource accounts
    /// prepay supervision controls and bounded reports before their first heap
    /// publication. Caller, table and service controls then borrow the same
    /// accounts; clones share their original cap and sticky terminal state.
    ///
    /// # Errors
    /// Refuses an invalid roster, insufficient authored service capacity, or an
    /// original preparation deadline without renewing its start or policy.
    pub fn new(
        budgets: HostOperationBudgets,
        outer: Option<Duration>,
        admitted: HostResourceVector,
    ) -> Result<Self, ProviderServiceAdmissionError> {
        Self::construct(budgets, outer, admitted, BinderPublication::Value)
    }

    /// Publishes a fresh quota binder in its prepaid opaque graph control.
    ///
    /// The original constructor already pays the binder value. This path adds
    /// only its aligned control header and retains the same service/account
    /// ancestors until the last graph alias closes that control.
    ///
    /// # Errors
    /// Returns the original fresh-service admission or supervision refusal.
    pub fn new_for_graph(
        budgets: HostOperationBudgets,
        outer: Option<Duration>,
        admitted: HostResourceVector,
    ) -> Result<StorePhysicalQuotaBinderHandle, ProviderServiceAdmissionError> {
        let binder = Self::construct(budgets, outer, admitted, BinderPublication::Graph)?;
        Ok(StorePhysicalQuotaBinderHandle::new(binder))
    }

    fn memory_namespace_call<T>(
        &self,
        work: impl FnOnce(&QuotaService) -> Result<T, ProviderCause>,
    ) -> Result<T, StoreError> {
        let diagnostic = MemoryDiagnosticCheckout::new(&self.service)?;
        match work(&self.service) {
            Ok(value) => Ok(value),
            Err(cause) => Err(diagnostic.retain(cause)),
        }
    }

    fn construct(
        budgets: HostOperationBudgets,
        outer: Option<Duration>,
        admitted: HostResourceVector,
        publication: BinderPublication,
    ) -> Result<Self, ProviderServiceAdmissionError> {
        Self::construct_with_operation(budgets, outer, admitted, publication, None)
            .map(|admission| admission.binder)
    }

    pub(crate) fn for_archive(
        class: HostOperationClass,
        budgets: HostOperationBudgets,
        lifetime: Duration,
        admitted: HostResourceVector,
    ) -> Result<
        crate::campaign_store_composition::CampaignArchiveHostOperation,
        ProviderServiceAdmissionError,
    > {
        let mut admission = Self::construct_with_operation(
            budgets,
            Some(lifetime),
            admitted,
            BinderPublication::Value,
            Some(class),
        )?;
        let operation =
            admission
                .archive_operation
                .take()
                .ok_or(StoreError::InvalidComposition {
                    reason: "admitted archive service has no original operation",
                })?;
        let supervisor = admission.binder.service.supervisor.clone();
        Ok(
            crate::campaign_store_composition::CampaignArchiveHostOperation::from_admitted_quota(
                operation,
                supervisor,
                admission.binder,
            ),
        )
    }

    fn construct_with_operation(
        budgets: HostOperationBudgets,
        outer: Option<Duration>,
        admitted: HostResourceVector,
        publication: BinderPublication,
        archive_class: Option<HostOperationClass>,
    ) -> Result<QuotaServiceAdmission, ProviderServiceAdmissionError> {
        let mut original = HostSupervisionBootstrap::new(budgets, outer)?;
        original.wait_slice()?;
        validate_quota_resources(admitted)?;
        let accounts = HostServiceBootstrap::new(
            admitted.task_slots,
            admitted.file_descriptors,
            admitted.resident_peak_bytes,
            admitted.metadata_bytes,
        )?
        .reserve_structure(quota_bootstrap_bytes(publication)?)?;
        let (supervisor, preparation) = original.publish(&accounts)?;
        // Both charged values remain original ancestors during these fixed,
        // infallible moves. Allocation failure aborts; no user callback or
        // recoverable validation can interrupt the two-control publication.
        let (resources, metadata) = accounts.publish();
        let mut construction = QuotaServiceConstruction {
            archive_operation: None,
            preparation,
            supervisor,
            resources,
            metadata,
        };
        // The original cap already includes constructor time. The archive
        // record starts before fallible service admission or namespace effects.
        if let Some(class) = archive_class {
            construction.archive_operation = Some(construction.supervisor.begin(class)?);
        }

        Self::finish(construction, admitted)
    }

    /// Shares an existing finite supervisor with a native inspection fixture.
    ///
    /// The caller retains its original inspection operation. This constructor
    /// begins preparation on that same supervisor and preserves its origin,
    /// identities and sticky state. Its caller owns supervision allocations;
    /// only the two new capacity controls are prepaid here.
    ///
    /// # Errors
    /// Refuses the original roster, preparation boundary or resource capacity.
    #[cfg(feature = "test-support")]
    pub fn for_inspection(
        supervisor: HostOperationSupervisor,
        admitted: HostResourceVector,
    ) -> Result<Self, ProviderServiceAdmissionError> {
        supervisor.budgets()?.1.validate(false)?;
        let preparation = supervisor.begin(HostOperationClass::Preparation)?;
        preparation.wait_slice()?;
        validate_quota_resources(admitted)?;

        let accounts = HostServiceBootstrap::new(
            admitted.task_slots,
            admitted.file_descriptors,
            admitted.resident_peak_bytes,
            admitted.metadata_bytes,
        )?
        .reserve_structure(HostServiceBootstrap::control_bytes()?)?;
        let (resources, metadata) = accounts.publish();
        Self::finish(
            QuotaServiceConstruction {
                archive_operation: None,
                preparation,
                supervisor,
                resources,
                metadata,
            },
            admitted,
        )
        .map(|admission| admission.binder)
    }

    fn finish(
        mut construction: QuotaServiceConstruction,
        admitted: HostResourceVector,
    ) -> Result<QuotaServiceAdmission, ProviderServiceAdmissionError> {
        let maximum_projects =
            usize::try_from(admitted.file_descriptors / 2).map_err(|_| StoreError::Quota)?;
        let constructor_bytes = quota_constructor_bytes(maximum_projects)?;
        let (metadata_credit, resident_credit) = construction
            .metadata
            .reserve_paired_bytes(&construction.resources, constructor_bytes)?;
        let project_metadata = QuotaMetadataCredit::new(resident_credit, metadata_credit);
        let caller = construction.resources.reserve_resources(
            1,
            0,
            admitted.resident_peak_bytes - admitted.metadata_bytes,
        )?;
        let mut charges = Vec::new();
        charges
            .try_reserve_exact(maximum_projects)
            .map_err(|_| StoreError::Quota)?;
        construction.preparation.complete()?;
        let archive_operation = construction.archive_operation.take();
        let binder = Self {
            service: QuotaServiceOwner::new(QuotaService {
                supervisor: construction.supervisor,
                resources: construction.resources,
                metadata: construction.metadata,
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
        };
        Ok(QuotaServiceAdmission {
            archive_operation,
            binder,
        })
    }
}

fn validate_quota_resources(admitted: HostResourceVector) -> Result<(), StoreError> {
    let subsets = admitted
        .metadata_bytes
        .checked_add(admitted.staging_bytes)
        .ok_or(StoreError::Quota)?;
    if admitted.cpu_slots == 0
        || admitted.task_slots == 0
        || admitted.paging_io_slots == 0
        || admitted.file_descriptors < LinuxProjectQuotaBinding::maximum_audit_file_descriptors()
        || admitted.staging_bytes < LinuxProjectQuotaBinding::maximum_audit_scratch_bytes()
        || subsets >= admitted.resident_peak_bytes
        || subsets > admitted.backing_peak_bytes
    {
        return Err(StoreError::Quota);
    }
    Ok(())
}

fn quota_bootstrap_bytes(
    publication: BinderPublication,
) -> Result<u64, ProviderServiceAdmissionError> {
    let bytes = HostSupervisionBootstrap::structure_bytes()?
        .checked_add(HostServiceBootstrap::control_bytes()?)
        .ok_or(StoreError::Quota)?;
    let extra = match publication {
        BinderPublication::Value => 0,
        BinderPublication::Graph => {
            StorePhysicalQuotaBinderHandle::allocation_bytes::<LinuxProjectQuotaBinder>()?
                .checked_sub(std::mem::size_of::<LinuxProjectQuotaBinder>())
                .ok_or(StoreError::Quota)?
        }
    };
    bytes
        .checked_add(u64::try_from(extra).map_err(|_| StoreError::Quota)?)
        .ok_or_else(|| StoreError::Quota.into())
}

fn quota_constructor_bytes(maximum_projects: usize) -> Result<u64, StoreError> {
    let mut bytes = maximum_projects
        .checked_mul(std::mem::size_of::<ProjectCharge>())
        .ok_or(StoreError::Quota)?;
    for extent in [
        arc_allocation_bytes::<QuotaService>()?,
        arc_allocation_bytes::<MemoryDiagnosticStorage>()?,
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
    fn reserve_memory_namespace(
        &self,
        bytes: u64,
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, StoreError> {
        if bytes == 0 {
            return Err(StoreError::Quota);
        }
        let controls = u64::try_from(lease_control_bytes()?)
            .map_err(|_| StoreError::Quota)?
            .checked_mul(2)
            .ok_or(StoreError::Quota)?;
        let charged = bytes
            .checked_add(
                crucible_cas::owned_decode::ResourceLoan::allocation_bytes::<MemoryNamespaceCredit>(
                ),
            )
            .and_then(|charged| charged.checked_add(controls))
            .ok_or(StoreError::Quota)?;
        self.memory_namespace_call(|service| {
            let operation = service.supervisor.begin(HostOperationClass::Preparation)?;
            operation.wait_slice()?;
            service.verify_memory_original()?;
            // Both original accounts grant all material before either lease
            // control or ResourceLoan control. No disk root is authenticated.
            let (metadata, resident) = service
                .metadata
                .reserve_paired_bytes(&service.resources, charged)?;
            let credit = QuotaMetadataCredit::new(resident, metadata);
            operation.wait_slice()?;
            let loan = crucible_cas::owned_decode::ResourceLoan::new(MemoryNamespaceCredit {
                _service: self.service.clone(),
                _credit: credit,
            });
            operation.complete()?;
            service.verify_memory_original()?;
            Ok(loan)
        })
    }

    fn verify_memory_namespace(&self) -> Result<(), StoreError> {
        self.memory_namespace_call(QuotaService::verify_memory_original)
    }

    fn bind(
        &self,
        root: &Path,
        project_id: u32,
        maximum_physical_bytes: u64,
        maximum_inodes: u64,
    ) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        self.bind_guard(root, project_id, maximum_physical_bytes, maximum_inodes)
            .map(|guard| guard as Arc<dyn StorePhysicalQuotaGuard>)
    }
}

impl LinuxProjectQuotaBinder {
    fn bind_guard(
        &self,
        root: &Path,
        project_id: u32,
        maximum_physical_bytes: u64,
        maximum_inodes: u64,
    ) -> Result<Arc<BoundLinuxProjectQuota>, StoreError> {
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
    fn verify_memory_original(&self) -> Result<(), ProviderCause> {
        self.supervisor.verify_original_live()?;
        self.resources.verify_live()?;
        self.metadata.verify_live()?;
        Ok(())
    }

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
        Ok(QuotaMetadataCredit::new(resident, metadata))
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

    mod archive_original;
    mod memory_namespace;
    mod terminal_control;

    struct Config {
        budgets: HostOperationBudgets,
        outer: Option<Duration>,
        resources: HostResourceVector,
    }

    impl Config {
        fn build(self) -> Result<LinuxProjectQuotaBinder, ProviderServiceAdmissionError> {
            LinuxProjectQuotaBinder::new(self.budgets, self.outer, self.resources)
        }
    }

    fn config() -> Config {
        Config {
            budgets: HostOperationBudgets {
                classes: [HostOperationBudget::finite(Duration::from_secs(60));
                    crucible_linux_resource::host_supervision::HOST_OPERATION_CLASS_COUNT],
            },
            outer: Some(Duration::from_secs(60)),
            resources: HostResourceVector {
                resident_peak_bytes: 1024 * 1024,
                backing_peak_bytes: 1024 * 1024,
                // Preserve the prior loan allowance while explicitly authoring
                // the newly covered structural peak in this fixture.
                metadata_bytes: 4096
                    + provider_diagnostic_bytes()
                    + quota_bootstrap_bytes(BinderPublication::Value)
                        .unwrap_or_else(|error| panic!("fixture structure: {error}")),
                staging_bytes: 128 * 1024,
                paging_io_slots: 1,
                cpu_slots: 1,
                task_slots: 1,
                file_descriptors: 36,
            },
        }
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn inspection_retains_existing_writeback_and_original_supervisor() {
        let authored = config();
        let supervisor = HostOperationSupervisor::new(authored.budgets, authored.outer)
            .unwrap_or_else(|error| panic!("original inspection supervisor: {error}"));
        let binding = supervisor
            .outer_cap_binding()
            .unwrap_or_else(|error| panic!("original inspection origin: {error}"));
        let operation = supervisor
            .begin(HostOperationClass::Writeback)
            .unwrap_or_else(|error| panic!("original inspection operation: {error}"));
        let original_id = operation
            .status()
            .unwrap_or_else(|error| panic!("original inspection identity: {error}"))
            .operation_id;
        let binder =
            LinuxProjectQuotaBinder::for_inspection(supervisor.clone(), authored.resources)
                .unwrap_or_else(|error| panic!("shared original inspection admission: {error}"));

        assert_eq!(binder.service.supervisor, supervisor);
        assert_eq!(
            binder
                .service
                .supervisor
                .outer_cap_binding()
                .unwrap_or_else(|error| panic!("retained inspection origin: {error}")),
            binding
        );
        assert_eq!(
            operation
                .status()
                .unwrap_or_else(|error| panic!("retained inspection identity: {error}"))
                .operation_id,
            original_id
        );
        assert!(operation.wait_slice().is_ok());
        supervisor
            .cancel()
            .unwrap_or_else(|error| panic!("original inspection cancellation: {error}"));
        assert!(operation.wait_slice().is_err());
        assert!(
            binder
                .service
                .supervisor
                .begin(HostOperationClass::Writeback)
                .is_err()
        );
    }

    #[test]
    fn terminal_service_and_binder_geometry_matches_existing_controls() {
        use crucible_cas::content_store::StorePhysicalQuotaBinderHandle;

        assert_eq!(
            std::mem::size_of::<QuotaServiceOwner>(),
            std::mem::size_of::<Arc<QuotaService>>()
        );
        assert_eq!(
            std::mem::size_of::<LinuxProjectQuotaBinder>(),
            std::mem::size_of::<QuotaServiceOwner>()
        );
        assert_eq!(
            std::mem::size_of::<StorePhysicalQuotaBinderHandle>(),
            std::mem::size_of::<Arc<dyn StorePhysicalQuotaBinder>>()
        );
        eprintln!(
            "service_value={} service_control={} service_owner={} binder_value={} binder_control={} opaque_binder={} optional_opaque_binder={} ordinary_optional_binder={} project_value={}",
            std::mem::size_of::<QuotaService>(),
            arc_allocation_bytes::<QuotaService>()
                .unwrap_or_else(|error| panic!("service control: {error}")),
            std::mem::size_of::<QuotaServiceOwner>(),
            std::mem::size_of::<LinuxProjectQuotaBinder>(),
            StorePhysicalQuotaBinderHandle::allocation_bytes::<LinuxProjectQuotaBinder>()
                .unwrap_or_else(|error| panic!("binder control: {error}")),
            std::mem::size_of::<StorePhysicalQuotaBinderHandle>(),
            std::mem::size_of::<Option<StorePhysicalQuotaBinderHandle>>(),
            std::mem::size_of::<Option<Arc<dyn StorePhysicalQuotaBinder>>>(),
            std::mem::size_of::<ProjectCharge>()
        );
    }

    #[test]
    fn constructor_funds_complete_inline_geometry_until_last_service_owner() {
        let mut contract = config();
        let maximum_projects = usize::try_from(contract.resources.file_descriptors / 2)
            .unwrap_or_else(|error| panic!("fixture project count: {error}"));
        let bytes = quota_constructor_bytes(maximum_projects)
            .unwrap_or_else(|error| panic!("complete constructor geometry: {error}"));
        contract.resources.metadata_bytes = bytes
            + quota_bootstrap_bytes(BinderPublication::Value)
                .unwrap_or_else(|error| panic!("fixture structure: {error}"));
        let binder = contract
            .build()
            .unwrap_or_else(|error| panic!("exact constructor capacity: {error}"));
        let last_owner = binder.clone();
        let metadata = binder.service.metadata.clone();

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
        assert!(metadata.reserve_resources(0, 0, 1).is_err());
        drop(last_owner);
        assert!(metadata.reserve_resources(0, 0, 1).is_ok());
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
    fn cloned_fresh_binder_retains_its_first_original_outer_anchor() {
        let binder = config()
            .build()
            .unwrap_or_else(|error| panic!("fresh original admission: {error}"));
        let original = binder
            .service
            .supervisor
            .outer_cap_binding()
            .unwrap_or_else(|error| panic!("first original cap: {error}"));
        let cloned = binder.clone();
        let retained = cloned
            .service
            .supervisor
            .outer_cap_binding()
            .unwrap_or_else(|error| panic!("same original cap: {error}"));

        assert_eq!(retained, original);
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
                contract.build(),
                Err(ProviderServiceAdmissionError::Store(StoreError::Quota))
            ));
        }
    }

    #[test]
    fn initial_slot_refusal_keeps_original_allocator_failure_inline() {
        let mut contract = config();
        contract.resources.metadata_bytes = provider_diagnostic_bytes() - 1;

        assert!(matches!(
            contract.build(),
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
                LinuxProjectQuotaBinder::new(budgets, outer, config().resources),
                Err(ProviderServiceAdmissionError::Supervision(
                    HostSupervisionError::InvalidBudget
                ))
            ));
        }
    }

    #[test]
    fn cloned_binder_retains_original_cancellation_before_opening_a_root() {
        let binder = config()
            .build()
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
        let binder = config()
            .build()
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
        let binder = config()
            .build()
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
        let binder = config()
            .build()
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
