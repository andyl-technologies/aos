//! Original resource account charged before the durable assignment ledger opens.
//!
//! This state has no ledger or admission route. It owns the same counters and
//! Service resource ledger later moved into the live supervisor. Filesystem
//! initialization therefore never borrows an uncharged temporary executor.

use super::*;
use crucible_api::host_operational::HostOperationalError;
use crucible_linux_resource::host_services::{HostServiceAllocator, HostServiceLease};
use crucible_linux_resource::host_supervision::{
    HostOperationClass, HostOperationGuard, HostOperationSupervisor,
};
use crucible_linux_resource::ram_policy::HostResourceVector;
use crucible_linux_resource::{LinuxProjectQuotaBinding, LinuxProjectQuotaLimits};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// Immutable deployed startup and assignment partitions, before filesystem I/O.
pub(crate) struct ExecutorBootstrapConfiguration {
    pub(crate) capacity: ExecutorCapacity,
    pub(crate) operational_capacity: HostOperationalCapacity,
    pub(crate) assignment_resources: HostResourceVector,
    pub(crate) assignment_limits: AttemptResourceLimits,
    pub(crate) watcher_resident_bytes: u64,
    pub(crate) registry_owner: [u8; 32],
    pub(crate) registry_resources: HostResourceVector,
    pub(crate) registry_maximum_inodes: u64,
    pub(crate) preparation_supervisor: HostOperationSupervisor,
}

/// Owns the actual precharged account while no durable ledger exists yet.
pub(crate) struct ExecutorBootstrapResources {
    account: Option<Arc<BootstrapAccount>>,
    io_started: bool,
}

struct BootstrapAccount {
    configuration: ExecutorBootstrapConfiguration,
    used: UsedCapacity,
    operational_used: HostOperationalUse,
    services: service_resources::HostServiceReservations,
    assignment_charge: UsedCapacity,
    budgets: crucible_linux_resource::host_supervision::HostOperationBudgets,
    operation: HostOperationGuard,
    allocator: HostServiceAllocator,
    ledger_lease: HostServiceLease,
    quota: Option<LinuxProjectQuotaBinding>,
    quota_lease: HostServiceLease,
}

/// Retains the physical namespace pin before returning its original audit credit.
pub(super) struct BootstrapLedgerQuota {
    _binding: Option<LinuxProjectQuotaBinding>,
    _lease: HostServiceLease,
}

fn quota_audit_resources() -> HostResourceVector {
    // The lower audit uses 17 bounded scan buffers and at most 36 FDs. Path
    // authentication and diagnostic copies are bounded by Linux's path limit.
    let metadata = std::mem::size_of::<LinuxProjectQuotaBinding>() as u64
        + 4 * 4096
        + HostServiceLease::metadata_bytes();
    let staging = LinuxProjectQuotaBinding::maximum_audit_scratch_bytes();
    HostResourceVector {
        metadata_bytes: metadata,
        staging_bytes: staging,
        resident_peak_bytes: metadata + staging,
        file_descriptors: LinuxProjectQuotaBinding::maximum_audit_file_descriptors(),
        ..HostResourceVector::default()
    }
}

impl ExecutorBootstrapResources {
    /// Validates and charges the complete registry Service before opening files.
    ///
    /// # Errors
    /// Refuses invalid authored partitions, overflow or aggregate exhaustion,
    /// and unavailable original finite preparation supervision.
    pub(crate) fn new(
        configuration: ExecutorBootstrapConfiguration,
    ) -> Result<Self, HostOperationalError> {
        LinuxProjectQuotaLimits::new(
            configuration.registry_resources.backing_peak_bytes,
            configuration.registry_maximum_inodes,
        )
        .map_err(|_| HostOperationalError::Unavailable)?;
        let capacity = configuration.capacity;
        let operational = configuration.operational_capacity;
        crate::HostOperationalRegistry::validate_service_resources(
            configuration.registry_owner,
            configuration.registry_resources,
        )?;
        if operational
            .maximum_metadata_bytes()
            .checked_add(operational.maximum_staging_bytes())
            .is_none_or(|bytes| bytes > capacity.maximum_resident_bytes)
            || operational.maximum_staging_bytes() > capacity.maximum_disk_bytes
        {
            return Err(HostOperationalError::Unavailable);
        }
        let assignment_charge = ram_policy::assignment_charge(
            capacity,
            operational,
            configuration.assignment_resources,
            configuration.assignment_limits,
            configuration.watcher_resident_bytes,
        )?;
        let mut used = UsedCapacity::default();
        let mut operational_used = HostOperationalUse::default();
        let mut services = service_resources::HostServiceReservations::new();
        service_resources::reserve_service_account(
            capacity,
            operational,
            &mut used,
            &mut operational_used,
            &mut services,
            configuration.registry_owner,
            configuration.registry_resources,
        )?;
        let registry_floor = crate::HostOperationalRegistry::minimum_service_resources()?;
        let ledger = crate::assignment_ledger::startup_inventory_resources();
        let entitlement = configuration.registry_resources;
        let quota = quota_audit_resources();
        if registry_floor
            .metadata_bytes
            .checked_add(ledger.metadata_bytes)
            .and_then(|bytes| bytes.checked_add(quota.metadata_bytes))
            .is_none_or(|bytes| bytes > entitlement.metadata_bytes)
            || registry_floor
                .staging_bytes
                .checked_add(ledger.staging_bytes)
                .is_none_or(|bytes| bytes > entitlement.staging_bytes)
            || registry_floor
                .file_descriptors
                .checked_add(ledger.file_descriptors)
                .is_none_or(|count| count > entitlement.file_descriptors)
        {
            return Err(HostOperationalError::Unavailable);
        }
        let allocator = HostServiceAllocator::new(
            entitlement.task_slots,
            entitlement.file_descriptors,
            entitlement.resident_peak_bytes,
        )
        .map_err(|_| HostOperationalError::Unavailable)?;
        let ledger_lease = allocator
            .reserve_resources(0, ledger.file_descriptors, ledger.resident_peak_bytes)
            .map_err(|_| HostOperationalError::Unavailable)?;
        let quota_lease = allocator
            .reserve_resources(0, quota.file_descriptors, quota.resident_peak_bytes)
            .map_err(|_| HostOperationalError::Unavailable)?;
        let budgets = configuration
            .preparation_supervisor
            .budgets()
            .map_err(|_| HostOperationalError::Unavailable)?
            .1;
        let operation = configuration
            .preparation_supervisor
            .begin_work(
                HostOperationClass::Preparation,
                configuration.registry_maximum_inodes,
            )
            .map_err(|_| HostOperationalError::Unavailable)?;
        Ok(Self {
            account: Some(Arc::new(BootstrapAccount {
                configuration,
                used,
                operational_used,
                services,
                assignment_charge,
                budgets,
                operation,
                allocator,
                ledger_lease,
                quota: None,
                quota_lease,
            })),
            io_started: false,
        })
    }

    /// Authenticates the operator's hard byte and inode quota before ledger I/O.
    ///
    /// The installed byte ceiling is exactly the already charged registry
    /// backing entitlement. Namespace admission uses the original preparation
    /// guard and allocator; it creates no second Service or deadline.
    ///
    /// # Errors
    /// Refuses invalid or competing namespace authority, expired original
    /// supervision, and absent or mismatched ext4 project enforcement.
    pub(crate) fn bind_ledger_quota(
        &mut self,
        root: &Path,
        project_id: u32,
    ) -> Result<(), crate::PackagedQemuExecutorError> {
        self.boundary()?;
        if project_id == 0 || project_id > 0x7fff_ffff {
            return Err(crucible_linux_resource::LinuxProjectQuotaError::InvalidProjectId.into());
        }
        if root.as_os_str().as_bytes().len() > 4096 {
            return Err(HostOperationalError::Unavailable.into());
        }
        let account = self
            .account
            .as_mut()
            .and_then(Arc::get_mut)
            .ok_or(HostOperationalError::Unavailable)?;
        if account.quota.is_some() {
            return Err(HostOperationalError::Unavailable.into());
        }
        // Namespace admission may create its cooperative lock. Every uncertain
        // result from this point retains the original account and physical pin.
        self.io_started = true;
        let binding = LinuxProjectQuotaBinding::bind_existing_under(
            root,
            project_id,
            account.configuration.registry_resources.backing_peak_bytes,
            account.configuration.registry_maximum_inodes,
            account.configuration.preparation_supervisor.clone(),
            &account.operation,
        )?;
        account.quota = Some(binding);
        self.boundary()?;
        Ok(())
    }

    /// Returns the same allocator that already retains the ledger's physical peak.
    pub(crate) fn services(&self) -> Result<HostServiceAllocator, HostOperationalError> {
        self.account
            .as_ref()
            .map(|account| account.allocator.clone())
            .ok_or(HostOperationalError::Unavailable)
    }

    /// Checks the original finite preparation scope before and after physical I/O.
    ///
    /// # Errors
    /// Refuses elapsed or canceled original supervision and uncertain ownership.
    pub(crate) fn boundary(&self) -> Result<(), HostOperationalError> {
        self.account
            .as_ref()
            .ok_or(HostOperationalError::Unavailable)?
            .operation
            .wait_slice()
            .map(|_| ())
            .map_err(|_| HostOperationalError::Unavailable)
    }

    /// Arms durable-effect custody before the first potentially mutating I/O.
    ///
    /// Marking before the syscall covers errors whose physical disposition is
    /// uncertain. Failed bootstrap retains its original account until a trusted
    /// cleanup path can prove the namespace gone; closing a lock is insufficient.
    ///
    /// # Errors
    /// Refuses an elapsed original scope before creating any new physical effect.
    pub(crate) fn before_io(&mut self) -> Result<(), HostOperationalError> {
        self.boundary()?;
        if self
            .account
            .as_ref()
            .is_none_or(|account| account.quota.is_none())
        {
            return Err(HostOperationalError::Unavailable);
        }
        self.io_started = true;
        Ok(())
    }

    /// Arms actor-only component I/O without claiming native quota admission.
    #[cfg(test)]
    pub(crate) fn before_component_io(&mut self) -> Result<(), HostOperationalError> {
        self.boundary()?;
        self.io_started = true;
        Ok(())
    }

    /// Moves the original charged account into its sole durable supervisor.
    ///
    /// The returned guard preserves the original preparation start while the
    /// caller opens the registry and binds the actor. It must complete before
    /// external admission routes become available. No counter is reconstructed
    /// from durable data or reset during this ownership transfer.
    ///
    /// # Errors
    /// Refuses elapsed original supervision or another retained account borrower.
    pub(crate) fn install<L, V>(
        mut self,
        ledger: L,
        validator: V,
        daemon_epoch: DaemonEpoch,
    ) -> Result<(LocalExecutorSupervisor<L, V>, HostOperationGuard), HostOperationalError> {
        if let Err(error) = self.boundary() {
            if self.io_started {
                // Its sole-writer exclusion belongs to the same uncertain
                // namespace. Dropping it would permit a fresh owner to reopen
                // persisted bytes while this original account stays held.
                std::mem::forget(ledger);
            }
            return Err(error);
        }
        let account = self
            .account
            .take()
            .ok_or(HostOperationalError::Unavailable)?;
        let account = match Arc::try_unwrap(account) {
            Ok(account) => account,
            Err(account) => {
                self.account = Some(account);
                if self.io_started {
                    std::mem::forget(ledger);
                }
                return Err(HostOperationalError::Unavailable);
            }
        };
        let configuration = account.configuration;
        Ok((
            LocalExecutorSupervisor {
                host_startup_namespace_owner: self
                    .io_started
                    .then_some(configuration.registry_owner),
                host_watcher_resident_bytes: Some(configuration.watcher_resident_bytes),
                host_assignment_resources: Some((
                    configuration.assignment_resources,
                    configuration.assignment_limits,
                    account.assignment_charge,
                )),
                host_operational_capacity: Some(configuration.operational_capacity),
                host_operational_used: account.operational_used,
                host_operational_registry: crate::HostOperationalRegistry::default(),
                host_ram_resources: BTreeMap::new(),
                host_retained_resources: BTreeMap::new(),
                host_service_resources: account.services,
                host_service_partitions: BTreeMap::new(),
                host_unpublished_quarantine: BTreeMap::new(),
                ledger,
                validator: Arc::new(validator),
                daemon_epoch,
                capacity: configuration.capacity,
                next_execution_ordinal: 0,
                #[cfg(test)]
                native_completed_transitions: 0,
                active: BTreeMap::new(),
                queued: VecDeque::new(),
                pending_completions: BTreeMap::new(),
                pending_cancellations: BTreeMap::new(),
                used: account.used,
                host_operation_budgets: Some(account.budgets),
                _host_startup_ledger_lease: Some(account.ledger_lease),
                _host_startup_ledger_quota: Some(BootstrapLedgerQuota {
                    _binding: account.quota,
                    _lease: account.quota_lease,
                }),
            },
            account.operation,
        ))
    }
}

impl Drop for ExecutorBootstrapResources {
    fn drop(&mut self) {
        if self.io_started
            && let Some(account) = self.account.take()
        {
            // Durable effects are not erased by dropping a failed constructor.
            // Preserve the same charged account, including its Service ledger;
            // no admission route exists while this bootstrap is quarantined.
            std::mem::forget(account);
        }
    }
}

#[cfg(test)]
mod tests {
    //! Component evidence for real startup account and durable ledger ownership.

    // crucible-lint: allow panic-shortcut -- checked fixtures panic on failed authored assumptions.
    #![allow(clippy::expect_used)]

    use super::*;
    use crucible_linux_resource::host_supervision::HostOperationBudgets;

    fn configuration() -> ExecutorBootstrapConfiguration {
        ExecutorBootstrapConfiguration {
            capacity: ExecutorCapacity::new(1, 4, 256 << 20, 128 << 20, 100)
                .expect("authored aggregate"),
            operational_capacity: HostOperationalCapacity::new(4, 16, 256, 96 << 20, 16 << 20)
                .expect("independent operational aggregate"),
            assignment_resources: HostResourceVector {
                cpu_slots: 2,
                resident_peak_bytes: 8 << 20,
                backing_peak_bytes: 16 << 20,
                metadata_bytes: 2 << 20,
                staging_bytes: 1 << 20,
                paging_io_slots: 1,
                task_slots: 4,
                file_descriptors: 8,
            },
            assignment_limits: AttemptResourceLimits::new(1, 1024, 0, 100)
                .expect("independent semantic limits"),
            watcher_resident_bytes: 1 << 20,
            registry_owner: [0x51; 32],
            registry_maximum_inodes: 65_536,
            registry_resources: HostResourceVector {
                cpu_slots: 1,
                resident_peak_bytes: 128 << 20,
                backing_peak_bytes: 16 << 20,
                metadata_bytes: 64 << 20,
                staging_bytes: 8 << 20,
                paging_io_slots: 1,
                task_slots: 1,
                file_descriptors: 128,
            },
            preparation_supervisor: HostOperationSupervisor::new(
                HostOperationBudgets::default(),
                None,
            )
            .expect("authored finite startup supervision"),
        }
    }

    #[test]
    fn startup_charge_precedes_ledger_io_and_moves_without_reset() {
        let directory = tempfile::tempdir().expect("owned temporary namespace");
        let ledger_root = directory.path().join("ledger");
        let authored = configuration();
        let registry = authored.registry_resources;
        let owner = authored.registry_owner;
        let mut bootstrap = ExecutorBootstrapResources::new(authored).expect("precharged account");
        assert!(!ledger_root.exists());
        let account = bootstrap.account.as_ref().expect("original account");
        assert_eq!(
            account.used.vcpus,
            u32::try_from(registry.cpu_slots).expect("bounded CPU count")
        );
        assert_eq!(
            account.operational_used.file_descriptors,
            registry.file_descriptors
        );

        bootstrap
            .before_component_io()
            .expect("original finite boundary");
        let ledger = crate::DirectoryAssignmentLedger::open(&ledger_root).expect("real ledger");
        bootstrap
            .boundary()
            .expect("same scope after ledger effects");
        let (mut supervisor, operation) = bootstrap
            .install(
                ledger,
                AllowAllAttemptAdmission,
                DaemonEpoch::from_bytes([0x41; 16]).expect("authored daemon epoch"),
            )
            .expect("move original counters and service ledger");
        operation
            .complete()
            .expect("original preparation completion");

        assert_eq!(supervisor.used.resident_bytes, registry.resident_peak_bytes);
        assert_eq!(supervisor.used.disk_bytes, registry.backing_peak_bytes);
        assert_eq!(
            supervisor.host_operational_used.metadata_bytes,
            registry.metadata_bytes
        );
        assert_eq!(supervisor.host_service_resources[&owner].0, registry);
        assert!(
            supervisor
                .reserve_host_ram_service(owner, registry)
                .is_err()
        );
        // Closing a ledger lock is not a durable namespace deletion receipt.
        assert!(
            supervisor
                .release_host_ram_service_after_cleanup(owner)
                .is_err()
        );
        assert_eq!(supervisor.used.disk_bytes, registry.backing_peak_bytes);
    }

    #[test]
    fn uncertain_startup_effect_retains_the_same_actual_account() {
        let directory = tempfile::tempdir().expect("owned temporary namespace");
        let namespace = directory.path().join("partially-created-ledger");
        let mut bootstrap =
            ExecutorBootstrapResources::new(configuration()).expect("charged account");
        let original = Arc::downgrade(bootstrap.account.as_ref().expect("same account"));
        bootstrap
            .before_component_io()
            .expect("arm before possible effects");
        std::fs::create_dir(&namespace).expect("real startup namespace effect");

        drop(bootstrap);

        let retained = original
            .upgrade()
            .expect("uncertain effects keep original account");
        assert_eq!(retained.used.disk_bytes, 16 << 20);
        assert_eq!(retained.services.len(), 1);
        assert!(namespace.is_dir());
    }

    #[test]
    fn unopened_failure_releases_local_account_and_exhaustion_has_no_io() {
        let bootstrap = ExecutorBootstrapResources::new(configuration()).expect("charged account");
        let original = Arc::downgrade(bootstrap.account.as_ref().expect("original account"));
        drop(bootstrap);
        assert!(original.upgrade().is_none());

        let directory = tempfile::tempdir().expect("owned temporary namespace");
        let ledger_root = directory.path().join("must-remain-absent");
        let mut exhausted = configuration();
        exhausted.registry_resources.file_descriptors = 257;
        assert!(ExecutorBootstrapResources::new(exhausted).is_err());
        assert!(!ledger_root.exists());
    }

    #[test]
    fn failed_install_retains_original_account_and_real_ledger_exclusion() {
        let directory = tempfile::tempdir().expect("owned temporary namespace");
        let ledger_root = directory.path().join("ledger");
        let mut bootstrap =
            ExecutorBootstrapResources::new(configuration()).expect("charged account");
        let borrower = Arc::clone(bootstrap.account.as_ref().expect("original account"));
        let original = Arc::downgrade(&borrower);
        bootstrap
            .before_component_io()
            .expect("original guarded effects");
        let ledger = crate::DirectoryAssignmentLedger::open(&ledger_root).expect("real writer");

        assert!(
            bootstrap
                .install(
                    ledger,
                    AllowAllAttemptAdmission,
                    DaemonEpoch::from_bytes([0x42; 16]).expect("authored daemon epoch"),
                )
                .is_err()
        );
        drop(borrower);

        assert_eq!(
            original
                .upgrade()
                .expect("same retained account")
                .used
                .disk_bytes,
            16 << 20
        );
        assert!(crate::DirectoryAssignmentLedger::open(&ledger_root).is_err());
    }
    #[test]
    fn registry_and_ledger_consume_the_same_descriptor_allocation() {
        let directory = tempfile::tempdir().expect("owned namespace");
        let bootstrap = ExecutorBootstrapResources::new(configuration()).expect("original account");
        let services = bootstrap.services().expect("same allocator");
        let remaining = services.maximum_file_descriptors()
            - crate::assignment_ledger::startup_inventory_resources().file_descriptors
            - quota_audit_resources().file_descriptors;
        let borrowed = services
            .reserve_resources(0, remaining, 0)
            .expect("all remaining original permits");

        assert!(
            crate::HostOperationalRegistry::open_admitted_with_services(
                &directory.path().join("must-remain-unopened"),
                [0x31; 32],
                configuration().registry_resources,
                services,
                None
            )
            .is_err()
        );
        assert!(!directory.path().join("must-remain-unopened").exists());
        drop(borrowed);
    }

    #[test]
    fn expired_streaming_boundary_keeps_the_actual_ledger_writer() {
        let directory = tempfile::tempdir().expect("owned namespace");
        let root = directory.path().join("ledger");
        let mut bootstrap =
            ExecutorBootstrapResources::new(configuration()).expect("original account");
        bootstrap
            .before_component_io()
            .expect("arm original effects");
        let mut visits = 0;
        let opened = crate::DirectoryAssignmentLedger::open_with_boundary(&root, &mut || {
            visits += 1;
            if visits == 3 {
                Err(crate::assignment_ledger::AssignmentLedgerError::Io {
                    operation: "original-startup-boundary",
                    path: root.clone(),
                    source: std::io::Error::other(
                        "original scope expired after writer acquisition",
                    ),
                })
            } else {
                Ok(())
            }
        });
        assert!(opened.is_err());
        drop(bootstrap);

        assert!(crate::DirectoryAssignmentLedger::open(&root).is_err());
    }

    #[test]
    fn absent_kernel_quota_refuses_before_any_ledger_publication() {
        let directory = tempfile::tempdir().expect("owned unqualified filesystem");
        let root = directory.path().join("uninstalled-registry");
        let mut bootstrap = ExecutorBootstrapResources::new(configuration())
            .expect("same original charged registry account");

        let error = bootstrap
            .bind_ledger_quota(&root, 701)
            .expect_err("missing operator-installed root must refuse");
        assert!(matches!(
            error,
            crate::PackagedQemuExecutorError::RegistryQuota(_)
        ));
        assert!(!root.exists());
        let original = Arc::downgrade(bootstrap.account.as_ref().expect("original account"));
        drop(bootstrap);

        // Binding can create a namespace lease on a qualified root before an
        // error. Its conservative failure custody retains the same account.
        assert_eq!(
            original
                .upgrade()
                .expect("retained original account")
                .used
                .disk_bytes,
            16 << 20
        );
    }

    #[test]
    fn quota_audit_peak_is_reserved_before_namespace_access() {
        let mut authored = configuration();
        let registry = crate::HostOperationalRegistry::minimum_service_resources()
            .expect("fixed registry roster");
        let ledger = crate::assignment_ledger::startup_inventory_resources();
        authored.registry_resources.file_descriptors =
            registry.file_descriptors + ledger.file_descriptors;
        assert!(ExecutorBootstrapResources::new(authored).is_err());

        let bootstrap =
            ExecutorBootstrapResources::new(configuration()).expect("complete authored peak");
        let services = bootstrap.services().expect("same allocator");
        let available = services.maximum_file_descriptors()
            - ledger.file_descriptors
            - quota_audit_resources().file_descriptors;
        let held = services
            .reserve_resources(0, available, 0)
            .expect("exact remaining descriptors");
        assert!(services.reserve_resources(0, 1, 0).is_err());
        drop(held);
    }

    #[test]
    fn production_io_gate_requires_physical_binding_even_in_component_builds() {
        let mut bootstrap = ExecutorBootstrapResources::new(configuration())
            .expect("same precharged account without a kernel binding");
        let original = Arc::downgrade(bootstrap.account.as_ref().expect("original account"));

        assert!(bootstrap.before_io().is_err());
        assert!(!bootstrap.io_started);
        drop(bootstrap);

        assert!(original.upgrade().is_none());
    }

    #[test]
    fn invalid_project_refuses_without_arming_durable_namespace_custody() {
        let mut bootstrap =
            ExecutorBootstrapResources::new(configuration()).expect("original precharged account");
        let original = Arc::downgrade(bootstrap.account.as_ref().expect("same account"));

        assert!(matches!(
            bootstrap.bind_ledger_quota(Path::new("/unused-registry"), 0),
            Err(crate::PackagedQemuExecutorError::RegistryQuota(
                crucible_linux_resource::LinuxProjectQuotaError::InvalidProjectId
            ))
        ));
        assert!(!bootstrap.io_started);
        drop(bootstrap);

        assert!(original.upgrade().is_none());
    }
}
