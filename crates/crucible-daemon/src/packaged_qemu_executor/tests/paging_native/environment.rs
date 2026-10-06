//! Genuine operator quota, catalog service, and original preparation ownership.
//!
//! Native companion flights share this setup without modeled registrar or
//! resource receipts. The operator quota and charged catalog owner remain live
//! through the callback and the actual preparation watchdog's terminal join.

use super::*;
use crate::packaged_qemu_executor::preparation::PackagedPreparation;

/// Actual admitted catalog backends retained through repository construction.
pub(in crate::packaged_qemu_executor::tests) struct NativeCampaignStorage {
    pub(in crate::packaged_qemu_executor::tests) backend: Arc<dyn ImmutableBlobBackend>,
    pub(in crate::packaged_qemu_executor::tests) refs:
        Arc<dyn crucible_cas::content_store::MutableRefBackend>,
    pub(in crate::packaged_qemu_executor::tests) blob_admin:
        Arc<dyn crucible_cas::content_store::BlobStoreAdmin>,
    pub(in crate::packaged_qemu_executor::tests) ref_admin:
        Arc<dyn crucible_cas::content_store::RefStoreAdmin>,
    _custody: crate::packaged_qemu_executor::ram_catalog::GuardedCampaignStorage,
}

pub(in crate::packaged_qemu_executor::tests) const OPERATOR: &str =
    "adadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadad";

pub(in crate::packaged_qemu_executor::tests) fn with_native_preparation<T>(
    source: &ScenarioDefForm,
    lane: &str,
    project: u32,
    run: impl FnOnce(
        &PackagedPreparation,
        &PackagedQemuExecutorConfig,
        &AttemptExecutionContext,
    ) -> Result<T, PackagedQemuExecutorError>,
) -> T {
    with_native_repository_environment(
        lane,
        project,
        |root, storage| super::super::hot_fork_native::native_repository(source, root, storage),
        |config| config,
        |prepared, config, _repository| {
            let available_before = prepared
                .actor
                .with_supervisor(|actor| Ok(actor.availability().resident_bytes()))
                .expect("catalog service remains independently charged");
            let assignment_peak = config
                .assignment_resources()
                .expect("authored assignment peak")
                .resident_peak_bytes;
            let result = run_capture(prepared, config, source, |context| {
                let supervisor = context
                    .host_operation_supervisor()
                    .expect("live original-start supervisor");
                let (revision, mut budgets) =
                    supervisor.budgets().expect("actual operation roster");
                for class in HostOperationClass::ALL {
                    if !matches!(
                        class,
                        HostOperationClass::Quantum | HostOperationClass::Preparation
                    ) {
                        budgets.classes[class as usize] =
                            HostOperationBudget::finite(Duration::from_secs(300));
                    }
                }
                supervisor
                    .update_budgets(revision, budgets)
                    .expect("finite nested-emulation infrastructure allowances");
                assert_eq!(
                    prepared
                        .actor
                        .with_supervisor(|actor| Ok(actor.availability().resident_bytes()))
                        .expect("real reserved service"),
                    available_before
                        .checked_sub(assignment_peak)
                        .expect("reserved full assignment peak")
                );
                run(prepared, config, context)
            })
            .expect("service reservation survives through native cleanup and watchdog join");
            assert_eq!(
                prepared
                    .actor
                    .with_supervisor(|actor| Ok(actor.availability().resident_bytes()))
                    .expect("real released service"),
                available_before
            );
            result
        },
    )
}

/// Constructs durable campaign storage inside the installed project quota.
pub(in crate::packaged_qemu_executor::tests) fn with_native_repository_environment<T>(
    lane: &str,
    project: u32,
    repository: impl FnOnce(&std::path::Path, NativeCampaignStorage) -> Arc<CampaignRepository>,
    configure: impl FnOnce(PackagedQemuExecutorConfig) -> PackagedQemuExecutorConfig,
    run: impl FnOnce(&PackagedPreparation, &PackagedQemuExecutorConfig, Arc<CampaignRepository>) -> T,
) -> T {
    with_native_repository_environment_with_catalog(
        lane,
        project,
        NativeCatalogBudget::default(),
        repository,
        configure,
        run,
    )
}

/// Authored kernel quota and independent full-vector catalog entitlement.
pub(in crate::packaged_qemu_executor::tests) struct NativeCatalogBudget {
    pub(in crate::packaged_qemu_executor::tests) resources:
        crucible_api::host_operational::HostResourceVector,
    pub(in crate::packaged_qemu_executor::tests) maximum_inodes: u64,
    pub(in crate::packaged_qemu_executor::tests) installation_capacity: Option<ExecutorCapacity>,
    pub(in crate::packaged_qemu_executor::tests) installation_operational_capacity:
        Option<crate::HostOperationalCapacity>,
}

impl Default for NativeCatalogBudget {
    fn default() -> Self {
        Self {
            resources: crucible_api::host_operational::HostResourceVector {
                resident_peak_bytes: 128 * 1024 * 1024,
                backing_peak_bytes: 512 * 1024 * 1024,
                metadata_bytes: 64 * 1024 * 1024,
                staging_bytes: 8 * 1024 * 1024,
                paging_io_slots: 1,
                cpu_slots: 1,
                task_slots: 1,
                file_descriptors: 128,
            },
            maximum_inodes: 262_144,
            installation_capacity: None,
            installation_operational_capacity: None,
        }
    }
}

/// Installs the supplied quota before any catalog repository is created.
pub(in crate::packaged_qemu_executor::tests) fn with_native_repository_environment_with_catalog<
    T,
>(
    lane: &str,
    project: u32,
    catalog: NativeCatalogBudget,
    repository: impl FnOnce(&std::path::Path, NativeCampaignStorage) -> Arc<CampaignRepository>,
    configure: impl FnOnce(PackagedQemuExecutorConfig) -> PackagedQemuExecutorConfig,
    run: impl FnOnce(&PackagedPreparation, &PackagedQemuExecutorConfig, Arc<CampaignRepository>) -> T,
) -> T {
    with_native_repository_storage(
        lane,
        project,
        catalog,
        repository,
        |_repository, _catalog_root, admitted_checkpoint_backend| admitted_checkpoint_backend(),
        configure,
        run,
    )
}

/// Selects checkpoint storage after its real project quota and repository exist.
///
/// The selector permits an archive flight to place exact roots in its campaign
/// namespace. Existing callers retain independently named checkpoint storage.
pub(in crate::packaged_qemu_executor::tests) fn with_native_repository_storage<T>(
    lane: &str,
    project: u32,
    catalog: NativeCatalogBudget,
    repository: impl FnOnce(&std::path::Path, NativeCampaignStorage) -> Arc<CampaignRepository>,
    checkpoint_backend: impl FnOnce(
        &Arc<CampaignRepository>,
        &std::path::Path,
        &mut dyn FnMut() -> Arc<dyn ImmutableBlobBackend>,
    ) -> Arc<dyn ImmutableBlobBackend>,
    configure: impl FnOnce(PackagedQemuExecutorConfig) -> PackagedQemuExecutorConfig,
    run: impl FnOnce(&PackagedPreparation, &PackagedQemuExecutorConfig, Arc<CampaignRepository>) -> T,
) -> T {
    let directory = tempfile::Builder::new()
        .prefix("paging-service-")
        .tempdir_in(environment_path("CRUCIBLE_PAGING_HISTORY"))
        .expect("independent disk-backed service history and RAM CAS");
    let mut config = config(&directory, 1);
    let cgroup = environment_path("CRUCIBLE_PAGING_CGROUP").join(lane);
    let storage = environment_path("CRUCIBLE_PAGING_STORAGE").join(lane);
    config.host = LinuxQemuAttemptHostConfig::new(
        cgroup,
        storage,
        format!("paging-{lane}"),
        project,
        1,
        65_534,
        65_534,
        64,
        TEST_HOST_FILE_DESCRIPTORS,
        TEST_HOST_SERVICE_TASKS,
        TEST_HOST_SERVICE_FILE_DESCRIPTORS,
        TEST_HOST_SERVICE_RESIDENT_BYTES,
        TEST_WATCHER_SERVICE_RESIDENT_BYTES,
        4096,
        Duration::from_secs(30),
    )
    .expect("genuine process and storage containment");
    config.lifecycle = Arc::new(
        ProductionVmLifecycleConfig::new(
            environment_path("CRUCIBLE_PAGING_QEMU"),
            environment_path("CRUCIBLE_PAGING_PLUGIN"),
            environment_path("CRUCIBLE_PAGING_KERNEL"),
            environment_path("CRUCIBLE_PAGING_ROOT"),
            directory.path().join("run-state"),
        )
        .with_initrd(environment_path("CRUCIBLE_PAGING_INITRD"))
        .with_root_image_format(crucible_qemu::QemuRootImageFormat::Raw)
        .with_kernel_cmdline_prefix("console=ttyS0 reboot=k panic=1 quiet rdinit=/init")
        .with_run_ceiling_ticks(50_000_000_000)
        .with_rendezvous_interval_ticks(8_000_000)
        .with_quantum_budget(256)
        .with_completion_timeout(Duration::from_secs(1200)),
    );
    config.capacity = ExecutorCapacity::new(1, 4, 1 << 30, 2 << 30, 150_000)
        .expect("full resident execution and complete backing peaks");
    config = config
        .with_assignment_resources(
            crucible_api::host_operational::HostResourceVector {
                resident_peak_bytes: 513 * 1024 * 1024,
                backing_peak_bytes: 1024 * 1024 * 1024,
                metadata_bytes: 128 * 1024 * 1024,
                staging_bytes: 16 * 1024 * 1024,
                paging_io_slots: 1,
                cpu_slots: 2,
                // The native process ceiling is 64, with four independent node
                // service tasks and one original-scope watchdog outside the node.
                task_slots: 69,
                file_descriptors: 1056,
            },
            AttemptResourceLimits::new(2, 512 * 1024 * 1024, 1024 * 1024 * 1024, 50_000)
                .expect("original native assignment request limits"),
        )
        .expect("complete native process and service peaks");

    let catalog_root = environment_path("CRUCIBLE_PAGING_STORAGE").join(format!("catalog-{lane}"));
    std::fs::create_dir(&catalog_root).expect("fresh operator-owned quota directory");
    let catalog_resources = catalog.resources;
    if let Some(capacity) = catalog.installation_capacity {
        config.capacity = capacity;
    }
    if let Some(capacity) = catalog.installation_operational_capacity {
        config.host_operational_capacity = capacity;
    }
    // The disposable VM acts as the deployment operator. The daemon receives
    // a genuine inherited kernel quota and independently admits its service;
    // no modeled test authority enters this native flight.
    let quota = crucible_linux_resource::LinuxProjectQuotaReservation::install(
        std::fs::File::open(environment_path("CRUCIBLE_PAGING_STORAGE"))
            .expect("quota filesystem")
            .into(),
        std::fs::File::open(&catalog_root)
            .expect("quota directory")
            .into(),
        &catalog_root,
        project + 50,
        crucible_linux_resource::LinuxProjectQuotaLimits::new(
            catalog_resources.backing_peak_bytes,
            catalog.maximum_inodes,
        )
        .expect("independent catalog byte and inode ceilings"),
    )
    .expect("operator-installed real ext4 project quota");
    // The ledger and registry share a distinct operator-installed physical
    // namespace. Its admitted Service owns this one byte/inode ceiling; it
    // cannot borrow the independently charged immutable catalog's quota.
    let registry_root =
        environment_path("CRUCIBLE_PAGING_STORAGE").join(format!("registry-{lane}"));
    std::fs::create_dir(&registry_root).expect("fresh operator-owned registry directory");
    // Native lanes reserve 100 project IDs each: process projects occupy the
    // start, the registry uses offset 25, and the catalog uses offset 50.
    let registry_project = project + 25;
    let registry_inodes = 65_536;
    let registry_quota = crucible_linux_resource::LinuxProjectQuotaReservation::install(
        std::fs::File::open(environment_path("CRUCIBLE_PAGING_STORAGE"))
            .expect("registry quota filesystem")
            .into(),
        std::fs::File::open(&registry_root)
            .expect("registry quota directory")
            .into(),
        &registry_root,
        registry_project,
        crucible_linux_resource::LinuxProjectQuotaLimits::new(16 * 1024 * 1024, registry_inodes)
            .expect("authored registry hard byte and inode ceilings"),
    )
    .expect("operator-installed independent registry project quota");
    config.ledger_root = registry_root;
    config = config
        .with_operational_registry_resources(crucible_api::host_operational::HostResourceVector {
            resident_peak_bytes: 128 * 1024 * 1024,
            backing_peak_bytes: 16 * 1024 * 1024,
            metadata_bytes: 64 * 1024 * 1024,
            staging_bytes: 8 * 1024 * 1024,
            paging_io_slots: 1,
            cpu_slots: 1,
            task_slots: 1,
            file_descriptors: 128,
        })
        .expect("independently charged durable operator registry")
        .with_operational_registry_quota(registry_project, registry_inodes)
        .expect("same registry Service backed by exact operator quota")
        .with_ram_catalog(
            crate::PackagedRamCatalogConfig::new(
                &catalog_root,
                project + 50,
                catalog.maximum_inodes,
                catalog_resources,
                8 * 1024 * 1024,
            )
            .expect("authored independent catalog service"),
        )
        .expect("catalog and assignment fit aggregate physical capacity");

    let mut budgets = crucible_api::host_operational::HostOperationBudgets {
        classes: [HostOperationBudget::finite(Duration::from_secs(300));
            crucible_linux_resource::host_supervision::HOST_OPERATION_CLASS_COUNT],
    };
    budgets.classes[HostOperationClass::Quantum as usize] =
        HostOperationBudget::unlimited_quantum();
    config = config
        .with_host_operation_budgets(budgets)
        .expect("authored finite native infrastructure roster under original outer cap");
    config = configure(config);
    // The deferred validator refuses all queues until the actual repository
    // and immutable campaign closure exist under this one admitted account.
    let admission = crate::packaged_qemu_executor::PackagedAttemptAdmission::default();
    let (actor, registry) =
        crate::packaged_qemu_executor::preparation::prepare_owner(&config, admission.clone())
            .expect("one original precharged registry actor before catalog opening");
    crate::packaged_qemu_executor::ram_catalog::admit_catalog_service(&config, &registry)
        .expect("actual catalog Service before repository metadata");
    let catalog = config.ram_catalog().expect("authored catalog");
    let repository_root = catalog_root.join("campaign-repository");
    let storage = catalog
        .open_guarded_storage(&repository_root)
        .expect("actual namespace metadata and descriptor authority");
    let repository = repository(
        &repository_root,
        NativeCampaignStorage {
            backend: storage.backend.clone(),
            refs: storage.refs.clone(),
            blob_admin: storage.blob_admin.clone(),
            ref_admin: storage.ref_admin.clone(),
            _custody: storage,
        },
    );
    let mut admitted_checkpoint_backend = || {
        catalog
            .open_guarded_storage(&catalog_root.join("campaign-checkpoints"))
            .expect("independent checkpoint backend with real catalog custody")
            .backend
    };
    let checkpoint_backend =
        checkpoint_backend(&repository, &catalog_root, &mut admitted_checkpoint_backend);
    let root_resources = config
        .lifecycle
        .ram_catalog_provider()
        .expect("actual catalog provider")
        .prepare_directory(config.lifecycle.run_state_root())
        .expect("actual run-state resource authority");
    let basis = authenticate_packaged_campaigns(&repository, &config.campaigns, false)
        .expect("actual packaged campaign basis under admitted metadata");
    let prepared = crate::packaged_qemu_executor::preparation::prepare_runtime_with_owner(
        &repository,
        checkpoint_backend,
        &basis,
        &config,
        crate::packaged_qemu_executor::preparation::RuntimeOwnership {
            actor,
            host_operational_registry: registry,
            admission,
            root_resources: Some(root_resources),
        },
    )
    .expect("reconciliation retains the identical original actor and catalog");
    prepared
        .host_operational_registry
        .grant_principal(OPERATOR)
        .expect("authenticated operator roster");
    // This synchronous driver borrows the catalog already admitted above.
    // Each owning model copy retains its child credit through its last user.
    let decoding = crucible::owned_decode::DecodeBudget::for_store(
        prepared
            .checkpoints
            .metadata_resource_authority()
            .expect("same admitted checkpoint namespace authority"),
    )
    .expect("original catalog metadata account");
    let _metadata_scope = decoding.enter();
    let result = run(&prepared, &config, repository);
    decoding.check().expect("native driver metadata admission");
    registry_quota
        .verify_usage()
        .expect("persistent ledger and history remain within their shared kernel quota");
    quota
        .verify_usage()
        .expect("persistent catalog bytes remain within their kernel quota");
    result
}

pub(in crate::packaged_qemu_executor::tests) fn environment_path(name: &str) -> std::path::PathBuf {
    std::env::var_os(name)
        .unwrap_or_else(|| panic!("isolated paging gate must supply {name}"))
        .into()
}
