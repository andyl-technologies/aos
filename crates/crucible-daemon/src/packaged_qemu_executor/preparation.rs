//! Genuine preparation owners charged before native baked-genesis work.
//!
//! One assignment ledger, registry, and capacity actor survive the transition
//! into the worker pool. Cold preparation joins its watchdog and proves every
//! native node cleaned before discharging its independent service entitlement.

use super::*;
use crate::executor_pool::{PausedCheckpointObserver, PreparedExecutorActor};
use crate::supervision::AssignmentHostWatchdogGuard;
use crucible_linux_resource::host_supervision::HostOperationSupervisor;

mod failure;
#[cfg(feature = "private-measurement-domain")]
pub use failure::OriginalCaptureFailure;
pub use failure::PreparationExpiredCause;

pub(super) struct PackagedPreparation {
    pub(super) actor: PreparedExecutorActor<DirectoryAssignmentLedger, PackagedAttemptAdmission>,
    pub(super) host_operational_registry: crate::HostOperationalRegistry,
    pub(super) checkpoints: Arc<ExactCheckpointStore>,
    pub(super) prepared_exact_pins: exact_pin_materializer::PreparedPackagedExactPinMaterializer,
    pub(super) checkpoint_observer: Arc<dyn PausedCheckpointObserver>,
    pub(super) prepared_results: PreparedResultJournalConfig,
}

/// Acquires and reconciles durable ownership before any preparation launch.
///
/// # Errors
/// Refuses conflicting ledger or registry ownership, unsafe stale catalog
/// state, unavailable retention, and invalid deployed resource ceilings.
pub(super) fn prepare_runtime(
    repository: &Arc<CampaignRepository>,
    checkpoint_backend: Arc<dyn ImmutableBlobBackend>,
    basis: &PackagedCampaignBasis,
    config: &PackagedQemuExecutorConfig,
) -> Result<PackagedPreparation, PackagedQemuExecutorError> {
    #[cfg(feature = "private-measurement-domain")]
    if let Some(original) = config.original_catalog.as_ref() {
        original.verify()?;
        let preparation = config
            .original_preparation
            .as_ref()
            .ok_or(PackagedQemuExecutorError::MissingOriginalFactoryPreparation)?;
        original.verify_preparation(preparation)?;
        return prepare_runtime_with_catalog(repository, checkpoint_backend, basis, config, |_| {
            original.verify()?;
            let resources = original
                .provider()
                .prepare_directory(config.lifecycle.run_state_root())?;
            Ok(Some(resources))
        });
    }
    prepare_runtime_with_catalog(repository, checkpoint_backend, basis, config, |registry| {
        ram_catalog::admit_catalog_service(config, registry)?;
        let resources = config
            .lifecycle
            .ram_catalog_provider()
            .ok_or(crucible_api::host_operational::HostOperationalError::Unavailable)?
            .prepare_directory(config.lifecycle.run_state_root())?;
        Ok(Some(resources))
    })
}

/// Shared charged actor and reconciliation pipeline, with a catalog authority
/// installed before any native namespace mutation. Production always supplies
/// the actual quota-backed service; component tests isolate actor ownership.
fn prepare_runtime_with_catalog(
    repository: &Arc<CampaignRepository>,
    checkpoint_backend: Arc<dyn ImmutableBlobBackend>,
    basis: &PackagedCampaignBasis,
    config: &PackagedQemuExecutorConfig,
    install_catalog: impl FnOnce(
        &crate::HostOperationalRegistry,
    ) -> Result<
        Option<Arc<dyn crucible_cas::content_store::StorePhysicalQuotaGuard>>,
        PackagedQemuExecutorError,
    >,
) -> Result<PackagedPreparation, PackagedQemuExecutorError> {
    let admission = PackagedAttemptAdmission::new(
        Arc::clone(repository),
        basis.profile.clone(),
        basis.scenarios.clone(),
    );

    // Acquire process-wide ownership before mutating any native run-state
    // namespace. A competing daemon must fail without retiring live state.
    let (actor, host_operational_registry) = prepare_owner(config, admission.clone())?;
    let root_resources = install_catalog(&host_operational_registry)?;
    prepare_runtime_with_owner(
        repository,
        checkpoint_backend,
        basis,
        config,
        RuntimeOwnership {
            actor,
            host_operational_registry,
            admission,
            root_resources,
        },
    )
}

/// Retains the sole original actor across charged repository bootstrap.
pub(super) struct RuntimeOwnership {
    pub(super) actor: PreparedExecutorActor<DirectoryAssignmentLedger, PackagedAttemptAdmission>,
    pub(super) host_operational_registry: crate::HostOperationalRegistry,
    pub(super) admission: PackagedAttemptAdmission,
    pub(super) root_resources:
        Option<Arc<dyn crucible_cas::content_store::StorePhysicalQuotaGuard>>,
}

/// Reconciles an authenticated repository using its already charged owner.
pub(super) fn prepare_runtime_with_owner(
    repository: &Arc<CampaignRepository>,
    checkpoint_backend: Arc<dyn ImmutableBlobBackend>,
    basis: &PackagedCampaignBasis,
    config: &PackagedQemuExecutorConfig,
    ownership: RuntimeOwnership,
) -> Result<PackagedPreparation, PackagedQemuExecutorError> {
    let RuntimeOwnership {
        actor,
        host_operational_registry,
        admission,
        root_resources,
    } = ownership;
    admission.bind(
        repository.clone(),
        basis.profile.clone(),
        basis.scenarios.clone(),
    )?;
    let gc_exclusion = repository.acquire_gc_exclusion_guard()?;
    let (checkpoints, prepared_exact_pins, checkpoint_observer, prepared_results) = actor
        .with_startup_supervisor(|supervisor| {
            let ledger = supervisor.startup_ledger_mut();
            reconcile_packaged_native_catalogs(config.lifecycle.run_state_root())?;
            let prepared_result_root =
                prepare_packaged_prepared_result_namespace(config.lifecycle.run_state_root())?;
            let prepared_result_namespace =
                PreparedResultJournalNamespace::open(prepared_result_root)?;
            let prepared_results = PreparedResultJournalConfig::new(
                prepared_result_namespace,
                MAX_PREPARED_SEMANTIC_RESULT_BYTES,
            );
            reconcile_stable_prepared_result_journals(
                ledger,
                &admission,
                &prepared_results,
                &gc_exclusion,
            )?;

            for campaign in &config.campaigns {
                loop {
                    let summary =
                        reconcile_pending_finding_candidates(repository.as_ref(), ledger, campaign)
                            .map_err(PackagedQemuExecutorError::FindingRestart)?;
                    if summary.remaining() == 0 {
                        break;
                    }
                    if summary.released() == 0 {
                        return Err(PackagedQemuExecutorError::FindingRestartNoProgress {
                            campaign: campaign.clone(),
                            remaining: summary.remaining(),
                        });
                    }
                }
            }
            let mut checkpoints = ExactCheckpointStore::new(
                checkpoint_backend,
                config.maximum_checkpoint_bytes,
                repository.ram_retention_authority(),
            )?;
            if let Some(resources) = root_resources {
                checkpoints = checkpoints.with_ram_root_resources(resources);
            }
            let checkpoints = Arc::new(checkpoints);
            let exact_pin_root = config.exact_pin_materialization_root();
            let (prepared_exact_pins, checkpoint_observer) =
                prepare_packaged_exact_pin_materializer(
                    Arc::clone(repository),
                    Arc::clone(&checkpoints),
                    config.campaigns.clone(),
                    ledger,
                    &exact_pin_root,
                )?;
            Ok::<_, PackagedQemuExecutorError>((
                checkpoints,
                prepared_exact_pins,
                checkpoint_observer,
                prepared_results,
            ))
        })??;
    drop(gc_exclusion);
    Ok(PackagedPreparation {
        actor,
        host_operational_registry,
        checkpoints,
        prepared_exact_pins,
        checkpoint_observer,
        prepared_results,
    })
}

/// Charges one original capacity actor before publishing campaign or catalog bytes.
///
/// Admission may refuse while the caller opens its durable repository. The
/// returned owner survives that bootstrap; no replacement ledger is created.
pub(super) fn prepare_owner<V>(
    config: &PackagedQemuExecutorConfig,
    admission: V,
) -> Result<
    (
        PreparedExecutorActor<DirectoryAssignmentLedger, V>,
        crate::HostOperationalRegistry,
    ),
    PackagedQemuExecutorError,
>
where
    V: AttemptAdmissionValidator + Clone + Send + Sync + 'static,
{
    prepare_owner_with_bootstrap(config, admission, |ownership, project| {
        ownership.bind_ledger_quota(&config.ledger_root, project)?;
        ownership.before_io()?;
        Ok(())
    })
}

fn prepare_owner_with_bootstrap<V>(
    config: &PackagedQemuExecutorConfig,
    admission: V,
    enter_io: impl FnOnce(
        &mut crate::executor_supervisor::ExecutorBootstrapResources,
        u32,
    ) -> Result<(), PackagedQemuExecutorError>,
) -> Result<
    (
        PreparedExecutorActor<DirectoryAssignmentLedger, V>,
        crate::HostOperationalRegistry,
    ),
    PackagedQemuExecutorError,
>
where
    V: AttemptAdmissionValidator + Clone + Send + Sync + 'static,
{
    use crate::executor_supervisor::{ExecutorBootstrapConfiguration, ExecutorBootstrapResources};
    use crucible_api::host_operational::HostOperationalError;

    #[cfg(feature = "private-measurement-domain")]
    let preparation_supervisor = if let Some(original) = &config.original_preparation {
        original.derive_supervisor(
            config
                .host_operation_budgets()
                .ok_or(HostOperationalError::Unavailable)?,
        )?
    } else {
        HostOperationSupervisor::new(
            config
                .host_operation_budgets()
                .ok_or(HostOperationalError::Unavailable)?,
            None,
        )
        .map_err(|_| HostOperationalError::Unavailable)?
    };
    #[cfg(not(feature = "private-measurement-domain"))]
    let preparation_supervisor = HostOperationSupervisor::new(
        config
            .host_operation_budgets()
            .ok_or(HostOperationalError::Unavailable)?,
        None,
    )
    .map_err(|_| HostOperationalError::Unavailable)?;
    let bootstrap = crucible_api::vm_lifecycle::HostRamBootstrapLimits::new(
        u64::from(config.host.maximum_tasks()),
        config.host.maximum_file_descriptors(),
        config.host.maximum_node_host_service_tasks(),
        config.host.maximum_node_host_service_file_descriptors(),
        config.host.maximum_node_host_service_resident_bytes(),
    )
    .map_err(|_| HostOperationalError::Unavailable)?;
    let registry_resources = config
        .operational_registry_resources()
        .ok_or(HostOperationalError::Unavailable)?;
    let (registry_project_id, registry_maximum_inodes) = config
        .operational_registry_quota()
        .ok_or(HostOperationalError::Unavailable)?;
    let mut registry_owner = blake3::Hasher::new();
    registry_owner.update(b"crucible.host.operational-registry-owner.v1\0");
    registry_owner.update(&config.daemon_epoch.as_bytes());
    let registry_owner = *registry_owner.finalize().as_bytes();
    let mut ownership = ExecutorBootstrapResources::new(ExecutorBootstrapConfiguration {
        capacity: config.capacity,
        operational_capacity: config.host_operational_capacity,
        assignment_resources: config
            .assignment_resources()
            .ok_or(HostOperationalError::Unavailable)?,
        assignment_limits: config
            .assignment_limits()
            .ok_or(HostOperationalError::Unavailable)?,
        watcher_resident_bytes: config.host.watcher_service_resident_bytes(),
        registry_owner,
        registry_resources,
        registry_maximum_inodes,
        preparation_supervisor: preparation_supervisor.clone(),
    })?;
    let startup_services = ownership.services()?;
    // The original complete account and finite scope exist before the ledger
    // can create its writer lock, retention record or any durable directory.
    enter_io(&mut ownership, registry_project_id)?;
    let ledger = DirectoryAssignmentLedger::open_with_boundary(&config.ledger_root, &mut || {
        ownership
            .boundary()
            .map_err(|source| AssignmentLedgerError::Io {
                operation: "check-original-startup-boundary",
                path: config.ledger_root.clone(),
                source: std::io::Error::other(source),
            })
    })?;
    let (supervisor, operation) = ownership.install(ledger, admission, config.daemon_epoch)?;
    let mut pending = PendingOriginalSupervisor {
        supervisor: Some(supervisor),
    };
    #[cfg(feature = "private-measurement-domain")]
    if config.original_preparation.is_some() {
        operation
            .wait_slice()
            .map_err(PackagedQemuExecutorError::OriginalPreparationBoundary)?;
    } else {
        operation
            .wait_slice()
            .map_err(|_| HostOperationalError::Unavailable)?;
    }
    #[cfg(not(feature = "private-measurement-domain"))]
    operation
        .wait_slice()
        .map_err(|_| HostOperationalError::Unavailable)?;
    let host_operational_registry = crate::HostOperationalRegistry::open_admitted_with_services(
        &config.ledger_root.join("host-control"),
        registry_owner,
        registry_resources,
        startup_services,
        Some(preparation_supervisor),
    )?;
    #[cfg(feature = "private-measurement-domain")]
    if config.original_preparation.is_some() {
        operation
            .wait_slice()
            .map_err(PackagedQemuExecutorError::OriginalPreparationBoundary)?;
    } else {
        operation
            .wait_slice()
            .map_err(|_| HostOperationalError::Unavailable)?;
    }
    #[cfg(not(feature = "private-measurement-domain"))]
    operation
        .wait_slice()
        .map_err(|_| HostOperationalError::Unavailable)?;
    host_operational_registry.configure_bootstrap_limits(bootstrap)?;
    pending.attach_registry(host_operational_registry.clone())?;
    #[cfg(feature = "private-measurement-domain")]
    if config.original_preparation.is_some() {
        operation
            .complete()
            .map_err(PackagedQemuExecutorError::OriginalPreparationBoundary)?;
    } else {
        operation
            .complete()
            .map_err(|_| HostOperationalError::Unavailable)?;
    }
    #[cfg(not(feature = "private-measurement-domain"))]
    operation
        .complete()
        .map_err(|_| HostOperationalError::Unavailable)?;
    let supervisor = pending
        .supervisor
        .take()
        .ok_or(HostOperationalError::Unavailable)?;
    let actor = PreparedExecutorActor::new(supervisor)?;
    Ok((actor, host_operational_registry))
}

/// Keeps original accounting and namespace locks when startup cannot prove cleanup.
struct PendingOriginalSupervisor<V> {
    supervisor: Option<LocalExecutorSupervisor<DirectoryAssignmentLedger, V>>,
}

impl<V> PendingOriginalSupervisor<V> {
    fn attach_registry(
        &mut self,
        registry: crate::HostOperationalRegistry,
    ) -> Result<(), crucible_api::host_operational::HostOperationalError> {
        // A refused attachment must leave the opened ledger and its original
        // complete account in this guard's uncertain-cleanup custody.
        self.supervisor
            .as_mut()
            .ok_or(crucible_api::host_operational::HostOperationalError::Unavailable)?
            .attach_host_operational_registry(registry)
    }
}

impl<V> Drop for PendingOriginalSupervisor<V> {
    fn drop(&mut self) {
        if let Some(supervisor) = self.supervisor.take() {
            std::mem::forget(supervisor);
        }
    }
}

/// Builds actor-only component fixtures without claiming physical quota admission.
#[cfg(test)]
pub(super) fn prepare_component_runtime(
    repository: &Arc<CampaignRepository>,
    checkpoint_backend: Arc<dyn ImmutableBlobBackend>,
    basis: &PackagedCampaignBasis,
    config: &PackagedQemuExecutorConfig,
) -> Result<PackagedPreparation, PackagedQemuExecutorError> {
    let admission = PackagedAttemptAdmission::new(
        repository.clone(),
        basis.profile.clone(),
        basis.scenarios.clone(),
    );
    let (actor, host_operational_registry) =
        prepare_owner_with_bootstrap(config, admission.clone(), |ownership, _project| {
            // This explicitly named component path tests original actor and
            // ledger custody. It makes no physical project-quota claim.
            ownership.before_component_io()?;
            Ok(())
        })?;
    let root_resources = crate::exact_checkpoint_store::test_support::fixture_ram_root_resources()
        .map_err(|_| crucible_api::host_operational::HostOperationalError::Unavailable)?;
    prepare_runtime_with_owner(
        repository,
        checkpoint_backend,
        basis,
        config,
        RuntimeOwnership {
            actor,
            host_operational_registry,
            admission,
            root_resources: Some(root_resources),
        },
    )
}

/// Runs one cold capture inside a real service reservation, then proves cleanup.
///
/// # Errors
/// Refuses malformed shapes, insufficient complete capacity, expired original
/// preparation supervision, capture failure, or incomplete physical cleanup.
/// An incomplete cleanup preserves the full service charge and primary error.
pub(super) fn run_capture<T>(
    preparation: &PackagedPreparation,
    config: &PackagedQemuExecutorConfig,
    scenario: &ScenarioDefForm,
    capture: impl FnOnce(&AttemptExecutionContext) -> Result<T, PackagedQemuExecutorError>,
) -> Result<T, PackagedQemuExecutorError> {
    #[cfg(feature = "private-measurement-domain")]
    if let Some(original) = &config.original_preparation {
        return run_original_capture(preparation, config, scenario, original, capture);
    }
    use crucible_api::host_operational::HostOperationalError;
    use crucible_api::vm_lifecycle::{
        ProductionHostRamLaunchShape, partition_host_ram_launch_resources,
    };

    // Cold capture has no queued execution input to install decoder custody.
    // Its host input/configuration copies belong to the original CatalogService
    // metadata account, as in ordinary campaign and interactive admission.
    // Active copies retain their child receipts after this lexical scope;
    // native node and watcher resources remain in the separate Service below.
    let decoding = crucible::owned_decode::DecodeBudget::for_store(
        preparation.checkpoints.metadata_resource_authority()?,
    )?;
    let _metadata_scope = decoding.enter();
    // Reserve the exact optional error box before capture effects. An expired
    // capture may still return a useful launch or checkpoint failure; its
    // storage keeps this original credit until the diagnostic's final drop.
    let expiry_cause_resources = decoding.reserve_scratch_array::<PackagedQemuExecutorError>(1)?;

    let ceiling = config
        .assignment_resources()
        .ok_or(HostOperationalError::Unavailable)?;
    let resources = config
        .assignment_limits()
        .ok_or(HostOperationalError::Unavailable)?;
    let watcher_resident_bytes = config.host.watcher_service_resident_bytes();
    if watcher_resident_bytes <= crate::supervision::HOST_WATCHDOG_STACK_BYTES as u64 {
        return Err(HostOperationalError::Unavailable.into());
    }
    // The immutable authored service peak includes its watcher. The native
    // node partition cannot consume that outside stack and bookkeeping owner.
    let mut node_ceiling = ceiling;
    node_ceiling.resident_peak_bytes = node_ceiling
        .resident_peak_bytes
        .checked_sub(watcher_resident_bytes)
        .ok_or(HostOperationalError::Unavailable)?;
    node_ceiling.task_slots = node_ceiling
        .task_slots
        .checked_sub(1)
        .ok_or(HostOperationalError::Unavailable)?;
    let physical_partition = AttemptResourceLimits::new(
        u32::try_from(node_ceiling.cpu_slots).map_err(|_| HostOperationalError::Unavailable)?,
        node_ceiling.resident_peak_bytes,
        node_ceiling.backing_peak_bytes,
        resources.maximum_execution_quanta(),
    )?;
    let shapes = scenario
        .world()
        .vm_nodes()
        .iter()
        .map(|node| {
            Ok(ProductionHostRamLaunchShape {
                node: node.id.name.clone(),
                declared_ram_bytes: u64::from(node.memory_mib)
                    .checked_mul(1024 * 1024)
                    .ok_or(HostOperationalError::Unavailable)?,
                vcpus: u32::from(node.smp_vcpus),
            })
        })
        .collect::<Result<Vec<_>, HostOperationalError>>()?;
    let bootstrap = preparation
        .host_operational_registry
        .bootstrap_limits()
        .ok_or(HostOperationalError::Unavailable)?;
    let requirements = crate::qemu_campaign_lifecycle::host_ram_launch_requirements(&shapes)?;
    let partition =
        partition_host_ram_launch_resources(&shapes, physical_partition, bootstrap, &requirements)
            .map_err(|_| HostOperationalError::Unavailable)?;
    if !partition.ceiling.fits(node_ceiling) {
        return Err(HostOperationalError::Unavailable.into());
    }

    let budgets = config
        .host_operation_budgets()
        .ok_or(HostOperationalError::Unavailable)?;
    let supervisor = HostOperationSupervisor::new(budgets, None).map_err(|error| {
        PackagedQemuExecutorError::PreparationSupervisor(std::io::Error::other(error))
    })?;
    let daemon =
        crate::host_operational_registry::operational_identity(config.daemon_epoch.as_bytes());
    let mut owner_hash = blake3::Hasher::new();
    owner_hash.update(b"crucible.host.preparation-owner.v1\0");
    owner_hash.update(&daemon);
    owner_hash.update(&supervisor.cap_id());
    let owner = *owner_hash.finalize().as_bytes();
    preparation.actor.with_supervisor(|actor| {
        actor.reserve_host_ram_service(owner, ceiling)?;
        if let Err(error) = actor.configure_host_ram_owner(daemon, owner, partition.ceiling) {
            // Configuration has not launched a node or watcher. Its actual
            // empty ledger permits rollback of this reservation.
            actor.release_host_ram_service_after_cleanup(owner)?;
            return Err(error);
        }
        Ok(())
    })?;

    let cancellation = ExecutionCancellation::default();
    let watchdog = AssignmentHostWatchdogGuard::start_preparation(supervisor, cancellation.clone());
    let mut watchdog = match watchdog {
        Ok(watchdog) => watchdog,
        Err(source) => {
            preparation
                .actor
                .with_supervisor(|actor| actor.release_host_ram_service_after_cleanup(owner))?;
            return Err(PackagedQemuExecutorError::PreparationSupervisor(source));
        }
    };
    let context = AttemptExecutionContext::for_preparation_service(
        resources,
        preparation.host_operational_registry.clone(),
        daemon,
        owner,
        watchdog.state.clone(),
        cancellation,
    );
    let result = context
        .map_err(PackagedQemuExecutorError::from)
        .and_then(|context| {
            let result = capture(&context)?;
            decoding.check()?;
            Ok(result)
        });
    let nodes_cleaned = preparation
        .actor
        .with_supervisor(|actor| actor.host_ram_service_nodes_cleaned(owner));
    if !matches!(nodes_cleaned, Ok(true)) {
        // The independently quarantined native owner may still access RAM.
        // Keep its original observer and the genuine charged actor alive even
        // if the caller drops the failed startup composition. A later daemon
        // cannot reopen this actor's still-owned ledger namespace.
        let custody = preparation.actor.preparation_custody();
        let _quarantined_for_process_lifetime = Box::leak(Box::new((custody, watchdog)));
        return Err(PackagedQemuExecutorError::PreparationCleanup {
            source: nodes_cleaned
                .err()
                .unwrap_or(HostOperationalError::Unavailable),
            preparation: result.err().map(Box::new),
        });
    }
    let expired = watchdog.stop();
    // Shutdown inside capture discharges each node only after reap, source joins,
    // descriptor closure and immutable lease cleanup. A refused release retains
    // the entire service and its original failure for containment diagnostics.
    let cleanup = preparation
        .actor
        .with_supervisor(|actor| actor.release_host_ram_service_after_cleanup(owner));
    if let Err(source) = cleanup {
        return Err(PackagedQemuExecutorError::PreparationCleanup {
            source,
            preparation: result.err().map(Box::new),
        });
    }
    failure::finish_capture(result, expired, expiry_cause_resources)
}

#[cfg(feature = "private-measurement-domain")]
fn run_original_capture<T>(
    preparation: &PackagedPreparation,
    config: &PackagedQemuExecutorConfig,
    scenario: &ScenarioDefForm,
    original: &crate::private_original_capture::OriginalPreparation,
    capture: impl FnOnce(&AttemptExecutionContext) -> Result<T, PackagedQemuExecutorError>,
) -> Result<T, PackagedQemuExecutorError> {
    use crucible_api::host_operational::HostOperationalError;
    use crucible_api::vm_lifecycle::{
        ProductionHostRamLaunchShape, partition_host_ram_launch_resources,
    };

    // Cold capture has no queued execution input to install decoder custody.
    // Its host input/configuration copies belong to the original CatalogService
    // metadata account, as in ordinary campaign and interactive admission.
    // Active copies retain their child receipts after this lexical scope;
    // native node and watcher resources remain in the separate Service below.
    let decoding = crucible::owned_decode::DecodeBudget::for_store(
        preparation.checkpoints.metadata_resource_authority()?,
    )?;
    let _metadata_scope = decoding.enter();
    // Reserve the exact optional error box before capture effects. An expired
    // capture may still return a useful launch or checkpoint failure; its
    // storage keeps this original credit until the diagnostic's final drop.
    let expiry_cause_resources =
        decoding.reserve_scratch_array::<failure::OriginalCaptureFailureBody>(1)?;
    let quarantine_resources =
        crate::private_original_capture::OriginalCaptureCustody::reserve(&decoding)?;
    let actor_custody = preparation.actor.preparation_custody();

    let ceiling = config
        .assignment_resources()
        .ok_or(HostOperationalError::Unavailable)?;
    let resources = config
        .assignment_limits()
        .ok_or(HostOperationalError::Unavailable)?;
    let watcher_resident_bytes = config.host.watcher_service_resident_bytes();
    if watcher_resident_bytes <= crate::supervision::HOST_WATCHDOG_STACK_BYTES as u64 {
        return Err(HostOperationalError::Unavailable.into());
    }
    // The immutable authored service peak includes its watcher. The native
    // node partition cannot consume that outside stack and bookkeeping owner.
    let mut node_ceiling = ceiling;
    node_ceiling.resident_peak_bytes = node_ceiling
        .resident_peak_bytes
        .checked_sub(watcher_resident_bytes)
        .ok_or(HostOperationalError::Unavailable)?;
    node_ceiling.task_slots = node_ceiling
        .task_slots
        .checked_sub(1)
        .ok_or(HostOperationalError::Unavailable)?;
    let physical_partition = AttemptResourceLimits::new(
        u32::try_from(node_ceiling.cpu_slots).map_err(|_| HostOperationalError::Unavailable)?,
        node_ceiling.resident_peak_bytes,
        node_ceiling.backing_peak_bytes,
        resources.maximum_execution_quanta(),
    )?;
    let shapes = scenario
        .world()
        .vm_nodes()
        .iter()
        .map(|node| {
            Ok(ProductionHostRamLaunchShape {
                node: node.id.name.clone(),
                declared_ram_bytes: u64::from(node.memory_mib)
                    .checked_mul(1024 * 1024)
                    .ok_or(HostOperationalError::Unavailable)?,
                vcpus: u32::from(node.smp_vcpus),
            })
        })
        .collect::<Result<Vec<_>, HostOperationalError>>()?;
    let bootstrap = preparation
        .host_operational_registry
        .bootstrap_limits()
        .ok_or(HostOperationalError::Unavailable)?;
    let requirements = crate::qemu_campaign_lifecycle::host_ram_launch_requirements(&shapes)?;
    let partition =
        partition_host_ram_launch_resources(&shapes, physical_partition, bootstrap, &requirements)
            .map_err(|_| HostOperationalError::Unavailable)?;
    if !partition.ceiling.fits(node_ceiling) {
        return Err(HostOperationalError::Unavailable.into());
    }

    let budgets = config
        .host_operation_budgets()
        .ok_or(HostOperationalError::Unavailable)?;
    let daemon =
        crate::host_operational_registry::operational_identity(config.daemon_epoch.as_bytes());
    let staged = match original.stage_capture(budgets, daemon) {
        Ok(staged) => staged,
        Err(start) => {
            return Err(failure::original_failure(
                failure::OriginalCaptureFailureBody {
                    capture: None,
                    start: Some(start),
                    completion: None,
                    watcher: None,
                    cleanup: None,
                    configuration_original: None,
                    release_original: None,
                },
                expiry_cause_resources,
            ));
        }
    };
    let owner = staged.service_owner();
    let mut custody = crate::private_original_capture::OriginalCaptureCustody::stage(
        actor_custody,
        original.clone(),
        quarantine_resources,
    );
    original
        .boundary()
        .map_err(PackagedQemuExecutorError::OriginalPreparationBoundary)?;
    let mut reserved = false;
    let configured = preparation.actor.with_supervisor(|actor| {
        actor.reserve_host_ram_service(owner, ceiling)?;
        custody.arm_reserved();
        reserved = true;
        actor.configure_host_ram_owner(daemon, owner, partition.ceiling)
    });
    let configured_original = original.boundary().err();
    if configured.is_err() || configured_original.is_some() {
        let (cleanup, release_original) = if reserved {
            release_original_service(preparation, owner, original)
        } else {
            (None, None)
        };
        if cleanup.is_none() && release_original.is_none() {
            custody.close();
        }
        return Err(failure::original_failure(
            failure::OriginalCaptureFailureBody {
                capture: configured.err().map(PackagedQemuExecutorError::from),
                start: None,
                completion: None,
                watcher: None,
                cleanup,
                configuration_original: configured_original,
                release_original,
            },
            expiry_cause_resources,
        ));
    }

    let cancellation = ExecutionCancellation::default();
    // The existing actor owns the full service before the real watcher starts.
    let (watchdog, state) = match staged.start(cancellation.clone()) {
        Ok(started) => started,
        Err(start) => {
            let (cleanup, release_original) =
                release_original_service(preparation, owner, original);
            if cleanup.is_none() && release_original.is_none() {
                custody.close();
            }
            return Err(failure::original_failure(
                failure::OriginalCaptureFailureBody {
                    capture: None,
                    start: Some(start),
                    completion: None,
                    watcher: None,
                    cleanup,
                    configuration_original: None,
                    release_original,
                },
                expiry_cause_resources,
            ));
        }
    };
    custody.attach_watchdog(watchdog);
    let context = AttemptExecutionContext::for_preparation_service(
        resources,
        preparation.host_operational_registry.clone(),
        daemon,
        owner,
        state,
        cancellation,
    );
    let result = context
        .map_err(PackagedQemuExecutorError::from)
        .and_then(|context| {
            let result = capture(&context)?;
            decoding.check()?;
            Ok(result)
        });
    let nodes_cleaned = preparation
        .actor
        .with_supervisor(|actor| actor.host_ram_service_nodes_cleaned(owner));
    if !matches!(nodes_cleaned, Ok(true)) {
        // The armed owner transfers its already-prepaid body on this refusal
        // or unwinding, retaining the same actor and actual watcher/guard.
        let watcher = custody.first_refusal();
        return Err(failure::original_failure(
            failure::OriginalCaptureFailureBody {
                capture: result.err(),
                start: None,
                completion: None,
                watcher,
                cleanup: Some(
                    nodes_cleaned
                        .err()
                        .unwrap_or(HostOperationalError::Unavailable),
                ),
                configuration_original: None,
                release_original: original.boundary().err(),
            },
            expiry_cause_resources,
        ));
    }
    let completion = custody.finish().ok_or(HostOperationalError::Unavailable)?;
    let (cleanup, release_original) = release_original_service(preparation, owner, original);
    if cleanup.is_none() && release_original.is_none() {
        custody.close();
    }
    failure::finish_original_capture(
        result,
        completion,
        cleanup,
        release_original,
        expiry_cause_resources,
    )
}

#[cfg(feature = "private-measurement-domain")]
fn release_original_service(
    preparation: &PackagedPreparation,
    owner: [u8; 32],
    original: &crate::private_original_capture::OriginalPreparation,
) -> (
    Option<crucible_api::host_operational::HostOperationalError>,
    Option<crucible_linux_resource::host_supervision::HostSupervisionError>,
) {
    if let Err(before) = original.boundary() {
        return (None, Some(before));
    }
    let cleanup = preparation
        .actor
        .with_supervisor(|actor| actor.release_host_ram_service_after_cleanup(owner))
        .err();
    // Retain the actual kernel/account outcome first, then sample the SAME
    // original even on refusal. Cleanup cannot renew the enclosing interval.
    let after = original.boundary().err();
    (cleanup, after)
}
