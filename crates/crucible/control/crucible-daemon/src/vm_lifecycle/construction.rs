//! Ordered production lifecycle assembly and rollback-safe owner admission.
//!
//! Construction validates the source and restore basis, launches each node,
//! assembles scheduler and fault continuations, then transfers the complete
//! resource set into the lifecycle. Keeping the transaction together makes
//! early-return cleanup and the final ownership transfer auditable.

use super::*;
mod custody;
mod retained_debug;
pub(super) use retained_debug::RetainedDebugConstruction;
#[cfg(target_os = "linux")]
mod returned;
#[cfg(target_os = "linux")]
pub use returned::{MainSourceLifecycle, MainSourceLifecycleFailure, MainSourceLifecycleRefusal};
#[cfg(target_os = "linux")]
mod publication;
pub(super) use custody::with_inputs as retain_construction_inputs;
pub use custody::{
    ProductionVmCleanupEarlierFailure, ProductionVmConstructionCleanupError,
    ProductionVmConstructionCustody, ProductionVmConstructionFailure,
};
mod branch_sequence;
pub(super) use branch_sequence::validate_configured_branch_sequence;
use branch_sequence::{configured_branches, first_configured_branch};

#[cfg(test)]
#[path = "construction_tests.rs"]
mod tests;

fn hydrate_checkpoint_event_log_dependencies(
    scheduler: &SingleSchedulerCheckpoint,
    objects: &BTreeMap<ContentHash, Vec<u8>>,
    store: &dyn DagStore,
) -> Result<(), LifecycleApiError> {
    let dependencies = scheduler.event_log_segment_dependencies();
    if dependencies.len() != objects.len() {
        return Err(loop_factory_error(
            "exact checkpoint event-log dependency count changed before restore",
        ));
    }

    // Validate the entire authenticated set before writing into the new run.
    for identity in dependencies {
        let bytes = objects.get(identity).ok_or_else(|| {
            loop_factory_error("exact checkpoint event-log dependency is missing before restore")
        })?;
        if ContentHash::from_bytes(bytes) != *identity {
            return Err(loop_factory_error(
                "exact checkpoint event-log dependency changed before restore",
            ));
        }
    }

    for identity in dependencies {
        let bytes = objects.get(identity).ok_or_else(|| {
            loop_factory_error("exact checkpoint event-log dependency disappeared during restore")
        })?;
        let stored = store.put(bytes).map_err(|error| {
            loop_factory_error(format!(
                "rehydrate exact checkpoint event-log dependency: {error}"
            ))
        })?;
        if stored != *identity {
            return Err(loop_factory_error(
                "exact checkpoint event-log dependency changed while rehydrating",
            ));
        }
    }

    Ok(())
}

pub(super) fn hydrate_checkpoint_signal_artifacts(
    objects: &BTreeMap<ContentHash, Vec<u8>>,
    store: &dyn DagStore,
) -> Result<(), LifecycleApiError> {
    // Validate every identity before exposing any bytes to the resumed run.
    for (identity, bytes) in objects {
        if ContentHash::from_bytes(bytes) != *identity {
            return Err(loop_factory_error(
                "exact checkpoint signal artifact changed before restore",
            ));
        }
    }

    for (identity, bytes) in objects {
        let stored = store.put(bytes).map_err(|error| {
            loop_factory_error(format!(
                "rehydrate exact checkpoint signal artifact: {error}"
            ))
        })?;
        if stored != *identity {
            return Err(loop_factory_error(
                "exact checkpoint signal artifact changed while rehydrating",
            ));
        }
    }

    Ok(())
}

fn reject_fresh_fault_replay_on_restore(
    restoring: bool,
    replay: Option<&SignalFaultCampaignReplayPlan>,
) -> Result<(), LifecycleApiError> {
    if restoring && replay.is_some_and(|replay| !replay.branches().is_empty()) {
        return Err(loop_factory_error(
            "exact-checkpoint restore cannot install a fresh signal-fault replay plan",
        ));
    }
    Ok(())
}

pub(super) fn build_production_vm_lifecycle_loop_with_restore(
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    config: &ProductionVmLifecycleConfig,
    restore_checkpoint: Option<ProductionVmExactCheckpointSet>,
    node_launcher: Box<dyn ProductionVmNodeLauncher>,
    hot_fork_restore: Option<ProductionVmHotForkRestore>,
) -> Result<ProductionVmLifecycleLoop, ProductionVmConstructionFailure> {
    build_production_vm_lifecycle_loop_with_restore_exposure(
        scenario,
        source,
        config,
        restore_checkpoint,
        node_launcher,
        hot_fork_restore,
        ExactRestoreExposure::Released,
    )
}

/// Physical preparation does not change the checkpoint's logical node states.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExactRestoreExposure {
    /// Applies each restored node's logical running or paused disposition.
    Released,
    /// Keeps every reconstructed live node stopped until ownership commits.
    AwaitingOwnershipCommit,
}

impl ExactRestoreExposure {
    fn physical_pause(self, state: ProductionNodeServiceState) -> Result<bool, LifecycleApiError> {
        // Validate the logical disposition before overriding the physical
        // pause. A failed logical target cannot become restorable by transfer.
        let logical_pause = restored_node_paused(state)?;
        Ok(logical_pause || self == Self::AwaitingOwnershipCommit)
    }
}

pub(super) fn build_production_vm_lifecycle_loop_with_restore_exposure(
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    config: &ProductionVmLifecycleConfig,
    restore_checkpoint: Option<ProductionVmExactCheckpointSet>,
    node_launcher: Box<dyn ProductionVmNodeLauncher>,
    hot_fork_restore: Option<ProductionVmHotForkRestore>,
    exposure: ExactRestoreExposure,
) -> Result<ProductionVmLifecycleLoop, ProductionVmConstructionFailure> {
    let custody = retain_construction_inputs(
        node_launcher,
        restore_checkpoint,
        hot_fork_restore,
        None,
        Vec::new(),
    )?;
    build_from_custody(scenario, source, config, custody, exposure)
}

pub(super) fn build_from_custody(
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    config: &ProductionVmLifecycleConfig,
    mut custody: Box<ProductionVmConstructionCustody>,
    exposure: ExactRestoreExposure,
) -> Result<ProductionVmLifecycleLoop, ProductionVmConstructionFailure> {
    if let Err(first) = prepare_from_custody(scenario, source, config, &mut custody, exposure) {
        return Err(custody.into_failure(first));
    }
    custody.into_loop().map_err(|custody| {
        custody.into_failure(loop_factory_error(
            "construction lost its complete lifecycle",
        ))
    })
}

/// Prepares a World while its containing owner retains the original carrier.
///
/// The caller installs all inputs before entry and keeps this carrier in its
/// admitted slot through every callback. Only successful validation permits
/// the separate, move-only transfer of its completed lifecycle.
///
/// # Errors
/// Retains the actual partial or complete phase when preparation, assembly or
/// initial debugger evidence fails. The caller retains the original cause.
pub(crate) fn prepare_from_custody(
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    config: &ProductionVmLifecycleConfig,
    custody: &mut ProductionVmConstructionCustody,
    exposure: ExactRestoreExposure,
) -> Result<(), LifecycleApiError> {
    let phase = custody.preparation_phase()?;
    let assemble = prepare_construction(scenario, source, config, phase, exposure)?;
    custody.complete_with(assemble)?;

    // Restore validation runs on the same complete retained lifecycle.
    custody
        .complete_mut()?
        .capture_debug_runtime_evidence()
        .map_err(|error| {
            loop_factory_error(format!(
                "capture initial debugger runtime evidence: {error}"
            ))
        })
}

fn prepare_construction(
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    config: &ProductionVmLifecycleConfig,
    phase: &mut custody::Partial,
    exposure: ExactRestoreExposure,
) -> Result<
    impl FnOnce(custody::Partial) -> Result<ProductionVmLifecycleLoop, custody::Partial> + use<>,
    LifecycleApiError,
> {
    if source.scenario_def() != *scenario {
        return Err(loop_factory_error(
            "production source does not reconstruct the requested scenario",
        ));
    }
    if exposure == ExactRestoreExposure::AwaitingOwnershipCommit
        && (phase.restore_checkpoint.is_none() || phase.hot_fork_restore.is_some())
    {
        return Err(loop_factory_error(
            "maintenance ownership preparation requires one complete exact restore",
        ));
    }
    if !cfg!(target_os = "linux") {
        return Err(loop_factory_error(
            "production local-QEMU lifecycle requires a Linux host",
        ));
    }

    let _retained_input_scope = if crucible_engine::owned_decode::current_custody().is_none() {
        config.enter_input_custody()
    } else {
        None
    };
    // Configuration ownership is admitted before any native launch effects.
    if phase.retained_config.is_none() {
        phase.retained_config = Some(config.try_clone_shared_admitted()?);
    }
    let retained_config = phase
        .retained_config
        .as_ref()
        .ok_or_else(|| loop_factory_error("construction lost its admitted configuration"))?;
    // Runtime replay buffers live as long as this world, so their copies use
    // the returned world's account rather than the caller's transient scope.
    let _world_input_scope = retained_config.enter_input_custody();
    phase.input_decode_custody = crucible_engine::owned_decode::current_custody();

    if config.branch.is_some() && !config.continuation_branches.is_empty() {
        return Err(loop_factory_error(
            "single and ordered production branch configurations cannot coexist",
        ));
    }
    if first_configured_branch(config).is_some()
        && config.signal_fault_replay.as_ref().is_some_and(|replay| {
            !replay.branches().is_empty() || !replay.network_branches().is_empty()
        })
    {
        return Err(loop_factory_error(
            "raw production branch configuration cannot coexist with typed fault replay",
        ));
    }
    if let Some(replay) = &config.signal_fault_replay
        && replay.target().def.id() != scenario.id()
    {
        return Err(loop_factory_error(
            "signal-fault replay target names a different scenario",
        ));
    }
    reject_fresh_fault_replay_on_restore(
        phase.restore_checkpoint.is_some(),
        config.signal_fault_replay.as_ref(),
    )?;
    let network_implementations = fault_implementation::network_effect_implementation_registry()
        .map_err(|error| {
            loop_factory_error(format!(
                "validate production network fault registry: {error}"
            ))
        })?;
    let storage_implementations = fault_implementation::storage_effect_implementation_registry()
        .map_err(|error| {
            loop_factory_error(format!(
                "validate production storage fault registry: {error}"
            ))
        })?;
    let host_fault_manifests = HostFaultAdapterManifests::from_registries(
        &network_implementations,
        &storage_implementations,
    )
    .map_err(|error| {
        loop_factory_error(format!(
            "derive production host fault capabilities from implementations: {error}"
        ))
    })?;
    let checkpoint_dag =
        checkpoint_store::checkpoint_dag_store(&config.run_state_root, scenario.id());
    if let Some(checkpoint) = &phase.restore_checkpoint
        && (checkpoint.configuration.def.id() != scenario.id()
            || checkpoint.configuration.id()
                != checkpoint
                    .scheduler
                    .configuration_for(scenario)
                    .map_err(|error| {
                        loop_factory_error(format!(
                            "decode production scheduler checkpoint: {error}"
                        ))
                    })?
                    .id())
    {
        return Err(loop_factory_error(
            "production exact checkpoint does not match the requested scenario and scheduler configuration",
        ));
    }
    if let Some(checkpoint) = &phase.restore_checkpoint {
        hydrate_checkpoint_event_log_dependencies(
            &checkpoint.scheduler,
            &checkpoint.event_log_objects,
            checkpoint_dag.as_ref(),
        )?;
    }
    let nodes = source.world().vm_nodes();
    // Reject incompatible per-node initrd identities before launching any VM.
    for vm in nodes {
        selected_initrd_for_vm(vm, config)?;
    }
    let cold_branches = configured_branches(config).cloned().collect::<Vec<_>>();
    validate_configured_branch_sequence(scenario, &cold_branches)?;
    validate_app_random_branch_replay_config(nodes, config)?;
    if let Some(checkpoint) = phase.restore_checkpoint.as_ref() {
        let expected_selectable_nodes = nodes
            .iter()
            .filter(|node| {
                checkpoint.node_service_states.get(&node.id)
                    != Some(&ProductionNodeServiceState::PermanentlyFailed)
                    && source
                        .selectables()
                        .guest_declarations(&node.id)
                        .next()
                        .is_some()
            })
            .map(|node| node.id.clone())
            .collect::<BTreeSet<_>>();
        if checkpoint
            .selectable_catalog_plans
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
            != expected_selectable_nodes
        {
            return Err(loop_factory_error(
                "production exact checkpoint selectable catalog node set differs from the scenario",
            ));
        }
    }
    if nodes.is_empty() {
        return Err(loop_factory_error("scenario World has no VM nodes"));
    }
    if config.run_ceiling_ticks == 0
        || config.quantum_budget == 0
        || config.maximum_host_workers == 0
        || config.maximum_host_workers > quantum_loop::MAX_PRODUCTION_QEMU_HOST_WORKERS
        || config.rendezvous_interval_ticks == Some(0)
    {
        return Err(loop_factory_error(
            "production QEMU lifecycle bounds must be nonzero",
        ));
    }
    if let Some(debug) = &config.debug
        && debug
            .node
            .as_ref()
            .is_some_and(|selected| !nodes.iter().any(|vm| vm.id.name == *selected))
    {
        return Err(loop_factory_error(format!(
            "debug node `{}` is not declared by the scenario World",
            debug.node.as_deref().unwrap_or_default()
        )));
    }
    if config.debug.is_some() && config.debug_gateway_executable.is_none() {
        return Err(loop_factory_error(
            "production QEMU debugging requires a standalone debugger gateway executable",
        ));
    }
    let mut bounded_scheduler_preemption =
        config
            .claim_bounded_scheduler_preemption()
            .map_err(|error| {
                loop_factory_error(format!(
                    "claim bounded scheduler-preemption evidence: {error}"
                ))
            })?;

    if let Some(factory) = &config.host_ram_registration_factory {
        let shape_budget = crucible_engine::owned_decode::current_child_budget()
            .map_err(LifecycleApiError::ConfigurationCopy)?;
        let _shape_scope = shape_budget
            .as_ref()
            .map(crucible_engine::owned_decode::DecodeBudget::enter);
        let mut shapes = Vec::new();
        crucible_engine::owned_decode::reserve_vec(&mut shapes, nodes.len())
            .map_err(LifecycleApiError::ConfigurationCopy)?;
        for vm in nodes {
            let declared_ram_bytes = u64::from(vm.memory_mib)
                .checked_mul(1024 * 1024)
                .ok_or_else(|| loop_factory_error("declared guest RAM overflow"))?;
            crucible_engine::owned_decode::charge_bytes(vm.id.name.len() as u64)
                .map_err(LifecycleApiError::ConfigurationCopy)?;
            shapes.push(ProductionHostRamLaunchShape {
                node: vm.id.name.clone(),
                declared_ram_bytes,
                vcpus: u32::from(vm.smp_vcpus),
            });
        }
        factory
            .configure_world(&shapes)
            .map_err(|error| loop_factory_error(error.to_string()))?;
    }

    let (run_directory, mut run_manifest, lifecycle_journal) = production_run_directory(
        scenario,
        config,
        source.plan().fault_signals().resource_limits(),
    )?;
    phase.run_directory = Some(run_directory);
    let run_directory = phase
        .run_directory
        .as_ref()
        .ok_or_else(|| loop_factory_error("construction lost its admitted run directory"))?;
    let checkpoint_targets = checkpoint_recovery::recover_published_checkpoint_states(
        &config.run_state_root,
        scenario,
        source,
        config.ram_catalog_provider(),
    )?;
    run_manifest
        .processes
        .try_reserve_exact(nodes.len())
        .map_err(|()| loop_factory_error("reserve initial QEMU process ownership"))?;
    phase.backends = Some(QemuNodeSet::new());
    let mut backends = phase
        .backends
        .as_mut()
        .ok_or_else(|| loop_factory_error("construction lost its backend set"))?;
    let node_launcher = phase
        .node_launcher
        .as_mut()
        .ok_or_else(|| loop_factory_error("construction lost its retained launcher"))?;

    let mut block_bindings = BTreeMap::new();
    let mut ninep_bindings = BTreeMap::new();
    let mut node_indexes = BTreeMap::new();
    let mut node_run_directories = BTreeMap::new();

    let mut node_service_states = BTreeMap::new();
    let mut immutable_root_images = BTreeMap::new();

    let mut hot_fork_backing_files = BTreeMap::new();
    let mut debug_backend_paths = BTreeMap::new();
    let mut initial_ticks = None;
    phase.repository_restore = phase
        .restore_checkpoint
        .as_mut()
        .and_then(|checkpoint| checkpoint.repository_restore.take());
    #[cfg(any(test, feature = "test-support"))]
    if let Some(authority) = phase.repository_restore.as_mut() {
        authority.ram_source_decorator = config.ram_source_decorator.clone();
    }
    let mut repository_parent_targets = BTreeMap::new();
    let scenario_seed = scenario.seed().bytes();
    let mut launch_seed_bytes = [0_u8; 8];
    launch_seed_bytes.copy_from_slice(&scenario_seed[..8]);
    let launch_seed = u64::from_le_bytes(launch_seed_bytes);
    let network_declaration = crucible_engine::NetworkFaultSelectable::declaration()
        .map_err(|error| loop_factory_error(format!("admit network choice schema: {error}")))?;
    let declared_network = source.selectables().declaration(network_declaration.name());
    if declared_network.is_some() && declared_network != Some(&network_declaration) {
        return Err(loop_factory_error(
            "network choice declaration differs from its production schema",
        ));
    }
    let campaign_marker_parking = declared_network.is_some();
    for (index, vm) in nodes.iter().enumerate() {
        let guest_assets = config.guest_assets.get(&vm.arch).ok_or_else(|| {
            loop_factory_error(format!(
                "production QEMU lifecycle has no boot artifacts for {:?}",
                vm.arch
            ))
        })?;
        validate_guest_asset_references(vm, guest_assets)?;
        let immutable_root_image = hash_file(&guest_assets.root_image).map_err(|error| {
            loop_factory_error(format!(
                "hash immutable root image for production node `{}` from {}: {error}",
                vm.id.name,
                guest_assets.root_image.display()
            ))
        })?;
        let node_directory = run_directory.path().join(format!("node-{index}"));
        let restore_target = phase
            .restore_checkpoint
            .as_ref()
            .and_then(|checkpoint| checkpoint.targets.get(&vm.id));
        let hot_fork_expected_time = phase
            .hot_fork_restore
            .as_mut()
            .and_then(|restore| restore.expected_times.remove(&vm.id));
        phase.pending_adoption = phase
            .hot_fork_restore
            .as_mut()
            .and_then(|restore| restore.adoptions.remove(&vm.id));
        let hot_fork_immutable_root = phase
            .hot_fork_restore
            .as_mut()
            .and_then(|restore| restore.immutable_root_images.remove(&vm.id));
        let hot_fork_disk_basis = phase
            .hot_fork_restore
            .as_mut()
            .and_then(|restore| restore.disk_bases.remove(&vm.id));
        let restored_service_state = phase
            .restore_checkpoint
            .as_ref()
            .and_then(|checkpoint| checkpoint.node_service_states.get(&vm.id))
            .copied();
        if phase.restore_checkpoint.is_some()
            && restore_target.is_none()
            && phase.pending_adoption.is_none()
            && restored_service_state != Some(ProductionNodeServiceState::PermanentlyFailed)
        {
            return Err(loop_factory_error(format!(
                "production restore has no exact or hot-fork target for `{}`",
                vm.id.name
            )));
        }
        let repository_parent_identity = if let Some(target) = restore_target {
            let fault_checkpoint = phase
                .restore_checkpoint
                .as_ref()
                .and_then(|checkpoint| checkpoint.fault_checkpoint.as_ref())
                .ok_or_else(|| {
                    loop_factory_error("exact checkpoint target lost its fault continuation")
                })?;
            let fault_identity = fault_checkpoint.id();
            let fault_manifest_identity = exact_checkpoint_fault_object_identity(
                fault_checkpoint,
                source.plan().fault_signals().resource_limits(),
            )?;
            let snapshot_identity = exact_checkpoint_snapshot_object_identity(
                &target.snapshot,
                source.plan().fault_signals().resource_limits(),
            )?;
            validate_exact_checkpoint_target(
                &vm.id,
                target,
                fault_manifest_identity,
                snapshot_identity,
            )?;
            let checkpoint_set = phase.restore_checkpoint.as_ref().ok_or_else(|| {
                loop_factory_error("exact RAM restore lost its authenticated checkpoint set")
            })?;
            let expected = exact_ram_checkpoint_qmp_identity(ExactRamCheckpointQmpIdentityBasis {
                configuration: &target.configuration,
                immutable_backing: target.immutable_backing,
                node: &vm.id,
                counter: target.counter,
                scheduler_time: target.scheduler_time,
                checkpoint: target.snapshot.checkpoint(),
                fault_identity,
                scheduler: &checkpoint_set.scheduler,
            })
            .map_err(|error| {
                loop_factory_error(format!(
                    "derive paged exact restore identity for `{}`: {error}",
                    vm.id.name
                ))
            })?;
            if let Some(exact_ram) = target.native_exact_ram()
                && QmpCheckpointIdentity::from(exact_ram.identity) != expected
            {
                return Err(loop_factory_error(format!(
                    "paged exact checkpoint identity for `{}` differs from its authenticated restore basis",
                    vm.id.name
                )));
            }
            if target.immutable_backing != immutable_root_image {
                return Err(loop_factory_error(format!(
                    "production exact checkpoint for `{}` names immutable backing {} but the selected root image hashes to {}",
                    vm.id.name,
                    target.immutable_backing.to_hex(),
                    immutable_root_image.to_hex()
                )));
            }
            matches!(
                &target.materialization,
                ProductionVmExactCheckpointMaterialization::Unmaterialized
            )
            .then_some(expected)
        } else {
            None
        };
        if phase.hot_fork_restore.is_some() {
            let expected = hot_fork_immutable_root.ok_or_else(|| {
                loop_factory_error(format!(
                    "hot-fork continuation has no immutable root identity for `{}`",
                    vm.id.name
                ))
            })?;
            if expected != immutable_root_image {
                return Err(loop_factory_error(format!(
                    "hot-fork continuation for `{}` names immutable backing {} but the retained root image hashes to {}",
                    vm.id.name,
                    expected.to_hex(),
                    immutable_root_image.to_hex()
                )));
            }
            if let Some(basis) = hot_fork_disk_basis {
                let mut files = basis
                    .reopen_current(immutable_root_image)
                    .map_err(|error| {
                        loop_factory_error(format!(
                            "recheck hot-fork child disk basis for `{}`: {error}",
                            vm.id.name
                        ))
                    })?;
                hot_fork_backing_files.insert(vm.id.clone(), basis.immutable_backing_chain());
                phase.retained_hot_fork_disk_files.append(&mut files);
            } else if !cfg!(any(test, feature = "test-support")) {
                return Err(loop_factory_error(format!(
                    "rooted hot-fork child `{}` has no sealed current disk basis",
                    vm.id.name
                )));
            }
        }
        immutable_root_images.insert(vm.id.clone(), immutable_root_image);
        let kernel_cmdline_prefix = production_kernel_cmdline_prefix(config, vm.arch, guest_assets);
        let kernel_cmdline = match kernel_cmdline_prefix {
            Some(prefix) if !prefix.trim().is_empty() => {
                format!("{} {}", prefix.trim(), vm.cmdline.trim())
            }
            _ => vm.cmdline.clone(),
        };
        let whitebox = production_whitebox_switch(vm.white_box);
        let generation = phase
            .restore_checkpoint
            .as_ref()
            .and_then(|checkpoint| checkpoint.node_generations.get(&vm.id))
            .copied()
            .unwrap_or(1);
        let qemu_executable = production_qemu_executable(&config.executable, vm.arch);
        let mut launch = QemuLiveNodeStepGateConfig::new_with_root_image(
            &qemu_executable,
            &config.plugin,
            &guest_assets.kernel,
            &guest_assets.root_image,
            &node_directory,
        )
        .with_guest_architecture(production_guest_architecture(vm.arch))
        .with_root_image_format(config.root_image_format)
        .with_kernel_cmdline(kernel_cmdline)
        .with_vm_shape(vm.memory_mib, vm.smp_vcpus)
        .with_scenario_seed(launch_seed)
        .with_whitebox(whitebox)
        .with_coverage(config.coverage)
        .with_fingerprint(crucible_qemu_host::QemuLaunchPluginSwitch::On)
        .with_queue_capacity(PRODUCTION_QUEUE_CAPACITY)
        .with_completion_timeout(config.completion_timeout)
        .with_unbounded_advance_completion(config.unbounded_advance_completion)
        .with_console_capture()
        .with_process_generation(generation)
        .with_fault_resource_limits(source.plan().fault_signals().resource_limits());
        if let Some(supervisor) = &config.host_operation_supervisor {
            launch = launch.with_host_operation_supervisor(supervisor.clone());
        }
        if let Some(factory) = &config.host_ram_registration_factory {
            let declared_ram_bytes = u64::from(vm.memory_mib)
                .checked_mul(1024 * 1024)
                .ok_or_else(|| loop_factory_error(String::from("declared guest RAM overflow")))?;
            let registration = factory
                .prepare(
                    &vm.id.name,
                    generation,
                    declared_ram_bytes,
                    u32::from(vm.smp_vcpus),
                )
                .map_err(|error| loop_factory_error(error.to_string()))?;
            launch = launch.with_ram_control_registration(registration);
        }
        phase.launch_configs.insert(vm.id.clone(), launch.clone());
        #[cfg(any(test, feature = "test-support"))]
        if let Some(entitlement) = config.fault_actor_test_entitlement {
            launch = launch
                .with_fault_actor_test_entitlement(entitlement)
                .map_err(|source| {
                    loop_factory_error(format!("authorize fault worker fixture: {source}"))
                })?;
        }
        if campaign_marker_parking {
            if vm.white_box != crucible_engine::WhiteBoxPolicy::Enabled {
                return Err(loop_factory_error(format!(
                    "network campaign VM `{}` requires authenticated guest markers",
                    vm.id.name
                )));
            }
            launch = launch.with_campaign_marker_parking();
        }
        // Reserve the existing fixed trace ceiling before guarded admission.
        // Only the explicit diagnostic opt-in reaches the plugin child.
        let control_callback_witness = std::env::var_os("CRUCIBLE_CONTROL_CALLBACK_WITNESS")
            .as_deref()
            == Some(std::ffi::OsStr::new("1"));
        if campaign_marker_parking || config.rr_control_boundary_trace || control_callback_witness {
            launch = launch.with_rr_control_boundary_trace();
        }
        if let Some(capabilities) = source
            .world()
            .fault_topology()
            .node_capabilities
            .iter()
            .find(|capabilities| capabilities.node.as_str() == vm.id.name.as_str())
        {
            if !capabilities.ready_markers.is_empty()
                && vm.white_box != crucible_engine::WhiteBoxPolicy::Enabled
            {
                return Err(loop_factory_error(format!(
                    "QEMU node `{}` declares guest ready markers but its authenticated white-box guest event channel is disabled",
                    vm.id.name
                )));
            }
            launch = launch.with_fault_capabilities(capabilities.clone());
            if !capabilities.accelerators.is_empty() {
                launch = launch.with_accelerator();
            }
        }
        if vm.white_box == crucible_engine::WhiteBoxPolicy::Enabled {
            let declarations = source
                .selectables()
                .guest_declarations(&vm.id)
                .map(|declaration| {
                    crucible_qemu_protocol::selectable_catalog_plan::SelectablePlanDeclaration::new(
                        declaration.name(),
                        declaration.domain().canonical_bytes(),
                        declaration.default().canonical_bytes(),
                        declaration.semantic_tags().iter().cloned().collect(),
                        if declaration.required() {
                            crucible_qemu_protocol::selectable_catalog_plan::SelectablePlanPresence::Required
                        } else {
                            crucible_qemu_protocol::selectable_catalog_plan::SelectablePlanPresence::Optional
                        },
                    )
                    .map_err(|error| {
                        loop_factory_error(format!(
                            "convert scenario selectable `{}` for `{}`: {error}",
                            declaration.name(), vm.id.name
                        ))
                    })
            })
            .collect::<Result<Vec<_>, LifecycleApiError>>()?;
            if !declarations.is_empty() {
                let limits = source.selectables().limits();
                let limits =
                    crucible_qemu_protocol::selectable_catalog_plan::SelectablePlanLimits::new(
                        limits.declarations_per_node() as usize,
                        limits.requests_per_selectable(),
                        limits.requests_per_node(),
                    )
                    .map_err(|error| {
                        loop_factory_error(format!(
                            "convert scenario selectable limits for `{}`: {error}",
                            vm.id.name
                        ))
                    })?;
                let cold_plan =
                    crucible_qemu_protocol::selectable_catalog_plan::SelectableCatalogPlan::new(
                    limits,
                    declarations,
                    crucible_qemu_protocol::selectable_catalog_plan::SelectablePlanContinuation::cold(),
                )
                .map_err(|error| {
                    loop_factory_error(format!(
                        "build scenario selectable catalog for `{}`: {error}",
                        vm.id.name
                    ))
                })?;
                let plan = if let Some(checkpoint) = phase.restore_checkpoint.as_ref()
                    && restored_service_state != Some(ProductionNodeServiceState::PermanentlyFailed)
                {
                    let restored = checkpoint.selectable_catalog_plans.get(&vm.id).ok_or_else(
                        || {
                            loop_factory_error(format!(
                                "exact checkpoint has no selectable catalog continuation for `{}`",
                                vm.id.name
                            ))
                        },
                    )?;
                    if restored.limits() != cold_plan.limits()
                        || restored.declarations() != cold_plan.declarations()
                        || !selectable_catalog_checkpoint_ready(
                            &checkpoint.configuration,
                            checkpoint.initial_lifecycle_observations_pending,
                            checkpoint.scheduler.event_log_offset().events,
                            restored,
                        )
                    {
                        return Err(loop_factory_error(format!(
                            "exact checkpoint selectable catalog basis differs for `{}`",
                            vm.id.name
                        )));
                    }
                    restored.clone()
                } else {
                    cold_plan
                };
                launch = launch.with_selectable_catalog_plan(plan);
            }
            let app_random = if let Some(checkpoint) = &phase.restore_checkpoint {
                production_app_random_checkpoint_config(
                    &checkpoint.scheduler,
                    scenario,
                    checkpoint.branch.as_slice(),
                    &vm.id,
                )
                .map_err(|error| {
                    loop_factory_error(format!(
                        "restore app-random continuation for `{}`: {error}",
                        vm.id.name
                    ))
                })?
            } else {
                production_app_random_launch_config(scenario, &cold_branches, &vm.id)
            }
            .with_branch_plan(
                config
                    .app_random_branch_plans
                    .get(&vm.id)
                    .cloned()
                    .unwrap_or_default(),
            );
            launch = launch.with_app_random(app_random);
        }
        if !source.world().links().is_empty() {
            launch = launch
                .with_shmem_network_mac(crucible_engine::deterministic_node_mac_string(&vm.id));
        }
        if let Some(target) = restore_target {
            let next_sequence = u32::try_from(
                target
                    .snapshot
                    .node_continuation()
                    .next_plugin_network_output_sequence(),
            )
            .map_err(|_error| {
                loop_factory_error(format!(
                    "restored network TX sequence for `{}` exceeds the plugin ABI",
                    vm.id.name
                ))
            })?;
            launch = launch.with_network_tx_next_sequence(next_sequence);
        }
        let block = if let Some(restore) = phase.hot_fork_restore.as_mut() {
            restore.block_bindings.remove(&vm.id)
        } else {
            block_binding_for_vm(source.world(), &vm.id, config.world_artifacts.as_ref())?
        };
        if let Some(block) = block {
            let queue_binding = crucible_qemu_host::QemuWorldIoBinding::from_world(
                source.world(),
                block.queue.node_for_world(source.world())?,
            )
            .map_err(|error| loop_factory_error(error.to_string()))?;

            if restored_service_state != Some(ProductionNodeServiceState::PermanentlyFailed) {
                launch = launch.with_world_shmem_block(
                    queue_binding,
                    block.base.clone(),
                    block.durability.clone(),
                );
            }
            block_bindings.insert(vm.id.clone(), block);
        }
        let ninep = if let Some(restore) = phase.hot_fork_restore.as_mut() {
            restore.ninep_bindings.remove(&vm.id)
        } else {
            ninep_binding_for_vm(source.world(), &vm.id, config.world_artifacts.as_ref())?
        };
        if let Some(ninep) = ninep {
            let queue_binding = crucible_qemu_host::QemuWorldIoBinding::from_world(
                source.world(),
                ninep.queue.node_for_world(source.world())?,
            )
            .map_err(|error| loop_factory_error(error.to_string()))?;

            if restored_service_state != Some(ProductionNodeServiceState::PermanentlyFailed) {
                launch =
                    launch.with_world_shmem_ninep(queue_binding, ninep.tree.clone(), ninep.latency);
            }
            ninep_bindings.insert(vm.id.clone(), ninep);
        }
        if let Some(initrd) = selected_initrd_for_vm(vm, config)? {
            launch = launch.with_initrd(initrd);
        }
        if config.debug.as_ref().is_some_and(|debug| {
            debug.all_nodes
                || debug
                    .node
                    .as_deref()
                    .map_or(index == 0, |selected| selected == vm.id.name)
        }) {
            let backend_path = private_backend_gdbstub_path(&node_directory);
            let backend_listen = live_unix_gdbstub_endpoint(&backend_path)?;
            let gdbstub = QemuGdbstubChannelConfig::new(backend_listen)
                .map_err(|error| loop_factory_error(format!("configure QEMU gdbstub: {error}")))?;
            launch = launch.with_gdbstub(gdbstub);
            debug_backend_paths.insert(vm.id.clone(), backend_path);
        }
        node_indexes.insert(vm.id.clone(), index);
        node_run_directories.insert(vm.id.clone(), node_directory.clone());
        let service_state = restored_service_state.unwrap_or(ProductionNodeServiceState::Running);
        phase.node_generations.insert(vm.id.clone(), generation);
        node_service_states.insert(vm.id.clone(), service_state);
        let crash_detector = format!("lifecycle-{}-generation-{generation}", vm.id.name);
        let preparation = match restore_target {
            Some(_) => ProductionVmNodePreparationKind::Exact,
            None => ProductionVmNodePreparationKind::Fresh {
                qemu_executable: &qemu_executable,
                root_image: &guest_assets.root_image,
            },
        };
        phase.pending_exact = if restore_target.is_some() {
            let snapshot = restore_target
                .ok_or_else(|| loop_factory_error("exact restore target disappeared"))?
                .snapshot
                .clone();
            let authority = phase.repository_restore.as_mut().ok_or_else(|| {
                loop_factory_error("exact restore has no repository target authority")
            })?;
            let physically_paused = exposure.physical_pause(service_state)?;
            let admission = authority.take_node_admission(&vm.id, snapshot, physically_paused)?;
            phase.pending_exact = Some(admission);
            let admission = phase
                .pending_exact
                .as_ref()
                .ok_or_else(|| loop_factory_error("exact restore admission disappeared"))?;
            if let Some(expected) = repository_parent_identity {
                let (checkpoint, target, frontier) = admission.basis.target.ram_identity();
                if QmpCheckpointIdentity::new(checkpoint, target, frontier) != expected {
                    return Err(loop_factory_error(format!(
                        "repository RAM parent for `{}` differs from its authenticated execution boundary",
                        vm.id.name
                    )));
                }
            }
            phase.pending_exact.take()
        } else {
            None
        };
        let launched = if phase.pending_adoption.is_some() {
            if restore_target.is_some()
                || service_state == ProductionNodeServiceState::PermanentlyFailed
                || hot_fork_expected_time.is_none()
            {
                return Err(loop_factory_error(format!(
                    "hot-fork child for `{}` conflicts with its restore state",
                    vm.id.name
                )));
            }
            let adoption = phase
                .pending_adoption
                .as_ref()
                .ok_or_else(|| loop_factory_error("hot-fork adoption disappeared"))?;
            if adoption.lease.identity().node() != &vm.id
                || adoption.lease.identity().generation() != generation
            {
                return Err(loop_factory_error(format!(
                    "hot-fork child lease for `{}` changed before adoption",
                    vm.id.name
                )));
            }
            let adoption = phase
                .pending_adoption
                .take()
                .ok_or_else(|| loop_factory_error("validated hot-fork adoption disappeared"))?;
            let (process, node, lease, run_directory) = adoption.into_parts();
            Ok((
                ProductionVmNodeLaunch {
                    node,
                    lease,
                    run_directory,
                },
                Some(process),
            ))
        } else {
            if service_state == ProductionNodeServiceState::PermanentlyFailed
                && phase.pending_exact.is_some()
            {
                return Err(loop_factory_error(format!(
                    "permanently failed node `{}` retains a live exact target",
                    vm.id.name
                )));
            }
            match (phase.pending_exact.take(), service_state) {
                (Some(admission), ProductionNodeServiceState::Running) => {
                    launch_production_node_generation(
                        node_launcher.as_mut(),
                        ProductionVmNodeLaunchBasis::new(
                            &launch,
                            &node_directory,
                            &vm.id,
                            generation,
                        ),
                        &crash_detector,
                        preparation,
                        ProductionVmNodeLaunchKind::Exact(Box::new(admission)),
                    )
                    .map(|launch| (launch, None))
                }
                (Some(admission), ProductionNodeServiceState::PoweredOff) => {
                    launch_production_node_generation(
                        node_launcher.as_mut(),
                        ProductionVmNodeLaunchBasis::new(
                            &launch,
                            &node_directory,
                            &vm.id,
                            generation,
                        ),
                        &crash_detector,
                        preparation,
                        ProductionVmNodeLaunchKind::Exact(Box::new(admission)),
                    )
                    .map(|launch| (launch, None))
                }
                (Some(_), ProductionNodeServiceState::PermanentlyFailed) => {
                    return Err(loop_factory_error(format!(
                        "exact checkpoint for permanently failed node `{}` unexpectedly contains a live process target",
                        vm.id.name
                    )));
                }
                (None, ProductionNodeServiceState::PermanentlyFailed) => continue,
                (None, _) => launch_production_node_generation(
                    node_launcher.as_mut(),
                    ProductionVmNodeLaunchBasis::new(&launch, &node_directory, &vm.id, generation),
                    &format!("lifecycle-{}", vm.id.name),
                    preparation,
                    ProductionVmNodeLaunchKind::Fresh,
                )
                .map(|launch| (launch, None)),
            }
        };
        let (launched, adopted_process) = launched?;
        phase.pending_launch = Some(launched);
        let launched = phase
            .pending_launch
            .as_mut()
            .ok_or_else(|| loop_factory_error("construction lost the returned node and lease"))?;
        if launched.run_directory().as_os_str().is_empty() {
            return Err(loop_factory_error(
                "returned QEMU node has an empty run directory",
            ));
        }
        if index == 0
            && let Some(evidence) = bounded_scheduler_preemption.take()
        {
            launched
                .node_mut()
                .enable_bounded_scheduler_preemption(evidence);
        }
        let observed = SimulationBackend::now(launched.node()).ticks;
        if let Some(expected_time) = hot_fork_expected_time {
            if expected_time.ticks != observed {
                return Err(loop_factory_error(format!(
                    "hot-fork QEMU node `{}` resumed at unauthenticated instruction boundary {observed}",
                    vm.id.name
                )));
            }
        } else if let Some(target) = restore_target {
            let restored_configuration = phase
                .restore_checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.configuration.id());
            if Some(target.configuration.id()) != restored_configuration
                || target.counter != observed
            {
                return Err(loop_factory_error(format!(
                    "QEMU node `{}` restored at unauthenticated instruction boundary {observed}",
                    vm.id.name
                )));
            }
            let Some(expected_fingerprint) = phase
                .restore_checkpoint
                .as_ref()
                .and_then(|checkpoint| checkpoint.fault_checkpoint.as_ref())
                .and_then(|checkpoint| checkpoint.qemu_fingerprint(&vm.id))
            else {
                return Err(loop_factory_error(format!(
                    "exact checkpoint for `{}` has no authenticated QEMU fingerprint",
                    vm.id.name
                )));
            };
            let restored_fingerprint = match launched.node_mut().execution_fingerprint() {
                Ok(fingerprint) => fingerprint.hash,
                Err(error) => {
                    return Err(loop_factory_error(format!(
                        "read restored QEMU fingerprint for `{}`: {error}",
                        vm.id.name
                    )));
                }
            };
            if restored_fingerprint != expected_fingerprint {
                return Err(loop_factory_error(format!(
                    "QEMU node `{}` restored with an unauthenticated execution fingerprint: expected {}, observed {}",
                    vm.id.name,
                    expected_fingerprint.to_hex(),
                    restored_fingerprint.to_hex(),
                )));
            }
        } else if initial_ticks.is_some_and(|initial| initial != observed) {
            return Err(loop_factory_error(format!(
                "QEMU node `{}` primed at {observed}, expected {}",
                vm.id.name,
                initial_ticks.unwrap_or_default()
            )));
        }
        if restore_target.is_none() && hot_fork_expected_time.is_none() {
            initial_ticks.get_or_insert(observed);
        }
        let process_identity = launched.node().process_identity().map_err(|error| {
            loop_factory_error(format!(
                "capture initial QEMU identity for `{}`: {error}",
                vm.id.name
            ))
        })?;
        if adopted_process
            .as_ref()
            .is_some_and(|expected| expected != &process_identity)
        {
            return Err(loop_factory_error(format!(
                "adopted hot-fork QEMU process for `{}` changed before lifecycle publication",
                vm.id.name
            )));
        }
        if let Some(identity) = repository_parent_identity
            && repository_parent_targets
                .insert(vm.id.clone(), identity)
                .is_some()
        {
            return Err(loop_factory_error(
                "authenticated repository restore repeated a QEMU parent target",
            ));
        }
        let launched_run_directory = launched.run_directory().to_path_buf();
        node_run_directories.insert(vm.id.clone(), launched_run_directory.clone());
        phase.launch_configs.insert(
            vm.id.clone(),
            launch.clone().with_run_directory(&launched_run_directory),
        );
        if debug_backend_paths.contains_key(&vm.id) {
            debug_backend_paths.insert(
                vm.id.clone(),
                private_backend_gdbstub_path(&launched_run_directory),
            );
        }
        if backends.contains(&vm.id) || phase.node_leases.contains_key(&vm.id) {
            return Err(loop_factory_error(format!(
                "duplicate QEMU node or lease identity `{}`",
                vm.id.name
            )));
        }
        let launched = phase
            .pending_launch
            .take()
            .ok_or_else(|| loop_factory_error("validated QEMU node disappeared before transfer"))?;
        let (backend, lease) = launched.into_parts();
        backends.insert(vm.id.clone(), backend);
        phase.node_leases.insert(vm.id.clone(), lease);
        run_manifest
            .processes
            .insert_reserved(vm.id.name.clone(), process_identity)
            .map_err(|()| loop_factory_error("initial QEMU process reservation was exhausted"))?;
        if let Err(error) = persist_run_state_atomic(
            &run_directory.path().join(PRODUCTION_RUN_STATE_FILE),
            &run_manifest,
            &lifecycle_journal,
            source.plan().fault_signals().resource_limits(),
            0,
            0,
        ) {
            return Err(loop_factory_error(format!(
                "persist initial QEMU process ownership: {error}"
            )));
        }
        #[cfg(any(test, feature = "test-support"))]
        if adopted_process.is_some() {
            hot_fork::record_hot_fork_adoption_for_test();
        }
    }

    if phase.hot_fork_restore.as_ref().is_some_and(|restore| {
        !restore.expected_times.is_empty()
            || !restore.adoptions.is_empty()
            || !restore.immutable_root_images.is_empty()
            || !restore.disk_bases.is_empty()
            || !restore.block_bindings.is_empty()
            || !restore.ninep_bindings.is_empty()
    }) {
        return Err(loop_factory_error(
            "hot-fork lifecycle retained unconsumed child-world state",
        ));
    }

    let initial_ticks = initial_ticks.unwrap_or_default();
    if phase.restore_checkpoint.is_none() && config.run_ceiling_ticks <= initial_ticks {
        return Err(loop_factory_error(format!(
            "QEMU run ceiling {} does not exceed primed boundary {initial_ticks}",
            config.run_ceiling_ticks
        )));
    }
    let mut runtime_scenario = SchedulerLivenessScenario::from_runnable_world(
        &scenario.id().to_hex(),
        config.quantum_budget,
        SimInstant {
            ticks: config.run_ceiling_ticks,
        },
        initial_ticks,
        source.world(),
    )
    .with_scenario_def(scenario.clone());
    if let Some(interval_ticks) = config.rendezvous_interval_ticks {
        runtime_scenario = runtime_scenario
            .with_rendezvous_interval(SimDuration {
                ticks: interval_ticks,
            })
            .map_err(|error| loop_factory_error(format!("configure QEMU rendezvous: {error}")))?;
    }
    let mut scheduler = SingleScheduler::new_with_event_log_segment_store(
        runtime_scenario,
        Arc::clone(&checkpoint_dag),
    )
    .map_err(|error| loop_factory_error(format!("construct QEMU scheduler: {error}")))?;
    if let Some(checkpoint) = &phase.restore_checkpoint {
        scheduler
            .attach_world_network_links(source.world())
            .map_err(|error| loop_factory_error(format!("attach QEMU World network: {error}")))?;
        checkpoint
            .scheduler
            .restore_into(&mut scheduler)
            .map_err(|error| {
                loop_factory_error(format!("restore exact scheduler continuation: {error}"))
            })?;
        if phase.hot_fork_restore.is_some() {
            // Boot must reactivate the captured Halted state, not a fresh runnable node.
            for (node, state) in &node_service_states {
                if *state == ProductionNodeServiceState::PoweredOff {
                    scheduler
                        .require_vm_node_activity(node, SchedulerNodeActivity::Halted)
                        .map_err(|error| {
                            loop_factory_error(format!(
                                "restore powered-off hot-fork scheduler node `{}`: {error}",
                                node.name
                            ))
                        })?;
                }
            }
        }
    } else {
        if let Some(frontier) = first_configured_branch(config)
            .map(|branch| branch.frontier)
            .or_else(|| {
                config
                    .signal_fault_replay
                    .as_ref()
                    .and_then(|replay| replay.branches().first())
                    .map(crucible_engine::SignalFaultCampaignBranch::frontier)
            })
        {
            scheduler
                .set_branch_frontier_cap(frontier)
                .map_err(|error| {
                    loop_factory_error(format!("cap QEMU branch frontier: {error}"))
                })?;
        }
        scheduler
            .attach_world_network_links(source.world())
            .map_err(|error| loop_factory_error(format!("attach QEMU World network: {error}")))?;
        scheduler
            .install_branch_network_choices(config.branch_network_choices.clone())
            .map_err(|error| {
                loop_factory_error(format!("install QEMU network branch choices: {error}"))
            })?;
        scheduler
            .install_app_random_branch_selections(config.app_random_branch_selections.clone())
            .map_err(|error| {
                loop_factory_error(format!(
                    "install QEMU app-random branch selections: {error}"
                ))
            })?;
    }
    if let Some(restore) = phase.hot_fork_restore.as_mut() {
        let scheduler_checkpoint = scheduler.checkpoint().map_err(|error| {
            loop_factory_error(format!(
                "capture adopted hot-fork scheduler continuation: {error}"
            ))
        })?;
        let scheduler_identity = scheduler_checkpoint
            .canonical_bytes()
            .map(|bytes| ContentHash::from_bytes(&bytes))
            .map_err(|error| {
                loop_factory_error(format!(
                    "authenticate adopted hot-fork scheduler continuation: {error}"
                ))
            })?;
        let expected_host_io = std::mem::take(&mut restore.active_host_io);
        for (node, expected) in expected_host_io {
            let observed = backends
                .checkpoint_host_io_projection(&node, scheduler_identity)
                .map_err(|error| {
                    loop_factory_error(format!(
                        "capture adopted host-I/O projection for `{}`: {error}",
                        node.name
                    ))
                })?;
            if observed != expected {
                return Err(loop_factory_error(format!(
                    "adopted host-I/O continuation differs for `{}`",
                    node.name
                )));
            }
        }
    }
    let repository_exact_ram_rebase = if repository_parent_targets.is_empty() {
        None
    } else {
        Some(ProductionRepositoryExactRamRebase {
            targets: repository_parent_targets,
        })
    };
    let trigger_graph = source
        .plan()
        .lower_to_event_graph_for_world(source.world())
        .map_err(|error| loop_factory_error(format!("lower scenario trigger plan: {error}")))?
        .into_event_graph();
    let signal_plan = source.plan().fault_signals().clone();
    let fault_search_overrides =
        production_fault_search_overrides(config.signal_fault_replay.as_ref())?;
    let signal_artifact_objects = if signal_plan.programs().is_empty() {
        Arc::new(BTreeMap::new())
    } else if let Some(checkpoint) = &phase.restore_checkpoint {
        hydrate_checkpoint_signal_artifacts(
            &checkpoint.signal_artifact_objects,
            checkpoint_dag.as_ref(),
        )?;
        Arc::clone(&checkpoint.signal_artifact_objects)
    } else {
        let store = config.signal_artifacts.as_ref().ok_or_else(|| {
            loop_factory_error(
                "a nonempty signal fault plan requires a production signal-artifact store",
            )
        })?;
        Arc::new(collect_signal_artifact_objects(
            &signal_plan,
            store.as_ref(),
        )?)
    };
    let signal_artifacts: Option<Arc<dyn SignalArtifactProvider>> =
        if signal_plan.programs().is_empty() {
            None
        } else {
            let store = if phase.restore_checkpoint.is_some() {
                Arc::clone(&checkpoint_dag)
            } else {
                config.signal_artifacts.clone().ok_or_else(|| {
                    loop_factory_error(
                        "a nonempty signal fault plan requires a production signal-artifact store",
                    )
                })?
            };
            Some(Arc::new(OwnedDagSignalArtifactProvider::new(store)))
        };
    let storage_fault_observations = Arc::new(std::sync::Mutex::new(
        storage_faults::ProductionFaultObservationJournal::default(),
    ));
    let signal_plan_active = !signal_plan.programs().is_empty();
    if signal_plan
        .bindings()
        .iter()
        .any(|binding| network_faults::campaign_network_binding_name(binding.id().as_str()))
    {
        return Err(loop_factory_error(
            "signal binding collides with a reserved campaign network effect owner",
        ));
    }
    let network_replay = if let Some(replay) = &config.signal_fault_replay
        && !replay.network_branches().is_empty()
    {
        let network_replay = crucible_engine::NetworkFaultCampaignReplayPlan::new(
            replay.target().clone(),
            replay.network_branches().to_vec(),
        )
        .map_err(|error| loop_factory_error(format!("admit network fault replay: {error}")))?;
        network_replay
            .validate_topology(source.world().fault_topology())
            .map_err(|error| {
                loop_factory_error(format!("admit network fault topology: {error}"))
            })?;
        Some(network_replay)
    } else {
        None
    };
    let copied_fault_replay = config
        .fault_replay
        .as_ref()
        .map(ResolvedEffectTrace::try_clone_admitted)
        .transpose()
        .map_err(ProductionVmLifecycleConfigCloneError::Replay)?;
    let (signal_effect_replay, campaign_effect_replay) = match copied_fault_replay {
        Some(trace) => {
            trace
                .validate(source.plan().fault_signals().resource_limits())
                .map_err(|error| loop_factory_error(format!("validate fault replay: {error}")))?;
            let (signal, campaign) =
                network_faults::split_campaign_network_trace(trace, network_replay.is_some())
                    .map_err(|error| {
                        loop_factory_error(format!("partition fault replay: {error}"))
                    })?;
            let signal = (signal_plan_active || !signal.work_items.is_empty()).then_some(signal);
            (signal, Some(campaign))
        }
        None => (None, None),
    };
    let (
        fault_runtime,
        fault_evaluation_cursor,
        mut network_interceptor,
        pending_network_outputs,
        restored_committed_frontier,
    ) = if let Some(checkpoint) = &mut phase.restore_checkpoint {
        for (node, target) in &checkpoint.targets {
            let scheduler_time = scheduler.scheduler_time_for_node(node).map_err(|error| {
                loop_factory_error(format!(
                    "read restored scheduler boundary for `{}`: {error}",
                    node.name
                ))
            })?;
            if scheduler_time != target.scheduler_time {
                return Err(loop_factory_error(format!(
                    "production exact checkpoint scheduler boundary differs for `{}`",
                    node.name
                )));
            }
        }
        let mut pending_outputs = Vec::new();
        let fault_checkpoint = checkpoint.fault_checkpoint.take().ok_or_else(|| {
            loop_factory_error("production exact checkpoint lost its fault continuation")
        })?;
        let (interceptor, committed_frontier) = ProductionFaultNetworkInterceptor::restore(
            signal_plan,
            signal_artifacts,
            scenario.id(),
            fault_checkpoint,
            host_fault_manifests.clone(),
            &mut backends,
            source.world().fault_topology().clone(),
            source.world().links().to_vec(),
            &mut scheduler,
            &mut pending_outputs,
            Arc::clone(&storage_fault_observations),
        )
        .map_err(|error| {
            loop_factory_error(format!(
                "restore signal, network, and device continuation: {error}"
            ))
        })?;
        (
            interceptor.shared_runtime(),
            interceptor.shared_cursor(),
            interceptor,
            pending_outputs,
            committed_frontier,
        )
    } else {
        let mut runtime = ProductionFaultRuntime::new_with_search_overrides(
            signal_plan,
            signal_artifacts,
            SignalBoundarySnapshot::default(),
            scenario.id(),
            host_fault_manifests,
            &backends,
            fault_search_overrides.clone(),
        )
        .map_err(|error| loop_factory_error(format!("admit signal fault runtime: {error}")))?;
        if let Some(trace) = signal_effect_replay {
            runtime.install_replay(trace).map_err(|error| {
                loop_factory_error(format!("install signal fault replay: {error}"))
            })?;
        }
        let runtime = Arc::new(std::sync::Mutex::new(runtime));
        let cursor: SharedProductionFaultEvaluationCursor = Arc::new(std::sync::Mutex::new(
            ProductionFaultEvaluationCursor::default(),
        ));
        let interceptor = ProductionFaultNetworkInterceptor::with_shared_runtime(
            Arc::clone(&runtime),
            Arc::clone(&cursor),
            Arc::clone(&storage_fault_observations),
            source.plan().fault_signals().resource_limits(),
            source.world().fault_topology().clone(),
            source.world().links().to_vec(),
        );
        (
            runtime,
            cursor,
            interceptor,
            Vec::new(),
            VirtualTime::default(),
        )
    };
    network_interceptor
        .install_campaign_replay(
            network_replay,
            phase
                .restore_checkpoint
                .as_ref()
                .map(|_| restored_committed_frontier),
        )
        .map_err(|error| loop_factory_error(format!("admit network fault replay: {error}")))?;
    network_interceptor
        .install_campaign_effect_replay(campaign_effect_replay, phase.restore_checkpoint.is_some())
        .map_err(|error| loop_factory_error(format!("admit network effect replay: {error}")))?;
    let fault_replay_installed = config.fault_replay.is_some() && signal_plan_active;
    let fault_search_overrides_installed = fault_runtime
        .lock()
        .map_err(|_| loop_factory_error("production fault runtime lock is poisoned"))?
        .has_search_overrides();

    for (node, block) in &block_bindings {
        if node_service_states.get(node) == Some(&ProductionNodeServiceState::PermanentlyFailed) {
            continue;
        }
        let handle = backends.shared_block_device(node).map_err(|error| {
            loop_factory_error(format!(
                "locate authoritative block device for `{}`: {error}",
                node.name
            ))
        })?;
        if phase
            .block_device_map
            .insert(block.device_hash(), handle)
            .is_some()
        {
            return Err(loop_factory_error(format!(
                "World block target for `{}` aliases another live device",
                node.name
            )));
        }
    }
    phase.block_devices = Some(Arc::new(std::sync::Mutex::new(std::mem::take(
        &mut phase.block_device_map,
    ))));
    let block_devices = phase
        .block_devices
        .as_ref()
        .ok_or_else(|| loop_factory_error("construction lost its block-device aliases"))?;
    for (node, block) in &block_bindings {
        if node_service_states.get(node) == Some(&ProductionNodeServiceState::PermanentlyFailed) {
            continue;
        }
        let coordinator = ProductionBlockFaultCoordinator::new(
            Arc::clone(&fault_runtime),
            Arc::clone(&fault_evaluation_cursor),
            Arc::clone(&storage_fault_observations),
            Arc::clone(&block_devices),
            source.world().clone(),
            block.target.clone(),
            source.plan().fault_signals(),
            scenario.id(),
        );
        #[cfg(any(test, feature = "test-support"))]
        let coordinator =
            coordinator.with_completion_observer(config.block_completion_observer.clone());
        #[cfg(any(test, feature = "test-support"))]
        if let Some(observer) = &config.block_completion_observer {
            backends
                .install_block_completion_observer_for_test(node, Arc::clone(observer))
                .map_err(|error| {
                    loop_factory_error(format!("attach actual block completion observer: {error}"))
                })?;
        }
        backends
            .install_block_fault_coordinator(node, Box::new(coordinator))
            .map_err(|error| {
                loop_factory_error(format!(
                    "attach signal-driven block coordinator to `{}`: {error}",
                    node.name
                ))
            })?;
    }
    for (node, ninep) in &ninep_bindings {
        if node_service_states.get(node) == Some(&ProductionNodeServiceState::PermanentlyFailed) {
            continue;
        }
        backends
            .install_ninep_fault_coordinator(
                node,
                Box::new(storage_faults::ProductionNinepFaultCoordinator::new(
                    Arc::clone(&fault_runtime),
                    Arc::clone(&fault_evaluation_cursor),
                    Arc::clone(&storage_fault_observations),
                    source.world().clone(),
                    ninep.target.clone(),
                    source.plan().fault_signals().resource_limits(),
                )),
            )
            .map_err(|error| {
                loop_factory_error(format!(
                    "attach signal-driven 9p coordinator to `{}`: {error}",
                    node.name
                ))
            })?;
    }

    let (active_branch, continuation_branches) = phase.restore_checkpoint.as_ref().map_or_else(
        || {
            let mut branches = configured_branches(config).cloned();
            (branches.next(), branches.collect())
        },
        |checkpoint| (checkpoint.branch.clone(), VecDeque::new()),
    );
    let signal_fault_branches = if phase.restore_checkpoint.is_some() {
        VecDeque::new()
    } else {
        config
            .signal_fault_replay
            .as_ref()
            .map_or_else(VecDeque::new, |replay| {
                replay.branches().iter().cloned().collect()
            })
    };
    let backends = phase.backends.take().ok_or_else(|| {
        loop_factory_error("construction lost its backend set before loop assembly")
    })?;
    phase.inner = Some(if phase.restore_checkpoint.is_some() {
        BackendQuantumLoop::from_restored_network_state(
            scheduler,
            backends,
            network_interceptor,
            pending_network_outputs,
            restored_committed_frontier,
        )
    } else {
        BackendQuantumLoop::with_network_output_interceptor(
            scheduler,
            backends,
            network_interceptor,
        )
    });
    let failed_host_io = phase
        .restore_checkpoint
        .as_ref()
        .map_or_else(BTreeMap::new, |checkpoint| {
            checkpoint.failed_host_io.clone()
        });

    if let Some(checkpoint) = &phase.restore_checkpoint {
        let targets = checkpoint
            .targets
            .iter()
            .filter_map(|(node, target)| {
                target
                    .native_exact_ram()
                    .cloned()
                    .map(|exact_ram| (node.clone(), exact_ram))
            })
            .collect::<BTreeMap<_, _>>();
        if !targets.is_empty() {
            phase.exact_ram_parents.insert(
                checkpoint.configuration.id(),
                ProductionExactRamPublishedParent {
                    closure: checkpoint.identity,
                    targets,
                },
            );
        }
    }
    let mut assertion_evaluator = HostAssertionEvaluator::new(source.properties())
        .and_then(|evaluator| evaluator.with_world_white_box_policies(source.world()))
        .map_err(|error| LifecycleApiError::BackendConstruction {
            source: crucible_control_api::LifecycleBackendConstructionError::from_shared(Arc::new(error)),
        })?;
    if let Some(checkpoint) = &phase.restore_checkpoint {
        let inner = phase.inner.as_ref().ok_or_else(|| {
            loop_factory_error("construction lost its loop before assertion restore")
        })?;
        checkpoint
            .assertion_state
            .restore_into(
                &mut assertion_evaluator,
                inner.loop_impl().condition_event_log_prefix(),
            )
            .map_err(|error| {
                loop_factory_error(format!("restore host assertion continuation: {error}"))
            })?;
    }
    let lifecycle_persistence =
        LifecycleStatePersistence::new(run_directory.path()).map_err(loop_factory_error)?;
    let owned_scenario = scenario.clone();
    let owned_source = source.clone();
    let owned_world = source.world().clone();

    Ok(move |partial: custody::Partial| {
        let custody::Partial {
            node_launcher: Some(node_launcher),
            retained_config: Some(retained_config),
            run_directory: Some(run_directory),
            inner: Some(inner),
            block_devices: Some(block_devices),
            restore_checkpoint,
            launch_configs,
            node_generations,
            node_leases,
            retained_hot_fork_disk_files,
            exact_ram_parents,
            input_decode_custody,
            pending_launch: None,
            pending_adoption: None,
            pending_exact: None,
            ..
        } = partial
        else {
            return Err(partial);
        };
        let lifecycle = ProductionVmLifecycleLoop {
            runtime_progress: runtime::progress::RuntimeProgress::from_environment(),
            inner,
            trigger_graph,
            trigger_state: restore_checkpoint
                .as_ref()
                .map_or_else(EventGraphState::default, |checkpoint| {
                    checkpoint.trigger_state.clone()
                }),
            trigger_world: owned_world,
            assertion_evaluator,
            assertion_oracle: BlackBoxHostOracle,
            terminal_verdict: restore_checkpoint
                .as_ref()
                .and_then(|checkpoint| checkpoint.terminal_verdict.clone()),
            checkpoint_terminal_cause: restore_checkpoint
                .as_ref()
                .and_then(|checkpoint| checkpoint.terminal_cause.clone()),
            initial_lifecycle_observations_pending: restore_checkpoint
                .as_ref()
                .is_none_or(|checkpoint| checkpoint.initial_lifecycle_observations_pending),
            branch: active_branch,
            continuation_branches,
            signal_fault_branches,
            promote_signal_fault_campaign_choices: false,
            pending_live_network_prefix: None,
            pending_held_host_outcomes: None,
            launch_configs,
            block_bindings,
            ninep_bindings,
            block_devices,
            failed_host_io,
            storage_fault_observations,
            fault_runtime,
            fault_replay_installed,
            fault_search_overrides_installed,
            node_indexes,
            node_run_directories,
            immutable_root_images,
            node_generations,
            node_leases,
            node_lease_cleanup_failed: false,
            retained_cleanup_failure: None,
            node_service_states,
            lifecycle_journal,
            lifecycle_persistence,
            run_manifest,
            scenario: owned_scenario,
            source: owned_source,
            config: retained_config,
            checkpoint_targets,
            exact_ram_parents,
            repository_exact_ram_rebase,
            recorded_controls: restore_checkpoint
                .as_ref()
                .map_or_else(Vec::new, |checkpoint| checkpoint.recorded_controls.clone()),
            signal_artifact_objects,
            debug_backend_paths,
            debug_gateway: None,
            debug_attach: None,
            debug_gateway_teardown_required: false,
            indeterminate_debug_candidate: None,
            retained_debug_construction: std::sync::Mutex::new(None),
            construction_custody: LifecycleConstructionCustody::Unissued(None),
            debug_runtime_evidence: Vec::new(),
            node_launcher,
            _run_directory: run_directory,
            hot_fork_backing_files,
            retained_hot_fork_disk_owners: retained_hot_fork_disk_files
                .into_iter()
                .map(|file| Box::new(file) as Box<dyn Send>)
                .collect(),
            retained_resource_owners: Vec::new(),
            input_decode_custody,
        };
        Ok(lifecycle)
    })
}
