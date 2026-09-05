//! Ordered production lifecycle assembly and rollback-safe owner admission.
//!
//! Construction validates the source and restore basis, launches each node,
//! assembles scheduler and fault continuations, then transfers the complete
//! resource set into the lifecycle. Keeping the transaction together makes
//! early-return cleanup and the final ownership transfer auditable.

use super::*;

pub(super) fn build_production_vm_lifecycle_loop_with_restore(
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    config: &ProductionVmLifecycleConfig,
    mut restore_checkpoint: Option<ProductionVmExactCheckpointSet>,
    mut node_launcher: Box<dyn ProductionVmNodeLauncher>,
    mut hot_fork_restore: Option<ProductionVmHotForkRestore>,
) -> Result<ProductionVmLifecycleLoop, LifecycleApiError> {
    if !cfg!(target_os = "linux") {
        return Err(loop_factory_error(
            "production local-QEMU lifecycle requires a Linux host",
        ));
    }

    if config.branch.is_some()
        && config
            .signal_fault_replay
            .as_ref()
            .is_some_and(|replay| !replay.branches().is_empty())
    {
        return Err(loop_factory_error(
            "raw production branch configuration cannot coexist with typed signal-fault replay",
        ));
    }
    if let Some(replay) = &config.signal_fault_replay
        && replay.target().def.id() != scenario.id()
    {
        return Err(loop_factory_error(
            "signal-fault replay target names a different scenario",
        ));
    }
    if restore_checkpoint.is_some()
        && config
            .signal_fault_replay
            .as_ref()
            .is_some_and(|replay| !replay.branches().is_empty())
    {
        return Err(loop_factory_error(
            "exact-checkpoint restore cannot install a fresh signal-fault replay plan",
        ));
    }
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
    if let Some(checkpoint) = &restore_checkpoint
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
    let nodes = source.world().vm_nodes();
    validate_app_random_branch_replay_config(nodes, config)?;
    if let Some(checkpoint) = restore_checkpoint.as_ref() {
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
    let first = nodes
        .first()
        .ok_or_else(|| loop_factory_error("scenario World has no VM nodes"))?;
    if nodes
        .iter()
        .any(|node| node.icount_shift != first.icount_shift)
    {
        return Err(loop_factory_error(
            "production QEMU lifecycle currently requires one shared icount shift",
        ));
    }
    if config.run_ceiling_icount == 0
        || config.quantum_budget == 0
        || config.rendezvous_interval_icount == Some(0)
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

    let (run_directory, mut run_manifest, lifecycle_journal) = production_run_directory(
        scenario,
        config,
        source.plan().fault_signals().resource_limits(),
    )?;
    let checkpoint_targets = checkpoint_recovery::recover_published_checkpoint_states(
        &config.run_state_root,
        scenario,
        source,
    )?;
    run_manifest
        .processes
        .try_reserve_exact(nodes.len())
        .map_err(|()| loop_factory_error("reserve initial QEMU process ownership"))?;
    let mut backends = ProductionNodeSet::new();
    let mut launch_configs = BTreeMap::new();
    let mut block_bindings = BTreeMap::new();
    let mut ninep_bindings = BTreeMap::new();
    let mut node_indexes = BTreeMap::new();
    let mut node_run_directories = BTreeMap::new();
    let mut node_generations = BTreeMap::new();
    let mut node_leases = BTreeMap::new();
    let mut node_service_states = BTreeMap::new();
    let mut immutable_root_images = BTreeMap::new();
    let mut debug_backend_paths = BTreeMap::new();
    let mut initial_ticks = None;
    let scenario_seed = scenario.seed().bytes();
    let mut launch_seed_bytes = [0_u8; 8];
    launch_seed_bytes.copy_from_slice(&scenario_seed[..8]);
    let launch_seed = u64::from_le_bytes(launch_seed_bytes);
    for (index, vm) in nodes.iter().enumerate() {
        let guest_assets = config.guest_assets.get(&vm.arch).ok_or_else(|| {
            loop_factory_error(format!(
                "production QEMU lifecycle has no boot artifacts for {:?}",
                vm.arch
            ))
        })?;
        if config.validate_guest_asset_references {
            validate_guest_asset_references(vm, guest_assets)?;
        }
        let immutable_root_image = hash_file(&guest_assets.root_image).map_err(|error| {
            loop_factory_error(format!(
                "hash immutable root image for production node `{}` from {}: {error}",
                vm.id.name,
                guest_assets.root_image.display()
            ))
        })?;
        let node_directory = run_directory.path().join(format!("node-{index}"));
        let restore_target = restore_checkpoint
            .as_ref()
            .and_then(|checkpoint| checkpoint.targets.get(&vm.id));
        let hot_fork_expected_time = hot_fork_restore
            .as_mut()
            .and_then(|restore| restore.expected_times.remove(&vm.id));
        let hot_fork_adoption = hot_fork_restore
            .as_mut()
            .and_then(|restore| restore.adoptions.remove(&vm.id));
        let hot_fork_immutable_root = hot_fork_restore
            .as_mut()
            .and_then(|restore| restore.immutable_root_images.remove(&vm.id));
        let restored_service_state = restore_checkpoint
            .as_ref()
            .and_then(|checkpoint| checkpoint.node_service_states.get(&vm.id))
            .copied();
        if restore_checkpoint.is_some()
            && restore_target.is_none()
            && hot_fork_adoption.is_none()
            && restored_service_state != Some(ProductionNodeServiceState::PermanentlyFailed)
        {
            return Err(loop_factory_error(format!(
                "production restore has no exact or hot-fork target for `{}`",
                vm.id.name
            )));
        }
        if let Some(target) = restore_target {
            let fault_identity = restore_checkpoint
                .as_ref()
                .and_then(|checkpoint| checkpoint.fault_checkpoint.as_ref())
                .map(ProductionFaultRuntimeCheckpoint::id)
                .ok_or_else(|| {
                    loop_factory_error("exact checkpoint target lost its fault continuation")
                })?;
            validate_exact_checkpoint_target(&vm.id, target, fault_identity)?;
            if let Some(expected) = target.immutable_backing
                && expected != immutable_root_image
            {
                return Err(loop_factory_error(format!(
                    "production exact checkpoint for `{}` names immutable backing {} but the selected root image hashes to {}",
                    vm.id.name,
                    expected.to_hex(),
                    immutable_root_image.to_hex()
                )));
            }
        }
        if hot_fork_restore.is_some() {
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
        let generation = restore_checkpoint
            .as_ref()
            .and_then(|checkpoint| checkpoint.node_generations.get(&vm.id))
            .copied()
            .unwrap_or(1);
        let qemu_executable = production_qemu_executable(&config.executable, vm.arch);
        let mut launch = ProductionLiveNodeStepGateConfig::new_with_root_image(
            &qemu_executable,
            &config.plugin,
            &guest_assets.kernel,
            &guest_assets.root_image,
            &node_directory,
        )
        .with_guest_architecture(production_guest_architecture(vm.arch))
        .with_root_image_format(config.root_image_format)
        .with_kernel_cmdline(kernel_cmdline)
        .with_vm_shape(vm.memory_mib, vm.smp_vcpus, vm.icount_shift)
        .with_scenario_seed(launch_seed)
        .with_whitebox(whitebox)
        .with_coverage(config.coverage)
        .with_fingerprint(crucible_qemu::QemuLaunchPluginSwitch::On)
        .with_queue_capacity(PRODUCTION_QUEUE_CAPACITY)
        .with_completion_timeout(config.completion_timeout)
        .with_console_capture()
        .with_second_run_scheduler_preemption(false)
        .with_process_generation(generation)
        .with_fault_resource_limits(source.plan().fault_signals().resource_limits());
        if let Some(capabilities) = source
            .world()
            .fault_topology()
            .node_capabilities
            .iter()
            .find(|capabilities| capabilities.node.as_str() == vm.id.name.as_str())
        {
            if !capabilities.ready_markers.is_empty()
                && vm.white_box != crucible::WhiteBoxPolicy::Enabled
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
        if vm.white_box == crucible::WhiteBoxPolicy::Enabled {
            let declarations = source
                .selectables()
                .guest_declarations(&vm.id)
                .map(|declaration| {
                    crucible_protocol::selectable_catalog_plan::SelectablePlanDeclaration::new(
                        declaration.name(),
                        declaration.domain().canonical_bytes(),
                        declaration.default().canonical_bytes(),
                        declaration.semantic_tags().iter().cloned().collect(),
                        if declaration.required() {
                            crucible_protocol::selectable_catalog_plan::SelectablePlanPresence::Required
                        } else {
                            crucible_protocol::selectable_catalog_plan::SelectablePlanPresence::Optional
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
                let limits = crucible_protocol::selectable_catalog_plan::SelectablePlanLimits::new(
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
                    crucible_protocol::selectable_catalog_plan::SelectableCatalogPlan::new(
                    limits,
                    declarations,
                    crucible_protocol::selectable_catalog_plan::SelectablePlanContinuation::cold(),
                )
                .map_err(|error| {
                    loop_factory_error(format!(
                        "build scenario selectable catalog for `{}`: {error}",
                        vm.id.name
                    ))
                })?;
                let plan = if let Some(checkpoint) = restore_checkpoint.as_ref()
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
                        || restored.continuation().phase()
                            != crucible_protocol::selectable_catalog_plan::SelectablePlanPhase::Frozen
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
            let app_random = if let Some(checkpoint) = &restore_checkpoint {
                production_app_random_checkpoint_config(
                    &checkpoint.scheduler,
                    scenario,
                    checkpoint.branch.as_ref(),
                    &vm.id,
                )
                .map_err(|error| {
                    loop_factory_error(format!(
                        "restore app-random continuation for `{}`: {error}",
                        vm.id.name
                    ))
                })?
            } else {
                production_app_random_launch_config(scenario, config.branch.as_ref(), &vm.id)
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
            launch = launch.with_shmem_network_mac(crucible::deterministic_node_mac_string(&vm.id));
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
        if restored_service_state != Some(ProductionNodeServiceState::PermanentlyFailed) {
            let block = if let Some(restore) = hot_fork_restore.as_mut() {
                restore.block_bindings.remove(&vm.id)
            } else {
                block_binding_for_vm(source.world(), &vm.id, config.world_artifacts.as_ref())?
            };
            if let Some(block) = block {
                launch = launch.with_shmem_block(block.base.clone(), block.durability.clone());
                block_bindings.insert(vm.id.clone(), block);
            }
            let ninep = if let Some(restore) = hot_fork_restore.as_mut() {
                restore.ninep_bindings.remove(&vm.id)
            } else {
                ninep_binding_for_vm(source.world(), &vm.id, config.world_artifacts.as_ref())?
            };
            if let Some(ninep) = ninep {
                launch = launch.with_shmem_ninep(ninep.tree.clone(), ninep.latency);
                ninep_bindings.insert(vm.id.clone(), ninep);
            }
        }
        if vm.initrd.is_some() && config.initrd.is_none() {
            return Err(loop_factory_error(format!(
                "QEMU node `{}` declares an initrd but no materialized initrd was configured",
                vm.id.name
            )));
        }
        if let Some(initrd) = &config.initrd {
            launch = launch.with_initrd(initrd);
        }
        if config.debug.as_ref().is_some_and(|debug| {
            debug.all_nodes
                || debug
                    .node
                    .as_deref()
                    .map_or(index == 0, |selected| selected == vm.id.name)
        }) {
            let debug = config.debug.as_ref().ok_or_else(|| {
                loop_factory_error("debug configuration disappeared during QEMU launch")
            })?;
            let backend_path = private_backend_gdbstub_path(&node_directory);
            let backend_listen = live_unix_gdbstub_endpoint(&backend_path)?;
            let gdbstub =
                ProductionGdbstubChannelConfig::new(backend_listen, debug.operator_listen.clone())
                    .map_err(|error| {
                        loop_factory_error(format!("configure QEMU gdbstub: {error}"))
                    })?;
            launch = launch.with_gdbstub(gdbstub);
            debug_backend_paths.insert(vm.id.clone(), backend_path);
        }
        launch_configs.insert(vm.id.clone(), launch.clone());
        node_indexes.insert(vm.id.clone(), index);
        node_run_directories.insert(vm.id.clone(), node_directory.clone());
        let service_state = restored_service_state.unwrap_or(ProductionNodeServiceState::Running);
        node_generations.insert(vm.id.clone(), generation);
        node_service_states.insert(vm.id.clone(), service_state);
        let crash_detector = format!("lifecycle-{}-generation-{generation}", vm.id.name);
        let preparation = match restore_target {
            Some(target) => ProductionVmNodePreparationKind::Exact {
                root: target.manifest_identity,
                root_overlay: ProductionVmNodeCheckpointArtifact {
                    artifact: &target.overlay_artifact,
                    role: "root overlay",
                },
                vmstate: ProductionVmNodeCheckpointArtifact {
                    artifact: &target.vmstate_artifact,
                    role: "VMState",
                },
            },
            None => ProductionVmNodePreparationKind::Fresh {
                qemu_executable: &qemu_executable,
                root_image: &guest_assets.root_image,
            },
        };
        let launched = if let Some(adoption) = hot_fork_adoption {
            if restore_target.is_some()
                || service_state != ProductionNodeServiceState::Running
                || hot_fork_expected_time.is_none()
            {
                return Err(loop_factory_error(format!(
                    "hot-fork child for `{}` conflicts with its restore state",
                    vm.id.name
                )));
            }
            let (process, node, lease, run_directory) = adoption.into_parts();
            if lease.identity().node() != &vm.id || lease.identity().generation() != generation {
                return Err(loop_factory_error(format!(
                    "hot-fork child lease for `{}` changed before adoption",
                    vm.id.name
                )));
            }
            Ok((
                ProductionVmNodeLaunch {
                    node,
                    lease,
                    run_directory,
                },
                Some(process),
            ))
        } else {
            match (restore_target, service_state) {
                (Some(target), ProductionNodeServiceState::Running) => {
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
                        ProductionVmNodeLaunchKind::Exact {
                            snapshot: &target.snapshot,
                            paused: false,
                        },
                    )
                    .map(|launch| (launch, None))
                }
                (Some(target), ProductionNodeServiceState::PoweredOff) => {
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
                        ProductionVmNodeLaunchKind::Exact {
                            snapshot: &target.snapshot,
                            paused: true,
                        },
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
        let (mut launched, adopted_process) = launched?;
        let observed = SimulationBackend::now(launched.node()).ticks;
        if let Some(expected_time) = hot_fork_expected_time {
            if expected_time.ticks != observed {
                let _ = launched.quarantine_and_finish();
                return Err(loop_factory_error(format!(
                    "hot-fork QEMU node `{}` resumed at unauthenticated instruction boundary {observed}",
                    vm.id.name
                )));
            }
        } else if let Some(target) = restore_target {
            let restored_configuration = restore_checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.configuration.id());
            if Some(target.configuration.id()) != restored_configuration
                || target.counter != observed
            {
                let _ = launched.quarantine_and_finish();
                return Err(loop_factory_error(format!(
                    "QEMU node `{}` restored at unauthenticated instruction boundary {observed}",
                    vm.id.name
                )));
            }
            let Some(expected_fingerprint) = restore_checkpoint
                .as_ref()
                .and_then(|checkpoint| checkpoint.fault_checkpoint.as_ref())
                .and_then(|checkpoint| checkpoint.qemu_fingerprint(&vm.id))
            else {
                let _ = launched.quarantine_and_finish();
                return Err(loop_factory_error(format!(
                    "exact checkpoint for `{}` has no authenticated QEMU fingerprint",
                    vm.id.name
                )));
            };
            let restored_fingerprint = match launched.node_mut().execution_fingerprint() {
                Ok(fingerprint) => fingerprint.hash,
                Err(error) => {
                    let _ = launched.quarantine_and_finish();
                    return Err(loop_factory_error(format!(
                        "read restored QEMU fingerprint for `{}`: {error}",
                        vm.id.name
                    )));
                }
            };
            if restored_fingerprint != expected_fingerprint {
                let _ = launched.quarantine_and_finish();
                return Err(loop_factory_error(format!(
                    "QEMU node `{}` restored with an unauthenticated execution fingerprint: expected {}, observed {}",
                    vm.id.name,
                    expected_fingerprint.to_hex(),
                    restored_fingerprint.to_hex(),
                )));
            }
        } else if initial_ticks.is_some_and(|initial| initial != observed) {
            let _ = launched.quarantine_and_finish();
            return Err(loop_factory_error(format!(
                "QEMU node `{}` primed at {observed}, expected {}",
                vm.id.name,
                initial_ticks.unwrap_or_default()
            )));
        }
        if restore_target.is_none() && hot_fork_expected_time.is_none() {
            initial_ticks.get_or_insert(observed);
        }
        let process_identity = match launched.node().process_identity() {
            Ok(identity) => identity,
            Err(error) => {
                let containment = launched.quarantine_and_finish();
                return Err(loop_factory_error(format!(
                    "capture initial QEMU identity for `{}`: {error}; process containment: {}",
                    vm.id.name,
                    containment.map_or_else(
                        |failure| failure.to_string(),
                        |()| String::from("reaped and lease released")
                    )
                )));
            }
        };
        if adopted_process
            .as_ref()
            .is_some_and(|expected| expected != &process_identity)
        {
            let containment = launched.quarantine_and_finish();
            return Err(loop_factory_error(format!(
                "adopted hot-fork QEMU process for `{}` changed before lifecycle publication; process containment: {}",
                vm.id.name,
                containment.map_or_else(
                    |failure| failure.to_string(),
                    |()| String::from("reaped and lease released")
                )
            )));
        }
        let launched_run_directory = launched.run_directory().to_path_buf();
        node_run_directories.insert(vm.id.clone(), launched_run_directory.clone());
        launch_configs.insert(
            vm.id.clone(),
            launch.clone().with_run_directory(&launched_run_directory),
        );
        if debug_backend_paths.contains_key(&vm.id) {
            debug_backend_paths.insert(
                vm.id.clone(),
                private_backend_gdbstub_path(&launched_run_directory),
            );
        }
        let (backend, lease) = launched.into_parts();
        if backends.insert(vm.id.clone(), backend).is_some() {
            return Err(loop_factory_error(format!(
                "duplicate QEMU node identity `{}`",
                vm.id.name
            )));
        }
        if node_leases.insert(vm.id.clone(), lease).is_some() {
            return Err(loop_factory_error(format!(
                "duplicate QEMU node lease identity `{}`",
                vm.id.name
            )));
        }
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
            let backend_cleanup = backends.shutdown();
            let lease_cleanup = if backend_cleanup.is_ok() {
                let nodes = node_leases.keys().cloned().collect::<Vec<_>>();
                finish_reaped_node_lease_map(&node_generations, &mut node_leases, &nodes)
            } else {
                Ok(())
            };
            let launcher_cleanup = if backend_cleanup.is_ok() && lease_cleanup.is_ok() {
                node_launcher.finish()
            } else {
                Ok(())
            };
            return Err(loop_factory_error(format!(
                "persist initial QEMU process ownership: {error}; backend cleanup: {}; generation-lease cleanup: {}; launcher cleanup: {}",
                backend_cleanup
                    .map_or_else(|failure| failure.to_string(), |()| String::from("reaped")),
                lease_cleanup.map_or_else(
                    |failure| failure.to_string(),
                    |()| String::from("released or retained")
                ),
                launcher_cleanup
                    .map_or_else(|failure| failure.to_string(), |()| String::from("released"))
            )));
        }
    }

    if hot_fork_restore.as_ref().is_some_and(|restore| {
        !restore.expected_times.is_empty()
            || !restore.adoptions.is_empty()
            || !restore.immutable_root_images.is_empty()
            || !restore.block_bindings.is_empty()
            || !restore.ninep_bindings.is_empty()
    }) {
        return Err(loop_factory_error(
            "hot-fork lifecycle retained unconsumed child-world state",
        ));
    }

    let initial_ticks = initial_ticks.unwrap_or_default();
    if restore_checkpoint.is_none() && config.run_ceiling_icount <= initial_ticks {
        return Err(loop_factory_error(format!(
            "QEMU run ceiling {} does not exceed primed boundary {initial_ticks}",
            config.run_ceiling_icount
        )));
    }
    let shift = Shift::new(first.icount_shift)
        .map_err(|error| loop_factory_error(format!("validate icount shift: {error}")))?;
    let time_limit_nanos = config
        .run_ceiling_icount
        .checked_shl(u32::from(first.icount_shift))
        .ok_or_else(|| loop_factory_error("QEMU lifecycle time limit overflow"))?;
    let mut runtime_scenario = SchedulerLivenessScenario::from_runnable_world(
        &scenario.id().to_hex(),
        shift,
        config.quantum_budget,
        SimInstant {
            nanos: time_limit_nanos,
        },
        initial_ticks,
        source.world(),
    )
    .with_scenario_def(scenario.clone());
    if let Some(interval_icount) = config.rendezvous_interval_icount {
        let interval_nanos = interval_icount
            .checked_shl(u32::from(first.icount_shift))
            .ok_or_else(|| loop_factory_error("QEMU rendezvous interval overflow"))?;
        runtime_scenario = runtime_scenario
            .with_rendezvous_interval(SimDuration {
                nanos: interval_nanos,
            })
            .map_err(|error| loop_factory_error(format!("configure QEMU rendezvous: {error}")))?;
    }
    let mut scheduler = SingleScheduler::new_with_event_log_segment_store(
        runtime_scenario,
        Arc::clone(&checkpoint_dag),
    )
    .map_err(|error| loop_factory_error(format!("construct QEMU scheduler: {error}")))?;
    if let Some(checkpoint) = &restore_checkpoint {
        scheduler
            .attach_world_network_links(source.world())
            .map_err(|error| loop_factory_error(format!("attach QEMU World network: {error}")))?;
        checkpoint
            .scheduler
            .restore_into(&mut scheduler)
            .map_err(|error| {
                loop_factory_error(format!("restore exact scheduler continuation: {error}"))
            })?;
    } else {
        if let Some(frontier) = config
            .branch
            .as_ref()
            .map(|branch| branch.frontier)
            .or_else(|| {
                config
                    .signal_fault_replay
                    .as_ref()
                    .and_then(|replay| replay.branches().first())
                    .map(crucible::SignalFaultCampaignBranch::frontier)
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
    let trigger_graph = source
        .plan()
        .lower_to_event_graph_for_world(source.world())
        .map_err(|error| loop_factory_error(format!("lower scenario trigger plan: {error}")))?
        .into_event_graph();
    let signal_plan = source.plan().fault_signals().clone();
    let fault_search_overrides = production_fault_search_overrides(
        config.branch.as_ref(),
        config.signal_fault_replay.as_ref(),
    )?;
    let signal_artifact_objects = if signal_plan.programs().is_empty() {
        BTreeMap::new()
    } else if let Some(checkpoint) = &restore_checkpoint {
        checkpoint.signal_artifact_objects.clone()
    } else {
        let store = config.signal_artifacts.as_ref().ok_or_else(|| {
            loop_factory_error(
                "a nonempty signal fault plan requires a production signal-artifact store",
            )
        })?;
        collect_signal_artifact_objects(&signal_plan, store.as_ref())?
    };
    let signal_artifacts: Option<Arc<dyn SignalArtifactProvider>> =
        if signal_plan.programs().is_empty() {
            None
        } else {
            let store = if restore_checkpoint.is_some() {
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
    let (
        fault_runtime,
        fault_evaluation_cursor,
        network_interceptor,
        pending_network_outputs,
        restored_committed_frontier,
    ) = if let Some(checkpoint) = &mut restore_checkpoint {
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
        if let Some(trace) = config.fault_replay.clone() {
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
    let fault_replay_installed = config.fault_replay.is_some();
    let fault_search_overrides_installed = fault_runtime
        .lock()
        .map_err(|_| loop_factory_error("production fault runtime lock is poisoned"))?
        .has_search_overrides();
    let mut block_device_map = BTreeMap::new();
    for (node, block) in &block_bindings {
        let handle = backends.shared_block_device(node).map_err(|error| {
            loop_factory_error(format!(
                "locate authoritative block device for `{}`: {error}",
                node.name
            ))
        })?;
        if block_device_map
            .insert(block.device_hash(), handle)
            .is_some()
        {
            return Err(loop_factory_error(format!(
                "World block target for `{}` aliases another live device",
                node.name
            )));
        }
    }
    let block_devices = Arc::new(std::sync::Mutex::new(block_device_map));
    for (node, block) in &block_bindings {
        backends
            .install_block_fault_coordinator(
                node,
                Box::new(ProductionBlockFaultCoordinator::new(
                    Arc::clone(&fault_runtime),
                    Arc::clone(&fault_evaluation_cursor),
                    Arc::clone(&storage_fault_observations),
                    Arc::clone(&block_devices),
                    source.world().clone(),
                    block.target.clone(),
                    source.plan().fault_signals(),
                    scenario.id(),
                    first.icount_shift,
                )),
            )
            .map_err(|error| {
                loop_factory_error(format!(
                    "attach signal-driven block coordinator to `{}`: {error}",
                    node.name
                ))
            })?;
    }
    for (node, ninep) in &ninep_bindings {
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
                    first.icount_shift,
                )),
            )
            .map_err(|error| {
                loop_factory_error(format!(
                    "attach signal-driven 9p coordinator to `{}`: {error}",
                    node.name
                ))
            })?;
    }

    let active_branch = restore_checkpoint.as_ref().map_or_else(
        || config.branch.clone(),
        |checkpoint| checkpoint.branch.clone(),
    );
    let signal_fault_branches = if restore_checkpoint.is_some() {
        VecDeque::new()
    } else {
        config
            .signal_fault_replay
            .as_ref()
            .map_or_else(VecDeque::new, |replay| {
                replay.branches().iter().cloned().collect()
            })
    };
    let inner = if restore_checkpoint.is_some() {
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
    };
    let mut lifecycle = ProductionVmLifecycleLoop {
        inner,
        trigger_graph,
        trigger_state: restore_checkpoint
            .as_ref()
            .map_or_else(EventGraphState::default, |checkpoint| {
                checkpoint.trigger_state.clone()
            }),
        trigger_world: source.world().clone(),
        assertion_evaluator: HostAssertionEvaluator::new(source.properties())
            .with_world_white_box_policies(source.world()),
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
        signal_fault_branches,
        promote_signal_fault_campaign_choices: false,
        launch_configs,
        block_bindings,
        ninep_bindings,
        block_devices,
        storage_fault_observations,
        fault_runtime,
        fault_replay_installed,
        fault_search_overrides_installed,
        fault_evaluation_cursor,
        icount_shift: first.icount_shift,
        node_indexes,
        node_run_directories,
        immutable_root_images,
        node_generations,
        node_leases,
        node_lease_cleanup_failed: false,
        node_service_states,
        lifecycle_journal,
        lifecycle_persistence: LifecycleStatePersistence::new(run_directory.path())
            .map_err(loop_factory_error)?,
        run_manifest,
        scenario: scenario.clone(),
        source: source.clone(),
        config: config.clone(),
        checkpoint_targets,
        recorded_controls: restore_checkpoint
            .as_ref()
            .map_or_else(Vec::new, |checkpoint| checkpoint.recorded_controls.clone()),
        signal_artifact_objects,
        debug_backend_paths,
        debug_gateway: None,
        debug_attach: None,
        debug_gateway_teardown_required: false,
        indeterminate_debug_candidate: None,
        debug_runtime_evidence: Vec::new(),
        node_launcher,
        _run_directory: run_directory,
    };
    if let Some(checkpoint) = &restore_checkpoint {
        let prefix = lifecycle
            .inner
            .loop_impl()
            .condition_event_log_prefix()
            .clone();
        if let Err(error) = checkpoint
            .assertion_state
            .restore_into(&mut lifecycle.assertion_evaluator, &prefix)
        {
            let cleanup = QuantumLoop::shutdown(&mut lifecycle);
            return Err(loop_factory_error(format!(
                "restore host assertion continuation: {error}; lifecycle cleanup: {}",
                cleanup.map_or_else(
                    |failure| failure.to_string(),
                    |_: Vec<_>| String::from("reaped and released")
                )
            )));
        }
    }
    if let Err(error) = lifecycle.capture_debug_runtime_evidence() {
        let cleanup = QuantumLoop::shutdown(&mut lifecycle);
        return Err(loop_factory_error(format!(
            "capture initial debugger runtime evidence: {error}; lifecycle cleanup: {}",
            cleanup.map_or_else(
                |failure| failure.to_string(),
                |_: Vec<_>| String::from("reaped and released")
            )
        )));
    }
    Ok(lifecycle)
}
