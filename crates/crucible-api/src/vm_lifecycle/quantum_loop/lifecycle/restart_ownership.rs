//! Pre-APPLY ownership for terminal-generation restart publication.

use super::*;

pub(in crate::vm_lifecycle::quantum_loop) struct PreparedLifecycleFaultCoordinators {
    pub(in crate::vm_lifecycle::quantum_loop) block: Option<Box<ProductionBlockFaultCoordinator>>,
    pub(in crate::vm_lifecycle::quantum_loop) ninep:
        Option<Box<storage_faults::ProductionNinepFaultCoordinator>>,
}

pub(in crate::vm_lifecycle::quantum_loop) struct PreparedLifecycleGenerationOwnership {
    pub(in crate::vm_lifecycle::quantum_loop) generation: u64,
    pub(in crate::vm_lifecycle::quantum_loop) run_directory: PathBuf,
    pub(in crate::vm_lifecycle::quantum_loop) artifact_paths: [PathBuf; 2],
    pub(in crate::vm_lifecycle::quantum_loop) launch: ProductionLiveNodeStepGateConfig,
    pub(in crate::vm_lifecycle::quantum_loop) debug_backend_path: Option<PathBuf>,
    pub(in crate::vm_lifecycle::quantum_loop) crash_detector: String,
    pub(in crate::vm_lifecycle::quantum_loop) fault_coordinators:
        PreparedLifecycleFaultCoordinators,
}

pub(in crate::vm_lifecycle::quantum_loop) struct PreparedLifecycleTerminalOwnership {
    pub(in crate::vm_lifecycle::quantum_loop) current: PreparedLifecycleGenerationOwnership,
    pub(in crate::vm_lifecycle::quantum_loop) successor:
        Option<PreparedLifecycleGenerationOwnership>,
}

pub(in crate::vm_lifecycle::quantum_loop) fn select_preowned_terminal_generation<T>(
    current: T,
    successor: Option<T>,
    service_state: ProductionNodeServiceState,
) -> Option<(T, Option<T>)> {
    match service_state {
        ProductionNodeServiceState::PermanentlyFailed => Some((current, None)),
        ProductionNodeServiceState::Running | ProductionNodeServiceState::PoweredOff => {
            successor.map(|successor| (successor, Some(current)))
        }
    }
}

fn bind_successor_app_random(
    launch: ProductionLiveNodeStepGateConfig,
    app_random: Option<ProductionAppRandomConfig>,
) -> ProductionLiveNodeStepGateConfig {
    app_random.map_or(launch.clone(), |config| launch.with_app_random(config))
}

impl ProductionVmLifecycleLoop {
    pub(in crate::vm_lifecycle::quantum_loop) fn prepare_terminal_lifecycle_ownership(
        &self,
        intent: &QemuNodeLifecycleIntent,
        current_generation: u64,
        next_generation: u64,
        scheduler_checkpoint: &SingleSchedulerCheckpoint,
        resource_current: usize,
        limits: FaultResourceLimits,
    ) -> Result<PreparedLifecycleTerminalOwnership, SchedulerError> {
        let node = &intent.node;
        let index = self.node_indexes.get(node).copied().ok_or_else(|| {
            SchedulerError::BoundaryViolation {
                message: format!(
                    "terminal lifecycle node `{}` has no launch index",
                    node.name
                ),
            }
        })?;
        let current_directory = self.node_run_directories.get(node).ok_or_else(|| {
            SchedulerError::BoundaryViolation {
                message: format!(
                    "terminal lifecycle node `{}` has no process-generation directory",
                    node.name
                ),
            }
        })?;
        let launch =
            self.launch_configs
                .get(node)
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "terminal lifecycle node `{}` has no launch configuration",
                        node.name
                    ),
                })?;

        let current_generation_ownership = self.prepare_lifecycle_generation_ownership(
            node,
            index,
            current_generation,
            current_directory.clone(),
            launch.clone(),
            resource_current,
            limits,
            false,
        )?;
        let successor_app_random = launch
            .app_random_configured()
            .then(|| {
                production_app_random_checkpoint_config(
                    scheduler_checkpoint,
                    &self.scenario,
                    self.branch.as_ref(),
                    node,
                )
            })
            .transpose()?;
        let successor =
            lifecycle_intent_may_require_successor_generation(intent.requested_transition)
                .then(|| {
                    let run_directory = self
                        ._run_directory
                        .path()
                        .join("lifecycle-generations")
                        .join(format!("node-{index}-generation-{next_generation}"));
                    let successor_launch =
                        bind_successor_app_random(launch.clone(), successor_app_random);
                    self.prepare_lifecycle_generation_ownership(
                        node,
                        index,
                        next_generation,
                        run_directory,
                        successor_launch,
                        resource_current,
                        limits,
                        true,
                    )
                })
                .transpose()?;
        Ok(PreparedLifecycleTerminalOwnership {
            current: current_generation_ownership,
            successor,
        })
    }

    // crucible-lint: allow rust-allow -- this narrowly scoped exception preserves the surrounding typed boundary.
    #[allow(
        clippy::too_many_arguments,
        reason = "restart ownership binds the authenticated node, generation, launch identity, resource coordinate, and coordinator policy"
    )]
    fn prepare_lifecycle_generation_ownership(
        &self,
        node: &NodeId,
        index: usize,
        generation: u64,
        run_directory: PathBuf,
        launch: ProductionLiveNodeStepGateConfig,
        current: usize,
        limits: FaultResourceLimits,
        prepare_coordinators: bool,
    ) -> Result<PreparedLifecycleGenerationOwnership, SchedulerError> {
        let artifact_paths = [
            run_directory.join(PRODUCTION_ROOT_OVERLAY_FILE_NAME),
            run_directory.join(PRODUCTION_VMSTATE_FILE_NAME),
        ];
        let mut launch = launch
            .with_run_directory(&run_directory)
            .with_process_generation(generation);
        let debug_selected = self.config.debug.as_ref().is_some_and(|debug| {
            debug.all_nodes
                || debug
                    .node
                    .as_deref()
                    .map_or(index == 0, |selected| selected == node.name)
        });
        if debug_selected {
            let backend_path = private_backend_gdbstub_path(&run_directory);
            let backend_listen = qemu_unix_gdbstub_endpoint(&backend_path).map_err(|error| {
                SchedulerError::BoundaryViolation {
                    message: format!(
                        "derive replacement QEMU gdbstub endpoint for `{}`: {error}",
                        node.name
                    ),
                }
            })?;
            let operator_listen = self
                .config
                .debug
                .as_ref()
                .map(|debug| debug.operator_listen.clone())
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: String::from("selected lifecycle debugger lost its configuration"),
                })?;
            let gdbstub = ProductionGdbstubChannelConfig::new(backend_listen, operator_listen)
                .map_err(|error| SchedulerError::BoundaryViolation {
                    message: format!(
                        "configure replacement QEMU gdbstub for `{}`: {error}",
                        node.name
                    ),
                })?;
            launch = launch.with_gdbstub(gdbstub);
        }
        let debug_backend_path = self
            .debug_backend_paths
            .contains_key(node)
            .then(|| private_backend_gdbstub_path(&run_directory));
        let crash_detector = try_lifecycle_crash_detector(&node.name, generation, current, limits)?;
        let fault_coordinators = if prepare_coordinators {
            self.prepare_lifecycle_fault_coordinators(node)
        } else {
            PreparedLifecycleFaultCoordinators {
                block: None,
                ninep: None,
            }
        };
        Ok(PreparedLifecycleGenerationOwnership {
            generation,
            run_directory,
            artifact_paths,
            launch,
            debug_backend_path,
            crash_detector,
            fault_coordinators,
        })
    }

    fn prepare_lifecycle_fault_coordinators(
        &self,
        node: &NodeId,
    ) -> PreparedLifecycleFaultCoordinators {
        let block = self.block_bindings.get(node).map(|binding| {
            Box::new(ProductionBlockFaultCoordinator::new(
                Arc::clone(&self.fault_runtime),
                Arc::clone(&self.fault_evaluation_cursor),
                Arc::clone(&self.storage_fault_observations),
                Arc::clone(&self.block_devices),
                self.source.world().clone(),
                binding.target.clone(),
                self.source.plan().fault_signals(),
                self.scenario.id(),
                self.icount_shift,
            ))
        });
        let ninep = self.ninep_bindings.get(node).map(|binding| {
            Box::new(storage_faults::ProductionNinepFaultCoordinator::new(
                Arc::clone(&self.fault_runtime),
                Arc::clone(&self.fault_evaluation_cursor),
                Arc::clone(&self.storage_fault_observations),
                self.source.world().clone(),
                binding.target.clone(),
                self.icount_shift,
            ))
        });
        PreparedLifecycleFaultCoordinators { block, ninep }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_generation_selection_moves_preowned_storage() {
        for service_state in [
            ProductionNodeServiceState::Running,
            ProductionNodeServiceState::PoweredOff,
        ] {
            let current = String::from("current-generation");
            let successor = String::from("successor-generation");
            let current_storage = current.as_ptr();
            let successor_storage = successor.as_ptr();
            let (selected, prior) =
                select_preowned_terminal_generation(current, Some(successor), service_state)
                    .unwrap_or_else(|| panic!("live terminal state should select its successor"));
            assert_eq!(selected.as_ptr(), successor_storage);
            assert_eq!(
                prior
                    .as_ref()
                    .map(|value| value.as_ptr())
                    .unwrap_or_else(|| panic!("live terminal state should retain prior ownership")),
                current_storage
            );
        }

        let current = String::from("permanently-failed-generation");
        let current_storage = current.as_ptr();
        let (selected, prior) = select_preowned_terminal_generation(
            current,
            None,
            ProductionNodeServiceState::PermanentlyFailed,
        )
        .unwrap_or_else(|| panic!("permanent failure should retain current ownership"));
        assert_eq!(selected.as_ptr(), current_storage);
        assert!(prior.is_none());
    }

    #[test]
    fn terminal_successor_launch_owns_exact_app_random_continuation() {
        let positions = BTreeMap::from([
            (String::from("node-a/requests"), 3),
            (String::from("node-a/workload"), 5),
        ]);
        let app_random = ProductionAppRandomConfig::new(11, 32, "node-a")
            .with_continuation(8, positions.clone());
        let launch =
            ProductionLiveNodeStepGateConfig::new("qemu", "plugin", "kernel", "firmware", "run");

        let rebound = bind_successor_app_random(launch, Some(app_random));
        let rebound = rebound
            .app_random_configuration()
            .unwrap_or_else(|| panic!("terminal successor must retain app-random continuation"));

        assert_eq!(rebound.draw_offset, 8);
        assert_eq!(rebound.stream_positions, positions);
    }
}
