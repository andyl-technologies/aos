//! Runtime process reconciliation and thin replay for production VM lifecycles.

use super::*;

impl ProductionVmLifecycleLoop {
    /// Returns the number of QEMU processes currently owned by this lifecycle.
    #[must_use]
    pub fn live_node_count(&self) -> usize {
        self.inner.backend().len()
    }

    /// Returns the number of scheduler crash applications reconciled to QEMU.
    #[must_use]
    pub const fn reconciled_crash_count(&self) -> usize {
        self.reconciled_crashes
    }

    /// Returns the number of scheduler restart applications reconciled to QEMU.
    #[must_use]
    pub const fn reconciled_restart_count(&self) -> usize {
        self.reconciled_restarts
    }

    pub(super) fn reposition_debug_world(
        &mut self,
        request: DebugRuntimeRepositionRequest,
    ) -> Result<DebugRuntimeRepositionReport, SchedulerError> {
        self.reconcile_indeterminate_debug_ownership()?;
        if !request.proves_target_oracle() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "debug runtime replacement request has no valid target replay-oracle proof",
                ),
            });
        }
        let attach = self
            .debug_attach
            .as_ref()
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from("production debugger runtime is not attached"),
            })?
            .clone();
        if attach.node != request.node {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "debug runtime replacement targets `{}`, but the gateway owns `{}`",
                    request.node.name, attach.node.name
                ),
            });
        }
        let active_endpoint =
            DebugGdbEndpoint::new("production_qemu_gdbstub", attach.qemu_endpoint.clone())
                .map_err(|error| SchedulerError::BoundaryViolation {
                    message: format!("validate active production debugger endpoint: {error}"),
                })?;
        if active_endpoint != request.current_qemu_gdbstub {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "debug runtime replacement does not name the gateway's active backend",
                ),
            });
        }
        if self.inner.loop_impl().configuration().id() != request.current_configuration {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("debug runtime replacement current configuration is stale"),
            });
        }

        let target_evidence = self
            .debug_runtime_evidence
            .iter()
            .find(|evidence| evidence.matches_target(&request))
            .cloned()
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from(
                    "debug runtime target has no fingerprint evidence from the original live execution",
                ),
            })?;

        let mut candidate = self.replay_debug_candidate(&request)?;
        let mut verifier = match self.replay_debug_candidate(&request) {
            Ok(verifier) => verifier,
            Err(error) => {
                let _ = candidate.shutdown();
                return Err(error);
            }
        };
        if let Err(error) = verify_debug_replay_pair(&mut candidate, &mut verifier) {
            let _ = verifier.shutdown();
            let _ = candidate.shutdown();
            return Err(error);
        }
        verifier.shutdown()?;
        if let Err(error) =
            verify_debug_replay_against_live_evidence(&mut candidate, &target_evidence)
        {
            let _ = candidate.shutdown();
            return Err(error);
        }
        let candidate_path = candidate
            .debug_backend_paths
            .get(&request.node)
            .cloned()
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: format!(
                    "debug replay candidate has no private endpoint for `{}`",
                    request.node.name
                ),
            })?;
        let candidate_endpoint = DebugGdbEndpoint::new(
            "production_qemu_gdbstub",
            candidate_path.to_string_lossy().into_owned(),
        )
        .map_err(|error| SchedulerError::BoundaryViolation {
            message: format!("validate candidate production debugger endpoint: {error}"),
        })?;

        let promotion = self
            .debug_gateway
            .as_mut()
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from("production debugger gateway process is unavailable"),
            })?
            .promote_backend(&candidate_path);
        let generation = match promotion {
            Ok(generation) => generation,
            Err(error) => {
                if error.promotion_requires_gateway_teardown() {
                    self.debug_gateway_teardown_required = true;
                    self.indeterminate_debug_candidate = Some(Box::new(candidate));
                    let teardown = self.reconcile_indeterminate_debug_ownership();
                    return Err(SchedulerError::BoundaryViolation {
                        message: format!(
                            "promote replayed debugger backend: {error}; gateway quarantine reconciliation: {}",
                            teardown.map_or_else(
                                |failure| failure.to_string(),
                                |()| String::from("gateway termination observed")
                            )
                        ),
                    });
                }
                let _ = candidate.shutdown();
                return Err(SchedulerError::BoundaryViolation {
                    message: format!("promote replayed debugger backend: {error}"),
                });
            }
        };

        let mut refreshed_attach = attach;
        refreshed_attach.qemu_endpoint = candidate_path.to_string_lossy().into_owned();
        candidate.debug_attach = Some(refreshed_attach);
        candidate.debug_gateway = self.debug_gateway.take();
        candidate.debug_runtime_evidence = self.debug_runtime_evidence.clone();
        let mut previous = std::mem::replace(self, candidate);
        let retired_world_cleanup = match previous.inner.shutdown() {
            Ok(_) => DebugRetiredWorldCleanup::Reaped,
            Err(error) => DebugRetiredWorldCleanup::DetachedCleanupPending {
                diagnostic: error.to_string().chars().take(512).collect(),
            },
        };
        drop(previous);

        Ok(DebugRuntimeRepositionReport::completed_with_cleanup(
            &request,
            candidate_endpoint,
            generation,
            retired_world_cleanup,
        ))
    }

    fn replay_debug_candidate(
        &self,
        request: &DebugRuntimeRepositionRequest,
    ) -> Result<ProductionVmLifecycleLoop, SchedulerError> {
        let replay_config = self.config.clone().for_thin_replay();
        let mut replay =
            build_production_vm_lifecycle_loop(&self.scenario, &self.source, &replay_config)
                .map_err(|error| SchedulerError::BoundaryViolation {
                    message: format!("construct whole-world debug replay candidate: {error}"),
                })?;
        let target = &request.target;
        let controls = self.recorded_controls.clone();
        let mut control_index = 0_usize;
        let mut configuration = Configuration::genesis(self.scenario.clone());
        let max_quanta =
            replay_config.maximum_scheduler_quanta(self.source.world().vm_nodes().len());
        for _ in 0..=max_quanta {
            if configuration == *target && debug_candidate_matches_target_runtime(&replay, request)?
            {
                return Ok(replay);
            }
            if configuration.schedule.len() > target.schedule.len() {
                let _ = replay.shutdown();
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "whole-world debug replay bypassed target configuration {}",
                        target.id().to_hex()
                    ),
                });
            }
            let prefix = target
                .schedule
                .prefix(configuration.schedule.len())
                .map_err(|error| SchedulerError::BoundaryViolation {
                    message: format!("validate whole-world debug replay prefix: {error}"),
                })?;
            if prefix != configuration.schedule {
                let _ = replay.shutdown();
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "whole-world debug replay diverged before target configuration {}",
                        target.id().to_hex()
                    ),
                });
            }
            let control = match controls.get(control_index) {
                Some(recorded) if recorded.configuration == configuration => {
                    let boundary_matches = recorded.node_times.iter().all(|(node, expected)| {
                        replay.inner.backend().node_now(node).is_ok()
                            && replay
                                .inner
                                .loop_impl()
                                .scheduler_time_for_node(node)
                                .is_ok_and(|at| at == *expected)
                    });
                    if !boundary_matches {
                        let _ = replay.shutdown();
                        return Err(SchedulerError::BoundaryViolation {
                            message: format!(
                                "whole-world debug replay reached control {} at the wrong node-time boundary",
                                control_index
                            ),
                        });
                    }
                    recorded.control.clone()
                }
                Some(recorded)
                    if recorded.configuration.schedule.len() <= configuration.schedule.len() =>
                {
                    let _ = replay.shutdown();
                    return Err(SchedulerError::BoundaryViolation {
                        message: format!(
                            "whole-world debug replay bypassed recorded control {} at configuration {}",
                            control_index,
                            recorded.configuration.id().to_hex()
                        ),
                    });
                }
                _ => Vec::new(),
            };
            if !control.is_empty() {
                control_index = control_index.saturating_add(1);
            }
            configuration = crucible_session::drive_engine_quantum(
                &mut replay,
                QuantumRequest {
                    configuration,
                    control,
                },
            )?
            .configuration;
        }
        let _ = replay.shutdown();
        Err(SchedulerError::BoundaryViolation {
            message: format!(
                "whole-world debug replay did not reach target configuration {} within {max_quanta} quanta",
                target.id().to_hex()
            ),
        })
    }

    pub(super) fn reconcile_backend_membership(&mut self) -> Result<(), SchedulerError> {
        let crashes =
            self.inner.loop_impl().node_crash_applications()[self.reconciled_crashes..].to_vec();
        for crash in &crashes {
            if self.inner.backend().contains(&crash.node) {
                self.inner.backend_mut().stop_intended_crash(&crash.node)?;
            }
        }
        self.reconciled_crashes = self.inner.loop_impl().node_crash_applications().len();

        let restarts =
            self.inner.loop_impl().node_restart_applications()[self.reconciled_restarts..].to_vec();
        for restart in &restarts {
            if !restart.restarted {
                continue;
            }
            if restart.restart == RestartPolicy::FromLastCheckpoint {
                self.relaunch_last_checkpoint(restart)?;
                continue;
            }
            self.relaunch_ready_point(restart)?;
        }
        self.reconciled_restarts = self.inner.loop_impl().node_restart_applications().len();
        Ok(())
    }

    pub(super) fn rollback_prelaunch_after_error(
        &mut self,
        nodes: &[NodeId],
        original: SchedulerError,
    ) -> SchedulerError {
        for node in nodes.iter().rev() {
            self.prelaunched_restarts.remove(node);
            if self.inner.backend().contains(node)
                && let Err(cleanup) = self.inner.backend_mut().stop_intended_crash(node)
            {
                return SchedulerError::BoundaryViolation {
                    message: format!(
                        "production QEMU prelaunch failed with `{original}` and rollback for `{}` failed with `{cleanup}`",
                        node.name
                    ),
                };
            }
        }
        original
    }

    pub(super) fn relaunch_ready_point(
        &mut self,
        restart: &crucible::SchedulerNodeRestartApplication,
    ) -> Result<(), SchedulerError> {
        if self.inner.backend().contains(&restart.node) {
            let observed = self.inner.backend().node_now(&restart.node)?.ticks;
            if self.prelaunched_restarts.get(&restart.node)
                == Some(&(RestartPolicy::FromReadyPoint, restart.counter.ticks))
            {
                self.prelaunched_restarts.remove(&restart.node);
                self.inner
                    .loop_impl_mut()
                    .rebase_restarted_backend_counter(
                        &restart.node,
                        crucible::NodeCounter { ticks: observed },
                    )?;
                return Ok(());
            }
            if observed == restart.counter.ticks {
                return Ok(());
            }
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "prelaunched QEMU node `{}` is at {observed}, expected ready-point counter {}",
                    restart.node.name, restart.counter.ticks
                ),
            });
        }
        let observed = self.launch_ready_point(&restart.node, restart.counter.ticks)?;
        self.inner.loop_impl_mut().rebase_restarted_backend_counter(
            &restart.node,
            crucible::NodeCounter { ticks: observed },
        )
    }

    pub(super) fn relaunch_last_checkpoint(
        &mut self,
        restart: &crucible::SchedulerNodeRestartApplication,
    ) -> Result<(), SchedulerError> {
        if self.inner.backend().contains(&restart.node) {
            let observed = self.inner.backend().node_now(&restart.node)?.ticks;
            if self.prelaunched_restarts.get(&restart.node)
                == Some(&(RestartPolicy::FromLastCheckpoint, restart.counter.ticks))
            {
                self.prelaunched_restarts.remove(&restart.node);
                self.inner
                    .loop_impl_mut()
                    .rebase_restarted_backend_counter(
                        &restart.node,
                        crucible::NodeCounter { ticks: observed },
                    )?;
                return Ok(());
            }
            if observed == restart.counter.ticks {
                return Ok(());
            }
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "prelaunched checkpoint QEMU node `{}` is at {observed}, expected {}",
                    restart.node.name, restart.counter.ticks
                ),
            });
        }
        let observed = self.relaunch_last_checkpoint_node(&restart.node, restart.counter.ticks)?;
        self.inner.loop_impl_mut().rebase_restarted_backend_counter(
            &restart.node,
            crucible::NodeCounter { ticks: observed },
        )
    }

    pub(super) fn relaunch_last_checkpoint_node(
        &mut self,
        node: &NodeId,
        expected_counter: u64,
    ) -> Result<u64, SchedulerError> {
        let target = self.checkpoint_targets.get(node).cloned().ok_or_else(|| {
            SchedulerError::BoundaryViolation {
                message: format!(
                    "production QEMU checkpoint restart for `{}` has no captured configuration",
                    node.name
                ),
            }
        })?;
        if target.counter != expected_counter {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "production QEMU checkpoint target for `{}` is {}, scheduler requested {expected_counter}",
                    node.name, target.counter
                ),
            });
        }
        let replay_config = self.config.clone().for_thin_replay();
        let mut replay =
            build_production_vm_lifecycle_loop(&self.scenario, &self.source, &replay_config)
                .map_err(|error| SchedulerError::BoundaryViolation {
                    message: format!(
                        "construct QEMU thin-replay lifecycle for `{}`: {error}",
                        node.name
                    ),
                })?;
        replay
            .inner
            .loop_impl_mut()
            .set_replay_time_limit(target.scheduler_time)?;
        let mut configuration = Configuration::genesis(self.scenario.clone());
        let controls = self.recorded_controls[..target.control_count].to_vec();
        let mut control_index = 0_usize;
        let max_quanta =
            replay_config.maximum_scheduler_quanta(self.source.world().vm_nodes().len());
        for _ in 0..=max_quanta {
            let observed_time = replay.inner.loop_impl().scheduler_time_for_node(node)?;
            if configuration == target.configuration && observed_time == target.scheduler_time {
                break;
            }
            if configuration.schedule.len() > target.configuration.schedule.len() {
                let _ = replay.shutdown();
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "QEMU thin replay bypassed checkpoint configuration {}",
                        target.configuration.id().to_hex()
                    ),
                });
            }
            let prefix = target
                .configuration
                .schedule
                .prefix(configuration.schedule.len())
                .map_err(|error| SchedulerError::BoundaryViolation {
                    message: format!("validate QEMU checkpoint replay prefix: {error}"),
                })?;
            if prefix != configuration.schedule {
                let mismatch_index = prefix
                    .decisions()
                    .iter()
                    .zip(configuration.schedule.decisions())
                    .position(|(expected, observed)| expected != observed)
                    .unwrap_or_else(|| {
                        prefix
                            .decisions()
                            .len()
                            .min(configuration.schedule.decisions().len())
                    });
                let _ = replay.shutdown();
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "QEMU thin replay diverged before checkpoint configuration {} at decision {mismatch_index}: expected {:?}, observed {:?}",
                        target.configuration.id().to_hex(),
                        prefix.decisions().get(mismatch_index),
                        configuration.schedule.decisions().get(mismatch_index),
                    ),
                });
            }
            let control = controls
                .get(control_index)
                .filter(|recorded| {
                    recorded.configuration == configuration
                        && recorded.node_times.iter().all(|(node, expected)| {
                            replay.inner.backend().node_now(node).is_ok_and(|_counter| {
                                replay
                                    .inner
                                    .loop_impl()
                                    .scheduler_time_for_node(node)
                                    .is_ok_and(|at| at == *expected)
                            })
                        })
                })
                .map(|recorded| recorded.control.clone())
                .unwrap_or_default();
            if !control.is_empty() {
                control_index = control_index.saturating_add(1);
            }
            configuration = crucible_session::drive_engine_quantum(
                &mut replay,
                QuantumRequest {
                    configuration,
                    control,
                },
            )?
            .configuration;
        }
        let replay_time = replay.inner.loop_impl().scheduler_time_for_node(node)?;
        if configuration != target.configuration || replay_time != target.scheduler_time {
            let _ = replay.shutdown();
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "QEMU thin replay did not reach checkpoint configuration {} at scheduler time {} within {max_quanta} quanta: reached configuration {} at scheduler time {}",
                    target.configuration.id().to_hex(),
                    target.scheduler_time.ticks,
                    configuration.id().to_hex(),
                    replay_time.ticks,
                ),
            });
        }
        let (mut backend, run_directory, debug_backend_path) = replay.take_replayed_node(node)?;
        let observed = SimulationBackend::now(&backend).ticks;
        if self.inner.backend().contains(node) {
            let _ = SimulationBackend::shutdown(&mut backend);
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "QEMU thin-replayed node `{}` would replace an existing runtime",
                    node.name
                ),
            });
        }
        if let Some(path) = debug_backend_path
            && let Err(error) = self.promote_replacement_debug_backend(node, path)
        {
            if self.debug_gateway_teardown_required {
                self.indeterminate_debug_backend = Some(ProductionVmQuarantinedBackend {
                    backend,
                    run_directory: Some(run_directory),
                });
            } else {
                let _ = SimulationBackend::shutdown(&mut backend);
            }
            return Err(error);
        }
        if let Some(previous) = self.inner.backend_mut().insert(node.clone(), backend) {
            if let Some(mut installed) = self.inner.backend_mut().take(node) {
                let _ = SimulationBackend::shutdown(&mut installed);
            }
            self.inner.backend_mut().insert(node.clone(), previous);
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "QEMU thin-replayed node `{}` replaced an existing runtime",
                    node.name
                ),
            });
        }
        self.retained_replay_directories.push(run_directory);
        Ok(observed)
    }

    pub(super) fn take_replayed_node(
        mut self,
        node: &NodeId,
    ) -> Result<(ProductionLiveNode, tempfile::TempDir, Option<PathBuf>), SchedulerError> {
        let mut backend = self.inner.backend_mut().take(node).ok_or_else(|| {
            SchedulerError::BoundaryViolation {
                message: format!("QEMU replay lifecycle has no node `{}`", node.name),
            }
        })?;
        if let Err(error) = self.inner.backend_mut().shutdown() {
            let _ = SimulationBackend::shutdown(&mut backend);
            return Err(SchedulerError::Backend(error));
        }
        let debug_backend_path = self.debug_backend_paths.remove(node);
        Ok((backend, self._run_directory, debug_backend_path))
    }

    pub(super) fn launch_ready_point(
        &mut self,
        node: &NodeId,
        _expected_counter: u64,
    ) -> Result<u64, SchedulerError> {
        if self.inner.backend().contains(node) {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "cannot launch replacement QEMU node `{}` while its runtime is still present",
                    node.name
                ),
            });
        }
        let index = self.node_indexes.get(node).copied().ok_or_else(|| {
            SchedulerError::BoundaryViolation {
                message: format!(
                    "production QEMU restart has no launch index for `{}`",
                    node.name
                ),
            }
        })?;
        let generation = *self
            .restart_generations
            .entry(node.clone())
            .and_modify(|generation| *generation = generation.saturating_add(1))
            .or_insert(1);
        let node_directory = self
            ._run_directory
            .path()
            .join(format!("node-{index}-restart-{generation}"));
        fs::create_dir_all(&node_directory).map_err(|error| SchedulerError::BoundaryViolation {
            message: format!(
                "create QEMU restart directory {}: {error}",
                node_directory.display()
            ),
        })?;
        prepare_root_overlay(&self.executable, &self.root_image, &node_directory).map_err(
            |error| SchedulerError::BoundaryViolation {
                message: format!("prepare QEMU restart overlay for `{}`: {error}", node.name),
            },
        )?;
        let white_box_enabled = self
            .trigger_world
            .vm_nodes()
            .iter()
            .find(|vm| vm.id == *node)
            .map(|vm| vm.white_box == crucible::WhiteBoxPolicy::Enabled)
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: format!(
                    "production QEMU restart has no World node for `{}`",
                    node.name
                ),
            })?;
        let mut launch = self
            .launch_configs
            .get(node)
            .cloned()
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: format!(
                    "production QEMU restart has no launch configuration for `{}`",
                    node.name
                ),
            })?
            .with_run_directory(&node_directory);
        let replacement_debug_path = if self.debug_backend_paths.contains_key(node) {
            let path = private_backend_gdbstub_path(&node_directory);
            let endpoint = qemu_unix_gdbstub_endpoint(&path).map_err(|error| {
                SchedulerError::BoundaryViolation {
                    message: format!(
                        "configure replacement QEMU debugger endpoint for `{}`: {error}",
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
                    message: format!(
                        "replacement QEMU debugger configuration for `{}` is unavailable",
                        node.name
                    ),
                })?;
            let gdbstub = ProductionGdbstubChannelConfig::new(endpoint, operator_listen).map_err(
                |error| SchedulerError::BoundaryViolation {
                    message: format!(
                        "configure replacement QEMU debugger channel for `{}`: {error}",
                        node.name
                    ),
                },
            )?;
            launch = launch.with_gdbstub(gdbstub);
            Some(path)
        } else {
            None
        };
        if white_box_enabled {
            launch = launch.with_app_random(self.app_random_continuation_config(node)?);
        }
        let mut backend = launch_production_live_node(
            &launch,
            &node_directory,
            &node.name,
            "crucible-router",
            &format!("lifecycle-{}-restart-{generation}", node.name),
        )
        .map_err(|error| SchedulerError::BoundaryViolation {
            message: format!("relaunch QEMU node `{}`: {error}", node.name),
        })?;
        let observed = SimulationBackend::now(&backend).ticks;
        if let Some(path) = replacement_debug_path
            && let Err(error) = self.promote_replacement_debug_backend(node, path)
        {
            if self.debug_gateway_teardown_required {
                self.indeterminate_debug_backend = Some(ProductionVmQuarantinedBackend {
                    backend,
                    run_directory: None,
                });
            } else {
                let _ = SimulationBackend::shutdown(&mut backend);
            }
            return Err(error);
        }
        if let Some(previous) = self.inner.backend_mut().insert(node.clone(), backend) {
            if let Some(mut installed) = self.inner.backend_mut().take(node) {
                let _ = SimulationBackend::shutdown(&mut installed);
            }
            self.inner.backend_mut().insert(node.clone(), previous);
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "restarted QEMU node `{}` replaced an existing runtime",
                    node.name
                ),
            });
        }
        Ok(observed)
    }

    fn promote_replacement_debug_backend(
        &mut self,
        node: &NodeId,
        path: PathBuf,
    ) -> Result<(), SchedulerError> {
        if self
            .debug_attach
            .as_ref()
            .is_none_or(|attach| attach.node != *node)
        {
            self.debug_backend_paths.insert(node.clone(), path);
            return Ok(());
        }
        let promotion = self
            .debug_gateway
            .as_mut()
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: format!(
                    "debugged QEMU node `{}` has no lifecycle-owned gateway",
                    node.name
                ),
            })?
            .promote_backend(&path);
        if let Err(error) = promotion {
            let teardown = if error.promotion_requires_gateway_teardown() {
                self.debug_gateway_teardown_required = true;
                format!(
                    "; gateway quarantine reconciliation: {}",
                    self.reconcile_indeterminate_debug_ownership().map_or_else(
                        |failure| failure.to_string(),
                        |()| String::from("gateway termination observed"),
                    )
                )
            } else {
                String::new()
            };
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "promote replacement debugger backend for `{}`: {error}{teardown}",
                    node.name
                ),
            });
        }
        self.debug_backend_paths.insert(node.clone(), path.clone());
        if let Some(attach) = &mut self.debug_attach {
            attach.qemu_endpoint = path.to_string_lossy().into_owned();
        }
        Ok(())
    }

    pub(super) fn reconcile_indeterminate_debug_ownership(&mut self) -> Result<(), SchedulerError> {
        if !self.debug_gateway_teardown_required {
            return Ok(());
        }
        let gateway =
            self.debug_gateway
                .as_mut()
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: String::from(
                        "debug gateway teardown is required but its process handle is unavailable",
                    ),
                })?;
        gateway
            .terminate()
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!(
                    "debug gateway ownership remains indeterminate; candidate runtime retained: {error}"
                ),
            })?;
        self.debug_gateway = None;
        self.debug_attach = None;
        self.debug_gateway_teardown_required = false;
        if let Some(mut candidate) = self.indeterminate_debug_candidate.take() {
            candidate.debug_gateway = None;
            candidate.debug_attach = None;
            candidate
                .shutdown()
                .map_err(|error| SchedulerError::BoundaryViolation {
                    message: format!(
                        "shutdown quarantined debugger replay candidate after gateway termination: {error}"
                    ),
                })?;
        }
        if let Some(mut candidate) = self.indeterminate_debug_backend.take() {
            SimulationBackend::shutdown(&mut candidate.backend).map_err(|error| {
                SchedulerError::BoundaryViolation {
                    message: format!(
                        "shutdown quarantined debugger node after gateway termination: {error}"
                    ),
                }
            })?;
            drop(candidate.run_directory);
        }
        Ok(())
    }

    pub(super) fn capture_debug_runtime_evidence(&mut self) -> Result<(), SchedulerError> {
        if self.config.debug.is_none() {
            return Ok(());
        }
        let nodes = self
            .source
            .world()
            .vm_nodes()
            .iter()
            .map(|vm| vm.id.clone())
            .collect::<Vec<_>>();
        let mut node_icounts = BTreeMap::new();
        let mut fingerprints = BTreeMap::new();
        for node in nodes {
            node_icounts.insert(
                node.clone(),
                Icount {
                    retired: self.inner.backend().node_now(&node)?.ticks,
                },
            );
            fingerprints.insert(node.clone(), self.inner.backend_mut().fingerprint(node)?);
        }
        let evidence = ProductionVmDebugRuntimeEvidence {
            configuration: self.inner.loop_impl().configuration().id(),
            event_log: self.inner.loop_impl().event_log_offset(),
            scheduler: self.inner.loop_impl().materialized_scheduler_state(),
            node_icounts,
            fingerprints,
            graph_runtimes: Vec::new(),
            runtime: None,
        };
        if self
            .debug_runtime_evidence
            .last()
            .is_none_or(|last| !last.same_sample(&evidence))
        {
            self.debug_runtime_evidence.push(evidence);
        }
        Ok(())
    }

    pub(super) fn bind_latest_debug_runtime_evidence(
        &mut self,
        configuration: &Configuration,
        runtime: &RuntimeState,
    ) -> Result<RuntimeState, SchedulerError> {
        if self.config.debug.is_none() {
            return Ok(runtime.clone());
        }
        let reduced =
            crucible::reduce(&configuration.def, &configuration.schedule).map_err(|error| {
                SchedulerError::BoundaryViolation {
                    message: format!(
                        "reduce graph runtime before debugger evidence binding: {error}"
                    ),
                }
            })?;
        let latest_index = self
            .debug_runtime_evidence
            .len()
            .checked_sub(1)
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from(
                    "production debugger runtime has no sampled boundary evidence to bind",
                ),
            })?;
        let evidence = &self.debug_runtime_evidence[latest_index];
        evidence.validate_graph_runtime(configuration.id(), reduced.id, runtime)?;
        let bound_runtime = evidence.bind_graph_runtime(runtime);
        let evidence = &mut self.debug_runtime_evidence[latest_index];
        if !evidence.graph_runtimes.contains(runtime) {
            evidence.graph_runtimes.push(runtime.clone());
        }
        evidence.runtime = Some(bound_runtime.clone());
        Ok(bound_runtime)
    }

    pub(super) fn resolve_recorded_debug_runtime_evidence(
        &self,
        runtime: &RuntimeState,
    ) -> Result<RuntimeState, SchedulerError> {
        if self.config.debug.is_none() {
            return Ok(runtime.clone());
        }
        let evidence = self
            .debug_runtime_evidence
            .iter()
            .rev()
            .find(|evidence| evidence.graph_runtimes.contains(runtime))
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from(
                    "graph debug target has no matching production runtime evidence",
                ),
            })?;
        evidence
            .runtime
            .clone()
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from(
                    "production runtime evidence was not bound to graph materialization",
                ),
            })
    }

    pub(super) fn resolve_recorded_debug_coordinate_runtime_evidence(
        &self,
        coordinate: &crucible::DebugCoordinate,
        runtime: &RuntimeState,
    ) -> Result<RuntimeState, SchedulerError> {
        let crucible::DebugCoordinate::EventSequence(sequence) = coordinate else {
            return self.resolve_recorded_debug_runtime_evidence(runtime);
        };
        let evidence = self
            .debug_runtime_evidence
            .iter()
            .find(|evidence| {
                evidence.event_log.events > *sequence
                    && evidence.graph_runtimes.contains(runtime)
                    && evidence.runtime.is_some()
            })
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: format!(
                    "event-log sequence {sequence} has no matching production runtime boundary evidence"
                ),
            })?;
        evidence
            .runtime
            .clone()
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from(
                    "production coordinate evidence was not bound to graph materialization",
                ),
            })
    }

    fn app_random_continuation_config(
        &self,
        node: &NodeId,
    ) -> Result<ProductionAppRandomConfig, SchedulerError> {
        let scheduler = self.inner.loop_impl();
        let streams = scheduler
            .configuration()
            .schedule
            .decisions()
            .iter()
            .filter_map(|decision| match decision {
                Decision::AppRandom(random) if random.node == *node => Some(random.stream.clone()),
                _ => None,
            })
            .collect::<std::collections::BTreeSet<_>>();
        let positions = scheduler
            .future_decision_rng_state()
            .positions
            .iter()
            .filter(|(stream, _position)| streams.contains(*stream))
            .map(|(stream, position)| (stream.name.clone(), position.draws))
            .collect::<BTreeMap<_, _>>();
        let draw_offset = positions.values().try_fold(0_u64, |sum, draws| {
            sum.checked_add(*draws)
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "app-random continuation cursor overflow for `{}`",
                        node.name
                    ),
                })
        })?;
        let mut config = ProductionAppRandomConfig::from_seed(
            scheduler.future_decision_seed(),
            self.scenario.app_random_draw_cap(),
            node.name.clone(),
        )
        .with_continuation(draw_offset, positions);
        if let Some(branch) = &self.branch
            && let Some(seed) = branch.seed
        {
            let prefix_draws = branch
                .base
                .schedule
                .decisions()
                .iter()
                .filter(|decision| {
                    matches!(decision, Decision::AppRandom(random) if random.node == *node)
                })
                .count() as u64;
            config = config.with_branch_seed(seed, prefix_draws);
        }
        Ok(config)
    }

    pub(super) fn settle_trigger_graph(
        &mut self,
    ) -> Result<Vec<SchedulerEventLogAppend>, SchedulerError> {
        let mut appends = Vec::new();
        if self.initial_lifecycle_observations_pending {
            let at = self.inner.loop_impl().frontier();
            let initial_events = initial_node_state_events(&self.source, at);
            appends.push(
                self.inner
                    .loop_impl_mut()
                    .append_observable_events(initial_events)?,
            );
            self.initial_lifecycle_observations_pending = false;
        }
        for _ in 0..MAX_TRIGGER_SETTLE_BATCHES {
            let assertion_outcomes = self.assertion_evaluator.observe_prefix(
                self.inner.loop_impl().condition_event_log_prefix(),
                &mut self.assertion_oracle,
            );
            let assertion_events = assertion_outcomes
                .iter()
                .filter_map(assertion_state_event_from_outcome)
                .collect::<Vec<_>>();
            let assertions_changed = !assertion_events.is_empty();
            if assertions_changed {
                appends.push(
                    self.inner
                        .loop_impl_mut()
                        .append_observable_events(assertion_events)?,
                );
            }

            let scheduler = self.inner.loop_impl();
            let mut pass = ConditionEvaluationPass::from_log_prefix(
                scheduler.condition_event_log_prefix().clone(),
                no_named_trigger_leaf,
            )
            .with_timer_fires(scheduler.trigger_actions().armed_timers.clone())
            .with_scheduler_quiescence(scheduler.quiescence()?)
            .with_world_white_box_policies(&self.trigger_world);
            let firings = pass.evaluate_event_graph(&self.trigger_graph, &mut self.trigger_state);
            if firings.is_empty() && !assertions_changed {
                return Ok(appends);
            }
            if !firings.is_empty() {
                merge_terminal_verdict(&mut self.terminal_verdict, &firings);
                let append = self.inner.loop_impl_mut().apply_trigger_firings(&firings)?;
                appends.push(append);
                self.inner
                    .loop_impl_mut()
                    .apply_queued_topology_changes_at_boundary()?;
            }
        }
        Err(SchedulerError::BoundaryViolation {
            message: format!(
                "trigger graph did not settle within {MAX_TRIGGER_SETTLE_BATCHES} batches"
            ),
        })
    }
}

fn initial_node_state_events(source: &ScenarioDefForm, at: VirtualTime) -> Vec<ObservableEvent> {
    source
        .world()
        .vm_nodes()
        .iter()
        .map(|node| ObservableEvent::node_state(at, node.id.clone(), NodeLifecycle::Started))
        .collect()
}

impl ProductionVmDebugRuntimeEvidence {
    fn same_sample(&self, other: &Self) -> bool {
        self.configuration == other.configuration
            && self.event_log == other.event_log
            && self.scheduler == other.scheduler
            && self.node_icounts == other.node_icounts
            && self.fingerprints == other.fingerprints
    }

    fn bind_graph_runtime(&self, runtime: &RuntimeState) -> RuntimeState {
        let mut bound = runtime.clone();
        bound.configuration = self.configuration;
        bound.event_log = self.event_log;
        bound.scheduler = self.scheduler.clone();
        bound.node_icounts = self.node_icounts.clone();
        bound
    }

    fn validate_graph_runtime(
        &self,
        configuration: ContentHash,
        reduced_state: ContentHash,
        runtime: &RuntimeState,
    ) -> Result<(), SchedulerError> {
        let graph_nodes = runtime
            .node_icounts
            .keys()
            .collect::<std::collections::BTreeSet<_>>();
        let evidence_nodes = self
            .node_icounts
            .keys()
            .collect::<std::collections::BTreeSet<_>>();
        let blob_nodes = runtime
            .node_blobs
            .keys()
            .collect::<std::collections::BTreeSet<_>>();
        let graph_nodes_valid = (graph_nodes.is_empty() && blob_nodes.is_empty())
            || (graph_nodes == evidence_nodes && blob_nodes == evidence_nodes);
        if self.configuration == configuration
            && runtime.configuration == configuration
            && runtime.id == reduced_state
            && graph_nodes_valid
        {
            return Ok(());
        }
        Err(SchedulerError::BoundaryViolation {
            message: format!(
                "graph runtime identity does not match the latest production debugger boundary: boundary_configuration_match={} runtime_configuration_match={} reduced_state_match={} node_sets_match={}",
                self.configuration == configuration,
                runtime.configuration == configuration,
                runtime.id == reduced_state,
                graph_nodes_valid,
            ),
        })
    }

    fn matches_target(&self, request: &DebugRuntimeRepositionRequest) -> bool {
        self.configuration == request.target.id()
            && self.event_log == request.target_runtime.event_log
            && self.scheduler == request.target_runtime.scheduler
            && self.node_icounts == request.target_runtime.node_icounts
            && self.runtime.as_ref() == Some(&request.target_runtime)
    }
}

fn debug_candidate_matches_target_runtime(
    candidate: &ProductionVmLifecycleLoop,
    request: &DebugRuntimeRepositionRequest,
) -> Result<bool, SchedulerError> {
    if candidate.inner.loop_impl().configuration() != &request.target
        || candidate.inner.loop_impl().event_log_offset() != request.target_runtime.event_log
        || candidate.inner.loop_impl().materialized_scheduler_state()
            != request.target_runtime.scheduler
    {
        return Ok(false);
    }
    let world_nodes = candidate
        .source
        .world()
        .vm_nodes()
        .iter()
        .map(|vm| vm.id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    if request
        .target_runtime
        .node_icounts
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        != world_nodes
    {
        return Ok(false);
    }
    for (node, expected) in &request.target_runtime.node_icounts {
        if candidate.inner.backend().node_now(node)?.ticks != expected.retired {
            return Ok(false);
        }
    }
    Ok(true)
}

fn verify_debug_replay_against_live_evidence(
    candidate: &mut ProductionVmLifecycleLoop,
    evidence: &ProductionVmDebugRuntimeEvidence,
) -> Result<(), SchedulerError> {
    for (node, expected) in &evidence.fingerprints {
        let actual = candidate.inner.backend_mut().fingerprint(node.clone())?;
        if actual != *expected {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "whole-world debugger replay for `{}` does not match the original live execution fingerprint",
                    node.name
                ),
            });
        }
    }
    Ok(())
}

fn verify_debug_replay_pair(
    candidate: &mut ProductionVmLifecycleLoop,
    verifier: &mut ProductionVmLifecycleLoop,
) -> Result<(), SchedulerError> {
    if candidate.inner.loop_impl().materialized_scheduler_state()
        != verifier.inner.loop_impl().materialized_scheduler_state()
    {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from(
                "whole-world debugger replay candidates produced different scheduler state",
            ),
        });
    }
    for vm in candidate.source.world().vm_nodes() {
        let candidate_counter = candidate.inner.backend().node_now(&vm.id)?;
        let verifier_counter = verifier.inner.backend().node_now(&vm.id)?;
        if candidate_counter != verifier_counter {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "whole-world debugger replay candidates disagree on `{}` counter",
                    vm.id.name
                ),
            });
        }
        let candidate_fingerprint = candidate.inner.backend_mut().fingerprint(vm.id.clone())?;
        let verifier_fingerprint = verifier.inner.backend_mut().fingerprint(vm.id.clone())?;
        if candidate_fingerprint != verifier_fingerprint {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "whole-world debugger replay candidates disagree on `{}` execution fingerprint",
                    vm.id.name
                ),
            });
        }
    }
    Ok(())
}

fn assertion_state_event_from_outcome(outcome: &HostAssertionOutcome) -> Option<ObservableEvent> {
    let state = match outcome.kind {
        HostAssertionOutcomeKind::Satisfied => AssertionPhase::Satisfied,
        HostAssertionOutcomeKind::Violated => AssertionPhase::Violated,
        HostAssertionOutcomeKind::Passed
        | HostAssertionOutcomeKind::Warning
        | HostAssertionOutcomeKind::NeverEvaluated
        | HostAssertionOutcomeKind::NeverTriggered
        | HostAssertionOutcomeKind::NeverReachedWarn
        | HostAssertionOutcomeKind::NeverReachedFail => return None,
    };
    Some(ObservableEvent::assertion_state_changed(
        outcome.at,
        outcome.assertion.clone(),
        state,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(domain: &str) -> ContentHash {
        ContentHash::from_canonical_material("debug-runtime-evidence-test", domain)
    }

    fn node() -> NodeId {
        NodeId {
            name: String::from("vm-a"),
        }
    }

    fn initially_violated_scenario() -> ScenarioDefForm {
        let base = crucible::crash_restart_scenario()
            .unwrap_or_else(|error| panic!("built-in scenario should validate: {error}"))
            .scenario;
        let world = base.world().clone();
        let assertion_id = crucible::AssertionId::from_name("db-0-must-remain-crashed");
        let properties = crucible::Properties::from_assertions_for_world(
            &world,
            vec![crucible::AssertionDef {
                id: assertion_id.clone(),
                message: String::from("db-0 must remain crashed"),
                property: crucible::Property::Always {
                    predicate: crucible::Predicate::node_state(
                        NodeId {
                            name: String::from("db-0"),
                        },
                        NodeLifecycle::Crashed,
                    ),
                },
            }],
        )
        .unwrap_or_else(|error| panic!("test assertions should validate: {error}"));
        let assertion_ids = vec![assertion_id.clone()];
        let graph = EventGraph::builder()
            .event("fail-on-initial-violation")
            .when(crucible::Predicate::assertion_state(
                assertion_id,
                AssertionPhase::Violated,
            ))
            .action(Action::fail("db-0 did not remain crashed"))
            .build_with_assertions_for_world(assertion_ids.clone(), &world)
            .unwrap_or_else(|error| panic!("test trigger should validate: {error}"));
        let plan = crucible::Plan::from_event_graph_with_assertions_for_world(
            &world,
            assertion_ids,
            graph,
        )
        .unwrap_or_else(|error| panic!("test plan should validate: {error}"));
        ScenarioDefForm::from_components_with_app_random_draw_cap(
            &world,
            &plan,
            &properties,
            Seed::from_u64(7),
            0,
        )
        .unwrap_or_else(|error| panic!("test scenario should validate: {error}"))
    }

    fn production_loop_without_backends(source: &ScenarioDefForm) -> ProductionVmLifecycleLoop {
        let scenario = source.scenario_def();
        let runtime_scenario = SchedulerLivenessScenario::from_runnable_world(
            &scenario.id().to_hex(),
            Shift::new(0).unwrap_or_else(|error| panic!("zero shift should validate: {error}")),
            4,
            SimInstant { nanos: 4 },
            0,
            source.world(),
        )
        .with_scenario_def(scenario.clone());
        let mut scheduler = SingleScheduler::new(runtime_scenario)
            .unwrap_or_else(|error| panic!("test scheduler should build: {error}"));
        scheduler
            .attach_world_network_links(source.world())
            .unwrap_or_else(|error| panic!("test world links should attach: {error}"));
        let trigger_graph = source
            .plan()
            .lower_to_event_graph_for_world(source.world())
            .unwrap_or_else(|error| panic!("test trigger plan should lower: {error}"))
            .into_event_graph();
        let config = ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root");

        ProductionVmLifecycleLoop {
            inner: BackendQuantumLoop::new(scheduler, ProductionNodeSet::new()),
            trigger_graph,
            trigger_state: EventGraphState::default(),
            trigger_world: source.world().clone(),
            assertion_evaluator: HostAssertionEvaluator::new(source.properties())
                .with_world_white_box_policies(source.world()),
            assertion_oracle: BlackBoxHostOracle,
            terminal_verdict: None,
            initial_lifecycle_observations_pending: true,
            branch: None,
            launch_configs: BTreeMap::new(),
            node_indexes: BTreeMap::new(),
            restart_generations: BTreeMap::new(),
            executable: PathBuf::from("qemu"),
            root_image: PathBuf::from("root"),
            scenario,
            source: source.clone(),
            config,
            checkpoint_targets: BTreeMap::new(),
            recorded_controls: Vec::new(),
            prelaunched_restarts: BTreeMap::new(),
            debug_backend_paths: BTreeMap::new(),
            debug_gateway: None,
            debug_attach: None,
            debug_gateway_teardown_required: false,
            indeterminate_debug_candidate: None,
            indeterminate_debug_backend: None,
            debug_runtime_evidence: Vec::new(),
            retained_replay_directories: Vec::new(),
            reconciled_crashes: 0,
            reconciled_restarts: 0,
            _run_directory: tempfile::tempdir()
                .unwrap_or_else(|error| panic!("test run directory should build: {error}")),
        }
    }

    fn graph_runtime(configuration: ContentHash, reduced_state: ContentHash) -> RuntimeState {
        RuntimeState {
            id: reduced_state,
            configuration,
            node_blobs: BTreeMap::new(),
            node_icounts: BTreeMap::new(),
            scheduler: SchedulerState::default(),
            event_log: EventLogOffset::default(),
        }
    }

    fn evidence(configuration: ContentHash) -> ProductionVmDebugRuntimeEvidence {
        ProductionVmDebugRuntimeEvidence {
            configuration,
            event_log: EventLogOffset::new(hash("event-log"), 3, 7),
            scheduler: SchedulerState::default(),
            node_icounts: BTreeMap::from([(node(), Icount { retired: 41 })]),
            fingerprints: BTreeMap::new(),
            graph_runtimes: Vec::new(),
            runtime: None,
        }
    }

    #[test]
    fn production_lifecycle_emits_initial_started_state_for_every_vm() {
        let scenario = crucible::happy_path_scenario()
            .unwrap_or_else(|error| panic!("built-in scenario should validate: {error}"))
            .scenario;
        let at = VirtualTime { ticks: 17 };

        let events = initial_node_state_events(&scenario, at);

        assert_eq!(events.len(), scenario.world().vm_nodes().len());
        for (event, node) in events.iter().zip(scenario.world().vm_nodes()) {
            assert!(
                event.at() == at
                    && matches!(
                        event.payload(),
                        crucible::ObservableEventPayload::NodeState {
                            node: observed,
                            state: NodeLifecycle::Started,
                        } if observed == &node.id
                    ),
                "initial lifecycle observations must preserve canonical world order"
            );
        }
    }

    #[test]
    fn initial_terminal_assertion_returns_without_advancing_a_backend() {
        let source = initially_violated_scenario();
        let mut lifecycle = production_loop_without_backends(&source);
        let configuration = lifecycle.inner.loop_impl().configuration().clone();
        let frontier = lifecycle.inner.loop_impl().frontier();

        let outcome = lifecycle
            .drive_quantum(QuantumRequest {
                configuration: configuration.clone(),
                control: Vec::new(),
            })
            .unwrap_or_else(|error| panic!("initial terminal boundary should settle: {error}"));

        assert_eq!(outcome.configuration, configuration);
        assert_eq!(outcome.frontier, frontier);
        assert_eq!(outcome.advanced_node, None);
        assert!(outcome.resolved_events.is_empty());
        assert!(outcome.decisions.is_empty());
        assert_eq!(outcome.event_log_entries.len(), 6);
        for (entry, node) in outcome.event_log_entries[..3]
            .iter()
            .zip(source.world().vm_nodes())
        {
            assert!(matches!(
                entry.payload(),
                crucible::SchedulerEventLogPayload::Observable(
                    crucible::ObservableEventPayload::NodeState {
                        node: observed,
                        state: NodeLifecycle::Started,
                    }
                ) if observed == &node.id
            ));
        }
        assert!(matches!(
            outcome.event_log_entries[3].payload(),
            crucible::SchedulerEventLogPayload::Observable(
                crucible::ObservableEventPayload::AssertionStateChanged {
                    state: AssertionPhase::Violated,
                    ..
                }
            )
        ));
        assert!(matches!(
            outcome.event_log_entries[4].payload(),
            crucible::SchedulerEventLogPayload::TriggerFired(_)
        ));
        assert!(matches!(
            outcome.event_log_entries[5].payload(),
            crucible::SchedulerEventLogPayload::TriggerActionApplied(_)
        ));
        assert!(matches!(
            lifecycle.take_terminal_verdict(),
            Some(QuantumTerminalVerdict::Failed(violations))
                if violations == vec![String::from("db-0 did not remain crashed")]
        ));
    }

    #[test]
    fn production_debug_evidence_hydrates_only_backend_owned_runtime_fields() {
        let configuration = hash("configuration");
        let reduced_state = hash("reduced-state");
        let mut graph = graph_runtime(configuration, reduced_state);
        graph
            .node_blobs
            .insert(node(), crucible::NodeBlobRef::baked(hash("blob")));
        graph.node_icounts.insert(node(), Icount { retired: 5 });
        let evidence = evidence(configuration);

        if let Err(error) = evidence.validate_graph_runtime(configuration, reduced_state, &graph) {
            panic!("complete graph identity should validate: {error}");
        }
        let bound = evidence.bind_graph_runtime(&graph);
        assert_eq!(bound.id, graph.id);
        assert_eq!(bound.node_blobs, graph.node_blobs);
        assert_eq!(bound.event_log, evidence.event_log);
        assert_eq!(bound.node_icounts, evidence.node_icounts);
    }

    #[test]
    fn production_debug_evidence_rejects_forged_or_partial_graph_identity() {
        let configuration = hash("configuration");
        let reduced_state = hash("reduced-state");
        let evidence = evidence(configuration);
        let mut forged = graph_runtime(configuration, hash("forged-state"));
        assert!(
            evidence
                .validate_graph_runtime(configuration, reduced_state, &forged)
                .is_err()
        );

        forged.id = reduced_state;
        forged.node_icounts.insert(node(), Icount { retired: 5 });
        assert!(
            evidence
                .validate_graph_runtime(configuration, reduced_state, &forged)
                .is_err()
        );
    }
}
