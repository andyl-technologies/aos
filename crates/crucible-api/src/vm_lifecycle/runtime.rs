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
        let (mut backend, run_directory) = replay.take_replayed_node(node)?;
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
    ) -> Result<(ProductionLiveNode, tempfile::TempDir), SchedulerError> {
        let mut backend = self.inner.backend_mut().take(node).ok_or_else(|| {
            SchedulerError::BoundaryViolation {
                message: format!("QEMU replay lifecycle has no node `{}`", node.name),
            }
        })?;
        if let Err(error) = self.inner.backend_mut().shutdown() {
            let _ = SimulationBackend::shutdown(&mut backend);
            return Err(SchedulerError::Backend(error));
        }
        Ok((backend, self._run_directory))
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
        let launch = self
            .launch_configs
            .get(node)
            .cloned()
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: format!(
                    "production QEMU restart has no launch configuration for `{}`",
                    node.name
                ),
            })?
            .with_app_random(self.app_random_continuation_config(node)?)
            .with_run_directory(&node_directory);
        let backend = launch_production_live_node(
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
        for _ in 0..MAX_TRIGGER_SETTLE_BATCHES {
            let scheduler = self.inner.loop_impl();
            let mut pass = ConditionEvaluationPass::from_log_prefix(
                scheduler.condition_event_log_prefix().clone(),
                no_named_trigger_leaf,
            )
            .with_timer_fires(scheduler.trigger_actions().armed_timers.clone())
            .with_scheduler_quiescence(scheduler.quiescence()?)
            .with_world_white_box_policies(&self.trigger_world);
            let firings = pass.evaluate_event_graph(&self.trigger_graph, &mut self.trigger_state);
            if firings.is_empty() {
                return Ok(appends);
            }
            merge_terminal_verdict(&mut self.terminal_verdict, &firings);
            let append = self.inner.loop_impl_mut().apply_trigger_firings(&firings)?;
            appends.push(append);
            self.inner
                .loop_impl_mut()
                .apply_queued_topology_changes_at_boundary()?;
        }
        Err(SchedulerError::BoundaryViolation {
            message: format!(
                "trigger graph did not settle within {MAX_TRIGGER_SETTLE_BATCHES} batches"
            ),
        })
    }
}
