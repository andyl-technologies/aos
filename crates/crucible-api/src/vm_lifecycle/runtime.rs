//! Runtime observation and trigger settlement for production VM lifecycles.

use super::*;

#[path = "runtime/debug_evidence.rs"]
mod debug_evidence;

use debug_evidence::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecordedControlBoundary {
    Pending,
    Ready,
    Bypassed,
}

fn classify_recorded_control_boundary(
    expected: &BTreeMap<NodeId, VirtualTime>,
    observed: &BTreeMap<NodeId, VirtualTime>,
) -> RecordedControlBoundary {
    let mut pending = false;
    for (node, expected_at) in expected {
        let Some(observed_at) = observed.get(node) else {
            return RecordedControlBoundary::Bypassed;
        };
        if observed_at > expected_at {
            return RecordedControlBoundary::Bypassed;
        }
        pending |= observed_at < expected_at;
    }
    if pending {
        RecordedControlBoundary::Pending
    } else {
        RecordedControlBoundary::Ready
    }
}

impl ProductionVmLifecycleLoop {
    /// Returns the number of QEMU processes currently owned by this lifecycle.
    #[must_use]
    pub fn live_node_count(&self) -> usize {
        self.inner.backend().len()
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
                    let mut observed = BTreeMap::new();
                    for node in recorded.node_times.keys() {
                        if replay.inner.backend().node_now(node).is_err() {
                            let _ = replay.shutdown();
                            return Err(SchedulerError::BoundaryViolation {
                                message: format!(
                                    "whole-world debug replay cannot observe node `{}` for control {}",
                                    node.name, control_index
                                ),
                            });
                        }
                        let at = match replay.inner.loop_impl().scheduler_time_for_node(node) {
                            Ok(at) => at,
                            Err(error) => {
                                let _ = replay.shutdown();
                                return Err(error);
                            }
                        };
                        observed.insert(node.clone(), at);
                    }
                    match classify_recorded_control_boundary(&recorded.node_times, &observed) {
                        RecordedControlBoundary::Pending => Vec::new(),
                        RecordedControlBoundary::Ready => recorded.control.clone(),
                        RecordedControlBoundary::Bypassed => {
                            let _ = replay.shutdown();
                            return Err(SchedulerError::BoundaryViolation {
                                message: format!(
                                    "whole-world debug replay bypassed control {} node-time boundary",
                                    control_index
                                ),
                            });
                        }
                    }
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
        let mut node_times = BTreeMap::new();
        let mut fingerprints = BTreeMap::new();
        for node in nodes {
            node_icounts.insert(
                node.clone(),
                Icount {
                    retired: self.inner.backend().node_now(&node)?.ticks,
                },
            );
            node_times.insert(
                node.clone(),
                self.inner.loop_impl().scheduler_time_for_node(&node)?,
            );
            fingerprints.insert(node.clone(), self.inner.backend_mut().fingerprint(node)?);
        }
        let evidence = ProductionVmDebugRuntimeEvidence {
            configuration: self.inner.loop_impl().configuration().id(),
            event_log: self.inner.loop_impl().event_log_offset(),
            scheduler: self.inner.loop_impl().materialized_scheduler_state(),
            node_icounts,
            node_times,
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
            .find(|evidence| evidence.matches_graph_runtime(runtime))
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
        let evidence = match coordinate {
            crucible::DebugCoordinate::EventSequence(sequence) => self
                .debug_runtime_evidence
                .iter()
                .filter(|evidence| {
                    evidence.matches_graph_runtime(runtime) && evidence.runtime.is_some()
                })
                .find(|evidence| evidence.event_log.events > *sequence),
            crucible::DebugCoordinate::VirtualTime(time) => self
                .debug_runtime_evidence
                .iter()
                .rev()
                .filter(|evidence| {
                    evidence.matches_graph_runtime(runtime) && evidence.runtime.is_some()
                })
                .find(|evidence| evidence.scheduler_frontier(*time) <= *time),
            crucible::DebugCoordinate::NodeIcount { node, icount } => self
                .debug_runtime_evidence
                .iter()
                .rev()
                .filter(|evidence| {
                    evidence.matches_graph_runtime(runtime) && evidence.runtime.is_some()
                })
                .find(|evidence| {
                    evidence
                        .node_icounts
                        .get(node)
                        .is_some_and(|observed| observed <= icount)
                }),
            crucible::DebugCoordinate::Configuration(_)
            | crucible::DebugCoordinate::Checkpoint(_) => self
                .debug_runtime_evidence
                .iter()
                .find(|evidence| evidence.runtime.as_ref() == Some(runtime))
                .or_else(|| {
                    self.debug_runtime_evidence.iter().rev().find(|evidence| {
                        evidence.matches_graph_runtime(runtime) && evidence.runtime.is_some()
                    })
                }),
        }
        .ok_or_else(|| SchedulerError::BoundaryViolation {
            message: format!(
                "debug coordinate {coordinate:?} has no matching production runtime boundary evidence"
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

    /// Resolves the production scheduler frontier recorded for a debug target.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when the resolved runtime
    /// has no corresponding production evidence sample.
    pub(super) fn resolve_recorded_debug_coordinate_frontier(
        &self,
        coordinate: &crucible::DebugCoordinate,
        runtime: &RuntimeState,
        graph_fallback: VirtualTime,
    ) -> Result<VirtualTime, SchedulerError> {
        let evidence = self
            .debug_runtime_evidence
            .iter()
            .find(|evidence| evidence.runtime.as_ref() == Some(runtime))
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: format!(
                    "debug coordinate {coordinate:?} has no matching production frontier evidence"
                ),
            })?;
        Ok(evidence.scheduler_frontier(graph_fallback))
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
#[path = "runtime/tests.rs"]
mod tests;
