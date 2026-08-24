//! `QuantumLoop` delegation for the production VM lifecycle.

use super::*;

mod lifecycle;
pub(super) use lifecycle::{
    DurableRunStateError, LifecycleStatePersistence, PRODUCTION_RUN_STATE_FILE,
    decode_prior_run_state, decode_run_json_bounded, persist_run_state_atomic,
};
#[cfg(test)]
pub(super) use lifecycle::{HARD_RUN_STATE_JSON_BYTES, validate_recovered_lifecycle_journal};
use lifecycle::{
    PreparedLifecyclePrecommit, PreparedLifecycleTerminal, PreparedTerminalReplacement,
    map_journal_limit, try_lifecycle_crash_detector,
};

impl QuantumLoop for ProductionVmLifecycleLoop {
    fn drive_quantum(
        &mut self,
        mut request: QuantumRequest,
    ) -> Result<QuantumOutcome, SchedulerError> {
        self.reconcile_indeterminate_debug_ownership()?;
        let mut pre_quantum_appends = Vec::new();
        let fault_append = self.evaluate_signal_fault_boundary()?;
        if !fault_append.entries.is_empty() {
            pre_quantum_appends.push(fault_append);
        }
        pre_quantum_appends.extend(self.settle_trigger_graph()?);
        let (pre_quantum_decisions, settled_configuration, network_appends) = self
            .inner
            .settle_pending_network_outputs_at_current_frontier()?
            .into_parts();
        pre_quantum_appends.extend(network_appends);
        if let Some(configuration) = settled_configuration {
            request.configuration = configuration;
        }
        if request.configuration != *self.inner.loop_impl().configuration() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "quantum request configuration is not the scheduler frontier",
                ),
            });
        }
        if self.terminal_verdict.is_some() {
            let scheduler = self.inner.loop_impl();
            let mut outcome = QuantumOutcome {
                configuration: scheduler.configuration().clone(),
                frontier: scheduler.frontier(),
                advanced_node: None,
                resolved_events: Vec::new(),
                decisions: Vec::new(),
                event_log_entries: Vec::new(),
                event_log_segment_bytes: Vec::new(),
                event_log_segment_text: String::new(),
                event_log_segment_hash: None,
                event_log_offset: scheduler.event_log_offset(),
                scheduler_quiescence: Some(scheduler.quiescence()?),
            };
            prepend_event_log_appends(&mut outcome, pre_quantum_appends);
            self.capture_debug_runtime_evidence()?;
            return Ok(outcome);
        }
        if self.branch.as_ref().is_some_and(|branch| {
            branch.base == request.configuration && !request.control.is_empty()
        }) {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "branch-prefix admission cannot discard simultaneous control",
                ),
            });
        }
        if !request.control.is_empty() {
            let mut node_times = BTreeMap::new();
            for node in self.source.world().vm_nodes() {
                if self.inner.backend().node_now(&node.id).is_err() {
                    continue;
                }
                let at = self.inner.loop_impl().scheduler_time_for_node(&node.id)?;
                node_times.insert(node.id.clone(), at);
            }
            self.recorded_controls.push(ProductionVmRecordedControl {
                configuration: request.configuration.clone(),
                node_times,
                control: request.control.clone(),
            });
        }
        if let Some(branch) = self.branch.as_ref() {
            let frontier = self.inner.loop_impl().frontier();
            if frontier > branch.frontier {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "production branch frontier {} was passed at {}",
                        branch.frontier.ticks, frontier.ticks
                    ),
                });
            }
            if frontier == branch.frontier && request.configuration != branch.base {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "production branch reached frontier {} with configuration {}, expected {}",
                        frontier.ticks,
                        request.configuration.id().to_hex(),
                        branch.base.id().to_hex(),
                    ),
                });
            }
            if frontier == branch.frontier && request.configuration == branch.base {
                if !request.control.is_empty() {
                    return Err(SchedulerError::BoundaryViolation {
                        message: String::from(
                            "branch-prefix admission cannot discard simultaneous control",
                        ),
                    });
                }
                let branch_decisions = branch.decisions.clone();
                let (configuration, append) = self
                    .inner
                    .loop_impl_mut()
                    .append_branch_prefix_overrides(branch_decisions.clone())?;
                if let Some(seed) = branch.seed {
                    self.inner.loop_impl_mut().reseed_future_decisions(seed)?;
                }
                self.inner.loop_impl_mut().clear_branch_frontier_cap();
                let frontier = self.inner.loop_impl().frontier();
                let scheduler_quiescence = Some(self.inner.loop_impl().quiescence()?);
                self.branch = None;
                let mut decisions = pre_quantum_decisions;
                decisions.extend(branch_decisions);
                let mut outcome = QuantumOutcome {
                    configuration,
                    frontier,
                    advanced_node: None,
                    resolved_events: Vec::new(),
                    decisions,
                    event_log_entries: append.entries,
                    event_log_segment_bytes: append.segment_bytes,
                    event_log_segment_text: append.segment_text,
                    event_log_segment_hash: append.segment_hash,
                    event_log_offset: append.offset,
                    scheduler_quiescence,
                };
                prepend_event_log_appends(&mut outcome, pre_quantum_appends);
                self.capture_debug_runtime_evidence()?;
                return Ok(outcome);
            }
            if request.configuration.schedule.len() > branch.base.schedule.len()
                || (request.configuration.schedule.len() == branch.base.schedule.len()
                    && request.configuration != branch.base)
            {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "branch-prefix replay bypassed base configuration {}",
                        branch.base.id().to_hex()
                    ),
                });
            }
        }
        let mut outcome = crucible_session::drive_engine_quantum(&mut self.inner, request)?;
        let observations = Arc::clone(&self.storage_fault_observations);
        let mut queued = observations
            .lock()
            .map_err(|_| SchedulerError::BoundaryViolation {
                message: String::from("production fault observation journal lock is poisoned"),
            })?;
        let storage_observations = queued.drain_ready(
            self.inner
                .loop_impl()
                .condition_event_log_prefix()
                .point()
                .at()
                .ticks,
        );
        if !storage_observations.is_empty() {
            let append = self
                .inner
                .loop_impl_mut()
                .append_fault_observations(storage_observations)?;
            merge_event_log_append(&mut outcome, append);
        }
        drop(queued);
        let pending_search_choices = self
            .fault_runtime
            .lock()
            .map_err(|_| SchedulerError::BoundaryViolation {
                message: String::from("production fault runtime lock is poisoned"),
            })?
            .drain_search_choices();
        self.inner
            .loop_impl_mut()
            .record_pending_signal_fault_search_frontiers(pending_search_choices)?;
        if !pre_quantum_decisions.is_empty() {
            let mut decisions = pre_quantum_decisions;
            decisions.extend(std::mem::take(&mut outcome.decisions));
            outcome.decisions = decisions;
        }
        prepend_event_log_appends(&mut outcome, pre_quantum_appends);
        for append in self.settle_trigger_graph()? {
            merge_event_log_append(&mut outcome, append);
        }
        self.capture_debug_runtime_evidence()?;
        Ok(outcome)
    }

    fn backend_step_ceiling(
        &self,
        outcome: &QuantumOutcome,
    ) -> Result<VirtualTime, SchedulerError> {
        self.inner.backend_step_ceiling(outcome)
    }

    fn sample_fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, SchedulerError> {
        self.inner.sample_fingerprint(node)
    }

    fn bind_debug_runtime_evidence(
        &mut self,
        configuration: &Configuration,
        runtime: &RuntimeState,
    ) -> Result<RuntimeState, SchedulerError> {
        self.bind_latest_debug_runtime_evidence(configuration, runtime)
    }

    fn resolve_debug_runtime_evidence(
        &self,
        runtime: &RuntimeState,
    ) -> Result<RuntimeState, SchedulerError> {
        self.resolve_recorded_debug_runtime_evidence(runtime)
    }

    fn resolve_debug_coordinate_runtime_evidence(
        &self,
        coordinate: &crucible::DebugCoordinate,
        runtime: &RuntimeState,
    ) -> Result<RuntimeState, SchedulerError> {
        self.resolve_recorded_debug_coordinate_runtime_evidence(coordinate, runtime)
    }

    fn resolve_debug_coordinate_frontier(
        &self,
        coordinate: &crucible::DebugCoordinate,
        runtime: &RuntimeState,
        graph_fallback: VirtualTime,
    ) -> Result<VirtualTime, SchedulerError> {
        self.resolve_recorded_debug_coordinate_frontier(coordinate, runtime, graph_fallback)
    }

    fn poll_gdb_run_control(&mut self) -> Result<Option<Vec<u8>>, SchedulerError> {
        self.reconcile_indeterminate_debug_ownership()?;
        self.debug_gateway.as_mut().map_or(Ok(None), |gateway| {
            gateway
                .poll_run_control()
                .map_err(|error| SchedulerError::BoundaryViolation {
                    message: format!("poll debugger scheduler run control: {error}"),
                })
        })
    }

    fn complete_gdb_run_control(&mut self, response: &[u8]) -> Result<(), SchedulerError> {
        self.reconcile_indeterminate_debug_ownership()?;
        self.debug_gateway
            .as_mut()
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from("production debugger gateway process is unavailable"),
            })?
            .complete_run_control(response)
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!("complete debugger scheduler run control: {error}"),
            })
    }

    fn acquire_internal_debug_run(&mut self) -> Result<(), SchedulerError> {
        self.reconcile_indeterminate_debug_ownership()?;
        self.debug_gateway
            .as_mut()
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from("production debugger gateway process is unavailable"),
            })?
            .acquire_scheduler_lease()
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!("acquire internal debugger scheduler ownership: {error}"),
            })
    }

    fn release_internal_debug_run(&mut self) -> Result<(), SchedulerError> {
        self.reconcile_indeterminate_debug_ownership()?;
        self.debug_gateway
            .as_mut()
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from("production debugger gateway process is unavailable"),
            })?
            .release_scheduler_lease()
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!("release internal debugger scheduler ownership: {error}"),
            })
    }

    fn apply_control_at_boundary(
        &mut self,
        control: Vec<ControlOperation>,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        let snapshot_requested = control
            .iter()
            .any(|operation| matches!(operation.kind, crucible::ControlOperationKind::Snapshot));
        let events = self.inner.apply_control_at_boundary(control)?;
        if snapshot_requested {
            let configuration = self.inner.loop_impl().configuration().clone();
            self.capture_exact_checkpoint_set(&configuration)?;
        }
        Ok(events)
    }

    fn capture_checkpoint(
        &mut self,
        configuration: &Configuration,
    ) -> Result<Option<ContentHash>, SchedulerError> {
        if self.inner.loop_impl().configuration() != configuration {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "production checkpoint configuration differs from the scheduler boundary",
                ),
            });
        }
        self.capture_exact_checkpoint_set(configuration).map(Some)
    }

    fn append_noncanonical_debug_event_log_entries(
        &mut self,
        entries: Vec<crucible::SchedulerEventLogEntry>,
    ) -> Result<Vec<crucible::SchedulerEventLogEntry>, SchedulerError> {
        self.inner
            .append_noncanonical_debug_event_log_entries(entries)
    }

    fn activate_debug_guest(&mut self, node: NodeId) -> Result<(), SchedulerError> {
        self.inner.activate_debug_guest(node)
    }

    fn send_guest_introspection(
        &mut self,
        node: NodeId,
        record: crucible_protocol::guest_introspection::GuestIntrospectionRecord,
    ) -> Result<(), SchedulerError> {
        self.inner.send_guest_introspection(node, record)
    }

    fn receive_guest_introspection(
        &mut self,
        node: NodeId,
    ) -> Result<
        Option<crucible_protocol::guest_introspection::GuestIntrospectionRecord>,
        SchedulerError,
    > {
        self.inner.receive_guest_introspection(node)
    }

    fn open_gdbstub(
        &mut self,
        node: NodeId,
        listen: GdbListen,
    ) -> Result<GdbAttachInfo, SchedulerError> {
        self.reconcile_indeterminate_debug_ownership()?;
        if let Some(attach) = &self.debug_attach {
            if attach.node == node && attach.operator_listen == listen {
                return Ok(attach.clone());
            }
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "production debugger gateway is already attached to another node or listener",
                ),
            });
        }
        let backend_path = self
            .debug_backend_paths
            .get(&node)
            .cloned()
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: format!(
                    "QEMU node `{}` has no configured debugger channel",
                    node.name
                ),
            })?;
        let configured =
            self.config
                .debug
                .as_ref()
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: String::from("production debugger configuration is unavailable"),
                })?;
        let requested = trusted_debug_listener(configured, &listen)?;
        let executable = self
            .config
            .debug_gateway_executable
            .as_ref()
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from("standalone debugger gateway executable is unavailable"),
            })?;
        let mut gateway = DebugGatewayProcess::launch_with_trusted_loopback(executable, requested)
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!("launch production debugger gateway: {error}"),
            })?;
        gateway.promote_backend(&backend_path).map_err(|error| {
            SchedulerError::BoundaryViolation {
                message: format!("promote production QEMU debugger backend: {error}"),
            }
        })?;
        let actual =
            gateway
                .operator_listen()
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: String::from(
                        "production debugger gateway did not bind a GDB listener",
                    ),
                })?;
        let actual_listen = GdbListen::new(actual.to_string()).map_err(SchedulerError::Backend)?;
        let info = GdbAttachInfo::new(
            node,
            backend_path.to_string_lossy().into_owned(),
            actual_listen,
        )
        .map_err(SchedulerError::Backend)?;
        self.debug_gateway = Some(gateway);
        self.debug_attach = Some(info.clone());
        Ok(info)
    }

    fn reposition_debug_runtime(
        &mut self,
        request: DebugRuntimeRepositionRequest,
    ) -> Result<DebugRuntimeRepositionReport, SchedulerError> {
        self.reposition_debug_world(request)
    }

    fn append_backend_observable_events(
        &mut self,
        events: Vec<crucible::ObservableEvent>,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        self.inner.append_backend_observable_events(events)
    }

    fn append_backend_evaluation_boundary(
        &mut self,
        at: VirtualTime,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        self.inner.append_backend_evaluation_boundary(at)
    }

    fn append_backend_observations_at_boundary(
        &mut self,
        events: Vec<crucible::ObservableEvent>,
        at: VirtualTime,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        self.inner
            .append_backend_observations_at_boundary(events, at)
    }

    fn append_backend_causal_decisions(
        &mut self,
        decisions: Vec<Decision>,
    ) -> Result<(Vec<Decision>, Configuration, SchedulerEventLogAppend), SchedulerError> {
        self.inner.append_backend_causal_decisions(decisions)
    }

    fn search_frontiers(&self) -> Result<Vec<crucible::SearchRuntimeFrontier>, SchedulerError> {
        Ok(self.inner.loop_impl().search_frontiers().to_vec())
    }

    fn pending_search_branch_choices(&self) -> usize {
        self.inner.loop_impl().pending_branch_effect_choice_count()
    }

    fn resolved_effect_trace(&self) -> Result<Option<Vec<u8>>, SchedulerError> {
        let runtime = self
            .fault_runtime
            .lock()
            .map_err(|_| SchedulerError::BoundaryViolation {
                message: String::from("production fault runtime lock is poisoned"),
            })?;
        match runtime.recorded_trace(crucible::model::FaultReplayMode::RecomputedCause) {
            Ok(trace) => trace.canonical_bytes().map(Some).map_err(|error| {
                SchedulerError::BoundaryViolation {
                    message: format!("encode production resolved-effect trace: {error}"),
                }
            }),
            Err(crucible_qemu::ProductionFaultRuntimeError::Execution(
                crucible::model::FaultExecutionError::CheckpointPresence,
            )) => Ok(None),
            Err(error) => Err(SchedulerError::BoundaryViolation {
                message: format!("capture production resolved-effect trace: {error}"),
            }),
        }
    }

    fn take_terminal_verdict(&mut self) -> Option<QuantumTerminalVerdict> {
        self.terminal_verdict.take()
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<QuantumTerminalVerdict> {
        self.terminal_verdict.clone()
    }

    fn prepare_terminal_checkpoint(
        &mut self,
        cause: CheckpointTerminalCause,
    ) -> Result<(), SchedulerError> {
        if self
            .checkpoint_terminal_cause
            .as_ref()
            .is_some_and(|retained| retained != &cause)
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "production lifecycle already retained a different terminal cause",
                ),
            });
        }
        self.checkpoint_terminal_cause = Some(cause);
        Ok(())
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.reconcile_indeterminate_debug_ownership()?;
        let pending = self.inner.loop_impl().pending_branch_effect_choice_count();
        let pending_error = (pending != 0).then(|| SchedulerError::BoundaryViolation {
            message: format!(
                "production lifecycle stopped with {pending} unconsumed branch effect choices"
            ),
        });
        let replay_error = if self.fault_replay_installed {
            let runtime =
                self.fault_runtime
                    .lock()
                    .map_err(|_| SchedulerError::BoundaryViolation {
                        message: String::from("production fault runtime lock is poisoned"),
                    })?;
            runtime
                .verify_replay_exhausted()
                .err()
                .map(|error| SchedulerError::BoundaryViolation {
                    message: format!("production fault replay was not exhausted: {error}"),
                })
        } else {
            None
        };
        let search_override_error = if self.fault_search_overrides_installed {
            let runtime =
                self.fault_runtime
                    .lock()
                    .map_err(|_| SchedulerError::BoundaryViolation {
                        message: String::from("production fault runtime lock is poisoned"),
                    })?;
            runtime
                .verify_search_overrides_consumed()
                .err()
                .map(|error| SchedulerError::BoundaryViolation {
                    message: format!("production fault search override was not consumed: {error}"),
                })
        } else {
            None
        };
        let gateway_shutdown = self.debug_gateway.take().map(|gateway| {
            gateway
                .shutdown()
                .map(|_| ())
                .map_err(|error| SchedulerError::BoundaryViolation {
                    message: format!("shutdown production debugger gateway: {error}"),
                })
        });
        let shutdown = self.inner.shutdown();
        if let Some(gateway_shutdown) = gateway_shutdown {
            gateway_shutdown?;
        }
        let events = shutdown?;
        if let Some(error) = pending_error {
            return Err(error);
        }
        if let Some(error) = replay_error {
            return Err(error);
        }
        if let Some(error) = search_override_error {
            return Err(error);
        }
        self.run_manifest.clean_shutdown = true;
        self.persist_lifecycle_state()?;
        Ok(events)
    }
}

impl ProductionVmLifecycleLoop {
    fn terminal_lifecycle_checkpoint(&mut self) -> Result<Checkpoint, SchedulerError> {
        let configuration = self.inner.loop_impl().configuration().clone();
        let parent = if configuration.schedule.is_empty() {
            None
        } else {
            let parent_len = configuration.schedule.len().saturating_sub(1);
            let parent_schedule = configuration.schedule.prefix(parent_len).map_err(|error| {
                SchedulerError::BoundaryViolation {
                    message: format!(
                        "derive terminal lifecycle checkpoint parent at schedule length {parent_len}: {error}"
                    ),
                }
            })?;
            Some(Configuration {
                def: configuration.def.clone(),
                schedule: parent_schedule,
            })
        };
        let mut node_icounts = BTreeMap::new();
        for vm in self.source.world().vm_nodes() {
            let physical = self.inner.backend().node_now(&vm.id)?;
            node_icounts.insert(
                vm.id.clone(),
                Icount {
                    retired: physical.ticks,
                },
            );
        }
        Checkpoint::from_recorded_configuration(
            &configuration,
            parent.as_ref(),
            self.inner.loop_impl().frontier(),
            node_icounts,
            CheckpointKind::Fat,
            BTreeMap::new(),
        )
        .map_err(|error| SchedulerError::BoundaryViolation {
            message: format!("materialize terminal lifecycle checkpoint: {error}"),
        })
    }

    fn prepare_terminal_replacements(
        &mut self,
        decisions: &[QemuNodeLifecycleDecision],
        limits: FaultResourceLimits,
        lifecycle_precommit: Option<&mut PreparedLifecyclePrecommit>,
    ) -> Result<Vec<PreparedTerminalReplacement>, SchedulerError> {
        let terminal_count = decisions
            .iter()
            .filter(|decision| decision.expected_exit_code.is_some())
            .count();
        if terminal_count == 0 {
            return Ok(Vec::new());
        }
        let lifecycle_precommit =
            lifecycle_precommit.ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from(
                    "terminal lifecycle decision has no precommit checkpoint owner",
                ),
            })?;
        let mut terminal = std::mem::take(&mut lifecycle_precommit.terminal_decisions);
        for decision in decisions
            .iter()
            .filter(|decision| decision.expected_exit_code.is_some())
        {
            let process_owner_index = lifecycle_precommit
                .process_owners
                .iter()
                .position(|owner| {
                    owner.as_ref().is_some_and(|owner| {
                        owner.action == decision.action
                            && owner.decision_node.as_ref() == Some(&decision.node)
                    })
                })
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "terminal lifecycle action for `{}` lost its precommit process owner",
                        decision.node.name
                    ),
                })?;
            let mut process_owner = lifecycle_precommit.process_owners[process_owner_index]
                .take()
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "terminal lifecycle action for `{}` reused its precommit process owner",
                        decision.node.name
                    ),
                })?;
            let decision_node = process_owner.decision_node.take().ok_or_else(|| {
                SchedulerError::BoundaryViolation {
                    message: format!(
                        "terminal lifecycle action for `{}` lost its precommit node owner",
                        decision.node.name
                    ),
                }
            })?;
            terminal.push(PreparedLifecycleTerminal {
                decision: QemuNodeLifecycleDecision {
                    node: decision_node,
                    action: decision.action,
                    requested_transition: decision.requested_transition,
                    effective_transition: decision.effective_transition,
                    cause: decision.cause,
                    expected_exit_code: decision.expected_exit_code,
                    observed_icount: decision.observed_icount,
                    pre_exit_hash: decision.pre_exit_hash,
                    event_evidence: decision.event_evidence,
                },
                process_owner,
            });
        }
        for terminal in &terminal {
            let decision = &terminal.decision;
            if !matches!(
                decision.effective_transition,
                crucible::model::NodeLifecycleTransition::Crash
                    | crucible::model::NodeLifecycleTransition::PowerOff
                    | crucible::model::NodeLifecycleTransition::PermanentFailure
            ) {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "terminal lifecycle decision for `{}` is not terminal",
                        decision.node.name
                    ),
                });
            }
            let current_directory =
                self.node_run_directories
                    .get(&decision.node)
                    .ok_or_else(|| SchedulerError::BoundaryViolation {
                        message: format!(
                            "terminal lifecycle node `{}` has no process-generation directory",
                            decision.node.name
                        ),
                    })?;
            let current_generation = self
                .node_generations
                .get(&decision.node)
                .copied()
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "terminal lifecycle node `{}` has no process generation",
                        decision.node.name
                    ),
                })?;
            if decision.effective_transition
                != crucible::model::NodeLifecycleTransition::PermanentFailure
            {
                current_generation.checked_add(1).ok_or_else(|| {
                    SchedulerError::BoundaryViolation {
                        message: format!(
                            "terminal lifecycle generation exhausted for `{}`",
                            decision.node.name
                        ),
                    }
                })?;
            }
            if !self.node_indexes.contains_key(&decision.node)
                || !self.launch_configs.contains_key(&decision.node)
            {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "terminal lifecycle node `{}` has incomplete launch identity",
                        decision.node.name
                    ),
                });
            }
            for artifact in [
                PRODUCTION_ROOT_OVERLAY_FILE_NAME,
                PRODUCTION_VMSTATE_FILE_NAME,
            ] {
                let source = current_directory.join(artifact);
                File::open(&source).map_err(|error| SchedulerError::BoundaryViolation {
                    message: format!(
                        "open terminal lifecycle source artifact {}: {error}",
                        source.display()
                    ),
                })?;
            }
        }
        self.inner
            .backend_mut()
            .prevalidate_terminal_lifecycle_snapshots(
                terminal.iter().map(|item| &item.decision.node),
                &lifecycle_precommit.checkpoint,
            )?;
        let mut prepared = std::mem::take(&mut lifecycle_precommit.prepared_replacements);
        debug_assert!(prepared.capacity() >= terminal.len());
        for terminal in terminal {
            let decision = terminal.decision;
            let mut process_owner = terminal.process_owner;
            let service_state = match decision.effective_transition {
                crucible::model::NodeLifecycleTransition::Crash => {
                    ProductionNodeServiceState::Running
                }
                crucible::model::NodeLifecycleTransition::PowerOff => {
                    ProductionNodeServiceState::PoweredOff
                }
                crucible::model::NodeLifecycleTransition::PermanentFailure => {
                    ProductionNodeServiceState::PermanentlyFailed
                }
                transition => {
                    return Err(SchedulerError::BoundaryViolation {
                        message: format!(
                            "terminal lifecycle replacement for `{}` has nonterminal transition {transition:?}",
                            decision.node.name
                        ),
                    });
                }
            };
            if !lifecycle_precommit.actions.contains(&decision.action) {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "terminal lifecycle action for `{}` lost its precommit checkpoint",
                        decision.node.name
                    ),
                });
            }
            let snapshot = self
                .inner
                .backend_mut()
                .capture_terminal_lifecycle_snapshot_shared(
                    &decision.node,
                    Arc::clone(&lifecycle_precommit.checkpoint),
                )?;
            let current_directory =
                self.node_run_directories
                    .get(&decision.node)
                    .ok_or_else(|| SchedulerError::BoundaryViolation {
                        message: format!(
                            "terminal lifecycle node `{}` has no process-generation directory",
                            decision.node.name
                        ),
                    })?;
            let current_generation = self
                .node_generations
                .get(&decision.node)
                .copied()
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "terminal lifecycle node `{}` lost its process generation",
                        decision.node.name
                    ),
                })?;
            let generation = if service_state == ProductionNodeServiceState::PermanentlyFailed {
                current_generation
            } else {
                current_generation.checked_add(1).ok_or_else(|| {
                    SchedulerError::BoundaryViolation {
                        message: format!(
                            "terminal lifecycle generation exhausted for `{}`",
                            decision.node.name
                        ),
                    }
                })?
            };
            let index = self
                .node_indexes
                .get(&decision.node)
                .copied()
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "terminal lifecycle node `{}` has no launch index",
                        decision.node.name
                    ),
                })?;
            let run_directory = if service_state == ProductionNodeServiceState::PermanentlyFailed {
                current_directory.clone()
            } else {
                self._run_directory
                    .path()
                    .join("lifecycle-generations")
                    .join(format!("node-{index}-generation-{generation}"))
            };
            fs::create_dir_all(&run_directory).map_err(|error| {
                SchedulerError::BoundaryViolation {
                    message: format!(
                        "create terminal lifecycle generation directory {}: {error}",
                        run_directory.display()
                    ),
                }
            })?;
            if run_directory != *current_directory {
                for artifact in [
                    PRODUCTION_ROOT_OVERLAY_FILE_NAME,
                    PRODUCTION_VMSTATE_FILE_NAME,
                ] {
                    let source = current_directory.join(artifact);
                    let target = run_directory.join(artifact);
                    fs::copy(&source, &target).map_err(|error| {
                        SchedulerError::BoundaryViolation {
                            message: format!(
                                "copy terminal lifecycle artifact {} to {}: {error}",
                                source.display(),
                                target.display()
                            ),
                        }
                    })?;
                }
            }
            let mut launch = self
                .launch_configs
                .get(&decision.node)
                .cloned()
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "terminal lifecycle node `{}` has no launch configuration",
                        decision.node.name
                    ),
                })?
                .with_run_directory(&run_directory)
                .with_process_generation(generation);
            if let Some(debug) = &self.config.debug
                && (debug.all_nodes
                    || debug
                        .node
                        .as_deref()
                        .map_or(index == 0, |selected| selected == decision.node.name))
            {
                let backend_path = private_backend_gdbstub_path(&run_directory);
                let backend_listen =
                    qemu_unix_gdbstub_endpoint(&backend_path).map_err(|error| {
                        SchedulerError::BoundaryViolation {
                            message: format!(
                                "derive replacement QEMU gdbstub endpoint for `{}`: {error}",
                                decision.node.name
                            ),
                        }
                    })?;
                let gdbstub = ProductionGdbstubChannelConfig::new(
                    backend_listen,
                    debug.operator_listen.clone(),
                )
                .map_err(|error| SchedulerError::BoundaryViolation {
                    message: format!(
                        "configure replacement QEMU gdbstub for `{}`: {error}",
                        decision.node.name
                    ),
                })?;
                launch = launch.with_gdbstub(gdbstub);
            }
            let crash_detector = try_lifecycle_crash_detector(
                &decision.node.name,
                generation,
                prepared.len(),
                limits,
            )?;
            prepared.push(PreparedTerminalReplacement {
                debug_backend_path: self
                    .debug_backend_paths
                    .contains_key(&decision.node)
                    .then(|| private_backend_gdbstub_path(&run_directory)),
                decision,
                snapshot,
                run_directory,
                launch,
                generation,
                replacement: None,
                service_state,
                crash_detector,
                backend_node: process_owner.backend_node.take(),
                observed_exit_node: process_owner.observed_exit_node.take(),
                process_owner: Some(process_owner),
            });
        }
        for replacement in &mut prepared {
            if let Err(error) = self.stage_terminal_replacement(replacement) {
                let containment = Self::abort_staged_terminal_replacements(&mut prepared);
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "stage terminal lifecycle replacement: {error}; staged-process containment: {}",
                        containment
                            .map_or_else(|error| error.to_string(), |()| String::from("reaped")),
                    ),
                });
            }
        }
        Ok(prepared)
    }

    fn abort_staged_terminal_replacements(
        prepared: &mut [PreparedTerminalReplacement],
    ) -> Result<(), SchedulerError> {
        let mut first_error = None;
        for item in prepared {
            if let Some(mut replacement) = item.replacement.take()
                && let Err(error) = replacement.force_quarantine_and_reap()
                && first_error.is_none()
            {
                first_error = Some(format!(
                    "reap staged replacement for `{}`: {error}",
                    item.decision.node.name
                ));
            }
        }
        first_error.map_or(Ok(()), |message| {
            Err(SchedulerError::BoundaryViolation { message })
        })
    }

    fn configure_replacement_fault_coordinators(
        &self,
        node: &NodeId,
        replacement: &mut QemuNode,
    ) -> Result<(), SchedulerError> {
        if let Some(block) = self.block_bindings.get(node).cloned() {
            if replacement.shared_block_device().is_none() {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "replacement QEMU node `{}` has no live block device",
                        node.name
                    ),
                });
            }
            replacement
                .install_block_fault_coordinator(Box::new(ProductionBlockFaultCoordinator::new(
                    Arc::clone(&self.fault_runtime),
                    Arc::clone(&self.fault_evaluation_cursor),
                    Arc::clone(&self.storage_fault_observations),
                    Arc::clone(&self.block_devices),
                    self.source.world().clone(),
                    block.target,
                    self.source.plan().fault_signals(),
                    self.scenario.id(),
                    self.icount_shift,
                )))
                .map_err(|error| SchedulerError::BoundaryViolation {
                    message: format!(
                        "install replacement block fault coordinator for `{}`: {error}",
                        node.name
                    ),
                })?;
        }
        if let Some(ninep) = self.ninep_bindings.get(node).cloned() {
            replacement
                .install_ninep_fault_coordinator(Box::new(
                    storage_faults::ProductionNinepFaultCoordinator::new(
                        Arc::clone(&self.fault_runtime),
                        Arc::clone(&self.fault_evaluation_cursor),
                        Arc::clone(&self.storage_fault_observations),
                        self.source.world().clone(),
                        ninep.target,
                        self.icount_shift,
                    ),
                ))
                .map_err(|error| SchedulerError::BoundaryViolation {
                    message: format!(
                        "install replacement 9p fault coordinator for `{}`: {error}",
                        node.name
                    ),
                })?;
        }
        Ok(())
    }

    fn stage_terminal_replacement(
        &self,
        prepared: &mut PreparedTerminalReplacement,
    ) -> Result<(), SchedulerError> {
        let node = &prepared.decision.node;
        let launched = match prepared.service_state {
            ProductionNodeServiceState::Running | ProductionNodeServiceState::PoweredOff => {
                Some(launch_production_live_node_exact_snapshot_paused(
                    &prepared.launch,
                    &prepared.run_directory,
                    &node.name,
                    "crucible-router",
                    &prepared.crash_detector,
                    &prepared.snapshot,
                ))
            }
            ProductionNodeServiceState::PermanentlyFailed => None,
        };
        if let Some(launched) = launched {
            let mut launched = launched.map_err(|error| SchedulerError::BoundaryViolation {
                message: format!(
                    "stage terminal lifecycle replacement for `{}`: {error}",
                    node.name
                ),
            })?;
            if let Err(error) = self.configure_replacement_fault_coordinators(node, &mut launched) {
                let containment = launched.force_quarantine_and_reap();
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "configure terminal lifecycle replacement for `{}`: {error}; process containment: {}",
                        node.name,
                        containment
                            .map_or_else(|error| error.to_string(), |()| String::from("reaped")),
                    ),
                });
            }
            prepared.replacement = Some(launched);
        }
        Ok(())
    }

    fn commit_terminal_replacements(
        &mut self,
        prepared: &mut Vec<PreparedTerminalReplacement>,
        lifecycle_precommit: &mut PreparedLifecyclePrecommit,
    ) -> Result<(), SchedulerError> {
        if prepared.is_empty() {
            return Ok(());
        }
        let mut block_handles = std::mem::take(&mut lifecycle_precommit.block_handles);
        debug_assert!(block_handles.capacity() >= prepared.len());
        for item in prepared.iter() {
            self.inner
                .loop_impl()
                .validate_vm_node_activity_target(&item.decision.node)?;
            if let Some(binding) = self.block_bindings.get(&item.decision.node)
                && let Some(replacement) = &item.replacement
            {
                let handle = replacement.shared_block_device().ok_or_else(|| {
                    SchedulerError::BoundaryViolation {
                        message: format!(
                            "replacement QEMU node `{}` lost its block device before commit",
                            item.decision.node.name
                        ),
                    }
                })?;
                block_handles.push((binding.device_hash(), handle));
            }
            if !self.node_service_states.contains_key(&item.decision.node)
                || !self.node_run_directories.contains_key(&item.decision.node)
                || !self.node_generations.contains_key(&item.decision.node)
                || !self.launch_configs.contains_key(&item.decision.node)
                || (self.debug_backend_paths.contains_key(&item.decision.node)
                    && item.debug_backend_path.is_none())
            {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "terminal replacement for `{}` lost a prevalidated host owner",
                        item.decision.node.name
                    ),
                });
            }
            self.validate_terminal_process_ownership(&item.decision.node, item.service_state)?;
        }
        let mut replacement_nodes = std::mem::take(&mut lifecycle_precommit.replacement_nodes);
        debug_assert!(replacement_nodes.capacity() >= prepared.len());
        for item in prepared.iter_mut() {
            replacement_nodes.push(item.backend_node.take().ok_or_else(|| {
                SchedulerError::BoundaryViolation {
                    message: format!(
                        "terminal replacement for `{}` lost its precommit backend owner",
                        item.decision.node.name
                    ),
                }
            })?);
        }
        let plan = self
            .inner
            .backend_mut()
            .prepare_terminal_replacements(replacement_nodes)?;
        let mut block_devices =
            self.block_devices
                .lock()
                .map_err(|_| SchedulerError::BoundaryViolation {
                    message: String::from("production block-device map lock is poisoned"),
                })?;
        if block_handles
            .iter()
            .any(|(device, _handle)| block_devices.get(device).is_none())
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("terminal replacement lost a prevalidated block owner"),
            });
        }
        let mut replacement_values = std::mem::take(&mut lifecycle_precommit.replacement_values);
        debug_assert!(replacement_values.capacity() >= prepared.len());
        for item in prepared.iter_mut() {
            replacement_values.push(item.replacement.take());
        }
        for item in prepared.iter() {
            let activity = match item.service_state {
                ProductionNodeServiceState::Running => SchedulerNodeActivity::Runnable,
                ProductionNodeServiceState::PoweredOff => SchedulerNodeActivity::Halted,
                ProductionNodeServiceState::PermanentlyFailed => SchedulerNodeActivity::Done,
            };
            self.inner
                .loop_impl_mut()
                .set_vm_node_activity(&item.decision.node, activity)?;
        }
        let retired = self
            .inner
            .backend_mut()
            .commit_terminal_replacements(plan, replacement_values);
        debug_assert!(retired.iter().all(|(_, node)| node.child_reaped()));
        for (device, handle) in block_handles {
            let slot = block_devices.get_mut(&device).ok_or_else(|| {
                SchedulerError::BoundaryViolation {
                    message: String::from(
                        "terminal replacement block owner disappeared during commit",
                    ),
                }
            })?;
            *slot = handle;
        }
        drop(block_devices);

        // Every Crash replacement is restored under the native QEMU pause.
        // Publish Runnable scheduler ownership and install the authoritative
        // backend generation before releasing guest execution.
        for item in prepared
            .iter()
            .filter(|item| item.service_state == ProductionNodeServiceState::Running)
        {
            self.inner.loop_impl().require_vm_node_activity(
                &item.decision.node,
                SchedulerNodeActivity::Runnable,
            )?;
            self.inner
                .backend_mut()
                .resume_restored_generation(&item.decision.node)?;
        }

        for item in prepared.drain(..) {
            let node = item.decision.node;
            self.commit_terminal_process_ownership(&node, item.service_state)?;
            *self.node_service_states.get_mut(&node).ok_or_else(|| {
                SchedulerError::BoundaryViolation {
                    message: String::from("validated lifecycle service owner disappeared"),
                }
            })? = item.service_state;
            *self.node_run_directories.get_mut(&node).ok_or_else(|| {
                SchedulerError::BoundaryViolation {
                    message: String::from("validated lifecycle directory owner disappeared"),
                }
            })? = item.run_directory;
            *self.node_generations.get_mut(&node).ok_or_else(|| {
                SchedulerError::BoundaryViolation {
                    message: String::from("validated lifecycle generation owner disappeared"),
                }
            })? = item.generation;
            *self.launch_configs.get_mut(&node).ok_or_else(|| {
                SchedulerError::BoundaryViolation {
                    message: String::from("validated lifecycle launch owner disappeared"),
                }
            })? = item.launch;
            if let Some(path) = item.debug_backend_path {
                *self.debug_backend_paths.get_mut(&node).ok_or_else(|| {
                    SchedulerError::BoundaryViolation {
                        message: String::from("validated lifecycle debug owner disappeared"),
                    }
                })? = path;
            }
        }
        Ok(())
    }

    fn supervise_terminal_lifecycle_exits(
        &mut self,
        prepared: &mut [PreparedTerminalReplacement],
        observed_exit_codes: &mut Vec<(NodeId, i32)>,
    ) -> Result<(), SchedulerError> {
        let mut first_error = None;
        debug_assert!(observed_exit_codes.capacity() >= prepared.len());
        for item in prepared.iter() {
            let decision = &item.decision;
            let generation = self
                .node_generations
                .get(&decision.node)
                .copied()
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "terminal lifecycle node `{}` has no authenticated process generation",
                        decision.node.name
                    ),
                })?;
            if generation == 0 {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "terminal lifecycle process generation is not positive for `{}`",
                        decision.node.name
                    ),
                });
            }
            if let Err(error) = self.inner.backend_mut().complete_terminal_lifecycle_exit(
                &decision.node,
                decision.action,
                decision.event_evidence,
                generation,
            ) && first_error.is_none()
            {
                first_error = Some(error.to_string());
            }
        }
        for item in prepared.iter_mut() {
            let decision = &item.decision;
            let expected =
                decision
                    .expected_exit_code
                    .ok_or_else(|| SchedulerError::BoundaryViolation {
                        message: String::from("terminal lifecycle decision lost its exit status"),
                    })?;
            match self.inner.backend_mut().await_intended_lifecycle_exit(
                &decision.node,
                expected,
                decision.action,
            ) {
                Ok(actual) => {
                    let node = item.observed_exit_node.take().ok_or_else(|| {
                        SchedulerError::BoundaryViolation {
                            message: format!(
                                "terminal lifecycle node `{}` lost its precommit exit owner",
                                decision.node.name
                            ),
                        }
                    })?;
                    observed_exit_codes.push((node, actual));
                }
                Err(error) if first_error.is_none() => {
                    first_error = Some(error.to_string());
                }
                Err(_) => {}
            }
        }
        if let Some(message) = first_error {
            Err(SchedulerError::BoundaryViolation {
                message: format!("terminal lifecycle process supervision failed: {message}"),
            })
        } else {
            Ok(())
        }
    }

    fn activate_node_boot_requests(&mut self, requests: &[NodeId]) -> Result<(), SchedulerError> {
        for node in requests {
            match self.node_service_states.get(node).copied() {
                Some(ProductionNodeServiceState::PoweredOff) => {}
                Some(ProductionNodeServiceState::Running) => {
                    return Err(SchedulerError::BoundaryViolation {
                        message: format!(
                            "boot requires powered-off node `{}`, but it is already running",
                            node.name
                        ),
                    });
                }
                Some(ProductionNodeServiceState::PermanentlyFailed) => {
                    return Err(SchedulerError::BoundaryViolation {
                        message: format!(
                            "boot cannot resurrect permanently failed node `{}`",
                            node.name
                        ),
                    });
                }
                None => {
                    return Err(SchedulerError::BoundaryViolation {
                        message: format!("boot names unknown lifecycle node `{}`", node.name),
                    });
                }
            }
        }
        self.inner
            .loop_impl_mut()
            .set_vm_nodes_activity(requests, SchedulerNodeActivity::Runnable)?;
        for node in requests {
            self.inner.backend_mut().boot_powered_off_generation(node)?;
        }
        for node in requests {
            let Some(state) = self.node_service_states.get_mut(node) else {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from("validated boot node disappeared before commit"),
                });
            };
            *state = ProductionNodeServiceState::Running;
        }
        Ok(())
    }

    fn capture_exact_checkpoint_set(
        &mut self,
        configuration: &Configuration,
    ) -> Result<ContentHash, SchedulerError> {
        if self.checkpoint_targets.contains_key(&configuration.id()) {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "exact checkpoint {} was already captured by this lifecycle",
                    configuration.id().to_hex()
                ),
            });
        }
        let checkpoint_virtual_time = self.inner.loop_impl().frontier();
        let network_committed_frontier = self.inner.committed_frontier();
        let fault_checkpoint = {
            let (scheduler, backend, interceptor, pending_outputs) =
                self.inner.network_transaction_parts_mut();
            interceptor
                .checkpoint(
                    scheduler,
                    network_committed_frontier,
                    pending_outputs,
                    backend,
                )
                .map_err(|error| SchedulerError::BoundaryViolation {
                    message: format!(
                        "capture signal, network, and device continuation at exact checkpoint boundary: {error}"
                    ),
                })?
        };
        let mut node_icounts = BTreeMap::new();
        let mut boundaries = Vec::new();
        for vm in self.source.world().vm_nodes() {
            let scheduler_time = self.inner.loop_impl().scheduler_time_for_node(&vm.id)?;
            if self.node_service_states.get(&vm.id)
                == Some(&ProductionNodeServiceState::PermanentlyFailed)
            {
                node_icounts.insert(
                    vm.id.clone(),
                    crucible::Icount {
                        retired: scheduler_time.ticks >> u32::from(self.icount_shift),
                    },
                );
                continue;
            }
            let physical = self.inner.backend().node_now(&vm.id)?;
            node_icounts.insert(
                vm.id.clone(),
                crucible::Icount {
                    retired: physical.ticks,
                },
            );
            let service_state = self
                .node_service_states
                .get(&vm.id)
                .copied()
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!("exact checkpoint has no service state for `{}`", vm.id.name),
                })?;
            boundaries.push((vm.id.clone(), physical.ticks, scheduler_time, service_state));
        }

        let checkpoint_parent = self._run_directory.path().join("exact-checkpoints");
        fs::create_dir_all(&checkpoint_parent).map_err(|error| {
            SchedulerError::BoundaryViolation {
                message: format!(
                    "create exact checkpoint parent directory {}: {error}",
                    checkpoint_parent.display()
                ),
            }
        })?;
        let checkpoint_root = checkpoint_parent.join(configuration.id().to_hex());
        if checkpoint_root.exists() {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "exact checkpoint artifact directory {} already exists",
                    checkpoint_root.display()
                ),
            });
        }
        let staging = tempfile::Builder::new()
            .prefix(".exact-checkpoint-")
            .tempdir_in(&checkpoint_parent)
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!(
                    "create exact checkpoint staging directory in {}: {error}",
                    checkpoint_parent.display()
                ),
            })?;

        let mut captured: Vec<(NodeId, QemuVmSnapshot)> = Vec::new();
        let result =
            (|| -> Result<BTreeMap<NodeId, ProductionVmExactCheckpointTarget>, SchedulerError> {
                let mut targets = BTreeMap::new();
                for (node, counter, scheduler_time, service_state) in boundaries {
                    let parent = if configuration.schedule.is_empty() {
                        None
                    } else {
                        let parent_len = configuration.schedule.len().saturating_sub(1);
                        let parent_schedule = configuration.schedule.prefix(parent_len).map_err(|error| {
                        SchedulerError::BoundaryViolation {
                            message: format!(
                                "derive exact checkpoint parent at schedule length {parent_len}: {error}"
                            ),
                        }
                    })?;
                        Some(Configuration {
                            def: configuration.def.clone(),
                            schedule: parent_schedule,
                        })
                    };
                    let checkpoint = Checkpoint::from_recorded_configuration(
                        configuration,
                        parent.as_ref(),
                        checkpoint_virtual_time,
                        node_icounts.clone(),
                        CheckpointKind::Fat,
                        BTreeMap::new(),
                    )
                    .map_err(|error| SchedulerError::BoundaryViolation {
                        message: format!("materialize exact scheduler checkpoint: {error}"),
                    })?;
                    let snapshot = match service_state {
                        ProductionNodeServiceState::Running => self
                            .inner
                            .backend_mut()
                            .capture_exact_snapshot(&node, checkpoint)?,
                        ProductionNodeServiceState::PoweredOff => self
                            .inner
                            .backend_mut()
                            .capture_exact_snapshot_paused(&node, checkpoint)?,
                        ProductionNodeServiceState::PermanentlyFailed => {
                            return Err(SchedulerError::BoundaryViolation {
                                message: format!(
                                    "permanently failed node `{}` unexpectedly reached snapshot capture",
                                    node.name
                                ),
                            });
                        }
                    };
                    captured.push((node.clone(), snapshot.clone()));
                    let index = self.node_indexes.get(&node).copied().ok_or_else(|| {
                        SchedulerError::BoundaryViolation {
                            message: format!(
                                "exact checkpoint has no launch index for `{}`",
                                node.name
                            ),
                        }
                    })?;
                    let source_directory =
                        self.node_run_directories.get(&node).ok_or_else(|| {
                            SchedulerError::BoundaryViolation {
                                message: format!(
                                    "exact checkpoint has no process-generation directory for `{}`",
                                    node.name
                                ),
                            }
                        })?;
                    let source_overlay = source_directory.join(PRODUCTION_ROOT_OVERLAY_FILE_NAME);
                    let artifact_name = format!("node-{index}.qcow2");
                    let staged_artifact = staging.path().join(&artifact_name);
                    fs::copy(&source_overlay, &staged_artifact).map_err(|error| {
                        SchedulerError::BoundaryViolation {
                            message: format!(
                                "stage exact QEMU artifact {} as {}: {error}",
                                source_overlay.display(),
                                staged_artifact.display()
                            ),
                        }
                    })?;
                    let artifact_hash = hash_file(&staged_artifact).map_err(|error| {
                        SchedulerError::BoundaryViolation {
                            message: format!(
                                "hash staged exact QEMU artifact {}: {error}",
                                staged_artifact.display()
                            ),
                        }
                    })?;
                    let artifact_length = fs::metadata(&staged_artifact)
                        .map_err(|error| SchedulerError::BoundaryViolation {
                            message: format!(
                                "inspect staged QEMU artifact {}: {error}",
                                staged_artifact.display()
                            ),
                        })?
                        .len();
                    let source_vmstate = source_directory.join(PRODUCTION_VMSTATE_FILE_NAME);
                    let vmstate_name = format!("node-{index}-vmstate.qcow2");
                    let staged_vmstate = staging.path().join(&vmstate_name);
                    fs::copy(&source_vmstate, &staged_vmstate).map_err(|error| {
                        SchedulerError::BoundaryViolation {
                            message: format!(
                                "stage exact VMState artifact {} as {}: {error}",
                                source_vmstate.display(),
                                staged_vmstate.display()
                            ),
                        }
                    })?;
                    let vmstate_hash = hash_file(&staged_vmstate).map_err(|error| {
                        SchedulerError::BoundaryViolation {
                            message: format!(
                                "hash staged exact VMState artifact {}: {error}",
                                staged_vmstate.display()
                            ),
                        }
                    })?;
                    let vmstate_length = fs::metadata(&staged_vmstate)
                        .map_err(|error| SchedulerError::BoundaryViolation {
                            message: format!(
                                "inspect staged VMState artifact {}: {error}",
                                staged_vmstate.display()
                            ),
                        })?
                        .len();
                    let manifest_identity = crucible::ContentHash::from_canonical_material(
                        "crucible.production-vm-exact-checkpoint.v1",
                        &format!(
                            "configuration={}\nnode={}\ncounter={counter}\nscheduler_time={}\nsnapshot={}\nfault={}\noverlay={}\nvmstate={}",
                            configuration.id().to_hex(),
                            node.name,
                            scheduler_time.ticks,
                            snapshot.id().to_hex(),
                            fault_checkpoint.id().to_hex(),
                            artifact_hash.to_hex(),
                            vmstate_hash.to_hex(),
                        ),
                    );
                    targets.insert(
                        node,
                        ProductionVmExactCheckpointTarget {
                            configuration: configuration.clone(),
                            counter,
                            scheduler_time,
                            snapshot,
                            overlay_artifact: ProductionCheckpointArtifact {
                                source: ProductionCheckpointArtifactSource::File(
                                    checkpoint_root.join(artifact_name),
                                ),
                                identity: artifact_hash,
                                length: artifact_length,
                                chunks: Vec::new(),
                            },
                            vmstate_artifact: ProductionCheckpointArtifact {
                                source: ProductionCheckpointArtifactSource::File(
                                    checkpoint_root.join(vmstate_name),
                                ),
                                identity: vmstate_hash,
                                length: vmstate_length,
                                chunks: Vec::new(),
                            },
                            manifest_identity,
                        },
                    );
                }
                fs::rename(staging.path(), &checkpoint_root).map_err(|error| {
                    SchedulerError::BoundaryViolation {
                        message: format!(
                            "publish exact checkpoint transaction {} as {}: {error}",
                            staging.path().display(),
                            checkpoint_root.display()
                        ),
                    }
                })?;
                Ok(targets)
            })();
        match result {
            Ok(targets) => {
                let event_log_objects = self
                    .inner
                    .loop_impl()
                    .event_log_dependency_objects()
                    .map_err(|error| SchedulerError::BoundaryViolation {
                        message: format!("capture exact event-log closure: {error}"),
                    })?
                    .into_iter()
                    .collect();
                let scheduler = self.inner.loop_impl().checkpoint().map_err(|error| {
                    SchedulerError::BoundaryViolation {
                        message: format!("capture exact scheduler continuation: {error}"),
                    }
                })?;
                let mut checkpoint_set = ProductionVmExactCheckpointSet {
                    identity: ContentHash::default(),
                    configuration: configuration.clone(),
                    scheduler,
                    event_log_objects,
                    signal_artifact_objects: self.signal_artifact_objects.clone(),
                    trigger_state: self.trigger_state.clone(),
                    assertion_state: self.assertion_evaluator.checkpoint(),
                    terminal_verdict: self.terminal_verdict.clone(),
                    terminal_cause: self.checkpoint_terminal_cause.clone(),
                    initial_lifecycle_observations_pending: self
                        .initial_lifecycle_observations_pending,
                    branch: self.branch.clone(),
                    recorded_controls: self.recorded_controls.clone(),
                    fault_checkpoint: Some(fault_checkpoint),
                    targets,
                    node_generations: self.node_generations.clone(),
                    node_service_states: self.node_service_states.clone(),
                };
                let publish_result = persist_exact_checkpoint_set(
                    &self.config.run_state_root,
                    self.scenario.id(),
                    self.source.plan().fault_signals().resource_limits(),
                    &mut checkpoint_set,
                );
                if let Err(error) = publish_result {
                    let artifact_cleanup =
                        fs::remove_dir_all(&checkpoint_root).map_err(|cleanup| {
                            SchedulerError::BoundaryViolation {
                                message: format!(
                                    "remove unpublished exact checkpoint directory {}: {cleanup}",
                                    checkpoint_root.display()
                                ),
                            }
                        });
                    let snapshot_cleanup = self.rollback_exact_captures(&captured);
                    artifact_cleanup?;
                    snapshot_cleanup?;
                    return Err(error);
                }
                fs::remove_dir_all(&checkpoint_root).map_err(|error| {
                    SchedulerError::BoundaryViolation {
                        message: format!(
                            "remove chunked exact checkpoint staging copy {}: {error}",
                            checkpoint_root.display()
                        ),
                    }
                })?;
                self.rollback_exact_captures(&captured)?;
                let checkpoint_set_identity = checkpoint_set.identity;
                let replaced = self
                    .checkpoint_targets
                    .insert(configuration.id(), checkpoint_set_identity);
                debug_assert!(replaced.is_none());
                Ok(checkpoint_set_identity)
            }
            Err(error) => {
                self.rollback_exact_captures(&captured)?;
                Err(error)
            }
        }
    }

    fn rollback_exact_captures(
        &mut self,
        captured: &[(NodeId, QemuVmSnapshot)],
    ) -> Result<(), SchedulerError> {
        for (node, snapshot) in captured.iter().rev() {
            self.inner
                .backend_mut()
                .delete_exact_snapshot(node, snapshot)?;
        }
        Ok(())
    }

    /// Evaluates the signal program exactly once in the ordered sequence of
    /// scheduler visits to the current virtual-time coordinate.
    fn evaluate_signal_fault_boundary(
        &mut self,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        let coordinate = self
            .inner
            .loop_impl()
            .condition_event_log_prefix()
            .point()
            .at()
            .ticks;
        let fault_coordinate = FaultCoordinate {
            virtual_nanos: coordinate,
            retired_instructions: None,
        };
        let lifecycle_intents = {
            let (_scheduler, backend, interceptor, _pending_outputs) =
                self.inner.network_transaction_parts_mut();
            interceptor.preview_node_lifecycle_intents(fault_coordinate, backend)?
        };
        let (resource_limits, runtime_event_records, runtime_event_log_bytes) = {
            let runtime =
                self.fault_runtime
                    .lock()
                    .map_err(|_| SchedulerError::BoundaryViolation {
                        message: String::from("production fault runtime lock is poisoned"),
                    })?;
            let (event_records, event_log_bytes) = runtime
                .lifecycle_journal_resource_usage()
                .map_err(|error| match error {
                    crucible_qemu::ProductionFaultRuntimeError::ResourceLimit(error) => {
                        map_journal_limit(error, runtime.resource_limits())
                    }
                    error => SchedulerError::BoundaryViolation {
                        message: format!("measure lifecycle journal resource base: {error}"),
                    },
                })?;
            (runtime.resource_limits(), event_records, event_log_bytes)
        };
        let mut lifecycle_precommit = if lifecycle_intents.is_empty() {
            None
        } else {
            Some(self.begin_terminal_lifecycle_intent(
                &lifecycle_intents,
                resource_limits,
                runtime_event_records,
                runtime_event_log_bytes,
            )?)
        };
        let (reserved_event_records, reserved_event_log_bytes) =
            lifecycle_precommit.as_ref().map_or((0, 0), |precommit| {
                (
                    precommit.reserved_event_records,
                    precommit.reserved_event_log_bytes,
                )
            });
        let evaluation = {
            let (scheduler, backend, interceptor, pending_outputs) =
                self.inner.network_transaction_parts_mut();
            interceptor.evaluate_boundary_with_event_reservation(
                fault_coordinate,
                scheduler,
                backend,
                pending_outputs,
                (reserved_event_records, reserved_event_log_bytes),
            )
        };
        let append = match evaluation {
            Ok(append) => append,
            Err(error) if lifecycle_intents.is_empty() => return Err(error),
            Err(error) => {
                if let Ok(mut runtime) = self.fault_runtime.lock() {
                    runtime.poison();
                }
                return Err(self.quarantine_precommit_lifecycle_intent(&lifecycle_intents, error));
            }
        };
        if !lifecycle_intents.is_empty()
            && let Err(error) = self.persist_lifecycle_state()
        {
            if let Ok(mut runtime) = self.fault_runtime.lock() {
                runtime.poison();
            }
            return Err(self.quarantine_precommit_lifecycle_intent(&lifecycle_intents, error));
        }
        let lifecycle_work = self
            .fault_runtime
            .lock()
            .map_err(|_| SchedulerError::BoundaryViolation {
                message: String::from("production fault runtime lock is poisoned"),
            })?
            .take_node_lifecycle_work()
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!("take production lifecycle work: {error}"),
            })?;
        if let Err(error) = self.authenticate_terminal_lifecycle_intent(
            lifecycle_work.decisions(),
            lifecycle_work.boot_requests(),
        ) {
            self.fault_runtime
                .lock()
                .map_err(|_| SchedulerError::BoundaryViolation {
                    message: String::from("production fault runtime lock is poisoned"),
                })?
                .poison();
            return Err(if lifecycle_intents.is_empty() {
                self.quarantine_terminal_lifecycle_transaction(
                    lifecycle_work.decisions(),
                    lifecycle_work.boot_requests(),
                    error,
                )
            } else {
                self.quarantine_precommit_lifecycle_intent(&lifecycle_intents, error)
            });
        }
        if let Err(error) = self.apply_signal_fault_lifecycle_work(
            lifecycle_work.decisions(),
            lifecycle_work.boot_requests(),
            resource_limits,
            lifecycle_precommit.as_mut(),
        ) {
            self.fault_runtime
                .lock()
                .map_err(|_| SchedulerError::BoundaryViolation {
                    message: String::from("production fault runtime lock is poisoned"),
                })?
                .poison();
            return Err(error);
        }
        self.fault_runtime
            .lock()
            .map_err(|_| SchedulerError::BoundaryViolation {
                message: String::from("production fault runtime lock is poisoned"),
            })?
            .acknowledge_node_lifecycle_work(lifecycle_work)
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!("acknowledge production lifecycle work: {error}"),
            })?;
        Ok(append)
    }

    fn apply_signal_fault_lifecycle_work(
        &mut self,
        decisions: &[QemuNodeLifecycleDecision],
        boot_requests: &[NodeId],
        resource_limits: FaultResourceLimits,
        mut lifecycle_precommit: Option<&mut PreparedLifecyclePrecommit>,
    ) -> Result<(), SchedulerError> {
        let has_lifecycle = !decisions.is_empty();
        if let Err(error) = self.activate_node_boot_requests(boot_requests) {
            return Err(self.quarantine_terminal_lifecycle_transaction(
                decisions,
                boot_requests,
                error,
            ));
        }
        let mut prepared = match self.prepare_terminal_replacements(
            decisions,
            resource_limits,
            lifecycle_precommit.as_deref_mut(),
        ) {
            Ok(prepared) => prepared,
            Err(capture_error) => {
                return Err(self.quarantine_terminal_lifecycle_transaction(
                    decisions,
                    boot_requests,
                    capture_error,
                ));
            }
        };
        if has_lifecycle && let Err(error) = self.record_prepared_lifecycle_processes(&mut prepared)
        {
            return Err(self.quarantine_terminal_lifecycle_transaction_with_staged(
                decisions,
                boot_requests,
                &mut prepared,
                error,
            ));
        }
        if !prepared.is_empty() {
            let precommit = lifecycle_precommit.as_deref_mut().ok_or_else(|| {
                SchedulerError::BoundaryViolation {
                    message: String::from(
                        "terminal lifecycle supervision lost its precommit storage",
                    ),
                }
            })?;
            if let Err(error) = self.supervise_terminal_lifecycle_exits(
                &mut prepared,
                &mut precommit.observed_exit_codes,
            ) {
                return Err(self.quarantine_terminal_lifecycle_transaction_with_staged(
                    decisions,
                    boot_requests,
                    &mut prepared,
                    error,
                ));
            }
        }
        for replacement in &prepared {
            if let Err(error) = self
                .inner
                .backend()
                .validate_terminal_exits_reaped(std::slice::from_ref(&replacement.decision.node))
            {
                return Err(self.quarantine_terminal_lifecycle_transaction_with_staged(
                    decisions,
                    boot_requests,
                    &mut prepared,
                    error,
                ));
            }
        }
        if has_lifecycle
            && let Err(error) =
                self.advance_lifecycle_journal(ProductionLifecycleJournalPhase::ExitsReaped)
        {
            return Err(self.quarantine_terminal_lifecycle_transaction_with_staged(
                decisions,
                boot_requests,
                &mut prepared,
                error,
            ));
        }
        if !prepared.is_empty() {
            let precommit = lifecycle_precommit.as_deref_mut().ok_or_else(|| {
                SchedulerError::BoundaryViolation {
                    message: String::from(
                        "terminal lifecycle commit lost its precommit storage",
                    ),
                }
            })?;
            if let Err(error) = self.commit_terminal_replacements(&mut prepared, precommit) {
                return Err(self.quarantine_terminal_lifecycle_transaction_with_staged(
                    decisions,
                    boot_requests,
                    &mut prepared,
                    error,
                ));
            }
        }
        if has_lifecycle
            && let Err(error) = self.retain_completed_lifecycle_exits(
                decisions,
                lifecycle_precommit
                    .as_deref()
                    .map_or(&[], |precommit| precommit.observed_exit_codes.as_slice()),
            )
        {
            return Err(self.quarantine_terminal_lifecycle_transaction(
                decisions,
                boot_requests,
                error,
            ));
        }
        if !has_lifecycle && !self.lifecycle_journal.nodes.is_empty() {
            self.lifecycle_journal.nodes.clear();
            self.lifecycle_journal.phase = ProductionLifecycleJournalPhase::Committed;
            self.persist_lifecycle_state()?;
        }
        Ok(())
    }
}

/// Validates an operator listener against the lifecycle's debugger policy.
fn trusted_debug_listener(
    configured: &ProductionVmDebugConfig,
    listen: &GdbListen,
) -> Result<SocketAddr, SchedulerError> {
    let requested: SocketAddr =
        listen
            .as_str()
            .parse()
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!(
                    "parse trusted debugger listener {}: {error}",
                    listen.as_str()
                ),
            })?;
    if !requested.ip().is_loopback() {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "unauthenticated production debugger listener must be loopback, not {requested}"
            ),
        });
    }
    if !configured.allow_requested_loopback_listen && listen.as_str() != configured.operator_listen
    {
        return Err(SchedulerError::BoundaryViolation {
            message: format!(
                "requested debugger listener {} does not match configured listener {}",
                listen.as_str(),
                configured.operator_listen
            ),
        });
    }
    Ok(requested)
}

#[cfg(test)]
#[path = "quantum_loop/tests.rs"]
mod tests;
