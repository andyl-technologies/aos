//! `QuantumLoop` delegation for the production VM lifecycle.

use super::*;

struct PreparedTerminalReplacement {
    decision: QemuNodeLifecycleDecision,
    snapshot: QemuVmSnapshot,
    run_directory: PathBuf,
    launch: ProductionLiveNodeStepGateConfig,
    generation: u64,
    replacement: Option<QemuNode>,
    service_state: ProductionNodeServiceState,
}

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
        self.persist_run_manifest()?;
        Ok(events)
    }
}

impl ProductionVmLifecycleLoop {
    fn persist_run_manifest(&self) -> Result<(), SchedulerError> {
        persist_atomic_json(
            &self._run_directory.path().join("run-manifest.json"),
            &self.run_manifest,
        )
        .map_err(|message| SchedulerError::BoundaryViolation { message })
    }

    pub(super) fn persist_lifecycle_journal(&self) -> Result<(), SchedulerError> {
        let path = self._run_directory.path().join("lifecycle-journal.json");
        let next = self._run_directory.path().join("lifecycle-journal.next");
        let bytes = serde_json::to_vec_pretty(&self.lifecycle_journal).map_err(|error| {
            SchedulerError::BoundaryViolation {
                message: format!("encode lifecycle transaction journal: {error}"),
            }
        })?;
        let mut file = File::create(&next).map_err(|error| SchedulerError::BoundaryViolation {
            message: format!(
                "create lifecycle transaction journal {}: {error}",
                next.display()
            ),
        })?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!(
                    "flush lifecycle transaction journal {}: {error}",
                    next.display()
                ),
            })?;
        fs::rename(&next, &path).map_err(|error| SchedulerError::BoundaryViolation {
            message: format!(
                "commit lifecycle transaction journal {}: {error}",
                path.display()
            ),
        })?;
        File::open(self._run_directory.path())
            .and_then(|directory| directory.sync_all())
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!("flush lifecycle journal directory: {error}"),
            })
    }

    fn begin_terminal_lifecycle_transaction(
        &mut self,
        decisions: &[QemuNodeLifecycleDecision],
    ) -> Result<(), SchedulerError> {
        let mut nodes = Vec::new();
        for decision in decisions {
            let current_generation = self
                .node_generations
                .get(&decision.node)
                .copied()
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "terminal lifecycle node `{}` has no authenticated generation",
                        decision.node.name
                    ),
                })?;
            let next_generation = if matches!(
                decision.effective_transition,
                crucible::model::NodeLifecycleTransition::Crash
                    | crucible::model::NodeLifecycleTransition::PowerOff
            ) {
                current_generation.checked_add(1).ok_or_else(|| {
                    SchedulerError::BoundaryViolation {
                        message: format!(
                            "terminal lifecycle generation exhausted for `{}`",
                            decision.node.name
                        ),
                    }
                })?
            } else {
                current_generation
            };
            let current_process = self.inner.backend().process_identity(&decision.node)?;
            nodes.push(ProductionLifecycleJournalNode {
                node: decision.node.name.clone(),
                current_process,
                replacement_process: None,
                current_generation,
                next_generation,
                transition: format!("{:?}", decision.effective_transition),
                action_sha256: decision.action.to_hex(),
                evidence_sha256: decision.event_evidence.to_hex(),
                expected_exit_code: decision.expected_exit_code,
            });
        }
        if nodes.is_empty() {
            return Ok(());
        }
        self.lifecycle_journal.transaction = self
            .lifecycle_journal
            .transaction
            .checked_add(1)
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from("lifecycle transaction sequence exhausted"),
            })?;
        self.lifecycle_journal.phase = ProductionLifecycleJournalPhase::Intent;
        self.lifecycle_journal.nodes = nodes;
        self.persist_lifecycle_journal()
    }

    fn advance_lifecycle_journal(
        &mut self,
        phase: ProductionLifecycleJournalPhase,
    ) -> Result<(), SchedulerError> {
        self.lifecycle_journal.phase = phase;
        self.persist_lifecycle_journal()
    }

    fn record_prepared_lifecycle_processes(
        &mut self,
        prepared: &[PreparedTerminalReplacement],
    ) -> Result<(), SchedulerError> {
        for item in prepared {
            let identity = item
                .replacement
                .as_ref()
                .map(QemuNode::process_identity)
                .transpose()
                .map_err(|error| SchedulerError::BoundaryViolation {
                    message: format!(
                        "capture staged process identity for `{}`: {error}",
                        item.decision.node.name
                    ),
                })?;
            let journal_node = self
                .lifecycle_journal
                .nodes
                .iter_mut()
                .find(|node| node.node == item.decision.node.name)
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "staged lifecycle node `{}` has no journal identity",
                        item.decision.node.name
                    ),
                })?;
            journal_node.replacement_process = identity;
            match &journal_node.replacement_process {
                Some(identity) => {
                    self.run_manifest
                        .staged_processes
                        .insert(item.decision.node.name.clone(), identity.clone());
                }
                None => {
                    self.run_manifest
                        .staged_processes
                        .remove(&item.decision.node.name);
                }
            }
        }
        self.persist_run_manifest()?;
        self.advance_lifecycle_journal(ProductionLifecycleJournalPhase::Prepared)
    }

    fn retain_completed_lifecycle_exits(
        &mut self,
        decisions: &[QemuNodeLifecycleDecision],
        observed_exit_codes: &BTreeMap<NodeId, i32>,
    ) -> Result<(), SchedulerError> {
        for decision in decisions {
            let Some(expected_exit_code) = decision.expected_exit_code else {
                continue;
            };
            let journal_node = self
                .lifecycle_journal
                .nodes
                .iter()
                .find(|node| node.node == decision.node.name)
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "completed lifecycle exit for `{}` lost its journal identity",
                        decision.node.name
                    ),
                })?;
            let observed_exit_code = observed_exit_codes
                .get(&decision.node)
                .copied()
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "completed lifecycle exit for `{}` lost its observed status",
                        decision.node.name
                    ),
                })?;
            self.lifecycle_journal
                .completed_exits
                .push(ProductionLifecycleCompletedExit {
                    transaction: self.lifecycle_journal.transaction,
                    node: decision.node.name.clone(),
                    process: journal_node.current_process.clone(),
                    generation: journal_node.current_generation,
                    transition: format!("{:?}", decision.effective_transition),
                    action_sha256: decision.action.to_hex(),
                    evidence_sha256: decision.event_evidence.to_hex(),
                    expected_exit_code,
                    observed_exit_code,
                });
        }
        self.lifecycle_journal.phase = ProductionLifecycleJournalPhase::Committed;
        self.persist_lifecycle_journal()
    }

    fn quarantine_terminal_lifecycle_transaction(
        &mut self,
        decisions: &[QemuNodeLifecycleDecision],
        primary: impl std::fmt::Display,
    ) -> SchedulerError {
        let affected_nodes = decisions
            .iter()
            .map(|decision| decision.node.clone())
            .collect::<Vec<_>>();
        let journal = self.advance_lifecycle_journal(ProductionLifecycleJournalPhase::Quarantined);
        let quarantine = self
            .inner
            .backend_mut()
            .quarantine_terminal_nodes(&affected_nodes);
        let activities = affected_nodes
            .iter()
            .cloned()
            .map(|node| (node, SchedulerNodeActivity::Done))
            .collect::<Vec<_>>();
        let scheduler = self
            .inner
            .loop_impl_mut()
            .set_vm_node_activities(&activities);
        SchedulerError::BoundaryViolation {
            message: format!(
                "terminal lifecycle transaction failed ({primary}); journal containment: {}; process containment: {}; scheduler containment: {}",
                journal.map_or_else(|error| error.to_string(), |()| String::from("recorded")),
                quarantine.map_or_else(|error| error.to_string(), |()| String::from("reaped")),
                scheduler.map_or_else(|error| error.to_string(), |()| String::from("closed")),
            ),
        }
    }

    fn quarantine_terminal_lifecycle_transaction_with_staged(
        &mut self,
        decisions: &[QemuNodeLifecycleDecision],
        prepared: &mut [PreparedTerminalReplacement],
        primary: impl std::fmt::Display,
    ) -> SchedulerError {
        let staged = Self::abort_staged_terminal_replacements(prepared);
        self.quarantine_terminal_lifecycle_transaction(
            decisions,
            format!(
                "{primary}; staged-process containment: {}",
                staged.map_or_else(|error| error.to_string(), |()| String::from("reaped"))
            ),
        )
    }

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
    ) -> Result<Vec<PreparedTerminalReplacement>, SchedulerError> {
        let terminal = decisions
            .iter()
            .filter(|decision| decision.expected_exit_code.is_some())
            .cloned()
            .collect::<Vec<_>>();
        if terminal.is_empty() {
            return Ok(Vec::new());
        }
        let checkpoint = self.terminal_lifecycle_checkpoint()?;
        for decision in &terminal {
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
        let terminal_nodes = terminal
            .iter()
            .map(|decision| decision.node.clone())
            .collect::<Vec<_>>();
        self.inner
            .backend_mut()
            .prevalidate_terminal_lifecycle_snapshots(&terminal_nodes, &checkpoint)?;
        let mut prepared = Vec::with_capacity(terminal.len());
        for decision in terminal {
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
            let snapshot = self
                .inner
                .backend_mut()
                .capture_terminal_lifecycle_snapshot(&decision.node, checkpoint.clone())?;
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
            prepared.push(PreparedTerminalReplacement {
                decision,
                snapshot,
                run_directory,
                launch,
                generation,
                replacement: None,
                service_state,
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
        let node = prepared.decision.node.clone();
        let crash_detector = format!("lifecycle-{}-generation-{}", node.name, prepared.generation);
        let launched = match prepared.service_state {
            ProductionNodeServiceState::Running => {
                Some(launch_production_live_node_exact_snapshot(
                    &prepared.launch,
                    &prepared.run_directory,
                    &node.name,
                    "crucible-router",
                    &crash_detector,
                    &prepared.snapshot,
                ))
            }
            ProductionNodeServiceState::PoweredOff => {
                Some(launch_production_live_node_exact_snapshot_paused(
                    &prepared.launch,
                    &prepared.run_directory,
                    &node.name,
                    "crucible-router",
                    &crash_detector,
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
            if let Err(error) = self.configure_replacement_fault_coordinators(&node, &mut launched)
            {
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
    ) -> Result<(), SchedulerError> {
        if prepared.is_empty() {
            return Ok(());
        }
        let activities = prepared
            .iter()
            .map(|item| {
                let activity = match item.service_state {
                    ProductionNodeServiceState::Running => SchedulerNodeActivity::Runnable,
                    ProductionNodeServiceState::PoweredOff => SchedulerNodeActivity::Halted,
                    ProductionNodeServiceState::PermanentlyFailed => SchedulerNodeActivity::Done,
                };
                (item.decision.node.clone(), activity)
            })
            .collect::<Vec<_>>();
        let mut block_handles = Vec::new();
        for item in prepared.iter() {
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
        }
        let replacement_nodes = prepared
            .iter()
            .map(|item| item.decision.node.clone())
            .collect::<Vec<_>>();
        let plan = self
            .inner
            .backend()
            .prepare_terminal_replacements(&replacement_nodes)?;
        let mut block_devices =
            self.block_devices
                .lock()
                .map_err(|_| SchedulerError::BoundaryViolation {
                    message: String::from("production block-device map lock is poisoned"),
                })?;
        self.inner
            .loop_impl_mut()
            .set_vm_node_activities(&activities)?;
        let replacement_values = prepared
            .iter_mut()
            .map(|item| (item.decision.node.clone(), item.replacement.take()))
            .collect();
        let retired = self
            .inner
            .backend_mut()
            .commit_terminal_replacements(plan, replacement_values);
        debug_assert!(retired.iter().all(|(_, node)| node.child_reaped()));
        for (device, handle) in block_handles {
            block_devices.insert(device, handle);
        }
        drop(block_devices);

        for item in prepared.drain(..) {
            let node = item.decision.node;
            match item.service_state {
                ProductionNodeServiceState::PermanentlyFailed => {
                    self.run_manifest.processes.remove(&node.name);
                }
                ProductionNodeServiceState::Running | ProductionNodeServiceState::PoweredOff => {
                    let identity = self
                        .lifecycle_journal
                        .nodes
                        .iter()
                        .find(|journal_node| journal_node.node == node.name)
                        .and_then(|journal_node| journal_node.replacement_process.clone())
                        .ok_or_else(|| SchedulerError::BoundaryViolation {
                            message: format!(
                                "committed replacement for `{}` lost its process identity",
                                node.name
                            ),
                        })?;
                    self.run_manifest
                        .processes
                        .insert(node.name.clone(), identity);
                }
            }
            self.run_manifest.staged_processes.remove(&node.name);
            self.node_service_states
                .insert(node.clone(), item.service_state);
            self.node_run_directories
                .insert(node.clone(), item.run_directory.clone());
            self.node_generations.insert(node.clone(), item.generation);
            self.launch_configs.insert(node.clone(), item.launch);
            if self.debug_backend_paths.contains_key(&node) {
                self.debug_backend_paths.insert(
                    node.clone(),
                    private_backend_gdbstub_path(&item.run_directory),
                );
            }
        }
        self.persist_run_manifest()
    }

    fn supervise_terminal_lifecycle_exits(
        &mut self,
        decisions: &[QemuNodeLifecycleDecision],
    ) -> Result<BTreeMap<NodeId, i32>, SchedulerError> {
        let terminal = decisions
            .iter()
            .filter_map(|decision| {
                decision
                    .expected_exit_code
                    .map(|expected| (decision, expected))
            })
            .collect::<Vec<_>>();
        let mut first_error = None;
        let mut observed_exit_codes = BTreeMap::new();
        for (decision, _) in &terminal {
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
        for (decision, expected) in terminal {
            match self.inner.backend_mut().await_intended_lifecycle_exit(
                &decision.node,
                expected,
                decision.action,
            ) {
                Ok(actual) => {
                    observed_exit_codes.insert(decision.node.clone(), actual);
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
            Ok(observed_exit_codes)
        }
    }

    fn activate_node_boot_requests(
        &mut self,
        requests: &std::collections::BTreeSet<NodeId>,
    ) -> Result<(), SchedulerError> {
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
        for node in requests {
            self.inner.backend_mut().boot_powered_off_generation(node)?;
        }
        let activities = requests
            .iter()
            .cloned()
            .map(|node| (node, SchedulerNodeActivity::Runnable))
            .collect::<Vec<_>>();
        self.inner
            .loop_impl_mut()
            .set_vm_node_activities(&activities)?;
        for node in requests {
            self.node_service_states
                .insert(node.clone(), ProductionNodeServiceState::Running);
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
        let fault_checkpoint = {
            let (scheduler, backend, interceptor, pending_outputs) =
                self.inner.network_transaction_parts_mut();
            interceptor
                .checkpoint(scheduler, pending_outputs, backend)
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
                            fault_checkpoint: fault_checkpoint.clone(),
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
                    fault_checkpoint,
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
        let append = {
            let (scheduler, backend, interceptor, pending_outputs) =
                self.inner.network_transaction_parts_mut();
            interceptor.evaluate_boundary(
                FaultCoordinate {
                    virtual_nanos: coordinate,
                    retired_instructions: None,
                },
                scheduler,
                backend,
                pending_outputs,
            )?
        };
        let (decisions, boot_requests) = {
            let runtime =
                self.fault_runtime
                    .lock()
                    .map_err(|_| SchedulerError::BoundaryViolation {
                        message: String::from("production fault runtime lock is poisoned"),
                    })?;
            (
                runtime.node_lifecycle_decisions().to_vec(),
                runtime.node_boot_requests().clone(),
            )
        };
        let has_lifecycle = !decisions.is_empty();
        if has_lifecycle {
            self.begin_terminal_lifecycle_transaction(&decisions)?;
        }
        if let Err(error) = self.activate_node_boot_requests(&boot_requests) {
            return Err(self.quarantine_terminal_lifecycle_transaction(&decisions, error));
        }
        let mut prepared = match self.prepare_terminal_replacements(&decisions) {
            Ok(prepared) => prepared,
            Err(capture_error) => {
                return Err(
                    self.quarantine_terminal_lifecycle_transaction(&decisions, capture_error)
                );
            }
        };
        if has_lifecycle && let Err(error) = self.record_prepared_lifecycle_processes(&prepared) {
            return Err(self.quarantine_terminal_lifecycle_transaction_with_staged(
                &decisions,
                &mut prepared,
                error,
            ));
        }
        let observed_exit_codes = match self.supervise_terminal_lifecycle_exits(&decisions) {
            Ok(observed) => observed,
            Err(error) => {
                return Err(self.quarantine_terminal_lifecycle_transaction_with_staged(
                    &decisions,
                    &mut prepared,
                    error,
                ));
            }
        };
        let retiring = prepared
            .iter()
            .map(|replacement| replacement.decision.node.clone())
            .collect::<Vec<_>>();
        if let Err(error) = self
            .inner
            .backend()
            .validate_terminal_exits_reaped(&retiring)
        {
            return Err(self.quarantine_terminal_lifecycle_transaction_with_staged(
                &decisions,
                &mut prepared,
                error,
            ));
        }
        if has_lifecycle
            && let Err(error) =
                self.advance_lifecycle_journal(ProductionLifecycleJournalPhase::ExitsReaped)
        {
            return Err(self.quarantine_terminal_lifecycle_transaction_with_staged(
                &decisions,
                &mut prepared,
                error,
            ));
        }
        if let Err(error) = self.commit_terminal_replacements(&mut prepared) {
            return Err(self.quarantine_terminal_lifecycle_transaction_with_staged(
                &decisions,
                &mut prepared,
                error,
            ));
        }
        if has_lifecycle
            && let Err(error) =
                self.retain_completed_lifecycle_exits(&decisions, &observed_exit_codes)
        {
            return Err(self.quarantine_terminal_lifecycle_transaction(&decisions, error));
        }
        if !decisions.is_empty() {
            let mut runtime =
                self.fault_runtime
                    .lock()
                    .map_err(|_| SchedulerError::BoundaryViolation {
                        message: String::from("production fault runtime lock is poisoned"),
                    })?;
            runtime.acknowledge_node_lifecycle_decisions();
            runtime.acknowledge_node_boot_requests();
        }
        Ok(append)
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
mod tests {
    use super::*;

    fn debug_config(allow_requested_loopback_listen: bool) -> ProductionVmDebugConfig {
        ProductionVmDebugConfig {
            node: None,
            operator_listen: String::from("127.0.0.1:0"),
            all_nodes: allow_requested_loopback_listen,
            allow_requested_loopback_listen,
        }
    }

    #[test]
    fn daemon_debug_policy_accepts_an_explicit_loopback_listener() {
        let listen = GdbListen::new("127.0.0.1:9000")
            .unwrap_or_else(|error| panic!("loopback listener should parse: {error}"));

        let requested = trusted_debug_listener(&debug_config(true), &listen)
            .unwrap_or_else(|error| panic!("daemon listener should be admitted: {error}"));

        assert_eq!(requested, SocketAddr::from(([127, 0, 0, 1], 9000)));
    }

    #[test]
    fn fixed_debug_policy_rejects_a_different_listener() {
        let listen = GdbListen::new("127.0.0.1:9000")
            .unwrap_or_else(|error| panic!("loopback listener should parse: {error}"));

        let error = match trusted_debug_listener(&debug_config(false), &listen) {
            Ok(address) => panic!("fixed listener policy admitted {address}"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("does not match configured listener")
        );
    }

    #[test]
    fn daemon_debug_policy_rejects_a_non_loopback_listener() {
        let listen = GdbListen::new("0.0.0.0:9000")
            .unwrap_or_else(|error| panic!("socket listener should parse: {error}"));

        let error = match trusted_debug_listener(&debug_config(true), &listen) {
            Ok(address) => panic!("daemon listener policy admitted {address}"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("must be loopback"));
    }
}
