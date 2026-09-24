//! `QuantumLoop` delegation for the production VM lifecycle.

use super::checkpoint_store::{
    PersistExactCheckpointError, hash_exact_checkpoint_open_file_sha256_with_boundary,
    prepare_exact_checkpoint_set_with_boundary,
    stage_open_checkpoint_artifact_chunks_with_boundary,
    stage_sparse_checkpoint_artifact_chunks_with_boundary,
};
use super::*;

mod attempt_boundary;
mod checkpoint_capture;
mod debug_policy;
mod host_concurrent;
mod lifecycle;
mod live_network_preselection;
mod signal_fault_campaign;
use attempt_boundary::{attempt_boundary_scheduler_error, combine_attempt_quantum_boundary};
pub(super) use checkpoint_capture::ExactCheckpointPublicationState;
use checkpoint_capture::{
    ExactCaptureDisposition, ExactCheckpointTransactionError, PendingExactCapture,
    PendingExactCheckpointCandidate, PreparedExactCheckpointTarget,
    combine_exact_checkpoint_transaction, exact_ram_capture_kind_for_parent,
    prepare_exact_checkpoint_targets, retained_exact_ram_parent_for_committed,
};
use crucible::BackendRngEvidence;
use debug_policy::private_gateway_listener_request;
#[cfg(test)]
use debug_policy::trusted_debug_listener;
use host_concurrent::merge_host_concurrent_outcomes;
pub(super) const MAX_PRODUCTION_QEMU_HOST_WORKERS: usize = 64;

pub(super) struct PendingLiveNetworkPrefix {
    decisions: Vec<Decision>,
    appends: Vec<SchedulerEventLogAppend>,
    pub(super) discoveries: Vec<crucible::campaign::ChoiceDiscovery>,
    signal_fault_frontier_start: usize,
}
pub(in crate::vm_lifecycle) use lifecycle::map_journal_limit;
pub(super) use lifecycle::{
    DurableRunStateError, LifecycleStatePersistence, PRODUCTION_RUN_STATE_FILE,
    decode_prior_run_state, decode_run_json_bounded, persist_run_state_atomic,
};
#[cfg(test)]
pub(super) use lifecycle::{HARD_RUN_STATE_JSON_BYTES, validate_recovered_lifecycle_journal};
use lifecycle::{
    PreparedLifecyclePrecommit, PreparedLifecycleTerminal, PreparedTerminalReplacement,
    release_restored_generation_after_scheduler_publication, select_preowned_terminal_generation,
};

impl QuantumLoop for ProductionVmLifecycleLoop {
    fn drive_quantum(
        &mut self,
        mut request: QuantumRequest,
    ) -> Result<QuantumOutcome, SchedulerError> {
        self.node_launcher
            .begin_execution_quantum()
            .map_err(|error| {
                attempt_boundary_scheduler_error(
                    "admit production attempt scheduler quantum",
                    error,
                )
            })?;
        let operation = (|| {
            self.reconcile_indeterminate_debug_ownership()?;
            let signal_fault_frontier_start = self.inner.loop_impl().search_frontiers().len();
            let mut pre_quantum_appends = Vec::new();
            if let Some(append) = self.settle_genesis_entrypoints()? {
                pre_quantum_appends.push(append);
            }
            let fault_append = self.evaluate_signal_fault_boundary()?;
            if !fault_append.entries.is_empty() {
                pre_quantum_appends.push(fault_append);
            }
            pre_quantum_appends.extend(self.settle_trigger_graph()?);
            let network_settlement = self
                .inner
                .settle_pending_network_outputs_at_current_frontier()?;
            let reserved_network_outcome = network_settlement.reservation().cloned();
            let (mut pre_quantum_decisions, settled_configuration, network_appends) =
                network_settlement.into_parts();
            if let Some(mut outcome) = reserved_network_outcome {
                if self.inner.choice_free_parallel_boot() {
                    self.inner.abort_live_network_preselection();
                    return Err(SchedulerError::BoundaryViolation {
                        message: String::from(
                            "choice-free parallel boot reached a queued network choice before readiness",
                        ),
                    });
                }
                if settled_configuration.as_ref() != Some(&outcome.configuration)
                    || pre_quantum_decisions != outcome.decisions
                {
                    return Err(SchedulerError::BoundaryViolation {
                        message: String::from(
                            "queued network reservation disagrees with its settled prefix",
                        ),
                    });
                }
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
                let mut discoveries = self
                    .signal_fault_campaign_discoveries_at_current_boundary_since(
                        signal_fault_frontier_start,
                    )?;
                outcome
                    .discovered_choices
                    .splice(0..0, discoveries.iter().cloned());
                self.pending_live_network_prefix = Some(PendingLiveNetworkPrefix {
                    decisions: Vec::new(),
                    appends: pre_quantum_appends.clone(),
                    discoveries: std::mem::take(&mut discoveries),
                    signal_fault_frontier_start: self.inner.loop_impl().search_frontiers().len(),
                });
                prepend_event_log_appends(&mut outcome, pre_quantum_appends);
                outcome.scheduler_quiescence = Some(self.inner.loop_impl().quiescence()?);
                self.capture_debug_runtime_evidence()?;
                return Ok(outcome);
            }
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
            let boundary_search_choices = self
                .fault_runtime
                .lock()
                .map_err(|_| SchedulerError::BoundaryViolation {
                    message: String::from("production fault runtime lock is poisoned"),
                })?
                .drain_search_choices();
            self.inner
                .loop_impl_mut()
                .record_pending_signal_fault_search_frontiers(boundary_search_choices)?;
            let live_signal_fault_discoveries = self
                .signal_fault_campaign_discoveries_at_current_boundary_since(
                    signal_fault_frontier_start,
                )?;
            let replaying_current_signal_fault_branch =
                self.signal_fault_branches.front().is_some_and(|branch| {
                    branch.parent() == self.inner.loop_impl().configuration()
                        && branch.frontier() == self.inner.loop_impl().frontier()
                });
            if !live_signal_fault_discoveries.is_empty() && !replaying_current_signal_fault_branch {
                let scheduler = self.inner.loop_impl();
                let mut outcome = QuantumOutcome {
                    configuration: scheduler.configuration().clone(),
                    frontier: scheduler.frontier(),
                    advanced_node: None,
                    resolved_events: Vec::new(),
                    decisions: pre_quantum_decisions,
                    discovered_choices: live_signal_fault_discoveries,
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
            if self.terminal_stop_ready() {
                let scheduler = self.inner.loop_impl();
                let mut outcome = QuantumOutcome {
                    configuration: scheduler.configuration().clone(),
                    frontier: scheduler.frontier(),
                    advanced_node: None,
                    resolved_events: Vec::new(),
                    decisions: Vec::new(),
                    discovered_choices: Vec::new(),
                    event_log_entries: Vec::new(),
                    event_log_segment_bytes: Vec::new(),
                    event_log_segment_text: String::new(),
                    event_log_segment_hash: None,
                    event_log_offset: scheduler.event_log_offset(),
                    scheduler_quiescence: Some(scheduler.quiescence()?),
                };
                prepend_event_log_appends(&mut outcome, pre_quantum_appends);
                self.append_live_signal_fault_campaign_discoveries(
                    signal_fault_frontier_start,
                    &mut outcome,
                )?;
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
            if self.signal_fault_branches.front().is_some_and(|branch| {
                branch.parent() == &request.configuration && !request.control.is_empty()
            }) {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from(
                        "signal-fault branch admission cannot discard simultaneous control",
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
            if let Some(branch) = self.signal_fault_branches.front().cloned() {
                let frontier = self.inner.loop_impl().frontier();
                if frontier > branch.frontier() {
                    return Err(SchedulerError::BoundaryViolation {
                        message: format!(
                            "signal-fault branch frontier {} was passed at {}",
                            branch.frontier().ticks,
                            frontier.ticks
                        ),
                    });
                }
                if frontier == branch.frontier() && request.configuration != *branch.parent() {
                    return Err(SchedulerError::BoundaryViolation {
                        message: format!(
                            "signal-fault branch reached frontier {} with configuration {}, expected {}",
                            frontier.ticks,
                            request.configuration.id().to_hex(),
                            branch.parent().id().to_hex(),
                        ),
                    });
                }
                if frontier == branch.frontier() && request.configuration == *branch.parent() {
                    if !request.control.is_empty() {
                        return Err(SchedulerError::BoundaryViolation {
                            message: String::from(
                                "signal-fault branch admission cannot discard simultaneous control",
                            ),
                        });
                    }
                    self.authenticate_signal_fault_campaign_branch(&branch)?;
                    let branch_decisions = branch.decisions().to_vec();
                    let (configuration, append) = self
                        .inner
                        .loop_impl_mut()
                        .append_signal_fault_campaign_branch(&branch)?;
                    let consumed = self.signal_fault_branches.pop_front();
                    if consumed.as_ref() != Some(&branch) {
                        return Err(SchedulerError::BoundaryViolation {
                            message: String::from(
                                "signal-fault branch queue changed during exact injection",
                            ),
                        });
                    }
                    if let Some(next) = self.signal_fault_branches.front() {
                        self.inner
                            .loop_impl_mut()
                            .set_branch_frontier_cap(next.frontier())?;
                    } else {
                        self.inner.loop_impl_mut().clear_branch_frontier_cap();
                    }
                    let frontier = self.inner.loop_impl().frontier();
                    let scheduler_quiescence = Some(self.inner.loop_impl().quiescence()?);
                    let mut decisions = pre_quantum_decisions;
                    decisions.extend(branch_decisions);
                    let mut outcome = QuantumOutcome {
                        configuration,
                        frontier,
                        advanced_node: None,
                        resolved_events: Vec::new(),
                        decisions,
                        discovered_choices: Vec::new(),
                        event_log_entries: append.entries,
                        event_log_segment_bytes: append.segment_bytes,
                        event_log_segment_text: append.segment_text,
                        event_log_segment_hash: append.segment_hash,
                        event_log_offset: append.offset,
                        scheduler_quiescence,
                    };
                    prepend_event_log_appends(&mut outcome, pre_quantum_appends);
                    for append in self.settle_trigger_graph()? {
                        merge_event_log_append(&mut outcome, append);
                    }
                    self.append_live_signal_fault_campaign_discoveries(
                        signal_fault_frontier_start,
                        &mut outcome,
                    )?;
                    self.capture_debug_runtime_evidence()?;
                    return Ok(outcome);
                }
                if request.configuration.schedule.len() > branch.parent().schedule.len()
                    || (request.configuration.schedule.len() == branch.parent().schedule.len()
                        && request.configuration != *branch.parent())
                {
                    return Err(SchedulerError::BoundaryViolation {
                        message: format!(
                            "signal-fault replay bypassed parent configuration {}",
                            branch.parent().id().to_hex()
                        ),
                    });
                }
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
                    let configuration = self.inner.loop_impl().configuration().clone();
                    let append = self.inner.loop_impl_mut().append_branch_boundary()?;
                    if let Some(seed) = branch.seed {
                        self.inner.loop_impl_mut().reseed_future_decisions(seed)?;
                    }
                    self.branch = self.continuation_branches.pop_front();
                    if let Some(next) = &self.branch {
                        self.inner
                            .loop_impl_mut()
                            .set_branch_frontier_cap(next.frontier)?;
                    } else {
                        self.inner.loop_impl_mut().clear_branch_frontier_cap();
                    }
                    let frontier = self.inner.loop_impl().frontier();
                    let scheduler_quiescence = Some(self.inner.loop_impl().quiescence()?);
                    let decisions = pre_quantum_decisions;
                    let mut outcome = QuantumOutcome {
                        configuration,
                        frontier,
                        advanced_node: None,
                        resolved_events: Vec::new(),
                        decisions,
                        discovered_choices: Vec::new(),
                        event_log_entries: append.entries,
                        event_log_segment_bytes: append.segment_bytes,
                        event_log_segment_text: append.segment_text,
                        event_log_segment_hash: append.segment_hash,
                        event_log_offset: append.offset,
                        scheduler_quiescence,
                    };
                    prepend_event_log_appends(&mut outcome, pre_quantum_appends);
                    for append in self.settle_trigger_graph()? {
                        merge_event_log_append(&mut outcome, append);
                    }
                    self.append_live_signal_fault_campaign_discoveries(
                        signal_fault_frontier_start,
                        &mut outcome,
                    )?;
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
            let maximum_host_workers = self
                .inner
                .backend()
                .len()
                .min(self.config.maximum_host_workers)
                .clamp(1, MAX_PRODUCTION_QEMU_HOST_WORKERS);
            let concurrent = crucible_session::drive_engine_concurrent_quantum(
                &mut self.inner,
                request,
                maximum_host_workers,
            )?;
            let mut outcome = merge_host_concurrent_outcomes(concurrent.outcomes)?;
            if self.inner.live_network_preselection().is_some() {
                self.pending_live_network_prefix = Some(PendingLiveNetworkPrefix {
                    decisions: pre_quantum_decisions.clone(),
                    appends: pre_quantum_appends.clone(),
                    discoveries: Vec::new(),
                    signal_fault_frontier_start,
                });
                pre_quantum_decisions.extend(std::mem::take(&mut outcome.decisions));
                outcome.decisions = pre_quantum_decisions;
                prepend_event_log_appends(&mut outcome, pre_quantum_appends);
                self.capture_debug_runtime_evidence()?;
                return Ok(outcome);
            }
            self.finish_quantum_after_backend(
                outcome,
                PendingLiveNetworkPrefix {
                    decisions: pre_quantum_decisions,
                    appends: pre_quantum_appends,
                    discoveries: Vec::new(),
                    signal_fault_frontier_start,
                },
            )
        })();
        let boundary = self.node_launcher.check_operational_boundary();
        if (operation.is_err() || boundary.is_err())
            && self.inner.live_network_preselection().is_some()
        {
            self.inner.abort_live_network_preselection();
            self.pending_live_network_prefix.take();
        }
        combine_attempt_quantum_boundary(operation, boundary)
    }

    fn backend_step_ceiling(
        &self,
        outcome: &QuantumOutcome,
    ) -> Result<VirtualTime, SchedulerError> {
        self.inner.backend_step_ceiling(outcome)
    }

    fn sample_fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, SchedulerError> {
        if self.node_service_states.get(&node)
            == Some(&ProductionNodeServiceState::PermanentlyFailed)
        {
            return self
                .failed_host_io
                .get(&node)
                .map(|failed| failed.fingerprint.clone())
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "permanently failed node `{}` has no retained fingerprint authority",
                        node.name
                    ),
                });
        }

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

    fn authorize_noncanonical_guest_write(&mut self) -> Result<(), SchedulerError> {
        let gateway =
            self.debug_gateway
                .as_mut()
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: String::from("private debugger gateway is not attached"),
                })?;
        gateway
            .authorize_noncanonical_guest_write()
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!("authorize noncanonical guest write at private gateway: {error}"),
            })
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
        private_gateway_listener_request(configured, &listen)?;
        let executable = self
            .config
            .debug_gateway_executable
            .as_ref()
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from("standalone debugger gateway executable is unavailable"),
            })?;
        let mut gateway =
            DebugGatewayProcess::launch_with_owner_unix(executable).map_err(|error| {
                SchedulerError::BoundaryViolation {
                    message: format!("launch production debugger gateway: {error}"),
                }
            })?;
        gateway.promote_backend(&backend_path).map_err(|error| {
            SchedulerError::BoundaryViolation {
                message: format!("promote production QEMU debugger backend: {error}"),
            }
        })?;
        let actual =
            gateway
                .operator_endpoint()
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: String::from(
                        "production debugger gateway did not bind a GDB listener",
                    ),
                })?;
        let actual_listen = GdbListen::new(actual.to_owned()).map_err(SchedulerError::Backend)?;
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

    fn append_backend_rng_evidence(
        &mut self,
        decisions: Vec<BackendRngEvidence>,
    ) -> Result<
        (
            Vec<Decision>,
            Vec<crucible::campaign::ChoiceDiscovery>,
            Configuration,
            SchedulerEventLogAppend,
        ),
        SchedulerError,
    > {
        self.inner.append_backend_rng_evidence(decisions)
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
        let recorded =
            match runtime.recorded_trace(crucible::model::FaultReplayMode::RecomputedCause) {
                Ok(trace) => Some(trace),
                Err(crucible_qemu::ProductionFaultRuntimeError::Execution(
                    crucible::model::FaultExecutionError::CheckpointPresence,
                )) => None,
                Err(error) => {
                    return Err(SchedulerError::BoundaryViolation {
                        message: format!("capture production resolved-effect trace: {error}"),
                    });
                }
            };
        let network = self.inner.network_output_interceptor();
        let combined = super::network_faults::trace_with_campaign_network_records(
            recorded,
            network.campaign_effect_records(),
            network.resource_limits(),
            crucible::model::FaultReplayMode::RecomputedCause,
        )?;
        combined
            .map(|trace| {
                trace
                    .canonical_bytes()
                    .map_err(|error| SchedulerError::BoundaryViolation {
                        message: format!("encode production resolved-effect trace: {error}"),
                    })
            })
            .transpose()
    }

    fn take_terminal_verdict(&mut self) -> Option<QuantumTerminalVerdict> {
        if self.terminal_stop_ready() {
            self.terminal_verdict.take()
        } else {
            None
        }
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<QuantumTerminalVerdict> {
        if self.terminal_stop_ready() {
            self.terminal_verdict.clone()
        } else {
            None
        }
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
        let signal_fault_branch_error =
            (!self.signal_fault_branches.is_empty()).then(|| SchedulerError::BoundaryViolation {
                message: format!(
                    "production lifecycle stopped with {} unconsumed signal-fault branches",
                    self.signal_fault_branches.len()
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
        let campaign_replay_error = self
            .inner
            .network_output_interceptor()
            .verify_campaign_effect_replay_exhausted()
            .err();
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
        let prior_node_lease_cleanup_failure = self.node_lease_cleanup_failed;
        let shutdown = self.inner.shutdown();
        let lease_shutdown = if shutdown.is_ok() {
            self.finish_all_reaped_node_leases()
        } else {
            Ok(())
        };
        let launcher_shutdown =
            if shutdown.is_ok() && lease_shutdown.is_ok() && !self.node_lease_cleanup_failed {
                self.node_launcher
                    .finish()
                    .map_err(|error| SchedulerError::BoundaryViolation {
                        message: format!("finish production node-launch authority: {error}"),
                    })
            } else {
                Ok(())
            };

        let mut failures = Vec::new();
        if let Some(Err(error)) = gateway_shutdown {
            failures.push(error);
        }
        let events = match shutdown {
            Ok(events) => Some(events),
            Err(error) => {
                failures.push(error);
                None
            }
        };
        if let Err(error) = lease_shutdown {
            failures.push(error);
        } else if prior_node_lease_cleanup_failure {
            failures.push(SchedulerError::BoundaryViolation {
                message: String::from(
                    "production QEMU generation lease remains owned by quarantine",
                ),
            });
        }
        if let Err(error) = launcher_shutdown {
            failures.push(error);
        }
        if let Some(error) = pending_error {
            failures.push(error);
        }
        if let Some(error) = signal_fault_branch_error {
            failures.push(error);
        }
        if let Some(error) = replay_error {
            failures.push(error);
        }
        if let Some(error) = campaign_replay_error {
            failures.push(error);
        }
        if let Some(error) = search_override_error {
            failures.push(error);
        }
        if failures.len() == 1 {
            return Err(failures.remove(0));
        }
        if !failures.is_empty() {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "production lifecycle shutdown failed: {}",
                    failures
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
            });
        }
        let events = events.ok_or_else(|| SchedulerError::BoundaryViolation {
            message: String::from("production lifecycle shutdown lost its event-log result"),
        })?;
        self.run_manifest.clean_shutdown = true;
        self.persist_lifecycle_state()?;
        Ok(events)
    }
}

impl ProductionVmLifecycleLoop {
    /// Retains failed-node counter origins without querying a retired process.
    fn checkpoint_node_icount(&self, node: &NodeId) -> Result<Icount, SchedulerError> {
        let retired = match self.node_service_states.get(node) {
            Some(ProductionNodeServiceState::PermanentlyFailed) => {
                // A failed node has no executable backend state. Its scheduler
                // counter remains metadata for the exact world continuation;
                // shifting logical time would lose a rebased counter origin.
                self.inner
                    .loop_impl()
                    .scheduler_counter_for_node(node)?
                    .ticks
            }
            Some(ProductionNodeServiceState::Running | ProductionNodeServiceState::PoweredOff) => {
                self.inner.backend().node_now(node)?.ticks
            }
            None => {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!("checkpoint has no service state for `{}`", node.name),
                });
            }
        };
        Ok(Icount { retired })
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
            node_icounts.insert(vm.id.clone(), self.checkpoint_node_icount(&vm.id)?);
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
            let ownership = terminal
                .process_owner
                .terminal_ownership
                .as_ref()
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "terminal lifecycle node `{}` lost its precommit restart ownership",
                        decision.node.name
                    ),
                })?;
            for source in &ownership.current.artifact_paths {
                File::open(source).map_err(|error| SchedulerError::BoundaryViolation {
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
        let mut terminal_fingerprints = BTreeMap::new();
        for item in &terminal {
            let node = &item.decision.node;
            if item.decision.effective_transition
                != crucible::model::NodeLifecycleTransition::PermanentFailure
            {
                continue;
            }

            let sample = self.inner.backend_mut().fingerprint(node.clone())?;
            let observed_time = self.inner.backend().node_now(node)?;
            if sample.node != *node || sample.at != observed_time {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "terminal fingerprint for `{}` differs from its live node boundary",
                        node.name
                    ),
                });
            }
            if terminal_fingerprints.insert(node.clone(), sample).is_some() {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "terminal lifecycle batch repeats permanently failed node `{}`",
                        node.name
                    ),
                });
            }
        }
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
            if service_state != ProductionNodeServiceState::PermanentlyFailed {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "terminal lifecycle restart for `{}` requires a descriptor-backed v9 checkpoint",
                        decision.node.name
                    ),
                });
            }
            if !lifecycle_precommit.actions.contains(&decision.action) {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "terminal lifecycle action for `{}` lost its precommit checkpoint",
                        decision.node.name
                    ),
                });
            }
            let terminal_fingerprint = terminal_fingerprints.remove(&decision.node);
            let snapshot = self
                .inner
                .backend_mut()
                .capture_terminal_lifecycle_snapshot_shared(
                    &decision.node,
                    Arc::clone(&lifecycle_precommit.checkpoint),
                )?;
            debug_assert!(terminal_fingerprint.as_ref().is_none_or(|sample| {
                sample.at == snapshot.node_continuation().last_observed_time()
            }));
            let ownership = process_owner.terminal_ownership.take().ok_or_else(|| {
                SchedulerError::BoundaryViolation {
                    message: format!(
                        "terminal lifecycle node `{}` reused its precommit restart ownership",
                        decision.node.name
                    ),
                }
            })?;
            let (selected, current_ownership) = select_preowned_terminal_generation(
                ownership.current,
                ownership.successor,
                service_state,
            )
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: format!(
                    "terminal lifecycle node `{}` has no preowned successor",
                    decision.node.name
                ),
            })?;
            debug_assert!(current_ownership.is_none());
            let next_network_sequence = u32::try_from(
                snapshot
                    .node_continuation()
                    .next_plugin_network_output_sequence(),
            )
            .map_err(|_error| SchedulerError::BoundaryViolation {
                message: format!(
                    "terminal network TX continuation for `{}` exceeds the plugin ABI",
                    decision.node.name
                ),
            })?;
            let launch = selected
                .launch
                .with_network_tx_next_sequence(next_network_sequence);
            let run_directory = selected.run_directory;
            fs::create_dir_all(&run_directory).map_err(|error| {
                SchedulerError::BoundaryViolation {
                    message: format!(
                        "create terminal lifecycle generation directory {}: {error}",
                        run_directory.display()
                    ),
                }
            })?;
            prepared.push(PreparedTerminalReplacement {
                debug_backend_path: selected.debug_backend_path,
                decision,
                snapshot,
                terminal_fingerprint,
                run_directory,
                launch,
                generation: selected.generation,
                replacement: None,
                service_state,
                backend_node: process_owner.backend_node.take(),
                observed_exit_node: process_owner.observed_exit_node.take(),
                process_owner: Some(process_owner),
            });
        }
        debug_assert!(terminal_fingerprints.is_empty());
        Ok(prepared)
    }

    fn abort_staged_terminal_replacements(
        prepared: &mut [PreparedTerminalReplacement],
    ) -> Result<(), SchedulerError> {
        let mut first_error = None;
        for item in prepared {
            if let Some(replacement) = item.replacement.take()
                && let Err(error) = replacement.quarantine_and_finish()
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

    pub(super) fn finish_reaped_node_leases(
        &mut self,
        nodes: &[NodeId],
    ) -> Result<(), SchedulerError> {
        let result =
            finish_reaped_node_lease_map(&self.node_generations, &mut self.node_leases, nodes);
        if result.is_err() {
            self.node_lease_cleanup_failed = true;
        }
        result
    }

    fn finish_all_reaped_node_leases(&mut self) -> Result<(), SchedulerError> {
        let nodes = self.node_leases.keys().cloned().collect::<Vec<_>>();
        self.finish_reaped_node_leases(&nodes)
    }

    fn commit_terminal_replacements(
        &mut self,
        prepared: &mut [PreparedTerminalReplacement],
        lifecycle_precommit: &mut PreparedLifecyclePrecommit,
    ) -> Result<(), SchedulerError> {
        if prepared.is_empty() {
            return Ok(());
        }
        if self.node_lease_cleanup_failed {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "production QEMU generation lease remains owned by quarantine",
                ),
            });
        }
        let mut block_handles = std::mem::take(&mut lifecycle_precommit.block_handles);
        debug_assert!(block_handles.capacity() >= prepared.len());
        let mut committed_failed_host_io = self.failed_host_io.clone();
        let mut failed_block_devices = Vec::new();
        for item in prepared.iter() {
            self.inner
                .loop_impl()
                .validate_vm_node_activity_target(&item.decision.node)?;
            if let Some(binding) = self.block_bindings.get(&item.decision.node)
                && let Some(replacement) = &item.replacement
            {
                let handle = replacement.node().shared_block_device().ok_or_else(|| {
                    SchedulerError::BoundaryViolation {
                        message: format!(
                            "replacement QEMU node `{}` lost its block device before commit",
                            item.decision.node.name
                        ),
                    }
                })?;
                block_handles.push((binding.device_hash(), handle));
            }
            if item.service_state == ProductionNodeServiceState::PermanentlyFailed {
                let failed = ProductionFailedNodeState::new(
                    &item.decision.node,
                    item.snapshot.host_io().clone(),
                    item.terminal_fingerprint.clone().ok_or_else(|| {
                        SchedulerError::BoundaryViolation {
                            message: format!(
                                "permanently failed node `{}` lost its terminal fingerprint",
                                item.decision.node.name
                            ),
                        }
                    })?,
                )?;
                if committed_failed_host_io
                    .insert(item.decision.node.clone(), failed)
                    .is_some()
                {
                    return Err(SchedulerError::BoundaryViolation {
                        message: format!(
                            "permanently failed node `{}` already owns retained host I/O",
                            item.decision.node.name
                        ),
                    });
                }
                if let Some(binding) = self.block_bindings.get(&item.decision.node) {
                    failed_block_devices.push(binding.device_hash());
                }
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
            || failed_block_devices
                .iter()
                .any(|device| block_devices.get(device).is_none())
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("terminal replacement lost a prevalidated block owner"),
            });
        }
        let mut replacement_leases = BTreeMap::new();
        let mut replacement_values = std::mem::take(&mut lifecycle_precommit.replacement_values);
        debug_assert!(replacement_values.capacity() >= prepared.len());
        for item in prepared.iter_mut() {
            let replacement = item.replacement.take().map(|replacement| {
                let (node, lease) = replacement.into_parts();
                replacement_leases.insert(item.decision.node.clone(), lease);
                node
            });
            replacement_values.push(replacement);
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
        self.failed_host_io = committed_failed_host_io;
        // Backend ownership changes atomically, but the exact generation
        // leases still have to move into the active map. Keep aggregate
        // authority quarantined if any invariant fails during that handoff.
        self.node_lease_cleanup_failed = true;
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
        for device in failed_block_devices {
            let removed = block_devices.remove(&device);
            debug_assert!(removed.is_some());
        }
        drop(block_devices);

        // Every Crash replacement is restored under the native QEMU pause.
        // Publish Runnable scheduler ownership and install the authoritative
        // backend generation before releasing guest execution.
        for item in prepared
            .iter()
            .filter(|item| item.service_state == ProductionNodeServiceState::Running)
        {
            release_restored_generation_after_scheduler_publication(
                self,
                &item.decision.node,
                item.service_state,
            )?;
        }

        for item in prepared.iter_mut() {
            let node = &item.decision.node;
            self.commit_terminal_process_ownership(node, item.service_state)?;
            match item.service_state {
                ProductionNodeServiceState::PermanentlyFailed => {
                    self.node_leases.remove(node);
                }
                ProductionNodeServiceState::Running | ProductionNodeServiceState::PoweredOff => {
                    let lease = replacement_leases.remove(node).ok_or_else(|| {
                        SchedulerError::BoundaryViolation {
                            message: format!(
                                "committed replacement for `{}` lost its generation lease",
                                node.name
                            ),
                        }
                    })?;
                    if self.node_leases.contains_key(node) {
                        return Err(SchedulerError::BoundaryViolation {
                            message: format!(
                                "committed replacement for `{}` retained an old generation lease",
                                node.name
                            ),
                        });
                    }
                    self.node_leases.insert(node.clone(), lease);
                }
            }
            *self.node_service_states.get_mut(node).ok_or_else(|| {
                SchedulerError::BoundaryViolation {
                    message: String::from("validated lifecycle service owner disappeared"),
                }
            })? = item.service_state;
            std::mem::swap(
                self.node_run_directories.get_mut(node).ok_or_else(|| {
                    SchedulerError::BoundaryViolation {
                        message: String::from("validated lifecycle directory owner disappeared"),
                    }
                })?,
                &mut item.run_directory,
            );
            *self.node_generations.get_mut(node).ok_or_else(|| {
                SchedulerError::BoundaryViolation {
                    message: String::from("validated lifecycle generation owner disappeared"),
                }
            })? = item.generation;
            std::mem::swap(
                self.launch_configs.get_mut(node).ok_or_else(|| {
                    SchedulerError::BoundaryViolation {
                        message: String::from("validated lifecycle launch owner disappeared"),
                    }
                })?,
                &mut item.launch,
            );
            if let Some(path) = item.debug_backend_path.as_mut() {
                std::mem::swap(
                    self.debug_backend_paths.get_mut(node).ok_or_else(|| {
                        SchedulerError::BoundaryViolation {
                            message: String::from("validated lifecycle debug owner disappeared"),
                        }
                    })?,
                    path,
                );
            }
        }
        self.node_lease_cleanup_failed = false;
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

    fn commit_node_boot_requests(&mut self, requests: &[NodeId]) -> Result<(), SchedulerError> {
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
            let Some(state) = self.node_service_states.get_mut(node) else {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from("validated boot node disappeared before commit"),
                });
            };
            *state = ProductionNodeServiceState::Running;
        }
        Ok(())
    }

    /// Commits a selected modeled Boot request in production lifecycle tests.
    ///
    /// # Errors
    ///
    /// Returns an error when the node is not powered off or its scheduler
    /// activity cannot become runnable at the current frontier.
    #[cfg(any(test, feature = "test-support"))]
    pub fn commit_modeled_boot_for_test(&mut self, node: &NodeId) -> Result<(), SchedulerError> {
        self.commit_node_boot_requests(std::slice::from_ref(node))
    }

    fn capture_reserved_exact_checkpoint_set(
        &mut self,
        configuration: &Configuration,
        boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
    ) -> Result<ContentHash, ExactCheckpointTransactionError> {
        boundary()?;
        if !self.continuation_branches.is_empty() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "exact checkpoint cannot retain unapplied cold-replay branch generations",
                ),
            }
            .into());
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
        boundary()?;
        let mut node_icounts = BTreeMap::new();
        let mut boundaries = Vec::new();
        for vm in self.source.world().vm_nodes() {
            boundary()?;
            if self.node_service_states.get(&vm.id)
                == Some(&ProductionNodeServiceState::PermanentlyFailed)
            {
                node_icounts.insert(vm.id.clone(), self.checkpoint_node_icount(&vm.id)?);
                continue;
            }
            let physical = self
                .inner
                .backend()
                .node_now(&vm.id)
                .map_err(SchedulerError::from)?;
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
            boundaries.push((vm.id.clone(), physical.ticks, service_state));
        }

        // Own every scheduler/controller input before the first QMP save can
        // pause a running node. Immutable object and manifest preparation is
        // fallible but remains rollback-safe under the capture owners below.
        let event_log_objects = Arc::new(
            self.inner
                .loop_impl()
                .event_log_dependency_objects()
                .map_err(|error| SchedulerError::BoundaryViolation {
                    message: format!("capture exact event-log closure: {error}"),
                })?
                .into_iter()
                .collect(),
        );
        let scheduler = self.inner.loop_impl().checkpoint().map_err(|error| {
            SchedulerError::BoundaryViolation {
                message: format!("capture exact scheduler continuation: {error}"),
            }
        })?;
        let signal_artifact_objects = self.signal_artifact_objects.clone();
        let trigger_state = self.trigger_state.clone();
        let assertion_state = self.assertion_evaluator.checkpoint();
        let terminal_verdict = self.terminal_verdict.clone();
        let terminal_cause = self.checkpoint_terminal_cause.clone();
        let branch = self.branch.clone();
        let recorded_controls = self.recorded_controls.clone();
        let node_generations = self.node_generations.clone();
        let node_service_states = self.node_service_states.clone();
        let resource_limits = self.source.plan().fault_signals().resource_limits();
        let fault_manifest_identity =
            exact_checkpoint_fault_object_identity(&fault_checkpoint, resource_limits).map_err(
                |error| SchedulerError::BoundaryViolation {
                    message: error.to_string(),
                },
            )?;

        boundary()?;
        let checkpoint_parent = self._run_directory.path().join("exact-checkpoints");
        fs::create_dir_all(&checkpoint_parent).map_err(|error| {
            SchedulerError::BoundaryViolation {
                message: format!(
                    "create exact checkpoint parent directory {}: {error}",
                    checkpoint_parent.display()
                ),
            }
        })?;
        let staging = tempfile::Builder::new()
            .prefix(".exact-checkpoint-")
            .tempdir_in(&checkpoint_parent)
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!(
                    "create exact checkpoint staging directory in {}: {error}",
                    checkpoint_parent.display()
                ),
            })?;

        let prepared_targets = prepare_exact_checkpoint_targets(
            configuration,
            checkpoint_virtual_time,
            &node_icounts,
            boundaries,
            &self.node_indexes,
            &self.node_run_directories,
            staging.path(),
        )?;
        boundary()?;
        let mut captured = Vec::new();
        captured
            .try_reserve_exact(prepared_targets.len())
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!("reserve exact checkpoint capture owners: {error}"),
            })?;
        let mut artifact_bytes = 0_u64;
        let capture_result = (|| -> Result<(), SchedulerError> {
            for prepared in prepared_targets {
                boundary()?;
                let PreparedExactCheckpointTarget {
                    node,
                    counter,
                    scheduler_time,
                    service_state,
                    checkpoint,
                    source_overlay,
                    staged_overlay_chunks,
                    ram_output,
                    device_output,
                    staged_ram_chunks,
                    staged_device_chunks,
                } = prepared;
                let immutable_root_image = self
                    .launch_configs
                    .get(&node)
                    .and_then(QemuLiveNodeStepGateConfig::root_image)
                    .ok_or_else(|| SchedulerError::BoundaryViolation {
                        message: format!(
                            "exact checkpoint has no immutable root image for `{}`",
                            node.name
                        ),
                    })?;
                let epoch = self
                    .inner
                    .backend_mut()
                    .query_exact_checkpoint_epoch(&node)?;
                if epoch.candidate().is_some() {
                    return Err(SchedulerError::BoundaryViolation {
                        message: format!(
                            "exact checkpoint capture for `{}` found an unresolved QEMU candidate",
                            node.name
                        ),
                    });
                }
                let committed = epoch.committed();
                let (parent_closure, parent_checkpoint) = retained_exact_ram_parent_for_committed(
                    &self.exact_ram_parents,
                    self.repository_exact_ram_rebase.as_ref(),
                    &node,
                    committed,
                )?;
                let capture_kind = exact_ram_capture_kind_for_parent(parent_checkpoint.as_ref());
                let capture_boundary = || crucible_qemu::QemuExactCheckpointCaptureBoundary {
                    configuration,
                    immutable_root_image,
                    node: &node,
                    counter,
                    scheduler_time,
                    checkpoint: &checkpoint,
                    fault: &fault_checkpoint,
                    scheduler: &scheduler,
                };
                let capture_outputs = || crucible_qemu::QemuExactCheckpointCaptureOutputs {
                    maximum_ram_bytes: resource_limits.fat_checkpoint_bytes,
                    maximum_device_bytes: resource_limits.fat_checkpoint_bytes,
                    ram: &ram_output,
                    device: &device_output,
                };
                let admission = match (committed, capture_kind) {
                    (Some(parent), ProductionExactRamKind::Delta) => {
                        QemuExactCheckpointCaptureAdmission::admit_delta(
                            capture_boundary(),
                            parent,
                            capture_outputs(),
                        )
                    }
                    _ => QemuExactCheckpointCaptureAdmission::admit_direct(
                        capture_boundary(),
                        capture_outputs(),
                    ),
                }
                .map_err(|error| SchedulerError::BoundaryViolation {
                    message: format!("admit exact checkpoint capture outputs: {error}"),
                })?;
                let mut exact_capture = match service_state {
                    ProductionNodeServiceState::Running => self
                        .inner
                        .backend_mut()
                        .capture_exact_checkpoint_for_publication_guarded(
                            &node, checkpoint, admission,
                        )?,
                    ProductionNodeServiceState::PoweredOff => self
                        .inner
                        .backend_mut()
                        .capture_exact_checkpoint_paused_guarded(&node, checkpoint, admission)?,
                    ProductionNodeServiceState::PermanentlyFailed => {
                        return Err(SchedulerError::BoundaryViolation {
                            message: format!(
                                "permanently failed node `{}` unexpectedly reached snapshot capture",
                                node.name
                            ),
                        });
                    }
                };
                let overlay_file = self
                    .node_leases
                    .get(&node)
                    .ok_or_else(|| SchedulerError::BoundaryViolation {
                        message: format!(
                            "exact checkpoint has no generation lease for `{}`",
                            node.name
                        ),
                    })?
                    .open_checkpoint_root_overlay()
                    .map_err(|error| SchedulerError::BoundaryViolation {
                        message: format!(
                            "open pinned exact-checkpoint overlay for `{}`: {error}",
                            node.name
                        ),
                    })?;
                captured.push(PendingExactCapture {
                    node,
                    counter,
                    scheduler_time,
                    snapshot: exact_capture.snapshot().clone(),
                    overlay_artifact: None,
                    exact_ram: None,
                    exact_checkpoint: Some(PendingExactCheckpointCandidate {
                        identity: exact_capture.identity(),
                        parent: committed,
                    }),
                    snapshot_cleanup_pending: false,
                    resume_pending: service_state == ProductionNodeServiceState::Running,
                });
                let capture =
                    captured
                        .last_mut()
                        .ok_or_else(|| SchedulerError::BoundaryViolation {
                            message: String::from(
                                "exact checkpoint capture owner disappeared after insertion",
                            ),
                        })?;
                let overlay_artifact = stage_sparse_checkpoint_artifact_chunks_with_boundary(
                    &overlay_file,
                    &source_overlay,
                    &staged_overlay_chunks,
                    "root overlay",
                    artifact_bytes,
                    resource_limits,
                    boundary,
                )?;
                artifact_bytes = artifact_bytes
                    .checked_add(overlay_artifact.length)
                    .ok_or_else(|| SchedulerError::BoundaryViolation {
                        message: String::from("exact-checkpoint artifact byte accounting overflow"),
                    })?;
                capture.overlay_artifact = Some(overlay_artifact);

                let expected_ram_bytes = exact_capture.ram_bytes();
                let expected_device_bytes = exact_capture.device_bytes();
                let (ram_file, device_file) = exact_capture.output_files_mut();
                let ram_length = ram_file
                    .metadata()
                    .map_err(|error| SchedulerError::BoundaryViolation {
                        message: format!(
                            "inspect exact RAM output {}: {error}",
                            ram_output.display()
                        ),
                    })?
                    .len();
                let device_length = device_file
                    .metadata()
                    .map_err(|error| SchedulerError::BoundaryViolation {
                        message: format!(
                            "inspect exact device-state output {}: {error}",
                            device_output.display()
                        ),
                    })?
                    .len();
                if ram_length != expected_ram_bytes || device_length != expected_device_bytes {
                    return Err(SchedulerError::BoundaryViolation {
                        message: String::from(
                            "exact checkpoint output lengths differ from QEMU's capture report",
                        ),
                    });
                }
                let qemu_output_bytes = ram_length.checked_add(device_length).ok_or_else(|| {
                    SchedulerError::BoundaryViolation {
                        message: String::from("exact QEMU output byte accounting overflow"),
                    }
                })?;
                resource_limits
                    .reserve("fat_checkpoint_bytes", artifact_bytes, qemu_output_bytes)
                    .map_err(|error| SchedulerError::BoundaryViolation {
                        message: format!("admit exact QEMU outputs: {error}"),
                    })?;

                let ram_content_sha256 = hash_exact_checkpoint_open_file_sha256_with_boundary(
                    ram_file,
                    &ram_output,
                    boundary,
                )?;
                let ram_artifact = stage_open_checkpoint_artifact_chunks_with_boundary(
                    ram_file,
                    &ram_output,
                    &staged_ram_chunks,
                    "exact RAM",
                    artifact_bytes,
                    resource_limits,
                    boundary,
                )?;
                artifact_bytes =
                    artifact_bytes
                        .checked_add(ram_artifact.length)
                        .ok_or_else(|| SchedulerError::BoundaryViolation {
                            message: String::from(
                                "exact-checkpoint artifact byte accounting overflow",
                            ),
                        })?;
                let device_content_sha256 = hash_exact_checkpoint_open_file_sha256_with_boundary(
                    device_file,
                    &device_output,
                    boundary,
                )?;
                let device_artifact = stage_open_checkpoint_artifact_chunks_with_boundary(
                    device_file,
                    &device_output,
                    &staged_device_chunks,
                    "exact device VMState",
                    artifact_bytes,
                    resource_limits,
                    boundary,
                )?;
                artifact_bytes = artifact_bytes
                    .checked_add(device_artifact.length)
                    .ok_or_else(|| SchedulerError::BoundaryViolation {
                        message: String::from("exact-checkpoint artifact byte accounting overflow"),
                    })?;
                if device_artifact.length != expected_device_bytes {
                    return Err(SchedulerError::BoundaryViolation {
                        message: String::from(
                            "exact device-state artifact length differs from QEMU's capture report",
                        ),
                    });
                }
                let layer = ProductionExactRamLayer::from_capture(
                    &exact_capture,
                    ram_content_sha256,
                    ram_artifact,
                )?;
                let exact_ram = ProductionExactRamCheckpoint::from_captured_layer(
                    parent_closure,
                    parent_checkpoint,
                    capture_kind,
                    device_content_sha256,
                    device_artifact.clone(),
                    layer,
                )?;
                capture.exact_ram = Some(exact_ram);
                boundary()?;
            }
            Ok(())
        })();
        if let Err(error) = capture_result {
            let cleanup =
                self.release_exact_captures(&mut captured, ExactCaptureDisposition::Unpublished);
            return combine_exact_checkpoint_transaction(
                Err(ExactCheckpointTransactionError::Unpublished(error)),
                cleanup,
                captured,
            );
        }

        let preparation = (|| -> Result<_, ExactCheckpointTransactionError> {
            let mut targets = BTreeMap::new();
            for capture in &captured {
                boundary()?;
                let overlay_artifact = capture.overlay_artifact.clone().ok_or_else(|| {
                    SchedulerError::BoundaryViolation {
                        message: format!(
                            "exact checkpoint root overlay for `{}` is not staged",
                            capture.node.name
                        ),
                    }
                })?;
                let exact_ram =
                    capture
                        .exact_ram
                        .clone()
                        .ok_or_else(|| SchedulerError::BoundaryViolation {
                            message: format!(
                                "exact checkpoint RAM closure for `{}` is not staged",
                                capture.node.name
                            ),
                        })?;
                let immutable_backing = self
                    .immutable_root_images
                    .get(&capture.node)
                    .copied()
                    .ok_or_else(|| SchedulerError::BoundaryViolation {
                        message: format!(
                            "exact checkpoint has no immutable root-image identity for `{}`",
                            capture.node.name
                        ),
                    })?;
                let manifest_basis = ExactCheckpointTargetManifestBasis {
                    configuration: configuration.id(),
                    immutable_backing,
                    node: &capture.node,
                    counter: capture.counter,
                    scheduler_time: capture.scheduler_time,
                    snapshot: exact_checkpoint_snapshot_object_identity(
                        &capture.snapshot,
                        resource_limits,
                    )
                    .map_err(|error| SchedulerError::BoundaryViolation {
                        message: error.to_string(),
                    })?,
                    fault_identity: fault_manifest_identity,
                    overlay: overlay_artifact.identity,
                    device_state: exact_ram.device_artifact.identity,
                };
                let manifest_identity =
                    exact_ram_checkpoint_target_manifest_identity(manifest_basis, &exact_ram);
                targets.insert(
                    capture.node.clone(),
                    ProductionVmExactCheckpointTarget {
                        configuration: Arc::new(configuration.clone()),
                        immutable_backing,
                        counter: capture.counter,
                        scheduler_time: capture.scheduler_time,
                        snapshot: capture.snapshot.clone(),
                        materialization: ProductionVmExactCheckpointMaterialization::Native {
                            overlay_artifact,
                            exact_ram: Box::new(exact_ram),
                            manifest_identity,
                        },
                    },
                );
            }

            validate_failed_host_io_topology(
                &self.source,
                &node_service_states,
                &self.failed_host_io,
            )
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!("validate failed-node host I/O: {error}"),
            })?;
            let mut checkpoint_set = ProductionVmExactCheckpointSet {
                identity: ContentHash::default(),
                configuration: configuration.clone(),
                scheduler: Arc::new(scheduler),
                event_log_objects,
                signal_artifact_objects,
                trigger_state,
                assertion_state,
                terminal_verdict,
                terminal_cause,
                initial_lifecycle_observations_pending: self.initial_lifecycle_observations_pending,
                branch,
                recorded_controls,
                selectable_catalog_plans: self.inner.backend_mut().selectable_catalog_plans(),
                fault_checkpoint: Some(fault_checkpoint),
                targets,
                failed_host_io: self.failed_host_io.clone(),
                node_generations,
                node_service_states,
                repository_restore: None,
            };
            let prepared = prepare_exact_checkpoint_set_with_boundary(
                &self.config.run_state_root,
                self.scenario.id(),
                resource_limits,
                &mut checkpoint_set,
                boundary,
            )
            .map_err(|error| match error {
                PersistExactCheckpointError::Unpublished(source) => {
                    ExactCheckpointTransactionError::Unpublished(source)
                }
                PersistExactCheckpointError::Indeterminate { identity, source } => {
                    ExactCheckpointTransactionError::Indeterminate {
                        identity: Some(identity),
                        captures: Vec::new(),
                        source,
                    }
                }
            })?;
            let mut retained_targets = BTreeMap::new();
            for (node, target) in &checkpoint_set.targets {
                let exact_ram = target.native_exact_ram().ok_or_else(|| {
                    ExactCheckpointTransactionError::Unpublished(
                        SchedulerError::BoundaryViolation {
                            message: String::from(
                                "captured checkpoint target lost native RAM state",
                            ),
                        },
                    )
                })?;
                retained_targets.insert(node.clone(), exact_ram.clone());
            }
            let parent = ProductionExactRamPublishedParent {
                closure: prepared.identity(),
                targets: retained_targets,
            };
            Ok((prepared, parent))
        })();
        let (prepared, retained_parent) = match preparation {
            Ok(prepared) => prepared,
            Err(error @ ExactCheckpointTransactionError::Unpublished(_)) => {
                let cleanup = self
                    .release_exact_captures(&mut captured, ExactCaptureDisposition::Unpublished);
                return combine_exact_checkpoint_transaction(Err(error), cleanup, captured);
            }
            Err(ExactCheckpointTransactionError::Indeterminate {
                identity, source, ..
            }) => {
                return Err(ExactCheckpointTransactionError::Indeterminate {
                    identity,
                    captures: captured,
                    source,
                });
            }
        };
        let identity = prepared.identity();
        self.exact_ram_parents
            .insert(configuration.id(), retained_parent);
        match prepared.publish() {
            Ok(()) => {
                if let Err(source) =
                    self.release_exact_captures(&mut captured, ExactCaptureDisposition::Published)
                {
                    return Err(ExactCheckpointTransactionError::Indeterminate {
                        identity: Some(identity),
                        captures: captured,
                        source,
                    });
                }
                self.exact_ram_parents
                    .retain(|candidate, _| *candidate == configuration.id());
                self.repository_exact_ram_rebase = None;
                Ok(identity)
            }
            Err(PersistExactCheckpointError::Unpublished(source)) => {
                self.exact_ram_parents.remove(&configuration.id());
                let cleanup = self
                    .release_exact_captures(&mut captured, ExactCaptureDisposition::Unpublished);
                combine_exact_checkpoint_transaction(
                    Err(ExactCheckpointTransactionError::Unpublished(source)),
                    cleanup,
                    captured,
                )
            }
            Err(PersistExactCheckpointError::Indeterminate { identity, source }) => {
                Err(ExactCheckpointTransactionError::Indeterminate {
                    identity: Some(identity),
                    captures: captured,
                    source,
                })
            }
        }
    }

    /// Evaluates the signal program exactly once in the ordered sequence of
    /// scheduler visits to the current virtual-time coordinate.
    pub(super) fn evaluate_signal_fault_boundary(
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
            let scheduler_checkpoint = self.inner.loop_impl().checkpoint().map_err(|error| {
                SchedulerError::BoundaryViolation {
                    message: format!("capture lifecycle scheduler continuation: {error}"),
                }
            })?;
            Some(self.begin_terminal_lifecycle_intent(
                &lifecycle_intents,
                &scheduler_checkpoint,
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
        let fault_runtime = Arc::clone(&self.fault_runtime);
        let mut release_runtime = match fault_runtime.lock() {
            Ok(runtime) => runtime,
            Err(_) => {
                return Err(self.quarantine_terminal_lifecycle_transaction(
                    lifecycle_work.decisions(),
                    lifecycle_work.boot_requests(),
                    SchedulerError::BoundaryViolation {
                        message: String::from("production fault runtime lock is poisoned"),
                    },
                ));
            }
        };
        let lifecycle_release =
            match release_runtime.acknowledge_node_lifecycle_work(lifecycle_work) {
                Ok(release) => release,
                Err(work) => {
                    release_runtime.poison();
                    drop(release_runtime);
                    return Err(self.quarantine_terminal_lifecycle_transaction(
                        work.decisions(),
                        work.boot_requests(),
                        SchedulerError::BoundaryViolation {
                            message: String::from(
                                "acknowledge production lifecycle work: lifecycle owner mismatch",
                            ),
                        },
                    ));
                }
            };
        // Hold this same guard from acknowledgement through release completion.
        // A newly resumed generation can immediately enter a block or 9p
        // coordinator on another host thread; that callback waits here until
        // the barrier is cleared instead of interleaving canonical fault state.
        for decision in lifecycle_release.decisions() {
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
                _ => continue,
            };
            if let Err(error) = release_restored_generation_after_scheduler_publication(
                self,
                &decision.node,
                service_state,
            ) {
                release_runtime.poison();
                drop(release_runtime);
                return Err(self.quarantine_terminal_lifecycle_transaction(
                    lifecycle_release.decisions(),
                    lifecycle_release.boot_requests(),
                    error,
                ));
            }
        }
        for node in lifecycle_release.boot_requests() {
            if let Err(error) = release_restored_generation_after_scheduler_publication(
                self,
                node,
                ProductionNodeServiceState::Running,
            ) {
                release_runtime.poison();
                drop(release_runtime);
                return Err(self.quarantine_terminal_lifecycle_transaction(
                    lifecycle_release.decisions(),
                    lifecycle_release.boot_requests(),
                    error,
                ));
            }
        }
        if let Err(release) = release_runtime.complete_node_lifecycle_release(lifecycle_release) {
            release_runtime.poison();
            drop(release_runtime);
            return Err(self.quarantine_terminal_lifecycle_transaction(
                release.decisions(),
                release.boot_requests(),
                SchedulerError::BoundaryViolation {
                    message: String::from(
                        "complete production lifecycle release: lifecycle owner mismatch",
                    ),
                },
            ));
        }
        drop(release_runtime);
        Ok(append)
    }

    fn apply_signal_fault_lifecycle_work(
        &mut self,
        decisions: &[QemuNodeLifecycleDecision],
        boot_requests: &[NodeId],
        mut lifecycle_precommit: Option<&mut PreparedLifecyclePrecommit>,
    ) -> Result<(), SchedulerError> {
        let has_lifecycle = !decisions.is_empty();
        if let Err(error) = self.commit_node_boot_requests(boot_requests) {
            return Err(self.quarantine_terminal_lifecycle_transaction(
                decisions,
                boot_requests,
                error,
            ));
        }
        let mut prepared = match self
            .prepare_terminal_replacements(decisions, lifecycle_precommit.as_deref_mut())
        {
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
        for replacement in &prepared {
            if let Err(error) =
                self.finish_reaped_node_leases(std::slice::from_ref(&replacement.decision.node))
            {
                return Err(self.quarantine_terminal_lifecycle_transaction_with_staged(
                    decisions,
                    boot_requests,
                    &mut prepared,
                    error,
                ));
            }
        }
        if !prepared.is_empty() {
            let precommit = lifecycle_precommit.as_deref_mut().ok_or_else(|| {
                SchedulerError::BoundaryViolation {
                    message: String::from("terminal lifecycle commit lost its precommit storage"),
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

#[cfg(test)]
#[path = "quantum_loop/tests.rs"]
mod tests;
