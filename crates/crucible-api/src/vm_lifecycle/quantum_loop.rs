//! `QuantumLoop` delegation for the production VM lifecycle.

use super::*;

impl QuantumLoop for ProductionVmLifecycleLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.reconcile_backend_membership()?;
        let mut pre_quantum_appends = Vec::new();
        let fault_append = self.evaluate_signal_fault_boundary()?;
        if !fault_append.entries.is_empty() {
            pre_quantum_appends.push(fault_append);
        }
        pre_quantum_appends.extend(self.settle_trigger_graph()?);
        self.reconcile_backend_membership()?;
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
                let Ok(_counter) = self.inner.backend().node_now(&node.id).map(|at| at.ticks)
                else {
                    continue;
                };
                let at = self.inner.loop_impl().scheduler_time_for_node(&node.id)?;
                node_times.insert(node.id.clone(), at);
            }
            self.recorded_controls.push(ProductionVmRecordedControl {
                configuration: request.configuration.clone(),
                node_times,
                control: request.control.clone(),
            });
        }
        let snapshot_counters = if request
            .control
            .iter()
            .any(|operation| matches!(operation.kind, crucible::ControlOperationKind::Snapshot))
        {
            let mut counters = Vec::new();
            for node in self.source.world().vm_nodes() {
                let counter = self.inner.backend().node_now(&node.id)?.ticks;
                let scheduler_time = self.inner.loop_impl().scheduler_time_for_node(&node.id)?;
                counters.push((node.id.clone(), counter, scheduler_time));
            }
            counters
        } else {
            Vec::new()
        };
        let snapshot_fault_checkpoint = if snapshot_counters.is_empty() {
            None
        } else {
            Some(
                self.fault_runtime
                    .checkpoint(self.inner.backend_mut())
                    .map_err(|error| SchedulerError::BoundaryViolation {
                        message: format!(
                            "capture signal fault continuation at checkpoint boundary: {error}"
                        ),
                    })?,
            )
        };
        let snapshot_configuration =
            (!snapshot_counters.is_empty()).then(|| request.configuration.clone());
        let snapshot_control_count = self.recorded_controls.len();
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
                let decisions = branch.decisions.clone();
                let (configuration, append) = self
                    .inner
                    .loop_impl_mut()
                    .append_branch_prefix_overrides(decisions.clone())?;
                if let Some(seed) = branch.seed {
                    self.inner.loop_impl_mut().reseed_future_decisions(seed)?;
                }
                self.inner.loop_impl_mut().clear_branch_frontier_cap();
                let frontier = self.inner.loop_impl().frontier();
                let scheduler_quiescence = Some(self.inner.loop_impl().quiescence()?);
                self.branch = None;
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
        prepend_event_log_appends(&mut outcome, pre_quantum_appends);
        for append in self.settle_trigger_graph()? {
            merge_event_log_append(&mut outcome, append);
        }
        for (node, counter, scheduler_time) in snapshot_counters {
            self.inner
                .loop_impl_mut()
                .record_node_checkpoint_at(&node, crucible::NodeCounter { ticks: counter })?;
            let fault_checkpoint =
                snapshot_fault_checkpoint.as_ref().cloned().ok_or_else(|| {
                    SchedulerError::BoundaryViolation {
                        message: String::from(
                            "checkpoint boundary completed without a signal fault continuation",
                        ),
                    }
                })?;
            self.checkpoint_targets.insert(
                node,
                ProductionVmCheckpointReplayTarget {
                    configuration: snapshot_configuration.as_ref().cloned().ok_or_else(|| {
                        SchedulerError::BoundaryViolation {
                            message: String::from(
                                "checkpoint boundary lost its configuration identity",
                            ),
                        }
                    })?,
                    counter,
                    scheduler_time,
                    control_count: snapshot_control_count,
                    fault_checkpoint,
                },
            );
        }
        self.reconcile_backend_membership()?;
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

    fn apply_control_at_boundary(
        &mut self,
        control: Vec<ControlOperation>,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.inner.apply_control_at_boundary(control)
    }

    fn open_gdbstub(
        &mut self,
        node: NodeId,
        listen: GdbListen,
    ) -> Result<GdbAttachInfo, SchedulerError> {
        self.inner.open_gdbstub(node, listen)
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

    fn take_terminal_verdict(&mut self) -> Option<QuantumTerminalVerdict> {
        self.terminal_verdict.take()
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        let pending = self.inner.loop_impl().pending_branch_effect_choice_count();
        let pending_error = (pending != 0).then(|| SchedulerError::BoundaryViolation {
            message: format!(
                "production lifecycle stopped with {pending} unconsumed branch effect choices"
            ),
        });
        let shutdown = self.inner.shutdown();
        if let Some(error) = pending_error {
            shutdown?;
            return Err(error);
        }
        shutdown
    }
}

impl ProductionVmLifecycleLoop {
    /// Evaluates the signal program exactly once in the ordered sequence of
    /// scheduler visits to the current virtual-time coordinate.
    fn evaluate_signal_fault_boundary(
        &mut self,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        let coordinate = self.inner.loop_impl().frontier().ticks;
        if self.fault_coordinate == Some(coordinate) {
            self.fault_coordinate_sequence = self
                .fault_coordinate_sequence
                .checked_add(1)
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: String::from(
                        "signal fault same-coordinate sequence space is exhausted",
                    ),
                })?;
        } else {
            self.fault_coordinate = Some(coordinate);
            self.fault_coordinate_sequence = 0;
        }
        let evaluation = self
            .fault_runtime
            .evaluate_boundary(
                FaultCoordinate {
                    virtual_nanos: coordinate,
                    retired_instructions: None,
                },
                self.fault_coordinate_sequence,
                self.inner.backend_mut(),
            )
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!("signal fault boundary failed closed: {error}"),
            })?;
        self.inner
            .loop_impl_mut()
            .set_signal_fault_wakeup(evaluation.next_wakeup_nanos)?;
        self.inner
            .loop_impl_mut()
            .append_fault_observations(evaluation.observations)
    }
}
