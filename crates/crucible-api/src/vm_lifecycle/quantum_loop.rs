//! `QuantumLoop` delegation for the production VM lifecycle.

use super::*;

impl QuantumLoop for ProductionVmLifecycleLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.reconcile_backend_membership()?;
        let pre_quantum_trigger_appends = self.settle_trigger_graph()?;
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
            let node_counters = self
                .source
                .world()
                .vm_nodes()
                .iter()
                .filter_map(|node| {
                    self.inner
                        .backend()
                        .node_now(&node.id)
                        .ok()
                        .map(|at| (node.id.clone(), at.ticks))
                })
                .collect();
            self.recorded_controls.push(ProductionVmRecordedControl {
                configuration: request.configuration.clone(),
                node_counters,
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
                counters.push((node.id.clone(), counter));
                self.checkpoint_targets.insert(
                    node.id.clone(),
                    ProductionVmCheckpointReplayTarget {
                        configuration: request.configuration.clone(),
                        counter,
                        control_count: self.recorded_controls.len(),
                    },
                );
            }
            counters
        } else {
            Vec::new()
        };
        let pending_restarts = self
            .inner
            .loop_impl()
            .preview_ready_point_control_restarts(&request.control);
        let mut prelaunched_this_quantum = Vec::new();
        for (node, counter) in pending_restarts {
            if let Err(error) = self.launch_ready_point(&node, counter.ticks) {
                return Err(self.rollback_prelaunch_after_error(&prelaunched_this_quantum, error));
            }
            self.prelaunched_restarts
                .insert(node.clone(), (RestartPolicy::FromReadyPoint, counter.ticks));
            prelaunched_this_quantum.push(node);
        }
        let pending_checkpoint_restarts = self
            .inner
            .loop_impl()
            .preview_checkpoint_control_restarts(&request.control);
        for node in pending_checkpoint_restarts {
            let expected = self
                .checkpoint_targets
                .get(&node)
                .map(|target| target.counter)
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: format!(
                        "production QEMU checkpoint restart for `{}` has no captured target",
                        node.name
                    ),
                })?;
            if let Err(error) = self.relaunch_last_checkpoint_node(&node, expected) {
                return Err(self.rollback_prelaunch_after_error(&prelaunched_this_quantum, error));
            }
            self.prelaunched_restarts
                .insert(node.clone(), (RestartPolicy::FromLastCheckpoint, expected));
            prelaunched_this_quantum.push(node);
        }
        if let Some(branch) = self.branch.as_ref() {
            if request.configuration == branch.base {
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
                prepend_event_log_appends(&mut outcome, pre_quantum_trigger_appends);
                return Ok(outcome);
            }
            if request.configuration.schedule.len() >= branch.base.schedule.len() {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "branch-prefix replay bypassed base configuration {}",
                        branch.base.id().to_hex()
                    ),
                });
            }
        }
        let mut outcome = match self.inner.drive_quantum(request) {
            Ok(outcome) => outcome,
            Err(error) => {
                return Err(self.rollback_prelaunch_after_error(&prelaunched_this_quantum, error));
            }
        };
        prepend_event_log_appends(&mut outcome, pre_quantum_trigger_appends);
        for append in self.settle_trigger_graph()? {
            merge_event_log_append(&mut outcome, append);
        }
        for (node, counter) in snapshot_counters {
            self.inner
                .loop_impl_mut()
                .record_node_checkpoint_at(&node, crucible::NodeCounter { ticks: counter })?;
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
        self.inner.loop_impl().pending_branch_fault_choice_count()
    }

    fn take_terminal_verdict(&mut self) -> Option<QuantumTerminalVerdict> {
        self.terminal_verdict.take()
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        let pending = self.inner.loop_impl().pending_branch_fault_choice_count();
        let pending_error = (pending != 0).then(|| SchedulerError::BoundaryViolation {
            message: format!(
                "production lifecycle stopped with {pending} unconsumed branch fault choices"
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
