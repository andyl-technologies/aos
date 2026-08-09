//! `QuantumLoop` delegation for the production VM lifecycle.

use super::*;

impl QuantumLoop for ProductionVmLifecycleLoop {
    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.reconcile_indeterminate_debug_ownership()?;
        self.reconcile_backend_membership()?;
        if request.configuration != *self.inner.loop_impl().configuration() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "quantum request configuration is not the scheduler frontier",
                ),
            });
        }
        let pre_quantum_trigger_appends = self.settle_trigger_graph()?;
        self.reconcile_backend_membership()?;
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
            prepend_event_log_appends(&mut outcome, pre_quantum_trigger_appends);
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
                counters.push((node.id.clone(), counter));
                self.checkpoint_targets.insert(
                    node.id.clone(),
                    ProductionVmCheckpointReplayTarget {
                        configuration: request.configuration.clone(),
                        counter,
                        scheduler_time,
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
                prepend_event_log_appends(&mut outcome, pre_quantum_trigger_appends);
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
        let mut outcome = match crucible_session::drive_engine_quantum(&mut self.inner, request) {
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
        self.inner.apply_control_at_boundary(control)
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
        self.inner.loop_impl().pending_branch_fault_choice_count()
    }

    fn take_terminal_verdict(&mut self) -> Option<QuantumTerminalVerdict> {
        self.terminal_verdict.take()
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.reconcile_indeterminate_debug_ownership()?;
        let pending = self.inner.loop_impl().pending_branch_fault_choice_count();
        let pending_error = (pending != 0).then(|| SchedulerError::BoundaryViolation {
            message: format!(
                "production lifecycle stopped with {pending} unconsumed branch choices"
            ),
        });
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
        if let Some(error) = pending_error {
            shutdown?;
            return Err(error);
        }
        shutdown
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
