//! `QuantumLoop` delegation for the production VM lifecycle.

use super::*;

struct PreparedTerminalReplacement {
    decision: QemuNodeLifecycleDecision,
    snapshot: QemuVmSnapshot,
    source_run_directory: PathBuf,
    run_directory: PathBuf,
    launch: ProductionLiveNodeStepGateConfig,
    generation: u64,
    replacement: Option<ProductionVmNodeLaunch>,
    service_state: ProductionNodeServiceState,
}

struct PendingExactCapture {
    node: NodeId,
    counter: u64,
    scheduler_time: VirtualTime,
    service_state: ProductionNodeServiceState,
    snapshot: QemuVmSnapshot,
}

fn checkpoint_artifact_from_stopped_file(
    source: &Path,
    role: &str,
) -> Result<ProductionCheckpointArtifact, SchedulerError> {
    let identity = hash_file(source).map_err(|error| SchedulerError::BoundaryViolation {
        message: format!(
            "hash stopped exact-checkpoint {role} {}: {error}",
            source.display()
        ),
    })?;
    let length = fs::metadata(source)
        .map_err(|error| SchedulerError::BoundaryViolation {
            message: format!(
                "inspect stopped exact-checkpoint {role} {}: {error}",
                source.display()
            ),
        })?
        .len();
    Ok(ProductionCheckpointArtifact {
        source: ProductionCheckpointArtifactSource::File(source.to_path_buf()),
        identity,
        length,
        chunks: Vec::new(),
    })
}

fn combine_exact_capture_result<T>(
    operation: Result<T, SchedulerError>,
    cleanup: Result<(), SchedulerError>,
) -> Result<T, SchedulerError> {
    match (operation, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(cleanup)) => Err(cleanup),
        (Err(error), Err(cleanup)) => Err(SchedulerError::BoundaryViolation {
            message: format!(
                "exact checkpoint failed ({error}); releasing paused QEMU nodes also failed ({cleanup})"
            ),
        }),
    }
}

fn combine_attempt_quantum_boundary<T>(
    operation: Result<T, SchedulerError>,
    boundary: Result<(), LifecycleApiError>,
) -> Result<T, SchedulerError> {
    match (operation, boundary) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(boundary)) => Err(attempt_boundary_scheduler_error(
            "check production attempt after scheduler quantum",
            boundary,
        )),
        (Err(error), Err(boundary)) => Err(attempt_boundary_scheduler_error(
            &format!(
                "production scheduler quantum failed ({error}); post-quantum attempt boundary"
            ),
            boundary,
        )),
    }
}

fn attempt_boundary_scheduler_error(context: &str, error: LifecycleApiError) -> SchedulerError {
    match error {
        LifecycleApiError::AttemptOperational { class, message } => {
            SchedulerError::OperationalBoundary {
                class,
                message: format!("{context} failed: {message}"),
            }
        }
        error => SchedulerError::BoundaryViolation {
            message: format!("{context} failed: {error}"),
        },
    }
}

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
                    discovered_choices: Vec::new(),
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
                        discovered_choices: Vec::new(),
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
            let mut queued =
                observations
                    .lock()
                    .map_err(|_| SchedulerError::BoundaryViolation {
                        message: String::from(
                            "production fault observation journal lock is poisoned",
                        ),
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
        })();
        let boundary = self.node_launcher.check_operational_boundary();
        combine_attempt_quantum_boundary(operation, boundary)
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
    ) -> Result<
        (
            Vec<Decision>,
            Vec<crucible::campaign::ChoiceDiscovery>,
            Configuration,
            SchedulerEventLogAppend,
        ),
        SchedulerError,
    > {
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
        if let Some(error) = replay_error {
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
                .map(ProductionVmNodeLaunch::node)
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
        boot_requests: &[NodeId],
        primary: impl std::fmt::Display,
    ) -> SchedulerError {
        let quarantine = self
            .inner
            .backend_mut()
            .quarantine_terminal_lifecycle_work(decisions, boot_requests);
        let scheduler = self.contain_terminal_lifecycle_scheduler(decisions, boot_requests);
        for node in decisions
            .iter()
            .map(|decision| &decision.node)
            .chain(boot_requests)
        {
            if let Some(state) = self.node_service_states.get_mut(node) {
                *state = ProductionNodeServiceState::PermanentlyFailed;
            }
        }
        let journal = self.advance_lifecycle_journal(ProductionLifecycleJournalPhase::Quarantined);
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
        boot_requests: &[NodeId],
        prepared: &mut [PreparedTerminalReplacement],
        primary: impl std::fmt::Display,
    ) -> SchedulerError {
        let staged = Self::abort_staged_terminal_replacements(prepared);
        self.quarantine_terminal_lifecycle_transaction(
            decisions,
            boot_requests,
            format!(
                "{primary}; staged-process containment: {}",
                staged.map_or_else(|error| error.to_string(), |()| String::from("reaped"))
            ),
        )
    }

    fn contain_terminal_lifecycle_scheduler(
        &mut self,
        decisions: &[QemuNodeLifecycleDecision],
        boot_requests: &[NodeId],
    ) -> Result<(), SchedulerError> {
        for node in decisions
            .iter()
            .map(|decision| &decision.node)
            .chain(boot_requests)
        {
            self.inner
                .loop_impl()
                .validate_vm_node_activity_target(node)?;
        }
        for node in decisions
            .iter()
            .map(|decision| &decision.node)
            .chain(boot_requests)
        {
            self.inner
                .loop_impl_mut()
                .set_vm_node_activity(node, SchedulerNodeActivity::Done)?;
        }
        Ok(())
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
                source_run_directory: current_directory.clone(),
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
        &mut self,
        prepared: &mut PreparedTerminalReplacement,
    ) -> Result<(), SchedulerError> {
        let node = prepared.decision.node.clone();
        let crash_detector = format!("lifecycle-{}-generation-{}", node.name, prepared.generation);
        let preparation = ProductionVmNodePreparationKind::Replacement {
            source_run_directory: &prepared.source_run_directory,
        };
        let launched = match prepared.service_state {
            ProductionNodeServiceState::Running => Some(launch_production_node_generation(
                self.node_launcher.as_mut(),
                ProductionVmNodeLaunchBasis::new(
                    &prepared.launch,
                    &prepared.run_directory,
                    &node,
                    prepared.generation,
                ),
                &crash_detector,
                preparation,
                ProductionVmNodeLaunchKind::Exact {
                    snapshot: &prepared.snapshot,
                    paused: false,
                },
            )),
            ProductionNodeServiceState::PoweredOff => Some(launch_production_node_generation(
                self.node_launcher.as_mut(),
                ProductionVmNodeLaunchBasis::new(
                    &prepared.launch,
                    &prepared.run_directory,
                    &node,
                    prepared.generation,
                ),
                &crash_detector,
                preparation,
                ProductionVmNodeLaunchKind::Exact {
                    snapshot: &prepared.snapshot,
                    paused: true,
                },
            )),
            ProductionNodeServiceState::PermanentlyFailed => None,
        };
        if let Some(launched) = launched {
            let mut launched = launched.map_err(|error| SchedulerError::BoundaryViolation {
                message: format!(
                    "stage terminal lifecycle replacement for `{}`: {error}",
                    node.name
                ),
            })?;
            if let Err(error) =
                self.configure_replacement_fault_coordinators(&node, launched.node_mut())
            {
                let containment = launched.quarantine_and_finish();
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "configure terminal lifecycle replacement for `{}`: {error}; process containment: {}",
                        node.name,
                        containment
                            .map_or_else(|error| error.to_string(), |()| String::from("reaped")),
                    ),
                });
            }
            prepared.run_directory = launched.run_directory().to_path_buf();
            prepared.launch = prepared
                .launch
                .clone()
                .with_run_directory(&prepared.run_directory);
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
        if self.node_lease_cleanup_failed {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "production QEMU generation lease remains owned by quarantine",
                ),
            });
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
        let mut replacement_leases = BTreeMap::new();
        let replacement_values = prepared
            .iter_mut()
            .map(|item| {
                let replacement = item.replacement.take().map(|replacement| {
                    let (node, lease) = replacement.into_parts();
                    replacement_leases.insert(item.decision.node.clone(), lease);
                    node
                });
                (item.decision.node.clone(), replacement)
            })
            .collect();
        let retired = self
            .inner
            .backend_mut()
            .commit_terminal_replacements(plan, replacement_values);
        // Backend ownership changes atomically, but the exact generation
        // leases still have to move into the active map. Keep aggregate
        // authority quarantined if any invariant fails during that handoff.
        self.node_lease_cleanup_failed = true;
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
                    self.node_leases.remove(&node);
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
                    let lease = replacement_leases.remove(&node).ok_or_else(|| {
                        SchedulerError::BoundaryViolation {
                            message: format!(
                                "committed replacement for `{}` lost its generation lease",
                                node.name
                            ),
                        }
                    })?;
                    if self.node_leases.contains_key(&node) {
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
        self.node_lease_cleanup_failed = false;
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

        let mut captured = Vec::new();
        let capture_result = (|| -> Result<(), SchedulerError> {
            for (node, counter, scheduler_time, service_state) in boundaries {
                let parent = if configuration.schedule.is_empty() {
                    None
                } else {
                    let parent_len = configuration.schedule.len().saturating_sub(1);
                    let parent_schedule = configuration.schedule.prefix(parent_len).map_err(
                        |error| SchedulerError::BoundaryViolation {
                            message: format!(
                                "derive exact checkpoint parent at schedule length {parent_len}: {error}"
                            ),
                        },
                    )?;
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
                        .capture_exact_snapshot_for_publication(&node, checkpoint)?,
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
                captured.push(PendingExactCapture {
                    node,
                    counter,
                    scheduler_time,
                    service_state,
                    snapshot,
                });
            }
            Ok(())
        })();
        if let Err(error) = capture_result {
            let cleanup = self.release_exact_captures(&captured);
            return combine_exact_capture_result(Err(error), cleanup);
        }

        let publication = (|| -> Result<ContentHash, SchedulerError> {
            let mut targets = BTreeMap::new();
            for capture in &captured {
                let source_directory =
                    self.node_run_directories
                        .get(&capture.node)
                        .ok_or_else(|| SchedulerError::BoundaryViolation {
                            message: format!(
                                "exact checkpoint has no process-generation directory for `{}`",
                                capture.node.name
                            ),
                        })?;
                let overlay_artifact = checkpoint_artifact_from_stopped_file(
                    &source_directory.join(PRODUCTION_ROOT_OVERLAY_FILE_NAME),
                    "root overlay",
                )?;
                let vmstate_artifact = checkpoint_artifact_from_stopped_file(
                    &source_directory.join(PRODUCTION_VMSTATE_FILE_NAME),
                    "VMState",
                )?;
                let manifest_identity = crucible::ContentHash::from_canonical_material(
                    "crucible.production-vm-exact-checkpoint.v1",
                    &format!(
                        "configuration={}\nnode={}\ncounter={}\nscheduler_time={}\nsnapshot={}\nfault={}\noverlay={}\nvmstate={}",
                        configuration.id().to_hex(),
                        capture.node.name,
                        capture.counter,
                        capture.scheduler_time.ticks,
                        capture.snapshot.id().to_hex(),
                        fault_checkpoint.id().to_hex(),
                        overlay_artifact.identity.to_hex(),
                        vmstate_artifact.identity.to_hex(),
                    ),
                );
                targets.insert(
                    capture.node.clone(),
                    ProductionVmExactCheckpointTarget {
                        configuration: configuration.clone(),
                        counter: capture.counter,
                        scheduler_time: capture.scheduler_time,
                        snapshot: capture.snapshot.clone(),
                        overlay_artifact,
                        vmstate_artifact,
                        manifest_identity,
                    },
                );
            }

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
                initial_lifecycle_observations_pending: self.initial_lifecycle_observations_pending,
                branch: self.branch.clone(),
                recorded_controls: self.recorded_controls.clone(),
                fault_checkpoint: Some(fault_checkpoint),
                targets,
                node_generations: self.node_generations.clone(),
                node_service_states: self.node_service_states.clone(),
            };
            persist_exact_checkpoint_set(
                &self.config.run_state_root,
                self.scenario.id(),
                self.source.plan().fault_signals().resource_limits(),
                &mut checkpoint_set,
            )?;
            Ok(checkpoint_set.identity)
        })();
        let cleanup = self.release_exact_captures(&captured);
        let checkpoint_set_identity = combine_exact_capture_result(publication, cleanup)?;
        let replaced = self
            .checkpoint_targets
            .insert(configuration.id(), checkpoint_set_identity);
        debug_assert!(replaced.is_none());
        Ok(checkpoint_set_identity)
    }

    fn release_exact_captures(
        &mut self,
        captured: &[PendingExactCapture],
    ) -> Result<(), SchedulerError> {
        let mut first_failure = None;
        for capture in captured.iter().rev() {
            if let Err(error) = self
                .inner
                .backend_mut()
                .delete_exact_snapshot(&capture.node, &capture.snapshot)
                && first_failure.is_none()
            {
                first_failure = Some(format!(
                    "delete paused exact snapshot for `{}`: {error}",
                    capture.node.name
                ));
            }
            if capture.service_state == ProductionNodeServiceState::Running
                && let Err(error) = self
                    .inner
                    .backend_mut()
                    .resume_after_exact_snapshot(&capture.node)
                && first_failure.is_none()
            {
                first_failure = Some(format!(
                    "resume `{}` after exact checkpoint publication: {error}",
                    capture.node.name
                ));
            }
        }
        if let Some(message) = first_failure {
            return Err(SchedulerError::BoundaryViolation { message });
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
        if let Err(error) = self.apply_signal_fault_lifecycle_work(
            lifecycle_work.decisions(),
            lifecycle_work.boot_requests(),
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
    ) -> Result<(), SchedulerError> {
        let has_lifecycle = !decisions.is_empty();
        if has_lifecycle && let Err(error) = self.begin_terminal_lifecycle_transaction(decisions) {
            return Err(self.quarantine_terminal_lifecycle_transaction(
                decisions,
                boot_requests,
                error,
            ));
        }
        if let Err(error) = self.activate_node_boot_requests(boot_requests) {
            return Err(self.quarantine_terminal_lifecycle_transaction(
                decisions,
                boot_requests,
                error,
            ));
        }
        let mut prepared = match self.prepare_terminal_replacements(decisions) {
            Ok(prepared) => prepared,
            Err(capture_error) => {
                return Err(self.quarantine_terminal_lifecycle_transaction(
                    decisions,
                    boot_requests,
                    capture_error,
                ));
            }
        };
        if has_lifecycle && let Err(error) = self.record_prepared_lifecycle_processes(&prepared) {
            return Err(self.quarantine_terminal_lifecycle_transaction_with_staged(
                decisions,
                boot_requests,
                &mut prepared,
                error,
            ));
        }
        let observed_exit_codes = match self.supervise_terminal_lifecycle_exits(decisions) {
            Ok(observed) => observed,
            Err(error) => {
                return Err(self.quarantine_terminal_lifecycle_transaction_with_staged(
                    decisions,
                    boot_requests,
                    &mut prepared,
                    error,
                ));
            }
        };
        let retiring = prepared
            .iter()
            .map(|replacement| replacement.decision.node.clone())
            .collect::<Vec<_>>();
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
        if let Err(error) = self.finish_reaped_node_leases(&retiring) {
            return Err(self.quarantine_terminal_lifecycle_transaction_with_staged(
                decisions,
                boot_requests,
                &mut prepared,
                error,
            ));
        }
        if let Err(error) = self.commit_terminal_replacements(&mut prepared) {
            return Err(self.quarantine_terminal_lifecycle_transaction_with_staged(
                decisions,
                boot_requests,
                &mut prepared,
                error,
            ));
        }
        if has_lifecycle
            && let Err(error) =
                self.retain_completed_lifecycle_exits(decisions, &observed_exit_codes)
        {
            return Err(self.quarantine_terminal_lifecycle_transaction(
                decisions,
                boot_requests,
                error,
            ));
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
