//! `QuantumLoop` delegation for the production VM lifecycle.

use super::*;

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
        let storage_observations = queued.snapshot();
        if !storage_observations.is_empty() {
            let append = self
                .inner
                .loop_impl_mut()
                .append_fault_observations(storage_observations)?;
            queued.clear();
            merge_event_log_append(&mut outcome, append);
        }
        drop(queued);
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

    fn take_terminal_verdict(&mut self) -> Option<QuantumTerminalVerdict> {
        self.terminal_verdict.take()
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.reconcile_indeterminate_debug_ownership()?;
        let pending = self.inner.loop_impl().pending_branch_effect_choice_count();
        let pending_error = (pending != 0).then(|| SchedulerError::BoundaryViolation {
            message: format!(
                "production lifecycle stopped with {pending} unconsumed branch effect choices"
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

impl ProductionVmLifecycleLoop {
    fn capture_exact_checkpoint_set(
        &mut self,
        configuration: &Configuration,
    ) -> Result<(), SchedulerError> {
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
            let physical = self.inner.backend().node_now(&vm.id)?;
            let scheduler_time = self.inner.loop_impl().scheduler_time_for_node(&vm.id)?;
            node_icounts.insert(
                vm.id.clone(),
                crucible::Icount {
                    retired: physical.ticks,
                },
            );
            boundaries.push((vm.id.clone(), physical.ticks, scheduler_time));
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
                for (node, counter, scheduler_time) in boundaries {
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
                    let snapshot = self
                        .inner
                        .backend_mut()
                        .capture_exact_snapshot(&node, checkpoint)?;
                    captured.push((node.clone(), snapshot.clone()));
                    let index = self.node_indexes.get(&node).copied().ok_or_else(|| {
                        SchedulerError::BoundaryViolation {
                            message: format!(
                                "exact checkpoint has no launch index for `{}`",
                                node.name
                            ),
                        }
                    })?;
                    let source_overlay = self
                        ._run_directory
                        .path()
                        .join(format!("node-{index}"))
                        .join(PRODUCTION_ROOT_OVERLAY_FILE_NAME);
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
                    let source_vmstate = self
                        ._run_directory
                        .path()
                        .join(format!("node-{index}"))
                        .join(PRODUCTION_VMSTATE_FILE_NAME);
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
                            overlay_artifact: checkpoint_root.join(artifact_name),
                            vmstate_artifact: checkpoint_root.join(vmstate_name),
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
                self.checkpoint_targets.extend(targets);
                Ok(())
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
        let coordinate = self.inner.loop_impl().frontier().ticks;
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
        )
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
