//! `QuantumLoop` delegation for the production VM lifecycle.

use super::*;

impl QuantumLoop for ProductionVmLifecycleLoop {
    fn drive_quantum(
        &mut self,
        mut request: QuantumRequest,
    ) -> Result<QuantumOutcome, SchedulerError> {
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
        if self.branch.as_ref().is_some_and(|branch| {
            branch.base == request.configuration && !request.control.is_empty()
        }) {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "branch-prefix admission cannot discard simultaneous control",
                ),
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
