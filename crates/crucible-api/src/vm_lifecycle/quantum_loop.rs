//! `QuantumLoop` delegation for the production VM lifecycle.

use super::checkpoint_store::{
    PersistExactCheckpointError, prepare_exact_checkpoint_set_with_boundary,
};
use super::*;

mod checkpoint_capture;
mod debug_policy;
mod lifecycle;
pub(super) use checkpoint_capture::ExactCheckpointPublicationState;
use checkpoint_capture::{ExactCheckpointTransactionError, PendingExactCapture};
use debug_policy::trusted_debug_listener;
pub(super) use lifecycle::{
    DurableRunStateError, LifecycleStatePersistence, PRODUCTION_RUN_STATE_FILE,
    decode_prior_run_state, decode_run_json_bounded, persist_run_state_atomic,
};
#[cfg(test)]
pub(super) use lifecycle::{HARD_RUN_STATE_JSON_BYTES, validate_recovered_lifecycle_journal};
use lifecycle::{
    PreparedLifecycleFaultCoordinators, PreparedLifecyclePrecommit, PreparedLifecycleTerminal,
    PreparedTerminalReplacement, map_journal_limit,
    release_restored_generation_after_scheduler_publication, select_preowned_terminal_generation,
};

const CHECKPOINT_BOUNDARY_CHUNK_BYTES: usize = 1024 * 1024;

#[cfg(test)]
fn checkpoint_artifact_from_stopped_file(
    source: &Path,
    role: &str,
) -> Result<ProductionCheckpointArtifact, SchedulerError> {
    checkpoint_artifact_from_stopped_file_with_boundary(source, role, &mut || Ok(()))
}

fn checkpoint_artifact_from_stopped_file_with_boundary(
    source: &Path,
    role: &str,
    boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
) -> Result<ProductionCheckpointArtifact, SchedulerError> {
    boundary()?;
    let mut file = File::open(source).map_err(|error| SchedulerError::BoundaryViolation {
        message: format!(
            "open stopped exact-checkpoint {role} {}: {error}",
            source.display()
        ),
    })?;
    let mut buffer = vec![0_u8; CHECKPOINT_BOUNDARY_CHUNK_BYTES];
    let mut hasher = blake3::Hasher::new();
    loop {
        boundary()?;
        let read = std::io::Read::read(&mut file, &mut buffer).map_err(|error| {
            SchedulerError::BoundaryViolation {
                message: format!(
                    "hash stopped exact-checkpoint {role} {}: {error}",
                    source.display()
                ),
            }
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    boundary()?;
    let identity = ContentHash {
        bytes: *hasher.finalize().as_bytes(),
    };
    let length = fs::metadata(source).map_err(|error| SchedulerError::BoundaryViolation {
        message: format!(
            "inspect stopped exact-checkpoint {role} {}: {error}",
            source.display()
        ),
    })?;
    let length = length.len();
    Ok(ProductionCheckpointArtifact {
        source: ProductionCheckpointArtifactSource::File(source.to_path_buf()),
        identity,
        length,
        chunks: Vec::new(),
    })
}

fn combine_exact_checkpoint_transaction(
    operation: Result<ContentHash, ExactCheckpointTransactionError>,
    cleanup: Result<(), SchedulerError>,
    captures: Vec<PendingExactCapture>,
) -> Result<ContentHash, ExactCheckpointTransactionError> {
    match (operation, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(identity), Err(source)) => Err(ExactCheckpointTransactionError::Indeterminate {
            identity: Some(identity),
            captures,
            source,
        }),
        (Err(ExactCheckpointTransactionError::Unpublished(error)), Err(cleanup)) => {
            Err(ExactCheckpointTransactionError::Indeterminate {
                identity: None,
                captures,
                source: SchedulerError::BoundaryViolation {
                    message: format!(
                        "exact checkpoint failed before publication ({error}); releasing paused QEMU nodes also failed ({cleanup})"
                    ),
                },
            })
        }
        (
            Err(ExactCheckpointTransactionError::Indeterminate {
                identity,
                captures: prior_captures,
                source,
            }),
            Err(cleanup),
        ) => {
            let captures = if captures.is_empty() {
                prior_captures
            } else {
                captures
            };
            Err(ExactCheckpointTransactionError::Indeterminate {
                identity,
                captures,
                source: SchedulerError::BoundaryViolation {
                    message: format!(
                        "exact checkpoint publication was indeterminate ({source}); releasing paused QEMU nodes also failed ({cleanup})"
                    ),
                },
            })
        }
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

impl ProductionVmLifecycleLoop {
    /// Enables exact live signal-fault campaign promotion from this boundary.
    ///
    /// Callers activate promotion only after deterministic prefix
    /// materialization reaches the attempt's admitted start. Previously
    /// retained search frontiers remain replay evidence and are not emitted.
    pub fn enable_signal_fault_campaign_promotion(&mut self) {
        self.promote_signal_fault_campaign_choices = true;
    }

    fn authenticate_signal_fault_campaign_branch(
        &self,
        branch: &crucible::SignalFaultCampaignBranch,
    ) -> Result<(), SchedulerError> {
        let authenticated = if let Some((choice, expected)) = branch.expected_search_override() {
            self.fault_runtime
                .lock()
                .map_err(|_| SchedulerError::BoundaryViolation {
                    message: String::from("production fault runtime lock is poisoned"),
                })?
                .search_override_consumed(choice, &expected)
        } else {
            self.inner
                .loop_impl()
                .search_frontiers()
                .iter()
                .any(|frontier| branch.matches_runtime_frontier(frontier))
        };
        if !authenticated {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "signal-fault campaign branch has no exact observed producer choice",
                ),
            });
        }
        Ok(())
    }

    /// Normalizes only signal-fault frontiers first observed by this quantum.
    ///
    /// The scheduler retains older frontiers for checkpoint and replay
    /// authentication. Re-emitting that history as a later discovery would
    /// manufacture a branch point after execution had already passed it, so
    /// callers supply the frontier count captured before the quantum began.
    fn signal_fault_campaign_discoveries_at_current_boundary_since(
        &self,
        first: usize,
    ) -> Result<Vec<crucible::campaign::ChoiceDiscovery>, SchedulerError> {
        if !self.promote_signal_fault_campaign_choices {
            return Ok(Vec::new());
        }
        let frontiers = self.inner.loop_impl().search_frontiers();
        let current = frontiers
            .get(first..)
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from("signal-fault frontier history shrank during one quantum"),
            })?;
        if current.len() > crucible::MAX_SIGNAL_FAULT_CAMPAIGN_BRANCHES {
            return Err(SchedulerError::ResourceLimit {
                field: "signal-fault campaign discoveries",
                current: 0,
                requested: u64::try_from(current.len()).unwrap_or(u64::MAX),
                configured: u64::try_from(crucible::MAX_SIGNAL_FAULT_CAMPAIGN_BRANCHES)
                    .unwrap_or(u64::MAX),
                hard: u64::try_from(crucible::MAX_SIGNAL_FAULT_CAMPAIGN_BRANCHES)
                    .unwrap_or(u64::MAX),
            });
        }

        let mut charged_records = BTreeSet::new();
        let mut charged_bytes = 0usize;
        let mut discoveries = Vec::with_capacity(current.len());
        let configuration = self.inner.loop_impl().configuration();
        let at = self.inner.loop_impl().frontier();
        for frontier in current
            .iter()
            .filter(|frontier| frontier.configuration == *configuration && frontier.at == at)
        {
            let discovery = crucible::SignalFaultSelectable::from_frontier(frontier)
                .and_then(|selectable| selectable.discovery())
                .map_err(|error| SchedulerError::BoundaryViolation {
                    message: format!("normalize live signal-fault campaign discovery: {error}"),
                })?;
            for (id, bytes) in [
                (
                    discovery.opportunity().declaration().content_id(),
                    discovery.declaration().canonical_bytes().len(),
                ),
                (
                    discovery.opportunity().domain().content_id(),
                    discovery.domain().canonical_bytes().len(),
                ),
                (
                    discovery
                        .opportunity()
                        .id()
                        .map_err(|error| SchedulerError::BoundaryViolation {
                            message: format!(
                                "identify live signal-fault campaign discovery: {error}"
                            ),
                        })?
                        .content_id(),
                    discovery.opportunity().canonical_bytes().len(),
                ),
            ] {
                if !charged_records.insert(id) {
                    continue;
                }
                charged_bytes = charged_bytes.checked_add(bytes).ok_or_else(|| {
                    SchedulerError::ResourceLimit {
                        field: "signal-fault campaign discovery bytes",
                        current: 0,
                        requested: u64::MAX,
                        configured: u64::try_from(
                            crucible::campaign::MAX_OBSERVATION_CHOICE_DISCOVERY_BYTES,
                        )
                        .unwrap_or(u64::MAX),
                        hard: u64::try_from(
                            crucible::campaign::MAX_OBSERVATION_CHOICE_DISCOVERY_BYTES,
                        )
                        .unwrap_or(u64::MAX),
                    }
                })?;
                if charged_bytes > crucible::campaign::MAX_OBSERVATION_CHOICE_DISCOVERY_BYTES {
                    return Err(SchedulerError::ResourceLimit {
                        field: "signal-fault campaign discovery bytes",
                        current: 0,
                        requested: u64::try_from(charged_bytes).unwrap_or(u64::MAX),
                        configured: u64::try_from(
                            crucible::campaign::MAX_OBSERVATION_CHOICE_DISCOVERY_BYTES,
                        )
                        .unwrap_or(u64::MAX),
                        hard: u64::try_from(
                            crucible::campaign::MAX_OBSERVATION_CHOICE_DISCOVERY_BYTES,
                        )
                        .unwrap_or(u64::MAX),
                    });
                }
            }
            discoveries.push(discovery);
        }
        Ok(discoveries)
    }

    fn append_live_signal_fault_campaign_discoveries(
        &self,
        first: usize,
        outcome: &mut QuantumOutcome,
    ) -> Result<(), SchedulerError> {
        outcome
            .discovered_choices
            .extend(self.signal_fault_campaign_discoveries_at_current_boundary_since(first)?);
        Ok(())
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
            let signal_fault_frontier_start = self.inner.loop_impl().search_frontiers().len();
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
            self.append_live_signal_fault_campaign_discoveries(
                signal_fault_frontier_start,
                &mut outcome,
            )?;
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
            let source_run_directory = current_ownership.as_ref().map_or_else(
                || selected.run_directory.clone(),
                |current| current.run_directory.clone(),
            );
            let source_paths = current_ownership.map(|current| current.artifact_paths);
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
            if let Some(source_paths) = source_paths {
                for (source, target) in source_paths.iter().zip(&selected.artifact_paths) {
                    fs::copy(source, target).map_err(|error| {
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
            prepared.push(PreparedTerminalReplacement {
                debug_backend_path: selected.debug_backend_path,
                decision,
                snapshot,
                source_run_directory,
                run_directory,
                launch,
                generation: selected.generation,
                replacement: None,
                service_state,
                crash_detector: selected.crash_detector,
                backend_node: process_owner.backend_node.take(),
                observed_exit_node: process_owner.observed_exit_node.take(),
                fault_coordinators: selected.fault_coordinators,
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

    fn install_prepared_fault_coordinators(
        node: &NodeId,
        coordinators: &mut PreparedLifecycleFaultCoordinators,
        replacement: &mut QemuNode,
    ) -> Result<(), SchedulerError> {
        if let Some(block) = coordinators.block.take() {
            if replacement.shared_block_device().is_none() {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "replacement QEMU node `{}` has no live block device",
                        node.name
                    ),
                });
            }
            replacement
                .install_block_fault_coordinator(block)
                .map_err(|error| SchedulerError::BoundaryViolation {
                    message: format!(
                        "install replacement block fault coordinator for `{}`: {error}",
                        node.name
                    ),
                })?;
        }
        if let Some(ninep) = coordinators.ninep.take() {
            replacement
                .install_ninep_fault_coordinator(ninep)
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
        let preparation = ProductionVmNodePreparationKind::Replacement {
            source_run_directory: &prepared.source_run_directory,
        };
        let launched = match prepared.service_state {
            ProductionNodeServiceState::Running | ProductionNodeServiceState::PoweredOff => {
                Some(launch_production_node_generation(
                    self.node_launcher.as_mut(),
                    ProductionVmNodeLaunchBasis::new(
                        &prepared.launch,
                        &prepared.run_directory,
                        &node,
                        prepared.generation,
                    ),
                    &prepared.crash_detector,
                    preparation,
                    ProductionVmNodeLaunchKind::Exact {
                        snapshot: &prepared.snapshot,
                        paused: true,
                    },
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
            if let Err(error) = Self::install_prepared_fault_coordinators(
                &node,
                &mut prepared.fault_coordinators,
                launched.node_mut(),
            ) {
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

    fn capture_reserved_exact_checkpoint_set(
        &mut self,
        configuration: &Configuration,
        boundary: &mut dyn FnMut() -> Result<(), SchedulerError>,
    ) -> Result<ContentHash, ExactCheckpointTransactionError> {
        boundary()?;
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
            boundaries.push((vm.id.clone(), physical.ticks, scheduler_time, service_state));
        }

        // Own every scheduler/controller input before the first QMP save can
        // pause a running node. Immutable object and manifest preparation is
        // fallible but remains rollback-safe under the capture owners below.
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
        let signal_artifact_objects = self.signal_artifact_objects.clone();
        let trigger_state = self.trigger_state.clone();
        let assertion_state = self.assertion_evaluator.checkpoint();
        let terminal_verdict = self.terminal_verdict.clone();
        let terminal_cause = self.checkpoint_terminal_cause.clone();
        let branch = self.branch.clone();
        let recorded_controls = self.recorded_controls.clone();
        let node_generations = self.node_generations.clone();
        let node_service_states = self.node_service_states.clone();

        let mut captured = Vec::new();
        captured
            .try_reserve_exact(boundaries.len())
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!("reserve exact checkpoint capture owners: {error}"),
            })?;
        let capture_result = (|| -> Result<(), SchedulerError> {
            for (node, counter, scheduler_time, service_state) in boundaries {
                boundary()?;
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
                    snapshot,
                    snapshot_cleanup_pending: true,
                    resume_pending: service_state == ProductionNodeServiceState::Running,
                });
                boundary()?;
            }
            Ok(())
        })();
        if let Err(error) = capture_result {
            let cleanup = self.release_exact_captures(&mut captured);
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
                let source_directory =
                    self.node_run_directories
                        .get(&capture.node)
                        .ok_or_else(|| SchedulerError::BoundaryViolation {
                            message: format!(
                                "exact checkpoint has no process-generation directory for `{}`",
                                capture.node.name
                            ),
                        })?;
                let overlay_artifact = checkpoint_artifact_from_stopped_file_with_boundary(
                    &source_directory.join(PRODUCTION_ROOT_OVERLAY_FILE_NAME),
                    "root overlay",
                    boundary,
                )?;
                let vmstate_artifact = checkpoint_artifact_from_stopped_file_with_boundary(
                    &source_directory.join(PRODUCTION_VMSTATE_FILE_NAME),
                    "VMState",
                    boundary,
                )?;
                let manifest_identity =
                    exact_checkpoint_target_manifest_identity(ExactCheckpointTargetManifestBasis {
                        configuration: configuration.id(),
                        node: &capture.node,
                        counter: capture.counter,
                        scheduler_time: capture.scheduler_time,
                        snapshot: capture.snapshot.id(),
                        fault_identity: fault_checkpoint.id(),
                        overlay: overlay_artifact.identity,
                        vmstate: vmstate_artifact.identity,
                    });
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

            let mut checkpoint_set = ProductionVmExactCheckpointSet {
                identity: ContentHash::default(),
                configuration: configuration.clone(),
                scheduler,
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
                node_generations,
                node_service_states,
            };
            prepare_exact_checkpoint_set_with_boundary(
                &self.config.run_state_root,
                self.scenario.id(),
                self.source.plan().fault_signals().resource_limits(),
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
            })
        })();
        let prepared = match preparation {
            Ok(prepared) => prepared,
            Err(error) => {
                let cleanup = self.release_exact_captures(&mut captured);
                return combine_exact_checkpoint_transaction(Err(error), cleanup, captured);
            }
        };
        let identity = prepared.identity();
        let was_already_published = prepared.was_already_published();
        if let Err(source) = self.release_exact_captures(&mut captured) {
            return Err(ExactCheckpointTransactionError::Indeterminate {
                identity: was_already_published.then_some(identity),
                captures: captured,
                source,
            });
        }
        prepared
            .publish()
            .map(|()| identity)
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
            })
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
