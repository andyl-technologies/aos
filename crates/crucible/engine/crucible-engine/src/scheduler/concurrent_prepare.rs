//! Speculative scheduler preparation and authoritative concurrent commit.

use super::event_log::HeldRunLineage;
use super::*;
use crate::backend::StepObservation;

/// Output produced by one bounded host-concurrent scheduler round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerConcurrentQuantumOutcome {
    /// RUN set selected from the same scheduler boundary before host dispatch.
    pub run_set: SchedulerConcurrentRunSet,
    /// Serialized scheduler completions for the dispatched RUN set.
    pub outcomes: Vec<QuantumOutcome>,
}

/// Deterministic set of RUNs eligible for host-level concurrent dispatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerConcurrentRunSet {
    /// RUN candidates selected in deterministic scheduler completion order.
    pub candidates: Vec<SchedulerConcurrentRunCandidate>,
}

/// One node RUN selected for bounded host-level concurrent dispatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerConcurrentRunCandidate {
    /// Scheduler node selected by PICK for this concurrent round.
    pub node: SchedulerNodeId,
    /// Node-local virtual time before RUN.
    pub current_time: SimInstant,
    /// Conservative lookahead-bounded virtual time for this RUN.
    pub target_time: SimInstant,
    /// Icount ceiling published before host dispatch.
    pub max_advance_icount: u64,
}

/// One backend RUN whose observable coordinate was fixed before host dispatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConcurrentBackendRun {
    /// Sealed semantic owner, actual input enumeration and current dispatch cap.
    pub admission: PreparedRunAdmission,
    /// Modeled preemptions applied before guest execution begins.
    pub preemptions: Vec<PreemptionDecision>,
}

impl ConcurrentBackendRun {
    /// Returns the logical node retained by the sealed scheduler admission.
    #[must_use]
    pub fn node(&self) -> &NodeId {
        self.admission.node()
    }

    /// Returns the finalized node-local logical dispatch ceiling.
    #[must_use]
    pub fn ceiling(&self) -> VirtualTime {
        VirtualTime {
            ticks: self.admission.dispatch_horizon().icount.retired,
        }
    }
}

/// Physical progress awaiting exact scheduler-owned input resolution.
///
/// This reports coordinates only. The backend retains its native owner, receipt
/// and pending settlement transport until an explicitly authenticated resume.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendRunInputBoundary {
    /// Original semantic owner and the inventory whose input cap was reached.
    pub admission: PreparedRunAdmission,
    /// Independently observed stopped node-local logical coordinate.
    pub reached: NodeCounter,
}

/// Unchanged physical stop awaiting a strictly tighter backend execution cap.
///
/// This is an observation, not native authority. The operational backend keeps
/// the exact cancelled receipt, unchanged-before full STOP, physical identity,
/// GRID and independently authenticated earlier-cap source privately.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendRunCapBoundary {
    /// Exact admission whose physical dispatch was cancelled before motion.
    pub admission: PreparedRunAdmission,
    /// Independently observed unchanged node-local logical coordinate.
    pub stopped: NodeCounter,
    /// Earlier native timer or private input cap in node-local logical ticks.
    pub tighter_cap: NodeCounter,
}

/// Physical progress at an internal dispatch cap before semantic completion.
///
/// The backend retains its original RUN and independently authenticated stopped
/// source. Reaching this cap alone permits no STEP, input effect or output drain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendRunDispatchBoundary {
    /// Exact original semantic owner and the physical wave that reached its cap.
    pub admission: PreparedRunAdmission,
    /// Independently observed stopped node-local logical coordinate.
    pub reached: NodeCounter,
}

/// Closed result of an admitted backend step before evidence is drained.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackendRunResult {
    /// Fully settled physical stop eligible for normal boundary evidence.
    Completed(StepObservation),
    /// Retained unsettled stop requiring actor-owned input staging.
    InputBoundary(BackendRunInputBoundary),
    /// Unchanged stop requiring explicit tighter physical readmission.
    CapBoundary(BackendRunCapBoundary),
    /// Internal physical wave requiring canonical actor arbitration.
    DispatchBoundary(BackendRunDispatchBoundary),
}

/// Closed result of one scheduler-owned concurrent RUN.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConcurrentBackendRunResult {
    /// Fully settled stop with its drained boundary evidence.
    Completed(ConcurrentBackendRunOutcome),
    /// Physical progress without semantic completion or output publication.
    InputBoundary(BackendRunInputBoundary),
    /// Unchanged stop requiring explicit tighter physical readmission.
    CapBoundary(BackendRunCapBoundary),
    /// Internal physical wave without semantic completion or drained evidence.
    DispatchBoundary(BackendRunDispatchBoundary),
}

/// Host-worker evidence for one completed backend RUN.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConcurrentBackendRunOutcome {
    /// Node advanced by this RUN.
    pub node: NodeId,
    /// Completed step observation at the ceiling or an earlier output boundary.
    pub step: StepObservation,
    /// Causal RNG evidence drained on the node owner thread.
    pub rng_evidence: Vec<BackendRngEvidence>,
    /// Network outputs drained on the node owner thread.
    pub network_outputs: Vec<BackendNetworkOutput>,
    /// Observational events drained on the node owner thread.
    pub observations: Vec<ObservableEvent>,
}

/// Backend collection capable of executing independent scheduler RUNs in parallel.
pub trait ConcurrentSimulationBackend: SimulationBackend {
    /// Executes every scheduler-fixed RUN and returns outcomes in input order.
    ///
    /// Implementations must retain exclusive ownership of every node until its
    /// result and boundary evidence have been captured. No host completion
    /// order may escape through the returned vector.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when a node is absent, a worker fails, or any
    /// backend cannot report an exact reached boundary and drain its evidence.
    fn execute_concurrent_runs(
        &mut self,
        runs: Vec<ConcurrentBackendRun>,
        max_host_workers: usize,
    ) -> Result<Vec<ConcurrentBackendRunResult>, BackendError>;

    /// Resumes a retained input stop after exact actor-owned input staging.
    ///
    /// # Errors
    ///
    /// The default refuses without effects. Operational implementations must
    /// match their retained native owner and exact stopped GRID independently.
    fn resume_input_boundary(
        &mut self,
        run: ConcurrentBackendRun,
        boundary: &BackendRunInputBoundary,
    ) -> Result<ConcurrentBackendRunResult, BackendError> {
        let _ = (run, boundary);
        Err(BackendError::Unsupported {
            capability: "resume_input_boundary",
        })
    }

    /// Readmits an unchanged stopped RUN with an explicitly tighter physical cap.
    ///
    /// # Errors
    ///
    /// The default refuses without effects. Operational implementations must
    /// authenticate their retained cancelled receipt, full STOP and current
    /// earlier-cap source; scalar observations alone do not permit readmission.
    fn resume_cap_boundary(
        &mut self,
        run: ConcurrentBackendRun,
        boundary: &BackendRunCapBoundary,
    ) -> Result<ConcurrentBackendRunResult, BackendError> {
        let _ = (run, boundary);
        Err(BackendError::Unsupported {
            capability: "resume_cap_boundary",
        })
    }

    /// Resumes a retained internal wave after fresh actor planner authorization.
    ///
    /// # Errors
    ///
    /// The default refuses. Operational implementations must authenticate their
    /// retained stopped source and every fixed-T input effect independently.
    fn resume_dispatch_boundary(
        &mut self,
        run: ConcurrentBackendRun,
        boundary: &BackendRunDispatchBoundary,
    ) -> Result<ConcurrentBackendRunResult, BackendError> {
        let _ = (run, boundary);
        Err(BackendError::Unsupported {
            capability: "resume_dispatch_boundary",
        })
    }
}

/// One scheduler RUN planned before host dispatch and committed after its evidence arrives.
#[derive(Clone, Debug)]
pub(super) struct PreparedHostRun {
    pub(super) plan: AdvancePlan,
    pub(super) admission: PreparedRunAdmission,
    // Retains the selected backend contract through held-stop validation.
    pub(super) dispatch_contract: crate::BackendDispatchContract,
    pub(super) preemptions: Vec<PlannedPreemptionApplication>,
    // Artificial watermark ceilings do not revoke a future command's natural horizon.
    pub(super) authorized_preemption_horizon: u64,
    // Only this validated request may retain that horizon through a later control cap.
    authorized_preemption_request: Option<PreemptionDecision>,
    pub(super) staged_input_events: Vec<ScheduledEvent>,
    pub(super) staged_device_decisions: Vec<Decision>,
    pub(super) canonical_lineage: Option<HeldRunLineage>,
}

/// Scheduler state after PICK and ceiling publication, before physical RUNs.
#[derive(Clone, Debug)]
pub(super) struct PreparedHostConcurrentQuantum {
    pub(super) next: SingleScheduler,
    pub(super) run_set: SchedulerConcurrentRunSet,
    pub(super) runs: Vec<PreparedHostRun>,
    pub(super) boundary_events: Vec<ScheduledEvent>,
    pub(super) control_applications: Vec<SchedulerControlApplication>,
    pub(super) topology_recomputed: bool,
}

impl SingleScheduler {
    /// Finishes unpublished RUN planning at its first exact native control boundary.
    fn prepare_host_preemptible_run(
        &mut self,
        mut plan: AdvancePlan,
        authorized_preemption_horizon: u64,
        previous_admission: Option<&PreparedRunAdmission>,
    ) -> Result<PreparedHostRun, SchedulerError> {
        let preemptions = self.planned_preemptions_for_authorized_run(
            &plan.node,
            plan.before,
            &plan.ceiling,
            authorized_preemption_horizon,
        )?;
        if let Some(preemption) = preemptions.first()
            && preemption.decision.at.ticks < plan.target_counter
        {
            let target_counter = preemption.decision.at.ticks;
            let target_time = self.node_time_for_counter(
                &self.nodes[plan.index],
                NodeCounter {
                    ticks: target_counter,
                },
            )?;
            plan.target_counter = target_counter;
            plan.projected_target_time = target_time;
            plan.quiescent_horizon = None;
            plan.subdivision =
                self.planned_run_subdivision(&plan.node, plan.before, target_counter)?;
            plan.ceiling.max_advance_icount = target_counter;
            plan.ceiling.target_time = target_time;
            let publication = self
                .ceiling_publications
                .get_mut(plan.ceiling.sequence as usize)
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: String::from("unpublished host RUN ceiling lost its sequence"),
                })?;
            *publication = plan.ceiling.clone();
        }
        let preemptions = self.planned_preemptions_for_authorized_run(
            &plan.node,
            plan.before,
            &plan.ceiling,
            authorized_preemption_horizon,
        )?;
        let authorized_preemption_request = self
            .preemption_requests
            .iter()
            .find(|request| request.node == plan.node.node)
            .cloned();
        let admission = self.seal_prepared_run(
            &plan,
            authorized_preemption_horizon,
            authorized_preemption_request.as_ref(),
            previous_admission,
        )?;
        Ok(PreparedHostRun {
            plan,
            admission,
            dispatch_contract: crate::BackendDispatchContract::PhysicalSource,
            preemptions,
            authorized_preemption_horizon,
            authorized_preemption_request,
            staged_input_events: Vec::new(),
            staged_device_decisions: Vec::new(),
            canonical_lineage: None,
        })
    }

    /// Plans one omitted producer's physical catch-up without publishing EMIT.
    pub(super) fn prepare_host_catchup_run(
        &mut self,
        index: usize,
        catchup_at: SimInstant,
    ) -> Result<Option<PreparedHostRun>, SchedulerError> {
        self.prepare_host_catchup_run_with_authorization(
            index,
            catchup_at,
            None,
            crate::BackendDispatchContract::PhysicalSource,
        )
    }

    pub(super) fn prepare_host_catchup_run_for_contract(
        &mut self,
        index: usize,
        catchup_at: SimInstant,
        dispatch_contract: crate::BackendDispatchContract,
    ) -> Result<Option<PreparedHostRun>, SchedulerError> {
        if dispatch_contract == crate::BackendDispatchContract::PhysicalSource {
            return self.prepare_host_catchup_run(index, catchup_at);
        }
        self.prepare_host_catchup_run_with_authorization(index, catchup_at, None, dispatch_contract)
    }

    /// Replans a completed catch-up without revoking its unchanged pending command.
    pub(super) fn prepare_host_catchup_run_after(
        &mut self,
        previous: &PreparedHostRun,
        catchup_at: SimInstant,
    ) -> Result<Option<PreparedHostRun>, SchedulerError> {
        self.prepare_host_catchup_run_with_authorization(
            previous.plan.index,
            catchup_at,
            Some(previous),
            previous.dispatch_contract,
        )
    }

    fn prepare_host_catchup_run_with_authorization(
        &mut self,
        index: usize,
        catchup_at: SimInstant,
        previous: Option<&PreparedHostRun>,
        dispatch_contract: crate::BackendDispatchContract,
    ) -> Result<Option<PreparedHostRun>, SchedulerError> {
        let node = self
            .nodes
            .get(index)
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from("causal catch-up lost its scheduler node"),
            })?;
        let candidate = self.advance_candidate(
            index,
            node,
            self.shared_rendezvous_cap()?,
            self.pending_topology_activation_cap()?,
        )?;
        let Some(candidate) = candidate else {
            if matches!(
                self.effective_node_activity(node),
                SchedulerNodeActivity::Idle
                    | SchedulerNodeActivity::Halted
                    | SchedulerNodeActivity::Done
            ) {
                return Ok(None);
            }
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "runnable producer `{}` cannot reach causal watermark {}",
                    node.id.node.name, catchup_at.ticks
                ),
            });
        };
        let candidate = self.prepare_host_candidate_for_contract(candidate, dispatch_contract)?;
        let draft = self.advance_plan_draft(&candidate)?;
        if let Some(previous) = previous
            && (previous.plan.node != draft.node
                || previous.plan.target_counter != draft.before.ticks)
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("completed catch-up authorization changed node or counter"),
            });
        }
        let authorized_horizon =
            self.retained_preemption_horizon(&draft.node, draft.target_counter, previous);
        let target_time = min_instant(candidate.target_time, catchup_at);
        let target_counter = if target_time == candidate.target_time {
            draft.target_counter
        } else {
            self.node_counter_for_time_floor(node, target_time)?.ticks
        };
        if target_counter <= draft.before.ticks {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "producer `{}` cannot represent causal catch-up at {}",
                    node.id.node.name, target_time.ticks
                ),
            });
        }
        let projected_target_time = self.node_time_for_counter(
            node,
            NodeCounter {
                ticks: target_counter,
            },
        )?;
        let subdivision =
            self.planned_run_subdivision(&draft.node, draft.before, target_counter)?;
        let ceiling = self.publish_run_ceiling(
            draft.node.clone(),
            draft.before,
            target_counter,
            target_time,
        )?;
        let plan = AdvancePlan {
            index,
            node: draft.node,
            before: draft.before,
            target_counter,
            projected_target_time,
            ceiling,
            subdivision,
            quiescent_horizon: if target_time == candidate.target_time {
                draft.quiescent_horizon
            } else {
                None
            },
        };
        let mut run = self.prepare_host_preemptible_run(
            plan,
            authorized_horizon,
            previous.map(|previous| &previous.admission),
        )?;
        run.dispatch_contract = dispatch_contract;
        Ok(Some(run))
    }

    /// Republishes the remaining part of an authorized RUN after an output yield.
    pub(super) fn prepare_host_run_continuation(
        &mut self,
        original: &PreparedHostRun,
        before: NodeCounter,
    ) -> Result<PreparedHostRun, SchedulerError> {
        let plan = &original.plan;
        let Some(node) = self.nodes.get(plan.index) else {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("output-yield continuation lost its scheduler node"),
            });
        };
        if node.id != plan.node || node.counter != before || before <= plan.before {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "output-yield continuation for `{}` changed node identity or physical counter",
                    plan.node.node.name,
                ),
            });
        }
        if before.ticks >= plan.target_counter {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "output-yield continuation for `{}` has no remaining authorized RUN",
                    plan.node.node.name,
                ),
            });
        }

        let candidate = self
            .advance_candidate(
                plan.index,
                node,
                self.shared_rendezvous_cap()?,
                self.pending_topology_activation_cap()?,
            )?
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from("residual host RUN has no fresh horizon authorization"),
            })?;
        let candidate =
            self.prepare_host_candidate_for_contract(candidate, original.dispatch_contract)?;
        let fresh = self.advance_plan_draft(&candidate)?;
        let target_counter = plan.target_counter.min(fresh.target_counter);
        if target_counter <= before.ticks {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "residual host RUN must settle its new exact boundary before execution",
                ),
            });
        }
        let target_time = self.node_time_for_counter(
            node,
            NodeCounter {
                ticks: target_counter,
            },
        )?;
        let subdivision = self.planned_run_subdivision(&plan.node, before, target_counter)?;
        let ceiling =
            self.publish_run_ceiling(plan.node.clone(), before, target_counter, target_time)?;
        let plan = AdvancePlan {
            index: plan.index,
            node: plan.node.clone(),
            before,
            target_counter,
            projected_target_time: target_time,
            ceiling,
            subdivision,
            quiescent_horizon: if target_counter == fresh.target_counter {
                fresh.quiescent_horizon
            } else {
                plan.quiescent_horizon
            },
        };
        let authorized_horizon =
            self.retained_preemption_horizon(&plan.node, fresh.target_counter, Some(original));
        let mut run =
            self.prepare_host_preemptible_run(plan, authorized_horizon, Some(&original.admission))?;
        run.dispatch_contract = original.dispatch_contract;
        Ok(run)
    }

    fn retained_preemption_horizon(
        &self,
        node: &SchedulerNodeId,
        fresh_horizon: u64,
        previous: Option<&PreparedHostRun>,
    ) -> u64 {
        let Some(previous) = previous else {
            return fresh_horizon;
        };
        let Some(request) = &previous.authorized_preemption_request else {
            return fresh_horizon;
        };
        if previous.plan.node == *node
            && self.preemption_requests.contains(request)
            && !self
                .preemption_applications
                .iter()
                .any(|application| application.decision == *request)
        {
            previous.authorized_preemption_horizon
        } else {
            fresh_horizon
        }
    }

    /// Fixes host RUN ceilings without committing their RESOLVE, EMIT, or STEP phases.
    pub(super) fn prepare_host_concurrent_quantum_limited(
        &self,
        request: QuantumRequest,
        maximum_runs: usize,
    ) -> Result<PreparedHostConcurrentQuantum, SchedulerError> {
        self.prepare_host_concurrent_quantum_for_contract(
            request,
            maximum_runs,
            crate::BackendDispatchContract::PhysicalSource,
        )
    }

    pub(super) fn prepare_host_concurrent_quantum_for_contract(
        &self,
        request: QuantumRequest,
        maximum_runs: usize,
        dispatch_contract: crate::BackendDispatchContract,
    ) -> Result<PreparedHostConcurrentQuantum, SchedulerError> {
        if request.configuration != self.configuration {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "quantum request configuration is not the scheduler frontier",
                ),
            });
        }

        let mut next = self.clone();
        next.last_advance = None;
        next.last_topology_recompute = false;
        next.refresh_device_horizons()?;
        next.admit_control_at_boundary(request.control);
        let SchedulerControlDrain {
            events: boundary_events,
            applications: control_applications,
        } = next.drain_control_events()?;
        let topology_recomputed = next.apply_topology_changes_at_boundary()?;
        next.last_topology_recompute = topology_recomputed;

        let mut candidates = next
            .advance_candidates()?
            .into_iter()
            .map(|candidate| next.prepare_host_candidate_for_contract(candidate, dispatch_contract))
            .collect::<Result<Vec<_>, _>>()?;
        candidates.sort_by(|left, right| {
            left.target_time
                .cmp(&right.target_time)
                .then_with(|| left.key.node.cmp(&right.key.node))
                .then_with(|| left.key.virtual_time.cmp(&right.key.virtual_time))
                .then_with(|| left.index.cmp(&right.index))
        });
        let mut run_set = next.concurrent_run_set_from_candidates(&candidates)?;
        run_set.candidates.truncate(maximum_runs.max(1));
        let selected_candidates = candidates
            .into_iter()
            .filter(|candidate| {
                run_set
                    .candidates
                    .iter()
                    .any(|run| run.node == next.nodes[candidate.index].id)
            })
            .collect::<Vec<_>>();
        let mut runs = Vec::with_capacity(run_set.candidates.len());
        for candidate in selected_candidates {
            let plan = {
                let critical_section = SchedulerCriticalSection::enter(&mut next);
                critical_section.advance_plan(candidate)?
            };
            let node = &next.nodes[plan.index];
            let window = next.advance_window(
                node,
                next.node_time_for_counter(node, plan.before)?,
                next.shared_rendezvous_cap()?,
                next.pending_topology_activation_cap()?,
            )?;
            let mut authorized_horizon = match window.semantic_icount_rounding {
                SchedulerIcountRounding::ConservativeFloor => {
                    next.node_counter_for_time_floor(node, window.semantic_target_time)?
                }
                SchedulerIcountRounding::ExactCeil => {
                    next.node_counter_for_time_ceil(node, window.semantic_target_time)?
                }
            }
            .ticks;
            // Complete retained device/link enumeration also constrains the
            // semantic owner, including replies not yet materialized as events.
            if let Some(input) = next.prepared_run_next_input(node)? {
                authorized_horizon = authorized_horizon.min(input.ticks);
            }
            let mut run = next.prepare_host_preemptible_run(plan, authorized_horizon, None)?;
            run.dispatch_contract = dispatch_contract;
            runs.push(run);
        }
        for candidate in &mut run_set.candidates {
            if let Some(run) = runs.iter().find(|run| run.plan.node == candidate.node) {
                candidate.max_advance_icount = run.plan.target_counter;
                candidate.target_time = run.plan.projected_target_time;
            }
        }

        Ok(PreparedHostConcurrentQuantum {
            next,
            run_set,
            runs,
            boundary_events,
            control_applications,
            topology_recomputed,
        })
    }

    fn prepare_host_candidate_for_contract(
        &self,
        mut candidate: AdvanceCandidate,
        dispatch_contract: crate::BackendDispatchContract,
    ) -> Result<AdvanceCandidate, SchedulerError> {
        if dispatch_contract != crate::BackendDispatchContract::ControlV3 {
            return Ok(candidate);
        }
        let consumer = &self.nodes[candidate.index];
        for edge in self.effective_topology.edges() {
            if edge.to != consumer.id {
                continue;
            }
            let producer = self
                .nodes
                .iter()
                .find(|node| node.id == edge.from)
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: String::from("control 3 incoming edge lost its actual producer"),
                })?;
            let earliest_delivery = self
                .node_current_time(producer)?
                .ticks
                .checked_add(edge.minimum_latency.ticks)
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: String::from("control 3 earliest delivery overflowed shared ticks"),
                })?;
            // Control 3 completes physical ceilings; it cannot retain a native
            // Source dispatch stop at an inclusive possible-delivery boundary.
            let strict_tick = earliest_delivery.checked_sub(1).ok_or_else(|| {
                SchedulerError::BoundaryViolation {
                    message: String::from("control 3 has no strictly safe delivery tick"),
                }
            })?;
            if strict_tick <= candidate.target_time.ticks {
                candidate.target_time = SimInstant { ticks: strict_tick };
                candidate.icount_rounding = SchedulerIcountRounding::ConservativeFloor;
            }
        }
        if !self.candidate_has_representable_advance(&candidate)? {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "control 3 has no strictly safe representable RUN for `{}`",
                    consumer.id.node.name,
                ),
            });
        }
        Ok(candidate)
    }

    pub(super) fn concurrent_run_set_from_candidates(
        &self,
        candidates: &[AdvanceCandidate],
    ) -> Result<SchedulerConcurrentRunSet, SchedulerError> {
        let mut selected = Vec::new();
        let frontier = SimInstant {
            ticks: self.frontier.ticks,
        };
        let target_time = candidates.first().map(|candidate| candidate.target_time);

        // A parked peer can hold the global frontier behind the canonical
        // global-minimum candidate. Batching frontier peers in that state would
        // reorder PICK relative to the authoritative serial path. Advance only
        // that canonical first candidate; normal independent batches resume
        // once the common frontier is restored.
        if let Some(candidate) = candidates.first() {
            let draft = self.advance_plan_draft(candidate)?;
            let current_time =
                self.node_time_for_counter(&self.nodes[draft.index], draft.before)?;
            if current_time != frontier {
                selected.push(SchedulerConcurrentRunCandidate {
                    node: draft.node,
                    current_time,
                    target_time: candidate.target_time,
                    max_advance_icount: draft.target_counter,
                });
                return Ok(SchedulerConcurrentRunSet {
                    candidates: selected,
                });
            }
        }

        for candidate in candidates {
            if Some(candidate.target_time) != target_time {
                break;
            }
            let draft = self.advance_plan_draft(candidate)?;
            let current_time =
                self.node_time_for_counter(&self.nodes[draft.index], draft.before)?;
            if current_time != frontier {
                continue;
            }
            selected.push(SchedulerConcurrentRunCandidate {
                node: draft.node,
                current_time,
                target_time: candidate.target_time,
                max_advance_icount: draft.target_counter,
            });
        }

        Ok(SchedulerConcurrentRunSet {
            candidates: selected,
        })
    }

    /// Returns the deterministic RUN set eligible for host-level concurrency.
    ///
    /// The set contains every same-boundary RUN admitted by the scheduler's
    /// conservative horizon computation. Host worker limits are deliberately
    /// absent from this semantic projection. RESOLVE and EMIT are not performed
    /// by this read-only query.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] if horizon projection discovers inconsistent
    /// scheduler state.
    pub fn concurrent_run_set(&self) -> Result<SchedulerConcurrentRunSet, SchedulerError> {
        let candidates = self.advance_candidates()?;
        self.concurrent_run_set_from_candidates(&candidates)
    }
}
