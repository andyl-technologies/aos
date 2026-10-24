//! Causal host RUN publication and held selectable continuations.

use super::cap_boundary::resolve_cap_boundary;
use super::dispatch_boundary::resolve_dispatch_boundary;
use super::held_boundary::{HeldBoundaryRun, backend_run, hold_run_result};
use super::held_stop::{CommittedHostStop, HeldHostStopKind};
use super::host_run_validation::validate_held_network_lookahead;
pub(super) use super::host_run_validation::validate_host_run_outcome;
use super::input_boundary::resolve_input_boundary;
use super::*;

#[derive(Clone, Debug)]
pub(super) struct HeldHostRun {
    pub(super) generation: u64,
    pub(super) run: PreparedHostRun,
    pub(super) completed: ConcurrentBackendRunOutcome,
}

#[derive(Clone, Debug)]
pub(super) struct HeldHostContinuation {
    pub(super) runs: BTreeMap<NodeId, HeldHostRun>,
    pub(super) boundary_runs: BTreeMap<NodeId, HeldBoundaryRun>,
    pub(super) original_runs: BTreeMap<NodeId, PreparedHostRun>,
    pub(super) generations: BTreeMap<NodeId, u64>,
    pub(super) topology: SchedulerLookaheadGraph,
    pub(super) boundary_events: Vec<ScheduledEvent>,
    pub(super) control_applications: Vec<SchedulerControlApplication>,
    pub(super) offer_configuration: Configuration,
    pub(super) offer_log_offset: EventLogOffset,
    pub(super) source_stop: Option<CommittedHostStop>,
    pub(super) lineage: HeldRunLineage,
}

fn execute_one_host_run<B: ConcurrentSimulationBackend>(
    backend: &mut B,
    run: &PreparedHostRun,
) -> Result<ConcurrentBackendRunResult, SchedulerError> {
    if backend.dispatch_contract() != run.dispatch_contract {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from("backend dispatch contract changed before physical RUN"),
        });
    }
    let mut results = backend.execute_concurrent_runs(vec![backend_run(run)], 1)?;
    if results.len() != 1 {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from("host worker continuation changed cardinality"),
        });
    }
    Ok(results.remove(0))
}

fn refresh_held_host_run_boundary(
    scheduler: &mut SingleScheduler,
    topology: &SchedulerLookaheadGraph,
) -> Result<(), SchedulerError> {
    scheduler.refresh_device_horizons()?;
    scheduler.apply_topology_changes_at_boundary()?;
    if &scheduler.effective_topology != topology {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from(
                "effective topology changed before resuming held physical RUN evidence",
            ),
        });
    }
    Ok(())
}

impl<L, B, I> BackendQuantumLoop<L, B, I>
where
    L: QuantumLoop,
    B: SimulationBackend,
    I: BackendNetworkOutputInterceptor<L, B>,
{
    /// Executes one scheduler-prepared RUN set on bounded host workers.
    ///
    /// Scheduler changes remain speculative while workers reach their ceiling
    /// or the first exact output boundary. Completed RUNs are published only
    /// after every producer can no longer emit an earlier output.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when planning, host dispatch, backend
    /// validation, or canonical boundary publication fails.
    fn drive_host_concurrent_quantum(
        &mut self,
        request: QuantumRequest,
        max_host_workers: usize,
    ) -> Result<SchedulerConcurrentQuantumOutcome, SchedulerError>
    where
        L: std::borrow::Borrow<SingleScheduler> + std::borrow::BorrowMut<SingleScheduler>,
        B: ConcurrentSimulationBackend,
        I: BackendNetworkOutputInterceptor<SingleScheduler, B> + Clone,
    {
        if self.continuation_poisoned {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("backend continuation is poisoned"),
            });
        }
        if self.device_group_selection.is_retained() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("original Device Group selection must settle before RUN"),
            });
        }
        if self.preselection.is_some() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "live-network preselection must be settled or handed off before another RUN",
                ),
            });
        }
        if self.held_host_continuation.is_some() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "held physical RUNs must settle before another scheduler PICK",
                ),
            });
        }
        if max_host_workers == 0 {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("concurrent backend max_host_workers must be positive"),
            });
        }
        if self.held_union_generation == u64::MAX {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("held union generation exhausted before RUN dispatch"),
            });
        }
        let maximum_runs =
            if self.pause_before_live_network_choice && !self.parallel_choice_free_boot {
                1
            } else {
                usize::MAX
            };
        let maximum_consumers = self
            .loop_impl
            .borrow()
            .nodes
            .iter()
            .filter(|node| node.id.kind == SchedulingNodeKind::Vm)
            .count();
        let mut published_consumers = BTreeSet::new();
        while let Some(result) = self.settle_current_fixed_input_excluding(&published_consumers)? {
            if result.state != crate::BackendFixedInputState::Published {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from("fixed input consumer remains retained before PICK"),
                });
            }
            if !published_consumers.insert(result.prepared.node().clone())
                || published_consumers.len() > maximum_consumers
            {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from(
                        "fixed input consumer exceeded the configured canonical batch",
                    ),
                });
            }
        }
        let dispatch_contract = self.selected_dispatch_contract()?;
        let mut prepared = self
            .loop_impl
            .borrow()
            .prepare_host_concurrent_quantum_for_contract(
                request.clone(),
                maximum_runs,
                dispatch_contract,
            )?;
        for run in &mut prepared.runs {
            run.dispatch_contract = dispatch_contract;
        }
        if prepared.runs.is_empty() {
            let mut next = SingleScheduler::clone(self.loop_impl.borrow());
            let outcome =
                next.drive_concurrent_authoritative_quantum_limited(request, maximum_runs)?;
            return self.complete_host_control_only(next, outcome);
        }
        let mut runs = Vec::with_capacity(prepared.runs.len());
        for planned in &prepared.runs {
            runs.push(ConcurrentBackendRun {
                admission: planned.admission.clone(),
                preemptions: planned
                    .preemptions
                    .iter()
                    .map(|application| application.decision.clone())
                    .collect(),
            });
        }
        self.selected_dispatch_contract()?;
        let completed = match self.backend.execute_concurrent_runs(runs, max_host_workers) {
            Ok(completed) => completed,
            Err(error) => return Err(self.poison_continuation(error.into())),
        };
        self.complete_prepared_host_run_set(prepared, completed)
    }

    pub(in crate::scheduler) fn complete_prepared_host_run_set(
        &mut self,
        prepared: PreparedHostConcurrentQuantum,
        completed: Vec<ConcurrentBackendRunResult>,
    ) -> Result<SchedulerConcurrentQuantumOutcome, SchedulerError>
    where
        L: std::borrow::BorrowMut<SingleScheduler>,
        B: ConcurrentSimulationBackend,
        I: BackendNetworkOutputInterceptor<SingleScheduler, B> + Clone,
    {
        let run_set = prepared.run_set.clone();
        if completed.len() != prepared.run_set.candidates.len() {
            let error = SchedulerError::BoundaryViolation {
                message: String::from("host worker outcome cardinality changed"),
            };
            return Err(self.poison_continuation(error));
        }
        let PreparedHostConcurrentQuantum {
            next: staged_scheduler,
            run_set: _,
            runs: prepared_runs,
            boundary_events,
            control_applications,
            topology_recomputed: _,
        } = prepared;
        let mut original_runs = BTreeMap::new();
        let mut held_runs = BTreeMap::new();
        let mut boundary_runs = BTreeMap::new();
        for (run, result) in prepared_runs.into_iter().zip(completed) {
            original_runs.insert(run.plan.node.node.clone(), run.clone());
            hold_run_result(run, result, 0, &mut held_runs, &mut boundary_runs)
                .map_err(|error| self.poison_continuation(error))?;
        }
        let initial_topology = staged_scheduler.effective_topology.clone();
        let generations = original_runs
            .keys()
            .cloned()
            .map(|node| (node, 0_u64))
            .collect::<BTreeMap<_, _>>();
        for held in held_runs.values() {
            if held.completed.network_outputs.is_empty() {
                continue;
            }
            let output_time = staged_scheduler
                .backend_network_output_time(
                    &held.completed.node,
                    Icount {
                        retired: held.completed.step.reached.ticks,
                    },
                )
                .map_err(|error| self.poison_continuation(error))?;
            validate_held_network_lookahead(
                &staged_scheduler,
                &held.run.plan.node,
                output_time,
                &held_runs,
                &boundary_runs,
            )
            .map_err(|error| self.poison_continuation(error))?;
        }

        self.held_union_generation =
            self.held_union_generation.checked_add(1).ok_or_else(|| {
                self.poison_continuation(SchedulerError::BoundaryViolation {
                    message: String::from("held union generation exhausted"),
                })
            })?;
        let lineage = HeldRunLineage::begin(
            self.held_stop_controller.clone(),
            self.held_union_generation,
            &staged_scheduler,
        );
        for held in held_runs.values_mut() {
            held.run.canonical_lineage = Some(lineage.clone());
        }
        for held in boundary_runs.values_mut() {
            held.run.canonical_lineage = Some(lineage.clone());
        }
        for run in original_runs.values_mut() {
            run.canonical_lineage = Some(lineage.clone());
        }
        let continuation = HeldHostContinuation {
            runs: held_runs,
            boundary_runs,
            original_runs,
            generations,
            topology: initial_topology,
            boundary_events,
            control_applications,
            offer_configuration: staged_scheduler.configuration().clone(),
            offer_log_offset: staged_scheduler.event_log_offset(),
            source_stop: None,
            lineage,
        };
        let published = self.publish_held_host_continuation(staged_scheduler, continuation)?;
        Ok(SchedulerConcurrentQuantumOutcome {
            run_set,
            outcomes: published,
        })
    }

    pub(super) fn publish_held_host_continuation(
        &mut self,
        mut staged_scheduler: SingleScheduler,
        continuation: HeldHostContinuation,
    ) -> Result<Vec<QuantumOutcome>, SchedulerError>
    where
        L: std::borrow::BorrowMut<SingleScheduler>,
        B: ConcurrentSimulationBackend,
        I: BackendNetworkOutputInterceptor<SingleScheduler, B> + Clone,
    {
        self.selected_dispatch_contract()
            .map_err(|error| self.poison_continuation(error))?;
        let HeldHostContinuation {
            runs: mut held_runs,
            mut boundary_runs,
            mut original_runs,
            mut generations,
            topology: initial_topology,
            mut boundary_events,
            mut control_applications,
            mut source_stop,
            mut lineage,
            ..
        } = continuation;
        if source_stop.is_some() {
            return Err(self.poison_continuation(SchedulerError::BoundaryViolation {
                message: String::from(
                    "guest stop requires explicit reply or marker release before peer publication",
                ),
            }));
        }
        let held_limit = staged_scheduler.nodes.len();
        let mut staged_interceptor = self.network_output_interceptor.clone();
        let mut staged_pending_network_outputs = self.pending_network_outputs.clone();
        let mut staged_frozen_network_output_times = self.frozen_network_output_times.clone();
        let mut staged_pending_observations = self.pending_observations.clone();
        let mut staged_preselection = None;
        let mut staged_frontier = self.committed_frontier;
        let mut published = Vec::with_capacity(held_limit);
        while !held_runs.is_empty() || !boundary_runs.is_empty() {
            if staged_scheduler.effective_topology != initial_topology {
                return Err(self.poison_continuation(SchedulerError::BoundaryViolation {
                    message: String::from(
                        "effective topology changed while physical RUN evidence was held",
                    ),
                }));
            }
            // Physical completion order and registration order are not PICK
            // order. Release equal-time evidence by canonical node identity.
            let next = held_runs
                .iter()
                .map(|(node, held)| {
                    staged_scheduler
                        .backend_network_output_time(
                            node,
                            Icount {
                                retired: held.completed.step.reached.ticks,
                            },
                        )
                        .map(|at| (at, node.clone()))
                })
                .chain(boundary_runs.iter().map(|(node, held)| {
                    staged_scheduler
                        .backend_network_output_time(
                            node,
                            Icount {
                                retired: held.boundary.stopped().ticks,
                            },
                        )
                        .map(|at| (at, node.clone()))
                }))
                .collect::<Result<Vec<_>, SchedulerError>>()
                .map_err(|error| self.poison_continuation(error))?
                .into_iter()
                .min();
            let Some((next_time, next_node)) = next else {
                break;
            };

            let mut omitted_run = None;
            let mut omitted_nodes = staged_scheduler
                .nodes
                .iter()
                .enumerate()
                .map(|(index, runtime)| (runtime.id.node.clone(), index))
                .collect::<Vec<_>>();
            omitted_nodes.sort_by(|left, right| left.0.cmp(&right.0));
            for (node, index) in omitted_nodes {
                if original_runs.contains_key(&node) {
                    continue;
                }
                let current = staged_scheduler
                    .node_current_time(&staged_scheduler.nodes[index])
                    .map_err(|error| self.poison_continuation(error))?;
                if current.ticks >= next_time.ticks {
                    continue;
                }
                refresh_held_host_run_boundary(&mut staged_scheduler, &initial_topology)
                    .map_err(|error| self.poison_continuation(error))?;
                let run = staged_scheduler
                    .prepare_host_catchup_run_for_contract(
                        index,
                        SimInstant {
                            ticks: next_time.ticks,
                        },
                        self.selected_dispatch_contract()
                            .map_err(|error| self.poison_continuation(error))?,
                    )
                    .map_err(|error| self.poison_continuation(error))?;
                if let Some(run) = run {
                    omitted_run = Some((node, current, run));
                    break;
                }
            }
            if let Some((node, current, mut run)) = omitted_run {
                run.dispatch_contract = self
                    .selected_dispatch_contract()
                    .map_err(|error| self.poison_continuation(error))?;
                run.canonical_lineage = Some(lineage.clone());
                validate_held_network_lookahead(
                    &staged_scheduler,
                    &run.plan.node,
                    VirtualTime {
                        ticks: current.ticks,
                    },
                    &held_runs,
                    &boundary_runs,
                )
                .map_err(|error| self.poison_continuation(error))?;
                let completed = execute_one_host_run(&mut self.backend, &run)
                    .map_err(|error| self.poison_continuation(error))?;
                if held_runs.len() + boundary_runs.len() >= held_limit {
                    return Err(self.poison_continuation(SchedulerError::BoundaryViolation {
                        message: String::from(
                            "held host RUN evidence exceeded scheduler node count",
                        ),
                    }));
                }
                original_runs.insert(node.clone(), run.clone());
                generations.insert(node.clone(), 0);
                hold_run_result(run, completed, 0, &mut held_runs, &mut boundary_runs)
                    .map_err(|error| self.poison_continuation(error))?;
                if let Some(held) = held_runs.get(&node)
                    && !held.completed.network_outputs.is_empty()
                {
                    let at = staged_scheduler
                        .backend_network_output_time(
                            &node,
                            Icount {
                                retired: held.completed.step.reached.ticks,
                            },
                        )
                        .map_err(|error| self.poison_continuation(error))?;
                    validate_held_network_lookahead(
                        &staged_scheduler,
                        &held.run.plan.node,
                        at,
                        &held_runs,
                        &boundary_runs,
                    )
                    .map_err(|error| self.poison_continuation(error))?;
                }
                continue;
            }

            let mut lagging = None;
            for (node, original) in &original_runs {
                if held_runs.contains_key(node) || boundary_runs.contains_key(node) {
                    continue;
                }
                let runtime = &staged_scheduler.nodes[original.plan.index];
                let current = staged_scheduler
                    .node_current_time(runtime)
                    .map_err(|error| self.poison_continuation(error))?;
                let before = runtime.counter;
                if current.ticks < next_time.ticks {
                    refresh_held_host_run_boundary(&mut staged_scheduler, &initial_topology)
                        .map_err(|error| self.poison_continuation(error))?;
                    let run = if before.ticks < original.plan.target_counter {
                        Some(
                            staged_scheduler
                                .prepare_host_run_continuation(original, before)
                                .map_err(|error| self.poison_continuation(error))?,
                        )
                    } else {
                        staged_scheduler
                            .prepare_host_catchup_run_after(
                                original,
                                SimInstant {
                                    ticks: next_time.ticks,
                                },
                            )
                            .map_err(|error| self.poison_continuation(error))?
                    };
                    if let Some(run) = run {
                        lagging = Some((node.clone(), run, current));
                        break;
                    }
                }
            }
            if let Some((node, mut run, current)) = lagging {
                run.dispatch_contract = self
                    .selected_dispatch_contract()
                    .map_err(|error| self.poison_continuation(error))?;
                run.canonical_lineage = Some(lineage.clone());
                validate_held_network_lookahead(
                    &staged_scheduler,
                    &run.plan.node,
                    VirtualTime {
                        ticks: current.ticks,
                    },
                    &held_runs,
                    &boundary_runs,
                )
                .map_err(|error| self.poison_continuation(error))?;
                let generation = generations
                    .get(&node)
                    .copied()
                    .and_then(|value| value.checked_add(1))
                    .ok_or_else(|| {
                        self.poison_continuation(SchedulerError::BoundaryViolation {
                            message: String::from("held RUN generation is absent or exhausted"),
                        })
                    })?;
                let completed = execute_one_host_run(&mut self.backend, &run)
                    .map_err(|error| self.poison_continuation(error))?;
                if held_runs.len() + boundary_runs.len() >= held_limit {
                    return Err(self.poison_continuation(SchedulerError::BoundaryViolation {
                        message: String::from(
                            "held host RUN evidence exceeded selected node count",
                        ),
                    }));
                }
                generations.insert(node.clone(), generation);
                original_runs.insert(node.clone(), run.clone());
                hold_run_result(
                    run,
                    completed,
                    generation,
                    &mut held_runs,
                    &mut boundary_runs,
                )
                .map_err(|error| self.poison_continuation(error))?;
                if let Some(held) = held_runs.get(&node)
                    && !held.completed.network_outputs.is_empty()
                {
                    let at = staged_scheduler
                        .backend_network_output_time(
                            &held.completed.node,
                            Icount {
                                retired: held.completed.step.reached.ticks,
                            },
                        )
                        .map_err(|error| self.poison_continuation(error))?;
                    validate_held_network_lookahead(
                        &staged_scheduler,
                        &held.run.plan.node,
                        at,
                        &held_runs,
                        &boundary_runs,
                    )
                    .map_err(|error| self.poison_continuation(error))?;
                }
                continue;
            }

            if let Some(mut held_boundary) = boundary_runs.remove(&next_node) {
                lineage
                    .ensure_extension_room()
                    .map_err(|error| self.poison_continuation(error))?;
                let held_delivery = HeldDeliveryCeiling::observe(&staged_scheduler, &held_runs);
                lineage
                    .authenticate(
                        &self.held_stop_controller,
                        self.held_union_generation,
                        &held_boundary.run,
                        &staged_scheduler,
                    )
                    .map_err(|error| self.poison_continuation(error))?;
                if generations.get(&next_node) != Some(&held_boundary.generation)
                    || staged_scheduler.nodes[held_boundary.run.plan.index].id
                        != held_boundary.run.plan.node
                    || staged_scheduler.nodes[held_boundary.run.plan.index].counter
                        != held_boundary.run.plan.before
                {
                    return Err(self.poison_continuation(SchedulerError::BoundaryViolation {
                        message: String::from(
                            "held unresolved RUN changed actual scheduler ownership",
                        ),
                    }));
                }
                let before_settlement = staged_scheduler.clone();
                let result = match held_boundary.boundary {
                    super::held_boundary::HeldRunBoundary::Input(boundary) => {
                        resolve_input_boundary(
                            &mut staged_scheduler,
                            &mut self.backend,
                            &mut held_boundary.run,
                            boundary,
                            &mut self.failed_input_resolution,
                            &held_delivery,
                        )
                    }
                    super::held_boundary::HeldRunBoundary::Cap(boundary) => resolve_cap_boundary(
                        &mut staged_scheduler,
                        &mut self.backend,
                        &mut held_boundary.run,
                        boundary,
                        &mut self.failed_cap_negotiation,
                    ),
                    super::held_boundary::HeldRunBoundary::Dispatch(boundary) => {
                        resolve_dispatch_boundary(
                            &mut staged_scheduler,
                            &mut self.backend,
                            &mut held_boundary.run,
                            boundary,
                            &held_delivery,
                            &mut self.failed_dispatch_resolution,
                        )
                    }
                }
                .map_err(|error| self.poison_continuation(error))?;
                if matches!(result, ConcurrentBackendRunResult::Completed(_)) {
                    let owner = &held_boundary.run.admission;
                    if self
                        .failed_input_resolution
                        .as_ref()
                        .is_some_and(|history| {
                            owner.shares_semantic_owner(&history.boundary().admission)
                        })
                    {
                        self.failed_input_resolution = None;
                    }
                    if self
                        .failed_dispatch_resolution
                        .as_ref()
                        .is_some_and(|history| {
                            owner.shares_semantic_owner(&history.boundary().admission)
                        })
                    {
                        self.failed_dispatch_resolution = None;
                    }
                    if self.failed_cap_negotiation.as_ref().is_some_and(|history| {
                        owner.shares_semantic_owner(&history.boundary().admission)
                    }) {
                        self.failed_cap_negotiation = None;
                    }
                }
                lineage
                    .extend_commit(&before_settlement, &staged_scheduler, &next_node)
                    .map_err(|error| self.poison_continuation(error))?;
                held_boundary.run.canonical_lineage = Some(lineage.clone());
                for held in held_runs.values_mut() {
                    held.run.canonical_lineage = Some(lineage.clone());
                }
                for held in boundary_runs.values_mut() {
                    held.run.canonical_lineage = Some(lineage.clone());
                }
                for run in original_runs.values_mut() {
                    run.canonical_lineage = Some(lineage.clone());
                }
                original_runs.insert(next_node.clone(), held_boundary.run.clone());
                hold_run_result(
                    held_boundary.run,
                    result,
                    held_boundary.generation,
                    &mut held_runs,
                    &mut boundary_runs,
                )
                .map_err(|error| self.poison_continuation(error))?;
                continue;
            }

            let Some(held) = held_runs.remove(&next_node) else {
                return Err(self.poison_continuation(SchedulerError::BoundaryViolation {
                    message: String::from("canonical held RUN vanished"),
                }));
            };
            let HeldHostRun {
                generation,
                run,
                completed,
            } = held;
            let node = run.plan.node.node.clone();
            if generations.get(&node) != Some(&generation)
                || staged_scheduler.nodes[run.plan.index].id != run.plan.node
                || staged_scheduler.nodes[run.plan.index].counter != run.plan.before
            {
                return Err(self.poison_continuation(SchedulerError::BoundaryViolation {
                    message: format!(
                        "held physical RUN for `{}` changed generation or scheduler node",
                        node.name
                    ),
                }));
            }
            let reached = completed.step.reached.ticks;
            let stop_kind = HeldHostStopKind::from_physical_stop(completed.step.physical_stop);
            let stop_node = run.plan.node.clone();
            let stop_index = run.plan.index;
            let release_at = staged_scheduler
                .backend_network_output_time(&node, Icount { retired: reached })
                .map_err(|error| self.poison_continuation(error))?;
            let staged_inputs = run
                .staged_input_events
                .iter()
                .map(|event| event.key.clone())
                .collect();
            let before_commit = staged_scheduler.clone();
            let retain_extension =
                !boundary_runs.is_empty() || lineage.context_is_current(&before_commit);
            if retain_extension {
                lineage
                    .ensure_extension_room()
                    .map_err(|error| self.poison_continuation(error))?;
            }
            let outcome = staged_scheduler
                .commit_prepared_host_run(
                    run,
                    reached,
                    &completed.step.applied_preemptions,
                    if published.is_empty() {
                        std::mem::take(&mut boundary_events)
                    } else {
                        Vec::new()
                    },
                    if published.is_empty() {
                        std::mem::take(&mut control_applications)
                    } else {
                        Vec::new()
                    },
                )
                .map_err(|error| self.poison_continuation(error))?;
            staged_frontier = outcome.frontier;
            let boundary = BackendBoundaryEvidence {
                staged_inputs,
                rng_evidence: completed.rng_evidence,
                network_outputs: completed.network_outputs,
                observations: completed.observations,
            };
            let release_at = release_at.max(outcome.frontier);
            let completed = complete_backend_outcome_on(
                BackendOutcomeAdmission {
                    loop_impl: &mut staged_scheduler,
                    backend: &mut self.backend,
                    network_output_interceptor: &mut staged_interceptor,
                    pending_network_outputs: &mut staged_pending_network_outputs,
                    frozen_network_output_times: &mut staged_frozen_network_output_times,
                    pending_observations: &mut staged_pending_observations,
                    preselection: &mut staged_preselection,
                    pause_before_live_network_choice: self.pause_before_live_network_choice,
                    network_release_at: release_at,
                },
                outcome,
                boundary,
            );
            match completed {
                Ok(outcome) => {
                    if retain_extension {
                        lineage
                            .extend_commit(&before_commit, &staged_scheduler, &node)
                            .map_err(|error| self.poison_continuation(error))?;
                    }
                    for held in held_runs.values_mut() {
                        held.run.canonical_lineage = Some(lineage.clone());
                    }
                    for held in boundary_runs.values_mut() {
                        held.run.canonical_lineage = Some(lineage.clone());
                    }
                    for run in original_runs.values_mut() {
                        run.canonical_lineage = Some(lineage.clone());
                    }
                    if let Some(kind) = stop_kind {
                        self.held_stop_generation =
                            self.held_stop_generation.checked_add(1).ok_or_else(|| {
                                self.poison_continuation(SchedulerError::BoundaryViolation {
                                    message: String::from(
                                        "held guest stop controller generation overflowed",
                                    ),
                                })
                            })?;
                        source_stop = Some(CommittedHostStop {
                            node: stop_node,
                            node_index: stop_index,
                            run_generation: generation,
                            controller_generation: self.held_stop_generation,
                            physical_pause: VirtualTime { ticks: reached },
                            kind,
                        });
                    }
                    if self.parallel_choice_free_boot
                        && (source_stop.is_some()
                            || staged_preselection.is_some()
                            || !outcome.discovered_choices.is_empty()
                            || outcome.decisions.iter().any(|decision| {
                                matches!(decision, Decision::Selection(_) | Decision::Override(_))
                            }))
                    {
                        return Err(self.poison_continuation(SchedulerError::BoundaryViolation {
                            message: String::from(
                                "choice-free parallel boot reached a selectable before the serial boundary",
                            ),
                        }));
                    }
                    published.push(outcome);
                    if source_stop.is_some() || staged_preselection.is_some() {
                        break;
                    }
                }
                Err(error) => return Err(self.poison_continuation(error)),
            }
        }

        let offer_configuration = staged_scheduler.configuration().clone();
        let offer_log_offset = staged_scheduler.event_log_offset();
        *self.loop_impl.borrow_mut() = staged_scheduler;
        self.network_output_interceptor = staged_interceptor;
        self.pending_network_outputs = staged_pending_network_outputs;
        self.frozen_network_output_times = staged_frozen_network_output_times;
        self.prune_frozen_network_output_times();
        self.pending_observations = staged_pending_observations;
        self.preselection = staged_preselection;
        self.committed_frontier = staged_frontier;
        self.held_host_continuation = if source_stop.is_some()
            || (self.preselection.is_some() && (!held_runs.is_empty() || !boundary_runs.is_empty()))
        {
            Some(HeldHostContinuation {
                runs: held_runs,
                boundary_runs,
                original_runs,
                generations,
                topology: initial_topology,
                boundary_events,
                control_applications,
                offer_configuration,
                offer_log_offset,
                source_stop,
                lineage,
            })
        } else {
            None
        };
        Ok(published)
    }

    fn complete_host_control_only(
        &mut self,
        mut staged_scheduler: SingleScheduler,
        outcome: SchedulerConcurrentQuantumOutcome,
    ) -> Result<SchedulerConcurrentQuantumOutcome, SchedulerError>
    where
        L: std::borrow::BorrowMut<SingleScheduler>,
        I: BackendNetworkOutputInterceptor<SingleScheduler, B> + Clone,
    {
        let mut outcomes = outcome.outcomes.into_iter();
        let Some(only) = outcomes.next() else {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("control-only scheduler quantum returned no outcome"),
            });
        };
        if outcomes.next().is_some() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("control-only scheduler quantum returned multiple outcomes"),
            });
        }

        let mut staged_interceptor = self.network_output_interceptor.clone();
        let mut staged_pending_network_outputs = self.pending_network_outputs.clone();
        let mut staged_frozen_network_output_times = self.frozen_network_output_times.clone();
        let mut staged_pending_observations = self.pending_observations.clone();
        let mut staged_preselection = None;
        let frontier = only.frontier;
        let completed = complete_backend_outcome_on(
            BackendOutcomeAdmission {
                loop_impl: &mut staged_scheduler,
                backend: &mut self.backend,
                network_output_interceptor: &mut staged_interceptor,
                pending_network_outputs: &mut staged_pending_network_outputs,
                frozen_network_output_times: &mut staged_frozen_network_output_times,
                pending_observations: &mut staged_pending_observations,
                preselection: &mut staged_preselection,
                pause_before_live_network_choice: self.pause_before_live_network_choice,
                network_release_at: frontier,
            },
            only,
            BackendBoundaryEvidence {
                staged_inputs: BTreeSet::new(),
                rng_evidence: Vec::new(),
                network_outputs: Vec::new(),
                observations: Vec::new(),
            },
        )
        .map_err(|error| self.poison_continuation(error))?;

        *self.loop_impl.borrow_mut() = staged_scheduler;
        self.network_output_interceptor = staged_interceptor;
        self.pending_network_outputs = staged_pending_network_outputs;
        self.frozen_network_output_times = staged_frozen_network_output_times;
        self.prune_frozen_network_output_times();
        self.pending_observations = staged_pending_observations;
        self.preselection = staged_preselection;
        self.committed_frontier = frontier;
        Ok(SchedulerConcurrentQuantumOutcome {
            run_set: outcome.run_set,
            outcomes: vec![completed],
        })
    }
}

impl<B, I> ConcurrentQuantumLoop for BackendQuantumLoop<SingleScheduler, B, I>
where
    B: ConcurrentSimulationBackend,
    I: BackendNetworkOutputInterceptor<SingleScheduler, B> + Clone,
{
    fn drive_concurrent_quantum(
        &mut self,
        request: QuantumRequest,
        max_host_workers: usize,
    ) -> Result<SchedulerConcurrentQuantumOutcome, SchedulerError> {
        self.drive_host_concurrent_quantum(request, max_host_workers)
    }
}

impl<B, I> BackendQuantumLoop<SingleScheduler, B, I>
where
    B: ConcurrentSimulationBackend,
    I: BackendNetworkOutputInterceptor<SingleScheduler, B> + Clone,
{
    /// Settles a live choice and publishes any already completed peer RUNs.
    ///
    /// Physical peer evidence stays private while a selectable is offered.
    /// Settlement resumes its causal publication before another backend RUN
    /// can be planned against the peer's old logical counter.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] if the offered prefix, peer identity, or
    /// physical evidence changed, or a resumed admission fails.
    pub fn settle_host_live_network_preselection(
        &mut self,
    ) -> Result<Vec<QuantumOutcome>, SchedulerError> {
        let validation = (|| {
            if let Some(state) = self.held_host_continuation.as_ref() {
                if self.loop_impl.configuration() != &state.offer_configuration
                    || self.loop_impl.event_log_offset() != state.offer_log_offset
                    || self.loop_impl.effective_topology != state.topology
                    || state.runs.len() > self.loop_impl.nodes.len()
                {
                    return Err(SchedulerError::BoundaryViolation {
                        message: String::from(
                            "held physical RUNs differ from the offered choice prefix",
                        ),
                    });
                }
                for (node, held) in &state.runs {
                    let Some(runtime) = self.loop_impl.nodes.get(held.run.plan.index) else {
                        return Err(SchedulerError::BoundaryViolation {
                            message: format!(
                                "held choice peer `{}` lost its scheduler node",
                                node.name
                            ),
                        });
                    };
                    if held.run.plan.node.node != *node
                        || held.completed.node != *node
                        || runtime.id != held.run.plan.node
                        || runtime.counter != held.run.plan.before
                        || state.generations.get(node) != Some(&held.generation)
                    {
                        return Err(SchedulerError::BoundaryViolation {
                            message: format!(
                                "held choice peer `{}` changed node, generation, or before counter",
                                node.name,
                            ),
                        });
                    }
                    validate_host_run_outcome(&held.run, &held.completed)?;
                }
            }

            Ok(())
        })();
        validation.map_err(|error| self.poison_continuation(error))?;
        let before_settlement = self.loop_impl.clone();
        let settlement_source = self
            .preselection
            .as_ref()
            .map(|pending| pending.choice.output.source.clone());
        if let Some(state) = self.held_host_continuation.as_ref() {
            state
                .lineage
                .ensure_extension_room()
                .map_err(|error| self.poison_continuation(error))?;
        }
        let continuation = self.held_host_continuation.take();
        let settled = match self.settle_live_network_preselection() {
            Ok(settled) => settled,
            Err(error) => {
                self.held_host_continuation = continuation;
                return Err(self.poison_continuation(error));
            }
        };
        let mut outcomes = vec![settled];
        if let Some(mut state) = continuation {
            let source = settlement_source.ok_or_else(|| {
                self.poison_continuation(SchedulerError::BoundaryViolation {
                    message: String::from(
                        "canonical choice settlement lost its actual output source",
                    ),
                })
            })?;
            state
                .lineage
                .extend_commit(&before_settlement, &self.loop_impl, &source)
                .map_err(|error| self.poison_continuation(error))?;
            for held in state.runs.values_mut() {
                held.run.canonical_lineage = Some(state.lineage.clone());
            }
            for held in state.boundary_runs.values_mut() {
                held.run.canonical_lineage = Some(state.lineage.clone());
            }
            for run in state.original_runs.values_mut() {
                run.canonical_lineage = Some(state.lineage.clone());
            }
            if state.source_stop.is_some() {
                state.offer_configuration = self.loop_impl.configuration().clone();
                state.offer_log_offset = self.loop_impl.event_log_offset();
                self.held_host_continuation = Some(state);
            } else {
                let scheduler = self.loop_impl.clone();
                outcomes.extend(self.publish_held_host_continuation(scheduler, state)?);
            }
        }
        Ok(outcomes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MockSimulationBackend;

    #[test]
    fn exhausted_actor_generation_refuses_before_backend_motion() {
        let scenario = SchedulerLivenessScenario::from_canonical_material(
            "exhausted-held-union",
            16,
            SimInstant { ticks: 64 },
            vec![SchedulerScenarioNode {
                id: SchedulerNodeId {
                    node: NodeId {
                        name: String::from("a"),
                    },
                    kind: SchedulingNodeKind::Vm,
                },
                counter: NodeCounter { ticks: 0 },
                activity: SchedulerNodeActivity::Runnable,
                network_lookahead: NetworkLookahead::Infinite,
                exact_local_event: ExactLocalEvent::NoArmedTimer,
            }],
            Vec::new(),
        );
        let scheduler = SingleScheduler::new(scenario)
            .unwrap_or_else(|error| panic!("actual runnable scenario: {error}"));
        let configuration = scheduler.configuration().clone();
        let mut actor = BackendQuantumLoop::new(scheduler, MockSimulationBackend::new());
        actor.held_union_generation = u64::MAX;

        assert!(
            actor
                .drive_concurrent_quantum(
                    QuantumRequest {
                        configuration: configuration.clone(),
                        control: Vec::new()
                    },
                    2
                )
                .is_err()
        );
        assert_eq!(actor.backend().now().ticks, 0);
        assert_eq!(actor.loop_impl().configuration(), &configuration);
        assert!(actor.loop_impl().ceiling_publications.is_empty());
    }
}
