//! Public fault bridges, scheduler traits, liveness gate, runtime nodes, and errors.

use super::*;
#[path = "liveness/network_branch.rs"]
mod network_branch;
mod quantum_loop;
pub(super) use network_branch::{
    LiveNetworkBranchChoice, is_live_network_branch_choice_name, live_network_branch_choices,
    live_network_branch_draws,
};
impl SchedulerSendAuthorizer for SingleScheduler {
    fn authorize_cross_node_send(
        &self,
        producer: &SchedulerNodeId,
        consumer: &SchedulerNodeId,
    ) -> Result<SchedulerSendAuthorization, SchedulerError> {
        SingleScheduler::authorize_cross_node_send(self, producer, consumer)
    }
}

impl ConcurrentQuantumLoop for SingleScheduler {
    fn drive_concurrent_quantum(
        &mut self,
        request: QuantumRequest,
        max_host_workers: usize,
    ) -> Result<SchedulerConcurrentQuantumOutcome, SchedulerError> {
        self.drive_concurrent_authoritative_quantum(request, max_host_workers)
    }
}

/// Drives the authoritative scheduler until it terminates or fails liveness.
///
/// # Errors
///
/// Returns [`SchedulerLivenessError`] when the scenario has no nodes, when the
/// scheduler detects deadlock or livelock, when it holds a lock across a node
/// advance, or when a lower-level scheduler operation fails.
pub fn check_scheduler_liveness(
    scenario: SchedulerLivenessScenario,
) -> Result<SchedulerLivenessReport, SchedulerLivenessError> {
    let mut scheduler = SingleScheduler::new(scenario)?;
    if scheduler.is_empty() {
        return Err(SchedulerLivenessError::EmptyScenario);
    }

    let mut advanced_nodes = Vec::new();
    let mut resolved_events = 0usize;
    let mut event_log_entry_hashes = Vec::new();
    let mut yielded_between_quanta = true;

    loop {
        if scheduler.quiescence()?.is_quiescent() {
            return Ok(SchedulerLivenessReport {
                terminal: SchedulerTerminal::Quiescent,
                quanta: scheduler.quanta(),
                frontier: scheduler.frontier(),
                advanced_nodes,
                resolved_events,
                event_log_entries: event_log_entry_hashes.len(),
                event_log_offset: scheduler.event_log_offset(),
                event_log_entry_hashes,
                yielded_between_quanta,
                final_configuration: scheduler.configuration().clone(),
            });
        }

        if scheduler.reached_time_limit()? || scheduler.exhausted_quantum_budget() {
            return Ok(SchedulerLivenessReport {
                terminal: SchedulerTerminal::TimeLimitReached,
                quanta: scheduler.quanta(),
                frontier: scheduler.frontier(),
                advanced_nodes,
                resolved_events,
                event_log_entries: event_log_entry_hashes.len(),
                event_log_offset: scheduler.event_log_offset(),
                event_log_entry_hashes,
                yielded_between_quanta,
                final_configuration: scheduler.configuration().clone(),
            });
        }

        let request = QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        };
        let outcome = scheduler.drive_quantum(request)?;

        match &scheduler.last_advance {
            Some(advance) => {
                if advance.after <= advance.before {
                    return Err(SchedulerLivenessError::Livelock {
                        quantum: scheduler.quanta().saturating_sub(1),
                        node: advance.node.clone(),
                        counter: advance.before,
                    });
                }
                if !advance.yielded_before_advance {
                    return Err(SchedulerLivenessError::LockHeldAcrossAdvance {
                        quantum: scheduler.quanta().saturating_sub(1),
                        node: advance.node.clone(),
                    });
                }
                yielded_between_quanta &= advance.yielded_before_advance;
                advanced_nodes.push(advance.node.clone());
            }
            None => {
                if scheduler.last_topology_recompute {
                    continue;
                }
                if let Some(node) = scheduler.stalled_active_node() {
                    return Err(SchedulerLivenessError::Livelock {
                        quantum: scheduler.quanta(),
                        node: node.id.clone(),
                        counter: node.counter,
                    });
                }

                return Err(SchedulerLivenessError::Deadlock {
                    frontier: scheduler.frontier(),
                    pending_events: scheduler.pending_events.len(),
                });
            }
        }

        resolved_events += outcome.resolved_events.len();
        event_log_entry_hashes.extend(
            outcome
                .event_log_entries
                .iter()
                .map(|entry| entry.content_hash),
        );
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RuntimeSchedulerNode {
    pub(super) id: SchedulerNodeId,
    pub(super) counter: NodeCounter,
    pub(super) time_mapping: NodeTimeMapping,
    pub(super) last_checkpoint: Option<SchedulerNodeCheckpoint>,
    pub(super) activity: SchedulerNodeActivity,
    pub(super) network_lookahead: NetworkLookahead,
    pub(super) exact_local_event: ExactLocalEvent,
    pub(super) vcpu_idle_states: Vec<SchedulerVcpuIdleState>,
}

impl From<SchedulerScenarioNode> for RuntimeSchedulerNode {
    fn from(node: SchedulerScenarioNode) -> Self {
        Self {
            id: node.id,
            counter: node.counter,
            time_mapping: NodeTimeMapping::default(),
            last_checkpoint: None,
            activity: node.activity,
            network_lookahead: node.network_lookahead,
            exact_local_event: node.exact_local_event,
            vcpu_idle_states: Vec::new(),
        }
    }
}

pub(super) fn assign_vcpu_idle_snapshots(
    nodes: &mut [RuntimeSchedulerNode],
    snapshots: &mut Vec<SchedulerNodeVcpuIdleSnapshot>,
    run_subdivision_policies: &[SchedulerRunSubdivisionPolicy],
) -> Result<(), SchedulerError> {
    snapshots.sort();
    for pair in snapshots.windows(2) {
        if pair[0].node == pair[1].node {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "scheduler vCPU idle snapshot repeated for {}:{:?}",
                    pair[0].node.node.name, pair[0].node.kind
                ),
            });
        }
    }

    for snapshot in snapshots {
        validate_vcpu_idle_snapshot(&snapshot.node, snapshot.vcpu_count, &mut snapshot.vcpus)?;
        if let Some(policy) = run_subdivision_policies
            .iter()
            .find(|policy| policy.node == snapshot.node)
            && policy.vcpu_count != snapshot.vcpu_count
        {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "scheduler vCPU idle snapshot count for {}:{:?} does not match RR policy: snapshot={} policy={}",
                    snapshot.node.node.name,
                    snapshot.node.kind,
                    snapshot.vcpu_count,
                    policy.vcpu_count
                ),
            });
        }
        let Some(node) = nodes.iter_mut().find(|node| node.id == snapshot.node) else {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "scheduler vCPU idle snapshot references missing node: {}:{:?}",
                    snapshot.node.node.name, snapshot.node.kind
                ),
            });
        };
        node.vcpu_idle_states = snapshot.vcpus.clone();
    }

    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AdvanceCandidate {
    pub(super) index: usize,
    pub(super) key: SharedTimelineKey,
    pub(super) target_time: SimInstant,
    pub(super) quiescent_horizon: Option<SimInstant>,
    pub(super) conservative_dependency: Option<UnresolvedCrossNodeDependency>,
    pub(super) allow_ceil_past_target: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum EffectiveHorizonProjection {
    Infinite,
    Finite {
        target_time: SimInstant,
        quiescent_horizon: Option<SimInstant>,
        conservative_dependency: Option<UnresolvedCrossNodeDependency>,
        allow_ceil_past_target: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AdvanceWindow {
    pub(super) target_time: SimInstant,
    pub(super) quiescent_horizon: Option<SimInstant>,
    pub(super) conservative_dependency: Option<UnresolvedCrossNodeDependency>,
    pub(super) allow_ceil_past_target: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct IdleWakeTarget {
    pub(super) wake_time: SimInstant,
    pub(super) allow_ceil_past_target: bool,
}

pub(super) fn merge_idle_wake_target(
    target: &mut Option<IdleWakeTarget>,
    wake_time: SimInstant,
    allow_ceil_past_target: bool,
) {
    match target {
        Some(current) if current.wake_time < wake_time => {}
        Some(current) if current.wake_time == wake_time => {
            current.allow_ceil_past_target &= allow_ceil_past_target;
        }
        _ => {
            *target = Some(IdleWakeTarget {
                wake_time,
                allow_ceil_past_target,
            });
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AdvancePlan {
    pub(super) index: usize,
    pub(super) node: SchedulerNodeId,
    pub(super) before: NodeCounter,
    pub(super) target_counter: u64,
    pub(super) projected_target_time: SimInstant,
    pub(super) ceiling: SchedulerRunCeilingPublication,
    pub(super) subdivision: Option<PlannedRunSubdivision>,
    pub(super) quiescent_horizon: Option<SimInstant>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AdvancePlanDraft {
    pub(super) index: usize,
    pub(super) node: SchedulerNodeId,
    pub(super) before: NodeCounter,
    pub(super) target_counter: u64,
    pub(super) projected_target_time: SimInstant,
    pub(super) quiescent_horizon: Option<SimInstant>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PlannedRunSubdivision {
    pub(super) policy: SchedulerRunSubdivisionPolicy,
    pub(super) slices: Vec<SchedulerRunSubdivisionSlice>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PlannedPreemptionApplication {
    pub(super) node: SchedulerNodeId,
    pub(super) decision: PreemptionDecision,
    pub(super) virtual_time: SimInstant,
    pub(super) deadline_icount: Icount,
    pub(super) horizon_icount: Icount,
    pub(super) ceiling: SchedulerRunCeilingPublication,
}

pub(super) fn preemption_event_times(
    preemptions: &[PlannedPreemptionApplication],
) -> Vec<(PreemptionDecision, SimInstant)> {
    preemptions
        .iter()
        .map(|application| (application.decision.clone(), application.virtual_time))
        .collect()
}

pub(super) fn concurrent_completion_order_key(
    plan: &AdvancePlan,
    preemptions: &[PlannedPreemptionApplication],
    _shift: Shift,
) -> Result<VirtualTime, SchedulerError> {
    let mut key = plan.projected_target_time;
    for preemption in preemptions {
        key = min_instant(key, preemption.virtual_time);
    }
    Ok(VirtualTime { ticks: key.nanos })
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct NodeAdvance {
    pub(super) node: SchedulerNodeId,
    pub(super) before: NodeCounter,
    pub(super) after: NodeCounter,
    pub(super) ceiling: SchedulerRunCeilingPublication,
    pub(super) yielded_before_advance: bool,
}

pub(super) struct SchedulerCriticalSection<'a> {
    pub(super) scheduler: &'a mut SingleScheduler,
}

impl<'a> SchedulerCriticalSection<'a> {
    pub(super) fn enter(scheduler: &'a mut SingleScheduler) -> Self {
        scheduler.lock_held = true;
        Self { scheduler }
    }

    pub(super) fn advance_plan(
        self,
        candidate: AdvanceCandidate,
    ) -> Result<AdvancePlan, SchedulerError> {
        let draft = self.scheduler.advance_plan_draft(&candidate)?;
        let subdivision = self.scheduler.planned_run_subdivision(
            &draft.node,
            draft.before,
            draft.target_counter,
        )?;
        let ceiling = self.scheduler.publish_run_ceiling(
            draft.node.clone(),
            draft.before,
            draft.target_counter,
            candidate.target_time,
        )?;
        Ok(AdvancePlan {
            index: draft.index,
            node: draft.node,
            before: draft.before,
            target_counter: draft.target_counter,
            projected_target_time: draft.projected_target_time,
            ceiling,
            subdivision,
            quiescent_horizon: draft.quiescent_horizon,
        })
    }
}

impl Drop for SchedulerCriticalSection<'_> {
    fn drop(&mut self) {
        self.scheduler.lock_held = false;
    }
}

pub(super) fn frontier_for(
    nodes: &[RuntimeSchedulerNode],
    shift: Shift,
) -> Result<VirtualTime, SchedulerError> {
    let mut frontier = None;
    for node in nodes {
        let virtual_time = if node.id.kind == SchedulingNodeKind::Vm {
            node.time_mapping.logical_time(node.counter, shift)?
        } else {
            node.counter.to_virtual(shift)?
        };
        frontier = Some(match frontier {
            Some(current) => min_instant(current, virtual_time),
            None => virtual_time,
        });
    }

    Ok(VirtualTime {
        ticks: frontier.unwrap_or(SimInstant::EPOCH).nanos,
    })
}

pub(super) fn min_instant(left: SimInstant, right: SimInstant) -> SimInstant {
    if left <= right { left } else { right }
}

/// Stable disposition of an attempt-scoped operational failure.
///
/// The scheduler carries this classification without interpreting daemon or
/// QEMU error types so an outer execution supervisor can distinguish a
/// transient availability failure, accepted cancellation, and a stable
/// terminal failure without parsing diagnostic text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedulerOperationalFailureClass {
    /// The same operation may succeed after transient availability recovers.
    Retryable,
    /// Attempt cancellation won at an operational boundary.
    Canceled,
    /// The attempt cannot safely continue or be retried unchanged.
    Terminal,
}

/// An error produced by the scheduler boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchedulerError {
    /// The scheduler behavior has not landed yet.
    NotImplemented {
        /// The deferred operation.
        operation: &'static str,
    },
    /// A backend operation failed while driven by the scheduler.
    Backend(BackendError),
    /// A component attempted to bypass the scheduler boundary.
    BoundaryViolation {
        /// Deterministic diagnostic text.
        message: String,
    },
    /// Attempt-scoped resource enforcement stopped scheduler progress.
    OperationalBoundary {
        /// Stable supervisor disposition, independent of diagnostic wording.
        class: SchedulerOperationalFailureClass,
        /// Deterministic operational diagnostic text.
        message: String,
    },
    /// A scheduler-owned representation could not reserve its admitted storage.
    ResourceLimit {
        /// Closed resource field whose reservation failed.
        field: &'static str,
        /// Existing admitted usage in field units.
        current: u64,
        /// Additional requested usage in field units.
        requested: u64,
        /// Scenario-authored ceiling in field units.
        configured: u64,
        /// Compiled ceiling in field units.
        hard: u64,
    },
    /// Virtual-time conversion failed while computing a scheduler horizon.
    TimeConversion(TimeConversionError),
    /// A topology change was armed at an activation virtual time the run has
    /// already passed.
    ///
    /// The activation cap can never reach `at` because the frontier has already
    /// advanced beyond it, so the change could never apply. Rejected at enqueue
    /// time by [`SingleScheduler::schedule_topology_change`] rather than wedging
    /// the run with a repeating boundary error at apply time.
    TopologyActivationInPast {
        /// The armed activation virtual time, in ticks.
        at: u64,
        /// The current frontier virtual time, in ticks.
        frontier: u64,
    },
}

impl fmt::Display for SchedulerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotImplemented { operation } => {
                write!(f, "scheduler operation {operation} is not implemented yet")
            }
            Self::Backend(error) => write!(f, "backend failed under scheduler control: {error}"),
            Self::BoundaryViolation { message } => f.write_str(message),
            Self::OperationalBoundary { message, .. } => f.write_str(message),
            Self::ResourceLimit {
                field,
                current,
                requested,
                configured,
                hard,
            } => write!(
                f,
                "scheduler resource `{field}` cannot reserve {requested} units at current {current}; configured {configured}, hard {hard}"
            ),
            Self::TimeConversion(error) => {
                write!(f, "scheduler virtual-time conversion failed: {error}")
            }
            Self::TopologyActivationInPast { at, frontier } => write!(
                f,
                "topology change armed at activation virtual time {at} is in the past: \
                 frontier already at {frontier}"
            ),
        }
    }
}

impl Error for SchedulerError {}

impl From<BackendError> for SchedulerError {
    fn from(error: BackendError) -> Self {
        Self::Backend(error)
    }
}

impl From<TimeConversionError> for SchedulerError {
    fn from(error: TimeConversionError) -> Self {
        Self::TimeConversion(error)
    }
}
