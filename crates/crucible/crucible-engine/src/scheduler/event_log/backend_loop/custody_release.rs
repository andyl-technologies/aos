//! Canonical publication of frames leaving adapter custody.
//!
//! A network adapter may hold a frame in custody until a release coordinate
//! later than its emission. While a host-concurrent RUN set publishes, such a
//! frame takes its log position at that release time, as its own cut ahead of
//! any RUN that settles later. Releasing it with the first RUN published after
//! that time would put it behind the RUN's deliveries, so whether it preceded
//! a delivery would depend on how the host happened to split RUNs, and replay
//! from another split would diverge (RFC-0010 SCHED-32 and EXEC-7).
//!
//! A RUN that settles exactly at the release time publishes first, and the
//! frame is admitted with that RUN's own outputs. Every other release path,
//! the pre-quantum settlement and a control-only quantum, admits a frame only
//! after the RUNs at its time commit, so this tie order is the one all paths
//! share.
//!
//! A release advances no node. Its decisions and entries ride ahead of the
//! next published RUN outcome, so every outcome still names the RUN it
//! commits.

use super::*;

/// Mutable publication state a held custody release admits frames into.
pub(super) struct HeldCustodyRelease<'a, B, I> {
    pub(super) scheduler: &'a mut SingleScheduler,
    pub(super) backend: &'a mut B,
    pub(super) network_output_interceptor: &'a mut I,
    pub(super) pending_network_outputs: &'a mut Vec<BackendNetworkOutput>,
    pub(super) frozen_network_output_times: &'a mut BTreeMap<(NodeId, u64), VirtualTime>,
    pub(super) pending_observations: &'a mut Vec<ObservableEvent>,
    pub(super) preselection: &'a mut Option<BackendPendingPreselection>,
    pub(super) pause_before_live_network_choice: bool,
    /// Committed frontier, which a release leaves unchanged.
    pub(super) frontier: VirtualTime,
}

/// Returns the next custody release due strictly before `run_time`.
///
/// The result names the release time and the frame's source. A cut is taken
/// once: a frame the interceptor returns to custody at an already released
/// time waits for the next RUN publication, so a release cannot repeat
/// without progress.
pub(super) fn next_custody_release(
    scheduler: &SingleScheduler,
    frozen_network_output_times: &BTreeMap<(NodeId, u64), VirtualTime>,
    pending_network_outputs: &[BackendNetworkOutput],
    run_time: VirtualTime,
    released_through: Option<VirtualTime>,
) -> Result<Option<(VirtualTime, NodeId)>, SchedulerError> {
    let release = super::admission::earliest_pending_network_release(
        scheduler,
        frozen_network_output_times,
        pending_network_outputs,
    )?
    .map(|(at, output)| (at, output.source.clone()))
    .filter(|(at, _)| *at < run_time && released_through.is_none_or(|through| *at > through));

    Ok(release)
}

/// Admits every pending frame whose release time is at or before `cut`.
///
/// Every live node has already executed to `cut`; the interceptor evaluates
/// each frame at its own release time.
///
/// # Errors
///
/// Returns [`SchedulerError`] when interception, routing, or the event-log
/// append fails.
pub(super) fn release_held_custody<B, I>(
    release: HeldCustodyRelease<'_, B, I>,
    cut: VirtualTime,
) -> Result<QuantumOutcome, SchedulerError>
where
    B: SimulationBackend,
    I: BackendNetworkOutputInterceptor<SingleScheduler, B>,
{
    let HeldCustodyRelease {
        scheduler,
        backend,
        network_output_interceptor,
        pending_network_outputs,
        frozen_network_output_times,
        pending_observations,
        preselection,
        pause_before_live_network_choice,
        frontier,
    } = release;
    let base = custody_release_outcome(scheduler, frontier);
    let _admission_path = crate::scheduler::network_admission_trace::enter_path("custody-release");

    complete_backend_outcome_on(
        BackendOutcomeAdmission {
            loop_impl: scheduler,
            backend,
            network_output_interceptor,
            pending_network_outputs,
            frozen_network_output_times,
            pending_observations,
            preselection,
            pause_before_live_network_choice,
            network_release_at: cut,
        },
        base,
        BackendBoundaryEvidence {
            staged_inputs: BTreeSet::new(),
            rng_evidence: Vec::new(),
            network_outputs: Vec::new(),
            observations: Vec::new(),
        },
    )
}

/// Starts the outcome of a custody release, which advances no node.
fn custody_release_outcome(scheduler: &SingleScheduler, frontier: VirtualTime) -> QuantumOutcome {
    QuantumOutcome {
        configuration: scheduler.configuration().clone(),
        frontier,
        advanced_node: None,
        resolved_events: Vec::new(),
        decisions: Vec::new(),
        discovered_choices: Vec::new(),
        event_log_entries: Vec::new(),
        event_log_segment_bytes: Vec::new(),
        event_log_segment_text: String::new(),
        event_log_segment_hash: None,
        event_log_offset: scheduler.event_log_offset(),
        scheduler_quiescence: None,
    }
}

/// Puts earlier custody releases ahead of `later` in one outcome.
///
/// The log already holds the released entries before `later`'s, so the
/// combined outcome lists them first and keeps `later`'s final state.
pub(super) fn carry_custody_release(
    earlier: Option<QuantumOutcome>,
    later: QuantumOutcome,
) -> QuantumOutcome {
    let Some(mut earlier) = earlier else {
        return later;
    };

    earlier.configuration = later.configuration;
    earlier.frontier = later.frontier;
    earlier.advanced_node = later.advanced_node;
    earlier.resolved_events.extend(later.resolved_events);
    earlier.decisions.extend(later.decisions);
    earlier.discovered_choices.extend(later.discovered_choices);
    earlier.event_log_entries.extend(later.event_log_entries);
    earlier.event_log_segment_bytes = later.event_log_segment_bytes;
    earlier.event_log_segment_text = later.event_log_segment_text;
    earlier.event_log_segment_hash = later.event_log_segment_hash;
    earlier.event_log_offset = later.event_log_offset;
    earlier.scheduler_quiescence = later.scheduler_quiescence;
    earlier
}
