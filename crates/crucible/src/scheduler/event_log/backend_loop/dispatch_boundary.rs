//! Retained internal physical stops and exact actor-owned delivery settlement.

use super::held_boundary::backend_run;
use super::host_concurrent::validate_host_run_outcome;
use super::*;

/// Cleanup-only ownership after internal-stop settlement or readmission fails.
///
/// An attempted key remains uncertain until the backend's actual publication
/// ledger proves its disposition. All earlier waves and their original RUN
/// survive; no failure creates a semantic STEP or permits restaging.
#[derive(Clone, Debug)]
pub struct FailedDispatchResolution {
    boundary: BackendRunDispatchBoundary,
    events: Vec<ScheduledEvent>,
    applied: Vec<ScheduledEventKey>,
    attempted: Option<ScheduledEventKey>,
    _run: PreparedHostRun,
    _decisions: Vec<Decision>,
    _source: Arc<SingleScheduler>,
}

impl FailedDispatchResolution {
    fn retain(
        run: &PreparedHostRun,
        boundary: &BackendRunDispatchBoundary,
        events: &[ScheduledEvent],
        decisions: &[Decision],
        source: &SingleScheduler,
    ) -> Self {
        let mut history = run.staged_input_events.clone();
        history.extend_from_slice(events);
        let mut decision_history = run.staged_device_decisions.clone();
        decision_history.extend_from_slice(decisions);
        Self {
            boundary: boundary.clone(),
            events: history,
            applied: run
                .staged_input_events
                .iter()
                .map(|event| event.key.clone())
                .collect(),
            attempted: None,
            _run: run.clone(),
            _decisions: decision_history,
            _source: Arc::new(source.clone()),
        }
    }

    /// Returns the retained internal stop and its immutable semantic owner.
    #[must_use]
    pub const fn boundary(&self) -> &BackendRunDispatchBoundary {
        &self.boundary
    }

    /// Returns all prior staged events followed by this stop's actual deliveries.
    #[must_use]
    pub fn events(&self) -> &[ScheduledEvent] {
        &self.events
    }

    /// Returns canonical keys acknowledged by actual staging hooks.
    #[must_use]
    pub fn applied_keys(&self) -> &[ScheduledEventKey] {
        &self.applied
    }

    /// Returns the exact last attempted key whose publication is uncertain.
    #[must_use]
    pub const fn attempted_key(&self) -> Option<&ScheduledEventKey> {
        self.attempted.as_ref()
    }
}

pub(super) fn validate_dispatch_boundary(
    run: &PreparedHostRun,
    boundary: &BackendRunDispatchBoundary,
) -> Result<(), SchedulerError> {
    if boundary.admission != run.admission
        || boundary.reached.ticks != run.plan.target_counter
        || boundary.reached <= run.plan.ceiling.current_icount
        || boundary.reached.ticks >= run.admission.semantic_horizon().icount.retired
    {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from("internal stop differs from its retained physical wave"),
        });
    }
    Ok(())
}

pub(super) fn resolve_dispatch_boundary<B: ConcurrentSimulationBackend>(
    scheduler: &mut SingleScheduler,
    backend: &mut B,
    run: &mut PreparedHostRun,
    boundary: BackendRunDispatchBoundary,
    held_delivery: &HeldDeliveryCeiling,
    retained: &mut Option<FailedDispatchResolution>,
) -> Result<ConcurrentBackendRunResult, SchedulerError> {
    *retained = Some(FailedDispatchResolution::retain(
        run,
        &boundary,
        &[],
        &[],
        scheduler,
    ));
    validate_dispatch_boundary(run, &boundary)?;
    let mut resolved = scheduler.clone();
    let time = resolved.node_time_for_counter(&resolved.nodes[run.plan.index], boundary.reached)?;
    let frames = resolve_due_scheduled_events(&mut resolved.pending_events, &run.plan.node, time)?;
    let (devices, decisions) =
        resolved.resolve_device_completions(&run.plan.node, boundary.reached.ticks)?;
    let events = merge_node_deliveries(frames, devices);
    if matches!(resolved.nodes[run.plan.index].exact_local_event,
        ExactLocalEvent::IoCompletion { virtual_time, .. } if virtual_time == time)
    {
        resolved.nodes[run.plan.index].exact_local_event = ExactLocalEvent::NoArmedTimer;
    }
    resolved.refresh_device_horizons()?;
    let mut refreshed =
        resolved.refresh_physical_boundary_run(run, boundary.reached, Some(held_delivery))?;
    *retained = Some(FailedDispatchResolution::retain(
        run, &boundary, &events, &decisions, &resolved,
    ));
    for event in &events {
        let at = resolved.backend_effect_time(&run.plan.node.node, event.key.virtual_time())?;
        let progress = retained
            .as_mut()
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from("internal-stop publication cursor is absent"),
            })?;
        progress.attempted = Some(event.key.clone());
        match &event.payload {
            ScheduledEventPayload::BackendInput(input) => backend.stage_dispatch_boundary_effect(
                &boundary,
                &event.key,
                &BackendEffect::DeliverInput(input.clone()),
                at,
            )?,
            ScheduledEventPayload::IoCompletion(completion) => backend
                .stage_dispatch_boundary_io_completion(&boundary, &event.key, completion, at)?,
            ScheduledEventPayload::Control(_) => {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from("internal stop contains an unadmitted control"),
                });
            }
        }
        // Keep the attempted key until both the physical ACK and its exact
        // imported-origin ledger update succeed. A ledger refusal cannot undo
        // ring publication or authorize retry of the uncertain delivery.
        resolved.record_imported_io_publication(event)?;
        progress.applied.push(event.key.clone());
        progress.attempted = None;
    }
    refreshed.staged_input_events.extend(events);
    refreshed.staged_device_decisions.extend(decisions);
    *run = refreshed;
    *scheduler = resolved;
    let result = backend.resume_dispatch_boundary(backend_run(run), &boundary)?;
    if let ConcurrentBackendRunResult::Completed(completed) = &result {
        validate_host_run_outcome(run, completed)?;
        *retained = None;
    }
    Ok(result)
}

#[cfg(test)]
mod tests;
