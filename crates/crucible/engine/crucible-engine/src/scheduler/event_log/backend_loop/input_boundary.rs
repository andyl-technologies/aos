//! Fixed-T input RESOLVE and explicit readmission of retained backend RUNs.
//!
//! No semantic STEP, boundary emission or output publication occurs until the
//! operational backend reports a fully settled stop. Failures leave its private
//! native owner retained and poison the enclosing actor continuation.

use super::held_boundary::backend_run;
use super::host_concurrent::validate_host_run_outcome;
use super::*;

/// Retained exact input resolution after a staging or readmission failure.
///
/// The actor becomes cleanup-only. An attempted key is uncertain until the
/// operational backend's own publication ledger proves its disposition; this
/// record never infers ring publication from an error or equal payload bytes.
#[derive(Clone, Debug)]
pub struct FailedInputResolution {
    boundary: BackendRunInputBoundary,
    events: Vec<ScheduledEvent>,
    applied: Vec<ScheduledEventKey>,
    attempted: Option<ScheduledEventKey>,
    _run: PreparedHostRun,
    _decisions: Vec<Decision>,
    _source: Arc<SingleScheduler>,
}

impl FailedInputResolution {
    fn retain(
        run: &PreparedHostRun,
        boundary: &BackendRunInputBoundary,
        events: &[ScheduledEvent],
        decisions: &[Decision],
        source: &SingleScheduler,
    ) -> Self {
        let mut retained_events = run.staged_input_events.clone();
        retained_events.extend_from_slice(events);
        let mut retained_decisions = run.staged_device_decisions.clone();
        retained_decisions.extend_from_slice(decisions);

        Self {
            boundary: boundary.clone(),
            events: retained_events,
            applied: run
                .staged_input_events
                .iter()
                .map(|event| event.key.clone())
                .collect(),
            attempted: None,
            _run: run.clone(),
            _decisions: retained_decisions,
            _source: Arc::new(source.clone()),
        }
    }

    /// Returns the original retained semantic owner and exact physical stop.
    #[must_use]
    pub const fn boundary(&self) -> &BackendRunInputBoundary {
        &self.boundary
    }

    /// Returns the accumulated staged history followed by this boundary's events.
    #[must_use]
    pub fn events(&self) -> &[ScheduledEvent] {
        &self.events
    }

    /// Returns the exact keys whose staging hooks acknowledged completion.
    #[must_use]
    pub fn applied_keys(&self) -> &[ScheduledEventKey] {
        &self.applied
    }

    /// Returns the last attempted key when its publication is uncertain.
    #[must_use]
    pub const fn attempted_key(&self) -> Option<&ScheduledEventKey> {
        self.attempted.as_ref()
    }
}

pub(super) fn resolve_input_boundary<B: ConcurrentSimulationBackend>(
    scheduler: &mut SingleScheduler,
    backend: &mut B,
    run: &mut PreparedHostRun,
    boundary: BackendRunInputBoundary,
    retained: &mut Option<FailedInputResolution>,
    held_delivery: &HeldDeliveryCeiling,
) -> Result<ConcurrentBackendRunResult, SchedulerError> {
    // Keep the complete prior RUN even when validation or RESOLVE fails
    // before a new publication attempt can be made.
    *retained = Some(FailedInputResolution::retain(
        run,
        &boundary,
        &[],
        &[],
        scheduler,
    ));
    validate_input_boundary(run, &boundary)?;

    // Only queue/device RESOLVE occurs here. The original RUN, config,
    // event-log prefix and semantic STEP remain unpublished until full STOP.
    let mut resolved = scheduler.clone();
    let time = resolved.node_time_for_counter(&resolved.nodes[run.plan.index], boundary.reached)?;
    let frames = resolve_due_scheduled_events(&mut resolved.pending_events, &run.plan.node, time)?;
    let (devices, decisions) =
        resolved.resolve_device_completions(&run.plan.node, boundary.reached.ticks)?;
    let events = merge_node_deliveries(frames, devices);
    if events.is_empty() {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from("input stop has no actual due scheduler input"),
        });
    }
    if matches!(resolved.nodes[run.plan.index].exact_local_event,
        ExactLocalEvent::IoCompletion { virtual_time, .. } if virtual_time == time)
    {
        resolved.nodes[run.plan.index].exact_local_event = ExactLocalEvent::NoArmedTimer;
    }
    resolved.refresh_device_horizons()?;
    let mut refreshed =
        resolved.refresh_physical_boundary_run(run, boundary.reached, Some(held_delivery))?;

    *retained = Some(FailedInputResolution::retain(
        run, &boundary, &events, &decisions, &resolved,
    ));
    for event in &events {
        let at = resolved.backend_effect_time(&run.plan.node.node, event.key.virtual_time())?;
        let progress = retained
            .as_mut()
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from("retained input publication cursor is absent"),
            })?;
        progress.attempted = Some(event.key.clone());
        match &event.payload {
            ScheduledEventPayload::BackendInput(input) => {
                backend.stage_input_boundary_effect(
                    &boundary,
                    &event.key,
                    &BackendEffect::DeliverInput(input.clone()),
                    at,
                )?;
            }
            ScheduledEventPayload::IoCompletion(completion) => {
                backend
                    .stage_input_boundary_io_completion(&boundary, &event.key, completion, at)?;
            }
            ScheduledEventPayload::Control(_) => {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from("input stop contains an unadmitted control"),
                });
            }
        }
        resolved.record_imported_io_publication(event)?;
        progress.applied.push(event.key.clone());
        progress.attempted = None;
    }
    refreshed.staged_input_events.extend(events);
    refreshed.staged_device_decisions.extend(decisions);
    *run = refreshed;
    *scheduler = resolved;
    let result = backend.resume_input_boundary(backend_run(run), &boundary)?;
    if let ConcurrentBackendRunResult::Completed(completed) = &result {
        validate_host_run_outcome(run, completed)?;
        *retained = None;
    }

    // Every refreshed physical stop returns to canonical peer arbitration.
    // Resolving the next wave here could pass an earlier held peer output.
    Ok(result)
}

pub(super) fn validate_input_boundary(
    run: &PreparedHostRun,
    boundary: &BackendRunInputBoundary,
) -> Result<(), SchedulerError> {
    if boundary.admission != run.admission
        || boundary.admission.input_inventory().next_input() != Some(boundary.reached)
        || boundary.reached.ticks < run.plan.before.ticks
        || boundary.reached.ticks > run.plan.target_counter
    {
        return Err(SchedulerError::BoundaryViolation {
            message: String::from("retained input stop differs from its sealed RUN inventory"),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn later_failure_carrier_keeps_the_original_run_and_acknowledged_history() {
        let node = SchedulerNodeId {
            node: NodeId {
                name: String::from("a"),
            },
            kind: SchedulingNodeKind::Vm,
        };
        let scenario = SchedulerLivenessScenario::from_canonical_material(
            "retained-input-history",
            16,
            SimInstant { ticks: 64 },
            vec![SchedulerScenarioNode {
                id: node.clone(),
                counter: NodeCounter { ticks: 0 },
                activity: SchedulerNodeActivity::Runnable,
                network_lookahead: NetworkLookahead::Infinite,
                exact_local_event: ExactLocalEvent::NoArmedTimer,
            }],
            Vec::new(),
        );
        let scheduler = SingleScheduler::new(scenario)
            .unwrap_or_else(|error| panic!("actual scheduler fixture: {error}"));
        let prepared = scheduler
            .prepare_host_concurrent_quantum_limited(
                QuantumRequest {
                    configuration: scheduler.configuration().clone(),
                    control: Vec::new(),
                },
                1,
            )
            .unwrap_or_else(|error| panic!("actual finalized RUN owner: {error}"));
        let mut run = prepared.runs[0].clone();
        let event = |tick, sequence| ScheduledEvent {
            key: ScheduledEventKey::new(
                SharedTimelineKey {
                    virtual_time: SimInstant { ticks: tick },
                    node: node.clone(),
                    sequence,
                },
                node.clone(),
            ),
            payload: ScheduledEventPayload::BackendInput(BackendInput {
                node: node.node.clone(),
                payload: vec![7],
            }),
        };
        let prior = event(20, 1);
        let current = event(30, 2);
        // This tests carrier consistency only. Native publication authority
        // stays in the operational backend; no mocked acknowledgement mints it.
        run.staged_input_events.push(prior.clone());
        let boundary = BackendRunInputBoundary {
            admission: run.admission.clone(),
            reached: NodeCounter { ticks: 30 },
        };

        let mut retained = FailedInputResolution::retain(
            &run,
            &boundary,
            std::slice::from_ref(&current),
            &[],
            &prepared.next,
        );
        retained.attempted = Some(current.key.clone());
        drop(run);

        assert_eq!(retained.events(), &[prior.clone(), current.clone()]);
        assert_eq!(retained.applied_keys(), std::slice::from_ref(&prior.key));
        assert_eq!(retained.attempted_key(), Some(&current.key));
        assert_eq!(retained._run.staged_input_events, vec![prior]);
        assert_eq!(retained._run.admission, boundary.admission);
        assert_eq!(retained._source.configuration(), scheduler.configuration());
    }
}
