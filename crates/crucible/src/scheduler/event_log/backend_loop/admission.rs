//! Canonical backend evidence admission after a prepared scheduler RUN.

use super::*;

pub(super) struct BackendBoundaryEvidence {
    pub(super) rng_evidence: Vec<BackendRngEvidence>,
    pub(super) network_outputs: Vec<BackendNetworkOutput>,
    pub(super) observations: Vec<ObservableEvent>,
}

pub(super) struct BackendOutcomeAdmission<'a, L, B, I> {
    pub(super) loop_impl: &'a mut L,
    pub(super) backend: &'a mut B,
    pub(super) network_output_interceptor: &'a mut I,
    pub(super) pending_network_outputs: &'a mut Vec<BackendNetworkOutput>,
    pub(super) pending_observations: &'a mut Vec<ObservableEvent>,
    pub(super) preselection: &'a mut Option<BackendPendingPreselection>,
    pub(super) pause_before_live_network_choice: bool,
}

pub(super) fn complete_backend_outcome_on<L, B, I>(
    admission: BackendOutcomeAdmission<'_, L, B, I>,
    mut outcome: QuantumOutcome,
    evidence: BackendBoundaryEvidence,
) -> Result<QuantumOutcome, SchedulerError>
where
    L: QuantumLoop,
    B: SimulationBackend,
    I: BackendNetworkOutputInterceptor<L, B>,
{
    let BackendBoundaryEvidence {
        rng_evidence,
        network_outputs,
        observations,
    } = evidence;
    let BackendOutcomeAdmission {
        loop_impl,
        backend,
        network_output_interceptor,
        pending_network_outputs,
        pending_observations,
        preselection,
        pause_before_live_network_choice,
    } = admission;

    for event in &outcome.resolved_events {
        let ScheduledEventPayload::BackendInput(input) = &event.payload else {
            continue;
        };
        let backend_time = loop_impl.backend_effect_time(&input.node, event.key.virtual_time())?;
        backend.apply_to_node(
            &input.node,
            &BackendEffect::DeliverInput(input.clone()),
            backend_time,
        )?;
    }
    let resolved_observations = outcome
        .resolved_events
        .iter()
        .map(|event| loop_impl.resolved_event_observation(event))
        .collect::<Result<Vec<_>, SchedulerError>>()?;
    pending_observations.extend(resolved_observations.into_iter().flatten());
    let observations = normalize_backend_observations(loop_impl, observations, outcome.frontier)?;
    pending_network_outputs.extend(network_outputs);
    let mut timed_network_outputs = std::mem::take(pending_network_outputs)
        .into_iter()
        .map(|output| {
            loop_impl
                .backend_network_output_time(&output.source, output.emit_icount)
                .map(|at| {
                    let resume = VirtualTime {
                        ticks: output.fault_continuation.cursor().not_before_ticks(),
                    };
                    (at.max(resume), output)
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    timed_network_outputs.sort_by(|(left_at, left), (right_at, right)| {
        (
            left_at,
            left.fault_continuation
                .cursor()
                .queue_priority()
                .unwrap_or(crate::model::NetworkBundlePriority::Normal.rank()),
            &left.source,
            left.sequence,
            &left.destination,
            &left.route,
            &left.fault_continuation,
            &left.payload,
        )
            .cmp(&(
                right_at,
                right
                    .fault_continuation
                    .cursor()
                    .queue_priority()
                    .unwrap_or(crate::model::NetworkBundlePriority::Normal.rank()),
                &right.source,
                right.sequence,
                &right.destination,
                &right.route,
                &right.fault_continuation,
                &right.payload,
            ))
    });
    let committed =
        timed_network_outputs.partition_point(|(at, _output)| at.ticks <= outcome.frontier.ticks);
    *pending_network_outputs = timed_network_outputs
        .drain(committed..)
        .map(|(_at, output)| output)
        .collect();
    let network_outputs = timed_network_outputs
        .into_iter()
        .map(|(_at, output)| output)
        .collect::<Vec<_>>();
    let batches = if pause_before_live_network_choice {
        network_outputs
            .into_iter()
            .map(|output| loop_impl.backend_network_routes(output))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .map(|output| vec![output])
            .collect()
    } else {
        vec![network_outputs]
    };
    let mut batches = batches.into_iter();
    while let Some(mut network_outputs) = batches.next() {
        if network_outputs.is_empty() {
            continue;
        }
        let appends = network_output_interceptor.intercept_network_outputs(
            loop_impl,
            backend,
            outcome.frontier,
            pending_network_outputs,
            &mut network_outputs,
        )?;
        for append in appends {
            outcome.event_log_entries.extend(append.entries);
            outcome.event_log_segment_bytes = append.segment_bytes;
            outcome.event_log_segment_text = append.segment_text;
            outcome.event_log_segment_hash = append.segment_hash;
            outcome.event_log_offset = append.offset;
        }
        if network_outputs.is_empty() {
            continue;
        }
        // The current physical route was intercepted before any later route.
        // A pure interceptor may produce a further ordered suffix; the
        // scheduler reserves that suffix without selecting it by default.
        let routes_are_exact = if pause_before_live_network_choice {
            network_outputs.iter().try_fold(true, |exact, output| {
                loop_impl
                    .backend_network_route_count(output)
                    .map(|count| exact && count == 1)
            })?
        } else {
            false
        };
        if pause_before_live_network_choice && !routes_are_exact {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "live network choice pause requires an exact directed World route",
                ),
            });
        }
        let can_pause = pause_before_live_network_choice;
        let admission = if can_pause {
            loop_impl.append_backend_network_outputs_until_choice(network_outputs)?
        } else {
            let (decisions, discoveries, configuration, append) =
                loop_impl.append_backend_network_outputs(network_outputs)?;
            BackendNetworkAdmission::Settled {
                decisions,
                discoveries,
                configuration,
                append,
            }
        };
        let (recorded, discovered_choices, configuration, append, pending) = match admission {
            BackendNetworkAdmission::Settled {
                decisions,
                discoveries,
                configuration,
                append,
            } => (decisions, discoveries, configuration, append, None),
            BackendNetworkAdmission::Preselection {
                decisions,
                discoveries,
                configuration,
                append,
                reservation,
                remaining,
            } => (
                decisions,
                discoveries,
                configuration,
                append,
                Some((*reservation, remaining)),
            ),
        };
        outcome.decisions.extend(recorded);
        outcome.discovered_choices.extend(discovered_choices);
        outcome.configuration = configuration;
        outcome.event_log_entries.extend(append.entries);
        outcome.event_log_segment_bytes = append.segment_bytes;
        outcome.event_log_segment_text = append.segment_text;
        outcome.event_log_segment_hash = append.segment_hash;
        outcome.event_log_offset = append.offset;
        if let Some((choice, remaining_outputs)) = pending {
            *preselection = Some(BackendPendingPreselection {
                choice,
                remaining_outputs,
                remaining_unintercepted_outputs: batches.flatten().collect(),
                pending_network_outputs: std::mem::take(pending_network_outputs),
                pending_observations: std::mem::take(pending_observations),
                rng_evidence,
                observations,
                outcome: outcome.clone(),
                handed_off: false,
                selected: None,
                selected_decision_count: 0,
                selected_event_count: 0,
            });
            return Ok(outcome);
        }
    }
    let causal_decisions = rng_evidence;
    if !causal_decisions.is_empty() {
        let (recorded, discovered_choices, configuration, append) =
            loop_impl.append_backend_rng_evidence(causal_decisions)?;
        outcome.decisions.extend(recorded);
        outcome.discovered_choices.extend(discovered_choices);
        outcome.configuration = configuration;
        outcome.event_log_entries.extend(append.entries);
        outcome.event_log_segment_bytes = append.segment_bytes;
        outcome.event_log_segment_text = append.segment_text;
        outcome.event_log_segment_hash = append.segment_hash;
        outcome.event_log_offset = append.offset;
    }
    pending_observations.extend(observations);
    pending_observations.sort_by_key(ObservableEvent::at);
    let committed =
        pending_observations.partition_point(|event| event.at().ticks <= outcome.frontier.ticks);
    let observations = pending_observations.drain(..committed).collect::<Vec<_>>();
    if !observations.is_empty() {
        let append =
            loop_impl.append_backend_observations_at_boundary(observations, outcome.frontier)?;
        outcome.event_log_entries.extend(append.entries);
        outcome.event_log_segment_bytes = append.segment_bytes;
        outcome.event_log_segment_text = append.segment_text;
        outcome.event_log_segment_hash = append.segment_hash;
        outcome.event_log_offset = append.offset;
    }
    Ok(outcome)
}
