//! Canonical backend evidence admission after a prepared scheduler RUN.

use super::*;

pub(super) struct BackendBoundaryEvidence {
    pub(super) rng_evidence: Vec<BackendRngEvidence>,
    pub(super) network_outputs: Vec<BackendNetworkOutput>,
    pub(super) observations: Vec<ObservableEvent>,
}

pub(super) fn complete_backend_outcome_on<L, B, I>(
    loop_impl: &mut L,
    backend: &mut B,
    network_output_interceptor: &mut I,
    pending_network_outputs: &mut Vec<BackendNetworkOutput>,
    pending_observations: &mut Vec<ObservableEvent>,
    preselection: &mut Option<BackendPendingPreselection>,
    pause_before_live_network_choice: bool,
    mut outcome: QuantumOutcome,
    evidence: BackendBoundaryEvidence,
) -> Result<QuantumOutcome, SchedulerError>
where
    L: QuantumLoop,
    B: SimulationBackend,
    I: BackendNetworkOutputInterceptor<L, B>,
{
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
    pending_network_outputs.extend(evidence.network_outputs);
    let mut timed_network_outputs = std::mem::take(pending_network_outputs)
        .into_iter()
        .map(|output| {
            loop_impl
                .backend_network_output_time(&output.source, output.emit_icount)
                .map(|at| {
                    let resume = VirtualTime {
                        ticks: output.fault_continuation.cursor().not_before_nanos(),
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
        // An interceptor may split one physical frame across routes. It may
        // already have mutated later routes, so only a single routed output
        // can establish a preselection stop at this physical parent.
        let can_pause = pause_before_live_network_choice
            && network_outputs.len() == 1
            && pending_network_outputs.is_empty()
            && pending_observations.is_empty()
            && loop_impl.backend_network_route_count(&network_outputs[0])? == 1;
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
                Some((reservation, remaining)),
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
                rng_evidence: evidence.rng_evidence,
                observations: evidence.observations,
                outcome: outcome.clone(),
                handed_off: false,
            });
            return Ok(outcome);
        }
    }
    let causal_decisions = evidence.rng_evidence;
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
    let observations = evidence
        .observations
        .into_iter()
        .map(|event| {
            let Some(node) = event.backend_node() else {
                return Ok(event);
            };
            let at = loop_impl.backend_observation_time(node, event.at())?;
            Ok(event.with_scheduler_time(at))
        })
        .collect::<Result<Vec<_>, SchedulerError>>()?;
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
