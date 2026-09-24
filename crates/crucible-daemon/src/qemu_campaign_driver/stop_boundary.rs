//! Modeled attempt stop admission and bounded timeout precedence.

use super::*;

pub(super) fn reached_requested_stop(
    requested: &StopCondition,
    evidence: &QuantumStopEvidence<'_>,
) -> Result<Option<ModeledStop>, QemuFreshModeledDriverError> {
    if let StopCondition::Bounded { primary, .. } = requested {
        let proof =
            BoundedStopProof::new(evidence.outcome.frontier.ticks, evidence.completed_quanta);
        if let Some(timeout) = policy_timeout_at(
            requested,
            evidence.outcome.frontier,
            evidence.completed_quanta,
        ) {
            return Ok(Some(timeout));
        }
        return reached_requested_stop(primary, evidence).map(|stop| {
            stop.map(|stop| match stop {
                ModeledStop::Reached(_) => ModeledStop::BoundedPrimaryReached {
                    stop: requested.clone(),
                    proof,
                },
                ModeledStop::ModeledTimeout(_) => ModeledStop::BoundedPrimaryTimeout {
                    stop: requested.clone(),
                    proof,
                },
                other => other,
            })
        });
    }

    let QuantumStopEvidence {
        outcome,
        observed_event_count,
        completed_quanta,
        discoveries,
        ..
    } = evidence;
    let pending_choice = || {
        has_unselected_discovery(
            &outcome.configuration,
            discoveries
                .values()
                .chain(outcome.discovered_choices.iter()),
        )
    };
    let reached = match requested {
        StopCondition::NextChoice => pending_choice()?,
        StopCondition::NextChoiceOrExecutionQuanta { execution_quanta } => {
            // A choice is eligible only before the intrinsic quantum fallback.
            // At the completed fallback quantum the timeout wins the tie.
            if *completed_quanta >= *execution_quanta {
                return Ok(Some(ModeledStop::ModeledTimeout(String::from(
                    "execution-quanta",
                ))));
            }
            if pending_choice()? {
                return Ok(Some(ModeledStop::Reached(requested.clone())));
            }
            return Ok(None);
        }
        StopCondition::NamedBoundary(name) => outcome.event_log_entries.iter().any(|entry| {
            matches!(
                entry.payload(),
                SchedulerEventLogPayload::Observable(ObservableEventPayload::GuestMarker {
                    marker,
                    ..
                }) if marker.name == *name
            )
        }),
        StopCondition::VirtualTimeNanoseconds(deadline) => outcome.frontier.ticks >= *deadline,
        StopCondition::EventCount(count) => observed_event_count
            .checked_add(outcome.event_log_entries.len())
            .and_then(|events| u64::try_from(events).ok())
            .is_some_and(|events| events >= *count),
        StopCondition::Terminal => false,
        StopCondition::ExecutionQuanta(bound) => completed_quanta >= bound,
        StopCondition::VirtualTimeOrExecutionQuanta {
            virtual_time_nanoseconds,
            execution_quanta,
        } => {
            outcome.frontier.ticks >= *virtual_time_nanoseconds
                || completed_quanta >= execution_quanta
        }
        StopCondition::Observation(condition) => {
            return observation_stop_proof(
                condition,
                evidence.properties,
                evidence.outcome,
                evidence.quantum_start_completed_quanta,
                evidence.completed_quanta,
                evidence.prior_entries,
            )
            .map(|reached| {
                reached.map(|(proof, evidence)| ModeledStop::ObservationReached {
                    proof: Box::new(proof),
                    evidence,
                })
            });
        }
        StopCondition::Bounded { .. } => {
            return Err(QemuFreshModeledDriverError::BoundedStopProof);
        }
    };
    Ok(reached.then(|| ModeledStop::Reached(requested.clone())))
}

pub(super) fn policy_timeout_at(
    requested: &StopCondition,
    frontier: VirtualTime,
    completed_quanta: u64,
) -> Option<ModeledStop> {
    let StopCondition::Bounded {
        virtual_time_nanoseconds,
        execution_quanta,
        ..
    } = requested
    else {
        return None;
    };
    let proof = BoundedStopProof::new(frontier.ticks, completed_quanta);
    let kind = if virtual_time_nanoseconds.is_some_and(|deadline| frontier.ticks >= deadline) {
        PolicyTimeoutKind::VirtualTime
    } else if execution_quanta.is_some_and(|deadline| completed_quanta >= deadline) {
        PolicyTimeoutKind::ExecutionQuanta
    } else {
        return None;
    };
    Some(ModeledStop::PolicyTimeout {
        stop: requested.clone(),
        kind,
        proof,
    })
}
