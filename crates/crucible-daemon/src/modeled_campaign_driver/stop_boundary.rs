//! Modeled attempt stop admission and bounded timeout precedence.

use super::selection_projection::has_unselected_discovery;
use super::*;

pub(crate) fn requested_attempt_stop_frontier(requested: &StopCondition) -> Option<VirtualTime> {
    match requested {
        StopCondition::Bounded {
            primary,
            virtual_time_picoseconds,
            ..
        } => requested_attempt_stop_frontier(primary)
            .map(|frontier| frontier.ticks)
            .into_iter()
            .chain(*virtual_time_picoseconds)
            .min()
            .map(|ticks| VirtualTime { ticks }),
        StopCondition::VirtualTimePicoseconds(deadline) => Some(VirtualTime { ticks: *deadline }),
        StopCondition::VirtualTimeOrExecutionQuanta {
            virtual_time_picoseconds,
            ..
        } => Some(VirtualTime {
            ticks: *virtual_time_picoseconds,
        }),
        StopCondition::NextChoice
        | StopCondition::NextChoiceOrExecutionQuanta { .. }
        | StopCondition::NamedBoundary(_)
        | StopCondition::EventCount(_)
        | StopCondition::Terminal
        | StopCondition::ExecutionQuanta(_)
        | StopCondition::Observation(_) => None,
    }
}

pub(crate) fn reached_requested_stop(
    requested: &StopCondition,
    evidence: &QuantumStopEvidence<'_>,
) -> Result<Option<ModeledStop>, ModeledCampaignError> {
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
        StopCondition::VirtualTimePicoseconds(deadline) => outcome.frontier.ticks >= *deadline,
        StopCondition::EventCount(count) => observed_event_count
            .checked_add(outcome.event_log_entries.len())
            .and_then(|events| u64::try_from(events).ok())
            .is_some_and(|events| events >= *count),
        StopCondition::Terminal => false,
        StopCondition::ExecutionQuanta(bound) => completed_quanta >= bound,
        StopCondition::VirtualTimeOrExecutionQuanta {
            virtual_time_picoseconds,
            execution_quanta,
        } => {
            outcome.frontier.ticks >= *virtual_time_picoseconds
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
            return Err(ModeledCampaignError::BoundedStopProof);
        }
    };
    Ok(reached.then(|| ModeledStop::Reached(requested.clone())))
}

pub(crate) fn policy_timeout_at(
    requested: &StopCondition,
    frontier: VirtualTime,
    completed_quanta: u64,
) -> Option<ModeledStop> {
    let StopCondition::Bounded {
        virtual_time_picoseconds,
        execution_quanta,
        ..
    } = requested
    else {
        return None;
    };
    let proof = BoundedStopProof::new(frontier.ticks, completed_quanta);
    let kind = if virtual_time_picoseconds.is_some_and(|deadline| frontier.ticks >= deadline) {
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

/// Records the semantic reason an admitted attempt stopped.
///
/// Proofs retain scheduler coordinates and canonical event evidence, never native
/// process receipts or authority to materialize another runtime.
#[derive(Debug)]
pub(crate) enum ModeledStop {
    Reached(StopCondition),
    BoundedPrimaryReached {
        stop: StopCondition,
        proof: BoundedStopProof,
    },
    BoundedPrimaryTimeout {
        stop: StopCondition,
        proof: BoundedStopProof,
    },
    PolicyTimeout {
        stop: StopCondition,
        kind: PolicyTimeoutKind,
        proof: BoundedStopProof,
    },
    ObservationReached {
        proof: Box<ObservationStopProof>,
        evidence: CrucibleObservationBoundaryEvidence,
    },
    ModeledTimeout(String),
    ReplayBoundary,
    TerminalPassed,
    TerminalFailed(Vec<String>),
}

/// Borrows the complete boundary used to evaluate a requested campaign stop.
///
/// Prior entries and the completed quantum form one dense event prefix; quantum
/// coordinates remain absolute across fresh and restored materializations.
pub(crate) struct QuantumStopEvidence<'a> {
    pub(crate) properties: &'a crucible::Properties,
    pub(crate) outcome: &'a QuantumOutcome,
    pub(crate) observed_event_count: usize,
    pub(crate) quantum_start_completed_quanta: u64,
    pub(crate) completed_quanta: u64,
    pub(crate) discoveries: &'a BTreeMap<ChoiceOpportunityId, ChoiceDiscovery>,
    pub(crate) prior_entries: &'a [SchedulerEventLogEntry],
}

pub(crate) fn observation_stop_proof(
    condition: &ObservationCondition,
    properties: &crucible::Properties,
    outcome: &QuantumOutcome,
    quantum_start_completed_quanta: u64,
    completed_quanta: u64,
    prior_entries: &[SchedulerEventLogEntry],
) -> Result<Option<(ObservationStopProof, CrucibleObservationBoundaryEvidence)>, ModeledCampaignError>
{
    let (satisfaction, assertion_witness) = match condition {
        ObservationCondition::SchedulerQuiescent => {
            if !outcome
                .scheduler_quiescence
                .as_ref()
                .is_some_and(SchedulerQuiescence::is_quiescent)
            {
                return Ok(None);
            }
            (ObservationStopSatisfaction::SchedulerQuiescent, None)
        }
        ObservationCondition::AssertionViolationTransition(assertion) => {
            let Some(entry) = outcome.event_log_entries.iter().find(|entry| {
                matches!(
                    entry.payload(),
                    SchedulerEventLogPayload::Observable(
                        ObservableEventPayload::AssertionStateChanged { name, state }
                    ) if name.name == *assertion
                        && *state == AssertionPhase::Violated
                        && assertion_is_declared(properties, &name.name)
                )
            }) else {
                return Ok(None);
            };
            (
                ObservationStopSatisfaction::AssertionViolationTransition,
                Some(AssertionViolationWitness::new(
                    assertion.clone(),
                    entry.sequence(),
                    CampaignHash::from_bytes(entry.content_hash().bytes),
                )?),
            )
        }
        ObservationCondition::AnyAssertionViolationTransition => {
            let Some((entry, assertion)) = outcome.event_log_entries.iter().find_map(|entry| {
                let SchedulerEventLogPayload::Observable(
                    ObservableEventPayload::AssertionStateChanged { name, state },
                ) = entry.payload()
                else {
                    return None;
                };
                (*state == AssertionPhase::Violated
                    && assertion_is_declared(properties, &name.name))
                .then_some((entry, name.name.as_str()))
            }) else {
                return Ok(None);
            };
            (
                ObservationStopSatisfaction::AssertionViolationTransition,
                Some(AssertionViolationWitness::new(
                    assertion,
                    entry.sequence(),
                    CampaignHash::from_bytes(entry.content_hash().bytes),
                )?),
            )
        }
        ObservationCondition::SchedulerQuiescentOrExecutionQuanta { execution_quanta } => {
            if outcome
                .scheduler_quiescence
                .as_ref()
                .is_some_and(SchedulerQuiescence::is_quiescent)
            {
                (ObservationStopSatisfaction::SchedulerQuiescent, None)
            } else if completed_quanta >= *execution_quanta {
                (ObservationStopSatisfaction::ExecutionQuanta, None)
            } else {
                return Ok(None);
            }
        }
    };
    if completed_quanta <= quantum_start_completed_quanta {
        return Err(ModeledCampaignError::QuantumCounterDidNotAdvance {
            before: quantum_start_completed_quanta,
            after: completed_quanta,
        });
    }
    let event_count = prior_entries
        .len()
        .checked_add(outcome.event_log_entries.len())
        .ok_or(ModeledCampaignError::LimitExceeded {
            limit: "observation-stop-event-count",
        })?;
    let portable_event_count =
        u64::try_from(event_count).map_err(|_| ModeledCampaignError::LimitExceeded {
            limit: "observation-stop-event-count",
        })?;
    if outcome.event_log_offset.events != portable_event_count {
        return Err(ModeledCampaignError::ObservationStopProof);
    }
    let offset = outcome.event_log_offset;
    let event_log = ObservationEventLogProof::new(
        CampaignHash::from_bytes(offset.prefix.bytes),
        offset
            .appended_segment
            .map(|hash| CampaignHash::from_bytes(hash.bytes)),
        offset.bytes,
        offset.events,
        CampaignHash::from_bytes(savepoint_event_prefix_digest_iter(
            event_count,
            prior_entries.iter().chain(&outcome.event_log_entries),
        )),
    );
    let quantum_start_events =
        u64::try_from(prior_entries.len()).map_err(|_| ModeledCampaignError::LimitExceeded {
            limit: "observation-stop-event-count",
        })?;
    let boundary = ObservationQuantumBoundary::new(
        outcome.frontier.ticks,
        quantum_start_completed_quanta,
        completed_quanta,
        quantum_start_events,
    )?;
    let retained_boundary = CrucibleObservationBoundaryEvidence::new(
        outcome.frontier,
        quantum_start_completed_quanta,
        completed_quanta,
        quantum_start_events,
        outcome.event_log_offset,
        outcome
            .scheduler_quiescence
            .as_ref()
            .is_some_and(SchedulerQuiescence::is_quiescent),
    )
    .map_err(ModeledCampaignError::Measurements)?;
    let proof = ObservationStopProof::new(
        condition.clone(),
        satisfaction,
        ConfigurationId::from_hash(CampaignHash::from_bytes(outcome.configuration.id().bytes)),
        boundary,
        event_log,
        assertion_witness,
    )?;
    Ok(Some((proof, retained_boundary)))
}

fn assertion_is_declared(properties: &crucible::Properties, assertion: &str) -> bool {
    properties
        .assertions()
        .iter()
        .any(|declaration| declaration.id.name == assertion)
}

pub(crate) fn initial_requested_stop(
    requested: &StopCondition,
    frontier: VirtualTime,
    completed_quanta: u64,
    observed_event_count: usize,
) -> Option<ModeledStop> {
    if let StopCondition::Bounded { primary, .. } = requested {
        let proof = BoundedStopProof::new(frontier.ticks, completed_quanta);
        if let Some(timeout) = policy_timeout_at(requested, frontier, completed_quanta) {
            return Some(timeout);
        }
        return initial_requested_stop(primary, frontier, completed_quanta, observed_event_count)
            .map(|stop| match stop {
                ModeledStop::Reached(_) => ModeledStop::BoundedPrimaryReached {
                    stop: requested.clone(),
                    proof,
                },
                ModeledStop::ModeledTimeout(_) => ModeledStop::BoundedPrimaryTimeout {
                    stop: requested.clone(),
                    proof,
                },
                other => other,
            });
    }

    let reached = match requested {
        StopCondition::VirtualTimePicoseconds(deadline) => frontier.ticks >= *deadline,
        StopCondition::ExecutionQuanta(bound) => completed_quanta >= *bound,
        StopCondition::VirtualTimeOrExecutionQuanta {
            virtual_time_picoseconds,
            execution_quanta,
        } => frontier.ticks >= *virtual_time_picoseconds || completed_quanta >= *execution_quanta,
        StopCondition::EventCount(count) => {
            u64::try_from(observed_event_count).is_ok_and(|observed| observed >= *count)
        }
        StopCondition::NextChoice
        | StopCondition::NamedBoundary(_)
        | StopCondition::Terminal
        | StopCondition::Observation(_) => false,
        StopCondition::NextChoiceOrExecutionQuanta { execution_quanta } => {
            return (completed_quanta >= *execution_quanta)
                .then(|| ModeledStop::ModeledTimeout(String::from("execution-quanta")));
        }
        StopCondition::Bounded { .. } => return None,
    };
    reached.then(|| ModeledStop::Reached(requested.clone()))
}

pub(crate) fn primary_stop_at(
    requested: &StopCondition,
    frontier: VirtualTime,
    completed_quanta: u64,
) -> ModeledStop {
    if matches!(requested, StopCondition::Bounded { .. }) {
        ModeledStop::BoundedPrimaryReached {
            stop: requested.clone(),
            proof: BoundedStopProof::new(frontier.ticks, completed_quanta),
        }
    } else {
        ModeledStop::Reached(requested.clone())
    }
}
