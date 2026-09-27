//! Canonical campaign observation construction after final QEMU drain.

use super::*;
use crucible_cas::content_store::ObjectKind;

pub(super) fn campaign_measurements(
    pending: &QemuFreshPendingObservation,
    configuration: crucible_campaign::ConfigurationId,
) -> Result<crate::CrucibleMeasurementPublication, QemuFreshModeledDriverError> {
    let definitions = pending.input.scenario().measurements();
    let mut node_icounts = BTreeMap::new();
    for entry in &pending.event_log {
        if let (Some(node), Some(retired)) = (&entry.time().stamp.node, entry.time().stamp.retired)
        {
            node_icounts
                .entry(node.clone())
                .and_modify(|value: &mut crucible::Icount| {
                    *value = (*value).max(retired);
                })
                .or_insert(retired);
        }
    }
    let terminal = MeasurementTerminalState {
        scenario_ready_at: pending
            .event_log
            .iter()
            .find(|entry| entry.event_payload().kind() == "scenario_ready")
            .map(SchedulerEventLogEntry::at),
        at: pending
            .event_log
            .last()
            .map_or(pending.terminal_at, |entry| {
                pending.terminal_at.max(entry.at())
            }),
        node_icounts,
        scheduler_quiescent: pending
            .terminal_quiescence
            .as_ref()
            .is_some_and(SchedulerQuiescence::is_quiescent),
    };
    let publication = match &pending.stop {
        ModeledStop::ObservationReached { evidence, .. } => {
            evaluate_crucible_observation_measurement_publication(
                pending.input.lineage().scenario(),
                configuration,
                definitions,
                pending.event_log.clone(),
                terminal,
                *evidence,
                MAX_QEMU_CAMPAIGN_EVENT_LOG_BYTES,
            )
        }
        _ => evaluate_crucible_measurement_publication(
            pending.input.lineage().scenario(),
            configuration,
            definitions,
            pending.event_log.clone(),
            terminal,
            MAX_QEMU_CAMPAIGN_EVENT_LOG_BYTES,
        ),
    };
    publication.map_err(QemuFreshModeledDriverError::Measurements)
}

pub(super) fn property_verdicts(
    report: &crucible::HostAssertionReport,
    supplemental: Option<&(GuardedCampaignFindingOracleEvaluation, ContentId)>,
) -> Result<PropertyVerdictSet, QemuFreshModeledDriverError> {
    let mut properties = BTreeMap::new();
    for outcome in report.outcomes() {
        let verdict = match outcome.kind {
            HostAssertionOutcomeKind::Passed | HostAssertionOutcomeKind::Satisfied => {
                PropertyVerdict::Passed
            }
            HostAssertionOutcomeKind::Violated | HostAssertionOutcomeKind::NeverReachedFail => {
                PropertyVerdict::Failed
            }
            HostAssertionOutcomeKind::Warning
            | HostAssertionOutcomeKind::NeverEvaluated
            | HostAssertionOutcomeKind::NeverTriggered
            | HostAssertionOutcomeKind::NeverReachedWarn => PropertyVerdict::Inconclusive,
        };
        let evidence = PropertyEvidence::new(verdict, BTreeSet::new())?;
        if properties
            .insert(outcome.assertion.name.clone(), evidence)
            .is_some()
        {
            return Err(QemuFreshModeledDriverError::LimitExceeded {
                limit: "fresh-campaign-duplicate-property-outcome",
            });
        }
    }
    if let Some((evaluation, source)) = supplemental {
        properties.insert(
            evaluation.property().to_owned(),
            PropertyEvidence::new(PropertyVerdict::Failed, BTreeSet::from([*source]))?,
        );
    }
    PropertyVerdictSet::new(properties).map_err(Into::into)
}

pub(super) fn build_observation_candidate(
    pending: QemuFreshPendingObservation,
    resolved_effect_trace: Option<Vec<u8>>,
) -> Result<AttemptExecutionProduct, QemuFreshModeledDriverError> {
    build_observation_candidate_inner(pending, None, resolved_effect_trace)
}

pub(super) fn build_observation_candidate_with_supplemental(
    pending: QemuFreshPendingObservation,
    oracle: &dyn GuardedCampaignFindingOracle,
    source: ContentId,
    resolved_effect_trace: Option<Vec<u8>>,
) -> Result<AttemptExecutionProduct, QemuFreshModeledDriverError> {
    build_observation_candidate_inner(pending, Some((oracle, source)), resolved_effect_trace)
}

fn build_observation_candidate_inner(
    pending: QemuFreshPendingObservation,
    supplemental_oracle: Option<(&dyn GuardedCampaignFindingOracle, ContentId)>,
    resolved_effect_trace: Option<Vec<u8>>,
) -> Result<AttemptExecutionProduct, QemuFreshModeledDriverError> {
    if let Some(bytes) = &resolved_effect_trace {
        crucible::model::ResolvedEffectTrace::from_canonical_bytes(
            bytes,
            pending
                .input
                .scenario()
                .plan()
                .fault_signals()
                .resource_limits(),
        )
        .map_err(QemuFreshModeledDriverError::ResolvedEffectTrace)?;
    }
    let projection = project_boundary(pending, true, supplemental_oracle)?;
    let observation = Observation::new(
        projection.input.attempt().id()?,
        Observation::outcome(
            projection.child.configuration(),
            projection.child.id()?,
            projection.input.path().id()?,
            projection
                .stop
                .ok_or(QemuFreshModeledDriverError::SelectedResumeBoundaryMismatch)?,
            projection.measurements.id()?,
            projection.properties.id()?,
            projection.coverage.id()?,
        ),
        projection.discovered_ids,
    )?;
    let observation = match &resolved_effect_trace {
        Some(bytes) => observation.with_resolved_effect_trace(ContentId::for_bytes(
            ObjectKind::Trace,
            1,
            bytes,
        ))?,
        None => observation,
    };
    let candidate = ObservationCandidate::new(
        projection.child,
        projection.measurements,
        projection.properties,
        projection.coverage,
        projection.discovered_choices,
        observation,
    )
    .and_then(|candidate| candidate.with_produced_selections(projection.produced_selections))?;
    let candidate = match resolved_effect_trace {
        Some(bytes) => candidate.with_resolved_effect_trace(bytes)?,
        None => candidate,
    };
    let result =
        PreparedSemanticAttemptResult::new(candidate, vec![projection.measurement_evidence], None)?;
    Ok(AttemptExecutionProduct::prepared_semantic(result))
}
