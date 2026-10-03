//! Canonical campaign observation construction after final QEMU drain.

use super::*;
use crucible_cas::content_store::ObjectKind;

pub(super) fn project_boundary(
    mut pending: QemuFreshPendingObservation,
    project_stop: bool,
    supplemental_oracle: Option<(&dyn GuardedCampaignFindingOracle, ContentId)>,
) -> Result<QemuBoundaryProjection, QemuFreshModeledDriverError> {
    validate_live_network_preselection(&pending)?;
    let timeout = retain_modeled_timeout(&mut pending)?;
    if project_stop {
        record_assertion_seal_input(&pending);
    }
    let report = check_pending_assertions(&pending)?;
    if project_stop {
        crate::crucible_execution::record_execution_phase_diagnostic(
            "seal-assertions-return",
            format_args!("outcomes={}", report.outcomes().len()),
        );
    }
    let supplemental = supplemental_oracle
        .map(|(oracle, source)| {
            oracle
                .evaluate(&pending.configuration)
                .map(|evaluation| evaluation.map(|evaluation| (evaluation, source)))
        })
        .transpose()
        .map_err(QemuFreshModeledDriverError::SupplementalFinding)?
        .flatten();
    if let Some((evaluation, _)) = &supplemental
        && !report
            .outcomes()
            .iter()
            .any(|outcome| outcome.assertion.name == evaluation.property())
    {
        return Err(QemuFreshModeledDriverError::ScenarioMismatch);
    }
    let properties = property_verdicts(&report, supplemental.as_ref())?;
    let mut failures: Vec<_> = report
        .violations()
        .iter()
        .cloned()
        .map(FailurePropertyViolationRecord::new)
        .map(FailureClusterReportFailure::property)
        .collect();
    if let Some((evaluation, _)) = &supplemental {
        failures.retain(|failure| {
            !matches!(
                failure,
                FailureClusterReportFailure::Property(record)
                    if record.violation.assertion.name == evaluation.property()
            )
        });
        failures.push(FailureClusterReportFailure::property(
            FailurePropertyViolationRecord::new(evaluation.violation().clone()),
        ));
    }
    if let Some(timeout) = timeout {
        failures.push(FailureClusterReportFailure::timeout(timeout));
    }

    if project_stop {
        crate::crucible_execution::record_execution_phase_diagnostic(
            "seal-configuration-enter",
            format_args!("events={}", pending.event_log.len()),
        );
    }
    let scenario_artifact = encode_crucible_scenario_artifact(pending.input.scenario())?;
    if scenario_artifact.id()? != pending.input.lineage().scenario_content()
        || scenario_artifact.scenario() != pending.input.lineage().scenario()
    {
        return Err(QemuFreshModeledDriverError::ScenarioMismatch);
    }
    let child = encode_crucible_configuration_artifact(
        &scenario_artifact,
        &pending.configuration.schedule,
    )?;
    if project_stop {
        crate::crucible_execution::record_execution_phase_diagnostic(
            "seal-configuration-return",
            format_args!("completed=true"),
        );
        crate::crucible_execution::record_execution_phase_diagnostic(
            "seal-measurements-enter",
            format_args!("events={}", pending.event_log.len()),
        );
    }
    let measurement_publication = campaign_measurements(&pending, child.configuration())?;
    if project_stop {
        crate::crucible_execution::record_execution_phase_diagnostic(
            "seal-measurements-return",
            format_args!("completed=true"),
        );
    }
    let (measurement_evidence, _, measurements) = measurement_publication.into_parts();
    let mut stop = project_stop
        .then(|| stop_outcome(pending.stop, &report))
        .transpose()?;
    if report.verdict().failures().is_empty()
        && let Some((evaluation, _)) = &supplemental
        && let Some(stop) = &mut stop
    {
        *stop = StopOutcome::AssertionFailure(evaluation.property().to_owned());
    }
    if project_stop {
        crate::crucible_execution::record_execution_phase_diagnostic(
            "seal-coverage-enter",
            format_args!("events={}", pending.event_log.len()),
        );
    }
    let coverage = coverage_projection(&pending.event_log)?;
    if project_stop {
        crate::crucible_execution::record_execution_phase_diagnostic(
            "seal-coverage-return",
            format_args!("completed=true"),
        );
    }
    let discovered_choices = pending.discoveries.into_values().collect::<Vec<_>>();
    let discovered_ids = discovered_choices
        .iter()
        .map(|discovery| discovery.opportunity().id())
        .collect::<Result<BTreeSet<_>, _>>()?;
    let produced_selections = produced_selections_after_start(
        pending.input.start().configuration(),
        &pending.configuration,
        &discovered_ids,
    )?;
    Ok(QemuBoundaryProjection {
        input: pending.input,
        child,
        measurement_evidence,
        measurements,
        properties,
        failures,
        coverage,
        discovered_choices,
        discovered_ids,
        produced_selections,
        stop,
    })
}

/// Counts retained input classes only after the existing opt-in notice is admitted.
/// These counts do not authenticate the log or decide checker eligibility.
fn record_assertion_seal_input(pending: &QemuFreshPendingObservation) {
    crate::crucible_execution::record_execution_phase_diagnostic_lazy(
        "seal-assertions-enter",
        || {
            let mut observable = 0;
            let mut causal = 0;
            let mut boundaries = 0;
            let mut enabled_markers = 0;
            let mut backwards_points = 0;
            let mut latest_ticks = 0;
            for entry in &pending.event_log {
                match entry.payload() {
                    SchedulerEventLogPayload::Observable(payload) => {
                        observable += 1;
                        if let ObservableEventPayload::GuestAssertionMarker { node, .. } = payload
                            && pending.input.scenario().world().vm_nodes().iter().any(
                                |world_node| {
                                    world_node.id == *node
                                        && world_node.white_box == crucible::WhiteBoxPolicy::Enabled
                                },
                            )
                        {
                            enabled_markers += 1;
                        }
                    }
                    SchedulerEventLogPayload::ResolvedHappening(_)
                    | SchedulerEventLogPayload::Decision(_) => causal += 1,
                    SchedulerEventLogPayload::EvaluationBoundary(_) => boundaries += 1,
                    _ => {}
                }
                latest_ticks = latest_ticks.max(entry.at().ticks);
                if latest_ticks
                    > crucible::EventEvaluationPoint::event_log_entry(entry)
                        .at()
                        .ticks
                {
                    backwards_points += 1;
                }
            }
            format!(
                "events={} properties={} observable={observable} causal={causal} boundaries={boundaries} enabled_markers={enabled_markers} backwards_points={backwards_points}",
                pending.event_log.len(),
                pending.input.scenario().properties().assertions().len()
            )
        },
    );
}

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
    crate::crucible_execution::record_execution_phase_diagnostic(
        "seal-effect-trace-enter",
        format_args!(
            "bytes={}",
            resolved_effect_trace.as_ref().map_or(0, Vec::len)
        ),
    );
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
    crate::crucible_execution::record_execution_phase_diagnostic(
        "seal-effect-trace-return",
        format_args!("completed=true"),
    );
    let projection = project_boundary(pending, true, supplemental_oracle)?;
    crate::crucible_execution::record_execution_phase_diagnostic(
        "seal-candidate-enter",
        format_args!("completed_projection=true"),
    );
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
    crate::crucible_execution::record_execution_phase_diagnostic(
        "seal-candidate-return",
        format_args!("completed=true"),
    );
    Ok(AttemptExecutionProduct::prepared_semantic(result))
}
