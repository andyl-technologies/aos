//! Canonical campaign observation construction after final QEMU drain.

use super::*;

/// Bounds the stop outcome rendered into the opt-in seal diagnostic.
const STOP_DIAGNOSTIC_CHARS: usize = 512;

/// Largest canonical measurement replay leaf one attempt publishes.
///
/// The leaf references the log's segments instead of embedding entries, so
/// it stays far below the 64 MiB component-message bound (RFC-0020 CMEAS-22).
pub(super) const MAX_MEASUREMENT_EVIDENCE_LEAF_BYTES: usize = 64 * 1024 * 1024;

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
        crate::crucible_execution::record_execution_phase_diagnostic(
            "seal-measurements-enter",
            format_args!("events={}", pending.event_log.len()),
        );
    }
    // Measurement evaluation seals the log into the segments its evidence
    // references, so every other reader of the log runs before it.
    let measurement_publication = campaign_measurements(&mut pending, child.configuration())?;
    if project_stop {
        crate::crucible_execution::record_execution_phase_diagnostic(
            "seal-measurements-return",
            format_args!("completed=true"),
        );
    }
    let (measurement_publication, log_segments) = measurement_publication;
    let (measurement_evidence, _, measurements) = measurement_publication.into_parts();
    let measurement_evidence = crate::CrucibleMeasurementEvidenceBundle::referencing(
        measurement_evidence,
        log_segments.into(),
    )
    .map_err(QemuFreshModeledDriverError::Measurements)?;
    let mut stop = project_stop
        .then(|| stop_outcome(pending.stop, &report))
        .transpose()?;
    if report.verdict().failures().is_empty()
        && let Some((evaluation, _)) = &supplemental
        && let Some(stop) = &mut stop
    {
        *stop = StopOutcome::AssertionFailure(evaluation.property().to_owned());
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
            // Diagnostic only: an unreadable segment leaves its entries uncounted.
            let _ = pending.event_log.try_for_each_entry(|entry| {
                match entry.payload() {
                    SchedulerEventLogPayload::Observable(payload) => {
                        observable += 1;
                        if let ObservableEventPayload::GuestAssertionMarker { node, .. } = payload
                            && pending.input.scenario().world().vm_nodes().iter().any(
                                |world_node| {
                                    world_node.id == *node
                                        && world_node.white_box
                                            == crucible_engine::WhiteBoxPolicy::Enabled
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
                    > crucible_engine::EventEvaluationPoint::event_log_entry(entry)
                        .at()
                        .ticks
                {
                    backwards_points += 1;
                }
                Ok(())
            });
            format!(
                "events={} properties={} observable={observable} causal={causal} boundaries={boundaries} enabled_markers={enabled_markers} backwards_points={backwards_points}",
                pending.event_log.len(),
                pending.input.scenario().properties().assertions().len()
            )
        },
    );
}

/// Evaluates the attempt's measurements over its sealed log.
///
/// Sealing consumes the retained log, leaving `pending` with an empty one;
/// the returned store holds exactly the segments the evidence references.
pub(super) fn campaign_measurements(
    pending: &mut QemuFreshPendingObservation,
    configuration: crucible_campaign::ConfigurationId,
) -> Result<
    (
        crate::CrucibleMeasurementPublication,
        crate::AttemptLogStore,
    ),
    QemuFreshModeledDriverError,
> {
    let definitions = pending.input.scenario().measurements();
    let mut node_icounts = BTreeMap::new();
    let mut scenario_ready_at = None;
    pending.event_log.try_for_each_entry(|entry| {
        if let (Some(node), Some(retired)) = (&entry.time().stamp.node, entry.time().stamp.retired)
        {
            node_icounts
                .entry(node.clone())
                .and_modify(|value: &mut crucible_engine::Icount| {
                    *value = (*value).max(retired);
                })
                .or_insert(retired);
        }
        if scenario_ready_at.is_none() && entry.event_payload().kind() == "scenario_ready" {
            scenario_ready_at = Some(entry.at());
        }
        Ok(())
    })?;
    let terminal = MeasurementTerminalState {
        scenario_ready_at,
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
    let maximum_bytes = pending.event_log.maximum_bytes();
    let retained = std::mem::replace(
        &mut pending.event_log,
        RetainedAttemptLog::new(maximum_bytes),
    );
    let (log, log_segments) = retained.seal()?;
    let publication = match &pending.stop {
        ModeledStop::ObservationReached { evidence, .. } => {
            evaluate_crucible_observation_measurement_publication(
                pending.input.lineage().scenario(),
                configuration,
                definitions,
                log,
                &log_segments,
                terminal,
                *evidence,
                MAX_MEASUREMENT_EVIDENCE_LEAF_BYTES,
            )
        }
        _ => evaluate_crucible_measurement_publication(
            pending.input.lineage().scenario(),
            configuration,
            definitions,
            log,
            &log_segments,
            terminal,
            MAX_MEASUREMENT_EVIDENCE_LEAF_BYTES,
        ),
    };
    let publication = publication.map_err(QemuFreshModeledDriverError::Measurements)?;
    Ok((publication, log_segments))
}

pub(super) fn property_verdicts(
    report: &crucible_engine::HostAssertionReport,
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
            | HostAssertionOutcomeKind::NeverReachedWarn
            | HostAssertionOutcomeKind::Undecided => PropertyVerdict::Inconclusive,
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

/// A sealed resolved-effect trace as an observation references it.
struct SealedTraceReference {
    reference: crucible_campaign::ResolvedEffectTraceRef,
    manifest: Vec<u8>,
    segments: crucible_engine::segment_store::SegmentSources,
}

/// Admits a recorded trace's manifest and names its manifest and segments.
fn sealed_trace_reference(
    trace: crucible_engine::model::ResolvedEffectTrace,
    pending: &QemuFreshPendingObservation,
) -> Result<SealedTraceReference, QemuFreshModeledDriverError> {
    let limits = pending
        .input
        .scenario()
        .plan()
        .fault_signals()
        .resource_limits();
    trace
        .manifest()
        .admit(limits)
        .map_err(QemuFreshModeledDriverError::ResolvedEffectTrace)?;

    let manifest_id = trace
        .manifest()
        .content_id()
        .map_err(QemuFreshModeledDriverError::ResolvedEffectTrace)?;
    let manifest = trace
        .manifest()
        .canonical_bytes()
        .map_err(QemuFreshModeledDriverError::ResolvedEffectTrace)?;
    let reference = crucible_campaign::ResolvedEffectTraceRef::new(
        manifest_id,
        trace.manifest().segment_ids().collect(),
    )?;
    let (_, segments) = trace.into_parts();

    Ok(SealedTraceReference {
        reference,
        manifest,
        segments,
    })
}

pub(super) fn build_observation_candidate(
    pending: QemuFreshPendingObservation,
    resolved_effect_trace: Option<crucible_engine::model::ResolvedEffectTrace>,
) -> Result<AttemptExecutionProduct, QemuFreshModeledDriverError> {
    build_observation_candidate_inner(pending, None, resolved_effect_trace)
}

pub(super) fn build_observation_candidate_with_supplemental(
    pending: QemuFreshPendingObservation,
    oracle: &dyn GuardedCampaignFindingOracle,
    source: ContentId,
    resolved_effect_trace: Option<crucible_engine::model::ResolvedEffectTrace>,
) -> Result<AttemptExecutionProduct, QemuFreshModeledDriverError> {
    build_observation_candidate_inner(pending, Some((oracle, source)), resolved_effect_trace)
}

fn build_observation_candidate_inner(
    pending: QemuFreshPendingObservation,
    supplemental_oracle: Option<(&dyn GuardedCampaignFindingOracle, ContentId)>,
    resolved_effect_trace: Option<crucible_engine::model::ResolvedEffectTrace>,
) -> Result<AttemptExecutionProduct, QemuFreshModeledDriverError> {
    crate::crucible_execution::record_execution_phase_diagnostic(
        "seal-effect-trace-enter",
        format_args!(
            "segments={}",
            resolved_effect_trace
                .as_ref()
                .map_or(0, |trace| trace.manifest().segments().len())
        ),
    );
    // The runtime sealed every segment under these limits; admitting the
    // manifest rechecks its counters without reading a segment. Publication
    // authenticates each segment when it streams it.
    let resolved_effect_trace = resolved_effect_trace
        .map(|trace| sealed_trace_reference(trace, &pending))
        .transpose()?;
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
        Some(sealed) => observation.with_resolved_effect_trace(sealed.reference.clone())?,
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
        Some(sealed) => candidate.with_resolved_effect_trace(sealed.manifest, sealed.segments)?,
        None => candidate,
    };
    let (measurement_evidence, log_segments) = projection.measurement_evidence.into_parts();
    let result = PreparedSemanticAttemptResult::new(
        candidate,
        vec![measurement_evidence],
        log_segments,
        None,
    )?;
    // The stop names any assertion that will start automatic finding
    // reduction; bound it so an observation proof cannot flood stderr.
    crate::crucible_execution::record_execution_phase_diagnostic_lazy(
        "seal-candidate-return",
        || {
            let stop = result.observation().observation().stop();
            let stop: String = format!("{stop:?}")
                .chars()
                .take(STOP_DIAGNOSTIC_CHARS)
                .collect();
            format!("completed=true stop={stop}")
        },
    );
    Ok(AttemptExecutionProduct::prepared_semantic(result))
}

fn coverage_projection(
    event_log: &RetainedAttemptLog,
) -> Result<CoverageProjection, QemuFreshModeledDriverError> {
    let mut identities = BTreeSet::new();
    event_log.try_for_each_entry(|entry| {
        if let Some(observation) = EventLogCoverageObservation::from_entry(entry) {
            identities.insert(coverage_identity(&observation));
        }
        Ok(())
    })?;
    CoverageProjection::new(identities, BTreeSet::new()).map_err(Into::into)
}

fn coverage_identity(observation: &EventLogCoverageObservation) -> CampaignHash {
    CampaignHash::from_bytes(observation.content_hash().bytes)
}
