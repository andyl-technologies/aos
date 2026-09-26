//! Canonical campaign observation construction after final QEMU drain.

use super::*;
use crucible_cas::content_store::ObjectKind;

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
