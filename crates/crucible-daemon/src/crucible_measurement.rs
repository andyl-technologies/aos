//! Crucible measurement-evaluation payloads retained by campaign observations.
//!
//! The campaign record layer deliberately treats execution-model evaluations
//! as opaque bytes. This adapter is the semantic boundary that converts a
//! verified Crucible evaluation into measurement-set schema v2 and recomputes
//! it from authenticated scheduler entries before accepting retained bytes.

use std::collections::{BTreeMap, BTreeSet};

use crucible::SchedulerEventLogEntry;
use crucible::model::{
    MeasurementAggregateValue, MeasurementDefinitions, MeasurementEvaluation,
    MeasurementEvaluationError, MeasurementRuntimeSample, MeasurementTerminalState,
    evaluate_measurements, verify_measurement_evaluation,
};
use crucible_campaign::{
    CampaignCodecError, CampaignHash, CampaignPolicy, MeasurementSet, ObjectiveEvaluation,
    ObjectiveValue, Observation, PropertyVerdictSet, evaluate_objectives,
};
use crucible_cas::content_store::ContentId;

/// Payload schema for a canonical Crucible measurement evaluation v1 body.
pub const CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V1: u32 = 1;

/// Failure while binding or verifying a Crucible measurement evaluation.
#[derive(Debug, thiserror::Error)]
pub enum CrucibleMeasurementError {
    /// The campaign record is a legacy claimed-series map, not a verified payload.
    #[error("legacy campaign measurement sets are not verified Crucible evaluations")]
    LegacyMeasurementSet,
    /// The measurement set names an unsupported Crucible payload schema.
    #[error("unsupported Crucible measurement payload schema {actual}; expected {expected}")]
    UnsupportedPayloadSchema {
        /// Unsupported retained schema.
        actual: u32,
        /// Exact schema implemented by this adapter.
        expected: u32,
    },
    /// The retained definition identity differs from the supplied scenario component.
    #[error("Crucible measurement definition identity does not match the campaign record")]
    DefinitionIdentityMismatch,
    /// The retained evaluation identity differs from exact replay output.
    #[error("Crucible measurement evaluation identity does not match the campaign record")]
    EvaluationIdentityMismatch,
    /// Pure evaluation or exact replay verification failed.
    #[error(transparent)]
    Evaluation(#[from] MeasurementEvaluationError),
    /// Campaign record construction rejected the verified payload.
    #[error(transparent)]
    Campaign(#[from] CampaignCodecError),
    /// More than one measurement/metric pair maps to the same policy name.
    #[error("Crucible objective name `{name}` is ambiguous")]
    AmbiguousObjectiveName {
        /// Ambiguous policy objective name.
        name: String,
    },
    /// A policy objective names a non-scalar aggregate.
    #[error("Crucible objective `{name}` has a nonnumeric aggregate")]
    NonnumericObjective {
        /// Rejected policy objective name.
        name: String,
    },
}

/// Encodes one already-verified Crucible evaluation as measurement-set v2.
///
/// `evidence` contains immutable campaign objects needed to reproduce or audit
/// the evaluation. The caller must supply the complete set required by its
/// execution-model retention policy.
///
/// # Errors
///
/// Returns [`CrucibleMeasurementError`] when the bounded campaign record cannot
/// retain the canonical evaluation or its evidence children.
pub fn encode_crucible_measurement_set(
    evaluation: &MeasurementEvaluation,
    evidence: BTreeSet<ContentId>,
) -> Result<MeasurementSet, CrucibleMeasurementError> {
    MeasurementSet::from_evaluation(
        campaign_hash(evaluation.definitions()),
        CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V1,
        campaign_hash(evaluation.content_hash()),
        evaluation.canonical_bytes().to_vec(),
        evidence,
    )
    .map_err(Into::into)
}

/// Evaluates one Crucible run and encodes the exact campaign measurement set.
///
/// # Errors
///
/// Returns [`CrucibleMeasurementError`] for invalid replay inputs, exceeded
/// evaluation bounds, exact-arithmetic failures, or campaign record limits.
pub fn evaluate_crucible_measurement_set(
    definitions: &MeasurementDefinitions,
    entries: &[SchedulerEventLogEntry],
    samples: Vec<MeasurementRuntimeSample>,
    terminal: &MeasurementTerminalState,
    evidence: BTreeSet<ContentId>,
) -> Result<MeasurementSet, CrucibleMeasurementError> {
    let evaluation = evaluate_measurements(definitions, entries, samples, terminal)?;
    encode_crucible_measurement_set(&evaluation, evidence)
}

/// Recomputes and authenticates one retained Crucible measurement-set payload.
///
/// # Errors
///
/// Returns [`CrucibleMeasurementError`] for a legacy or unsupported payload,
/// mismatched definition/evaluation identities, or any exact replay failure.
pub fn verify_crucible_measurement_set(
    measurement_set: &MeasurementSet,
    definitions: &MeasurementDefinitions,
    entries: &[SchedulerEventLogEntry],
    samples: Vec<MeasurementRuntimeSample>,
    terminal: &MeasurementTerminalState,
) -> Result<MeasurementEvaluation, CrucibleMeasurementError> {
    let retained = measurement_set
        .evaluation()
        .ok_or(CrucibleMeasurementError::LegacyMeasurementSet)?;
    if retained.payload_schema() != CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V1 {
        return Err(CrucibleMeasurementError::UnsupportedPayloadSchema {
            actual: retained.payload_schema(),
            expected: CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V1,
        });
    }
    if retained.definitions() != campaign_hash(definitions.content_hash()) {
        return Err(CrucibleMeasurementError::DefinitionIdentityMismatch);
    }

    let evaluation =
        verify_measurement_evaluation(definitions, entries, samples, terminal, retained.payload())?;
    if retained.evaluation() != campaign_hash(evaluation.content_hash()) {
        return Err(CrucibleMeasurementError::EvaluationIdentityMismatch);
    }
    Ok(evaluation)
}

/// Projects numeric aggregates from a verified Crucible evaluation.
///
/// Policy objective names use the exact `measurement-id.metric-id` spelling.
/// Since both component identifiers may themselves contain `.`, the adapter
/// fails closed if two declared pairs would produce the same qualified name.
/// Missing objectives are omitted so generic campaign evaluation retains them
/// as explicit filtering evidence.
///
/// # Errors
///
/// Returns [`CrucibleMeasurementError::AmbiguousObjectiveName`] for a qualified
/// name collision or [`CrucibleMeasurementError::NonnumericObjective`] when a
/// referenced aggregate is Boolean, enumerated, vector, or histogram-valued.
pub fn project_crucible_objective_values(
    evaluation: &MeasurementEvaluation,
    policy: &CampaignPolicy,
) -> Result<BTreeMap<String, ObjectiveValue>, CrucibleMeasurementError> {
    let mut values = BTreeMap::new();
    for (measurement, outcome) in evaluation.outcomes() {
        for (metric, outcome) in outcome.metrics() {
            let name = format!("{measurement}.{metric}");
            if !policy.objectives().contains_key(&name) {
                continue;
            }
            let value = match outcome.aggregate() {
                MeasurementAggregateValue::Signed(value) => ObjectiveValue::Signed(*value),
                MeasurementAggregateValue::Unsigned(value) => ObjectiveValue::Unsigned(*value),
                MeasurementAggregateValue::Rational(value) => ObjectiveValue::rational(
                    value.is_negative(),
                    value.numerator(),
                    value.denominator(),
                )?,
                MeasurementAggregateValue::Boolean(_)
                | MeasurementAggregateValue::Enumerated(_)
                | MeasurementAggregateValue::SignedVector(_)
                | MeasurementAggregateValue::UnsignedVector(_)
                | MeasurementAggregateValue::Histogram(_) => {
                    return Err(CrucibleMeasurementError::NonnumericObjective { name });
                }
            };
            if values.insert(name.clone(), value).is_some() {
                return Err(CrucibleMeasurementError::AmbiguousObjectiveName { name });
            }
        }
    }
    Ok(values)
}

/// Evaluates one verified Crucible measurement result under campaign policy.
///
/// The retained measurement set and typed evaluation must identify one another
/// exactly, and the observation must name that set. This function is the
/// execution-model semantic boundary; the generic campaign ranker never parses
/// Crucible-specific payload bytes.
///
/// # Errors
///
/// Returns [`CrucibleMeasurementError`] for unsupported or mismatched payload
/// identity, observation mismatch, ambiguous/nonnumeric objective sources, or
/// generic exact-evaluation bounds and invariants.
pub fn evaluate_crucible_objectives(
    measurement_set: &MeasurementSet,
    evaluation: &MeasurementEvaluation,
    policy: &CampaignPolicy,
    observation: &Observation,
    properties: &PropertyVerdictSet,
) -> Result<ObjectiveEvaluation, CrucibleMeasurementError> {
    let retained = measurement_set
        .evaluation()
        .ok_or(CrucibleMeasurementError::LegacyMeasurementSet)?;
    if retained.payload_schema() != CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V1 {
        return Err(CrucibleMeasurementError::UnsupportedPayloadSchema {
            actual: retained.payload_schema(),
            expected: CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V1,
        });
    }
    if retained.definitions() != campaign_hash(evaluation.definitions()) {
        return Err(CrucibleMeasurementError::DefinitionIdentityMismatch);
    }
    if retained.evaluation() != campaign_hash(evaluation.content_hash())
        || retained.payload() != evaluation.canonical_bytes()
    {
        return Err(CrucibleMeasurementError::EvaluationIdentityMismatch);
    }
    if measurement_set.id()? != observation.measurements() {
        return Err(CrucibleMeasurementError::Campaign(
            CampaignCodecError::InvalidValue {
                reason: "objective measurement set disagrees with observation",
            },
        ));
    }
    let values = project_crucible_objective_values(evaluation, policy)?;
    evaluate_objectives(policy, observation, properties, values).map_err(Into::into)
}

const fn campaign_hash(value: crucible::ContentHash) -> CampaignHash {
    CampaignHash::from_bytes(value.bytes)
}

#[cfg(test)]
mod tests;
