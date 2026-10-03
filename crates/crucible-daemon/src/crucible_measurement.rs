//! Crucible measurement-evaluation payloads retained by campaign observations.
//!
//! The campaign record layer deliberately treats execution-model evaluations
//! as opaque bytes. This adapter is the semantic boundary that converts a
//! verified Crucible evaluation into measurement-set schema v2 and recomputes
//! it from authenticated scheduler entries before accepting retained bytes.

use std::collections::BTreeMap;

use crucible::model::{
    MeasurementAggregateValue, MeasurementEvaluation, MeasurementEvaluationError,
};
#[cfg(test)]
use crucible::model::{MeasurementDefinitions, MeasurementTerminalState};
use crucible_campaign::{
    CampaignCodecError, CampaignHash, CampaignPolicy, MeasurementSet, ObjectiveEvaluation,
    ObjectiveValue, Observation, PropertyVerdictSet, evaluate_objectives,
};
use crucible_cas::content_store::ContentId;

mod evidence;

pub(crate) use evidence::{
    observation_event_prefix_digest, verified_assertion_transition,
    verify_assertion_failure_boundary,
};

pub use evidence::{
    CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V2,
    CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_SCHEMA_V2, CrucibleMeasurementPublication,
    CrucibleMeasurementReplayEvidence, CrucibleMeasurementStopEvidence,
    CrucibleObservationBoundaryEvidence, MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES,
    derive_crucible_measurement_samples, evaluate_crucible_measurement_publication,
    evaluate_crucible_observation_measurement_publication, verify_crucible_measurement_publication,
};

/// Failure while binding or verifying a Crucible measurement evaluation.
#[derive(Debug, thiserror::Error)]
pub enum CrucibleMeasurementError {
    /// The measurement set names an unsupported Crucible payload schema.
    #[error("unsupported Crucible measurement payload schema {actual}; expected {expected}")]
    UnsupportedPayloadSchema {
        /// Unsupported retained schema.
        actual: u32,
        /// Exact schema implemented by this adapter.
        expected: u32,
    },
    /// The raw replay leaf names an unsupported schema.
    #[error("unsupported Crucible measurement evidence schema {actual}; expected {expected}")]
    UnsupportedEvidenceSchema {
        /// Unsupported retained schema.
        actual: u32,
        /// Exact schema implemented by this adapter.
        expected: u32,
    },
    /// Canonical raw replay evidence exceeded its operational bound.
    #[error("Crucible measurement evidence has {actual} bytes; maximum is {maximum}")]
    EvidenceTooLarge {
        /// Actual encoded or input byte length.
        actual: usize,
        /// Active format or caller-selected ceiling.
        maximum: usize,
    },
    /// Canonical evidence CBOR could not be encoded or decoded.
    #[error("Crucible measurement evidence encoding failed: {reason}")]
    EvidenceEncoding {
        /// Stable serializer or parser detail.
        reason: String,
    },
    /// Decoded evidence was valid CBOR but not its unique canonical encoding.
    #[error("Crucible measurement evidence is not canonically encoded")]
    NonCanonicalEvidence,
    /// Raw evidence was replayed against a different semantic owner.
    #[error("Crucible measurement evidence {binding} binding does not match")]
    EvidenceBindingMismatch {
        /// Mismatched scenario, configuration, or definition binding.
        binding: &'static str,
    },
    /// The measurement set does not own exactly its one raw replay leaf.
    #[error("Crucible measurement set has {actual_count} evidence edges; expected only {expected}")]
    ReplayEvidenceSetMismatch {
        /// Required singleton trace identity.
        expected: ContentId,
        /// Actual number of retained evidence edges.
        actual_count: usize,
    },
    /// A typed guest measurement message violated its scenario contract.
    #[error("Crucible guest measurement protocol failed at sequence {sequence}: {reason}")]
    GuestMeasurementProtocol {
        /// Exact scheduler sequence carrying the invalid message.
        sequence: u64,
        /// Stable validation detail.
        reason: String,
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

#[cfg(test)]
pub(crate) fn empty_test_measurement_set() -> MeasurementSet {
    let publication = evaluate_crucible_measurement_publication(
        crucible_campaign::ScenarioDefId::from_hash(CampaignHash::derive(
            "crucible.test.measurement-scenario",
            b"empty",
        )),
        crucible_campaign::ConfigurationId::from_hash(CampaignHash::derive(
            "crucible.test.measurement-configuration",
            b"empty",
        )),
        &MeasurementDefinitions::empty(),
        Vec::new(),
        MeasurementTerminalState {
            scenario_ready_at: None,
            at: Default::default(),
            node_icounts: BTreeMap::new(),
            scheduler_quiescent: true,
        },
        MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES,
    );
    let Ok(publication) = publication else {
        panic!("empty test measurement publication must be valid: {publication:?}");
    };

    publication.measurement_set().clone()
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
    let retained = measurement_set.evaluation();
    if retained.payload_schema() != CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V2 {
        return Err(CrucibleMeasurementError::UnsupportedPayloadSchema {
            actual: retained.payload_schema(),
            expected: CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V2,
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
