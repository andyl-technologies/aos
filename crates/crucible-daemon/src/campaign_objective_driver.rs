//! Admission-ordered objective publication ahead of campaign supervision.
//!
//! Beam selection consumes only policy evaluations indexed by the repository.
//! This driver drains one accepted unevaluated observation per bounded runtime
//! step before allowing the planner or executor supervisor to advance. Crucible
//! measurement payload v2 is replayed from its authenticated raw evidence leaf;
//! legacy payloads publish explicit missing-measurement rejections through the
//! generic evaluator so they cannot enter a Beam survivor set silently.

use std::collections::BTreeMap;
use std::sync::Arc;

use crucible_campaign::{
    CampaignRepository, CampaignRepositoryError, ObjectiveEvaluationCursor,
    ObjectiveEvaluationInput, evaluate_objectives,
};

use crate::{
    CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V2, CampaignRuntimeDriver,
    CampaignRuntimeStepDisposition, CrucibleArtifactError, CrucibleMeasurementError,
    CrucibleMeasurementReplayEvidence, MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES,
    decode_crucible_scenario_artifact, evaluate_crucible_objectives,
    verify_crucible_measurement_publication,
};

/// Runtime driver that publishes one objective evaluation before inner work.
pub struct ObjectivePublishingCampaignDriver<D> {
    repository: Arc<CampaignRepository>,
    campaign: String,
    cursor: Option<ObjectiveEvaluationCursor>,
    inner: D,
}

const OBJECTIVE_EVALUATION_SCAN_PAGE_ITEMS: u32 = 1_024;

impl<D> ObjectivePublishingCampaignDriver<D> {
    /// Wraps one campaign driver with admission-ordered evaluation publication.
    #[must_use]
    pub fn new(repository: Arc<CampaignRepository>, campaign: String, inner: D) -> Self {
        Self {
            repository,
            campaign,
            cursor: None,
            inner,
        }
    }

    /// Consumes the wrapper and returns the underlying campaign driver.
    #[must_use]
    pub fn into_inner(self) -> D {
        self.inner
    }
}

impl<D> CampaignRuntimeDriver for ObjectivePublishingCampaignDriver<D>
where
    D: CampaignRuntimeDriver,
{
    type Error = ObjectivePublishingCampaignDriverError<D::Error>;

    fn step(&mut self) -> Result<CampaignRuntimeStepDisposition, Self::Error> {
        if publish_next_objective_evaluation(&self.repository, &self.campaign, &mut self.cursor)? {
            return Ok(CampaignRuntimeStepDisposition::Continue);
        }
        self.inner
            .step()
            .map_err(ObjectivePublishingCampaignDriverError::Inner)
    }
}

/// Publishes at most one active-policy evaluation in admission order.
///
/// Returns `true` when one evaluation was published or replayed, one bounded
/// scan page was consumed, or a concurrent owner required a scan restart. The
/// caller can make immediate progress in each case. Returns `false` only when
/// the exact cursor-bound admission view is complete.
///
/// # Errors
///
/// Returns an error when repository authentication, Crucible evidence replay,
/// scenario decoding, generic evaluation, or publication fails.
pub fn publish_next_objective_evaluation(
    repository: &CampaignRepository,
    campaign: &str,
    cursor: &mut Option<ObjectiveEvaluationCursor>,
) -> Result<bool, ObjectiveEvaluationDriverError> {
    let page = repository.scan_objective_evaluation_inputs(
        campaign,
        cursor.clone(),
        OBJECTIVE_EVALUATION_SCAN_PAGE_ITEMS,
    )?;
    let next_cursor = page.cursor();
    let complete = page.complete();
    let Some(input) = page.into_input() else {
        *cursor = Some(next_cursor);
        return Ok(!complete);
    };
    let evaluation = evaluate_input(repository, &input)?;
    match repository.publish_objective_evaluation(campaign, input.snapshot(), &evaluation) {
        Ok(_) => {
            *cursor = Some(next_cursor);
            Ok(true)
        }
        Err(
            CampaignRepositoryError::Stale { .. } | CampaignRepositoryError::RefConflict { .. },
        ) => {
            *cursor = None;
            Ok(true)
        }
        Err(error) => Err(error.into()),
    }
}

fn evaluate_input(
    repository: &CampaignRepository,
    input: &ObjectiveEvaluationInput,
) -> Result<crucible_campaign::ObjectiveEvaluation, ObjectiveEvaluationDriverError> {
    let Some(retained) = input.measurements().evaluation() else {
        return evaluate_objectives(
            input.policy(),
            input.observation(),
            input.properties(),
            BTreeMap::new(),
        )
        .map_err(ObjectiveEvaluationDriverError::Campaign);
    };
    if input.policy().objectives().is_empty()
        || retained.payload_schema() != CRUCIBLE_MEASUREMENT_EVALUATION_PAYLOAD_SCHEMA_V2
    {
        return evaluate_objectives(
            input.policy(),
            input.observation(),
            input.properties(),
            BTreeMap::new(),
        )
        .map_err(ObjectiveEvaluationDriverError::Campaign);
    }

    let mut evidence = retained.evidence().iter();
    let evidence_id = match (evidence.next(), evidence.next()) {
        (Some(evidence_id), None) => *evidence_id,
        _ => {
            return Err(
                ObjectiveEvaluationDriverError::InvalidReplayEvidenceCardinality {
                    actual: retained.evidence().len(),
                },
            );
        }
    };
    let evidence_bytes = repository.read_objective_evidence_leaf(
        input,
        evidence_id,
        MAX_CRUCIBLE_MEASUREMENT_REPLAY_EVIDENCE_BYTES as u64,
    )?;
    let evidence = CrucibleMeasurementReplayEvidence::from_canonical_bytes(&evidence_bytes)?;
    let scenario = decode_crucible_scenario_artifact(input.scenario())?;
    let evaluation = verify_crucible_measurement_publication(
        input.measurements(),
        &evidence,
        input.configuration().scenario(),
        input.configuration().configuration(),
        scenario.measurements(),
    )?;
    evaluate_crucible_objectives(
        input.measurements(),
        &evaluation,
        input.policy(),
        input.observation(),
        input.properties(),
    )
    .map_err(Into::into)
}

/// Failure while preparing one exact objective evaluation.
#[derive(Debug, thiserror::Error)]
pub enum ObjectiveEvaluationDriverError {
    /// The retained v2 measurement payload did not name exactly one replay leaf.
    #[error("Crucible measurement payload v2 named {actual} replay evidence leaves; expected one")]
    InvalidReplayEvidenceCardinality {
        /// Number of evidence leaves named by the retained payload.
        actual: usize,
    },
    /// Repository evidence loading or authentication failed.
    #[error(transparent)]
    Repository(#[from] CampaignRepositoryError),
    /// Crucible scenario decoding failed.
    #[error(transparent)]
    Artifact(#[from] CrucibleArtifactError),
    /// Crucible measurement replay or objective projection failed.
    #[error(transparent)]
    Measurement(#[from] CrucibleMeasurementError),
    /// Generic objective evaluation rejected the canonical input.
    #[error(transparent)]
    Campaign(#[from] crucible_campaign::CampaignCodecError),
}

/// Failure from evaluation publication or the wrapped runtime driver.
#[derive(Debug, thiserror::Error)]
pub enum ObjectivePublishingCampaignDriverError<E> {
    /// Repository scanning or publication failed.
    #[error(transparent)]
    Repository(#[from] CampaignRepositoryError),
    /// Execution-model objective evaluation failed.
    #[error(transparent)]
    Evaluation(#[from] ObjectiveEvaluationDriverError),
    /// The wrapped campaign driver failed.
    #[error("campaign supervisor failed")]
    Inner(#[source] E),
}
