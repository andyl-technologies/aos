//! Durable reconstruction of one source-stage plan admitted at stage entry.
//!
//! The image template fixes package and source authority. An independently
//! authenticated root observation fixes the live provider assignments. This
//! record retains their exact plan and pure constructor transcript so recovery
//! can replay the plan without executing provider constructors again.

use aos_ability_model::{EffectPlanDocument, EnvironmentDocument, PlanId};
use aos_ability_validate::CheckedEffectPlan;
use aos_contract::Sha256Digest;
use aos_contract::limits::BoundedWriter;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{CompositionEvaluator, TransitionError, TransitionEvaluation, TransitionPlanner};

use super::{
    SOURCE_STAGE_BUNDLE_MAX_BYTES, SourceStageBundle, SourceStageBundleError, source_stage_limits,
};

/// Schema for the plan admitted from an immutable source-stage template.
pub const SOURCE_STAGE_ADMISSION_SCHEMA: &str = "aos.ability.source-stage-admission/v1";

/// Retains the exact boot-time root inventory and source-authored plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceStageAdmission {
    schema: String,
    template: Sha256Digest,
    observed_environment: EnvironmentDocument,
    effect_plan: PlanId,
    effect_document: EffectPlanDocument,
    evaluations: Vec<TransitionEvaluation>,
}

/// Carries a replayed, executable source-stage plan and its retained record.
#[derive(Debug)]
pub struct CheckedSourceStageAdmission {
    admission: SourceStageAdmission,
    digest: Sha256Digest,
    plan: CheckedEffectPlan,
}

/// Reports why an admitted source-stage plan cannot be reconstructed.
#[derive(Debug, Error)]
pub enum SourceStageAdmissionError {
    /// The retained admission is malformed or exceeds its document bound.
    #[error("source-stage admission decoding failed: {0}")]
    Decode(#[source] anyhow::Error),
    /// Canonical serialization failed.
    #[error("source-stage admission encoding failed: {0}")]
    Encode(#[source] anyhow::Error),
    /// The encoded admission exceeds its explicit bound.
    #[error("source-stage admission exceeds its encoded byte limit")]
    EncodedSizeLimit,
    /// The admission uses another schema.
    #[error("source-stage admission has an unsupported schema")]
    UnsupportedSchema,
    /// The supplied JSON is not the canonical representation.
    #[error("source-stage admission is not canonically encoded")]
    NoncanonicalEncoding,
    /// The admission differs from an independently retained commitment.
    #[error("source-stage admission differs from its external commitment")]
    CommitmentMismatch,
    /// The immutable template differs from the one admitted at stage entry.
    #[error("source-stage admission names another image template")]
    TemplateMismatch,
    /// A fresh root observation differs from the admitted assignment.
    #[error("source-stage admission names another root observation")]
    ObservationMismatch,
    /// The retained graph differs from the replayed constructor transcript.
    #[error("source-stage admission names another effect graph")]
    PlanMismatch,
    /// The image template or observed binding did not validate.
    #[error("source-stage admission source is invalid: {0}")]
    Source(#[from] SourceStageBundleError),
    /// A retained constructor exchange did not replay exactly.
    #[error("source-stage admission transition is invalid: {0}")]
    Transition(#[from] TransitionError),
}

impl SourceStageBundle {
    /// Retains one executable plan constructed from an authenticated root view.
    ///
    /// The caller must authenticate and freshness-check `observed` before this
    /// call. The resulting record still requires a fresh matching observation
    /// during recovery; possession of its bytes is not proof of live readiness.
    ///
    /// # Errors
    ///
    /// Returns an error when the source template, root inventory, constructor
    /// results, or reconstructed executable plan is invalid.
    pub fn admit_from_trusted_environment(
        &self,
        observed: EnvironmentDocument,
        evaluator: &mut impl CompositionEvaluator,
    ) -> Result<SourceStageAdmission, SourceStageAdmissionError> {
        let transition = self.instantiate_from_trusted_environment(observed.clone(), evaluator)?;
        let admission = SourceStageAdmission {
            schema: SOURCE_STAGE_ADMISSION_SCHEMA.to_string(),
            template: self.digest()?,
            observed_environment: observed.clone(),
            effect_plan: transition.checked_effect().id(),
            effect_document: transition.checked_effect().document().clone(),
            evaluations: transition.evaluations().to_vec(),
        };
        admission.clone().check(self, observed, None)?;
        Ok(admission)
    }
}

impl SourceStageAdmission {
    /// Returns the exact source template commitment.
    #[must_use]
    pub const fn template(&self) -> Sha256Digest {
        self.template
    }

    /// Returns the admitted root inventory retained for recovery comparison.
    #[must_use]
    pub const fn observed_environment(&self) -> &EnvironmentDocument {
        &self.observed_environment
    }

    /// Returns the identity of the admitted effect graph.
    #[must_use]
    pub const fn effect_plan(&self) -> PlanId {
        self.effect_plan
    }

    /// Encodes the admission in bounded canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns an error when serialization fails or exceeds the stage bound.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SourceStageAdmissionError> {
        if self.schema != SOURCE_STAGE_ADMISSION_SCHEMA {
            return Err(SourceStageAdmissionError::UnsupportedSchema);
        }
        let mut writer = BoundedWriter::new(
            SOURCE_STAGE_BUNDLE_MAX_BYTES as u64,
            "serialized source-stage admission exceeds its byte limit",
        );
        serde_json::to_writer(&mut writer, self).map_err(|error| {
            if writer.exceeded() {
                SourceStageAdmissionError::EncodedSizeLimit
            } else {
                SourceStageAdmissionError::Encode(error.into())
            }
        })?;
        aos_contract::canonical::to_vec(self).map_err(SourceStageAdmissionError::Encode)
    }

    /// Computes the domain-separated commitment to the admitted plan.
    ///
    /// # Errors
    ///
    /// Returns an error when canonical encoding fails.
    pub fn digest(&self) -> Result<Sha256Digest, SourceStageAdmissionError> {
        Ok(Sha256Digest::separated(
            SOURCE_STAGE_ADMISSION_SCHEMA,
            self.canonical_bytes()?,
        ))
    }

    /// Decodes a canonical, bounded admission record.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, malformed, or noncanonical input.
    pub fn decode(bytes: &[u8]) -> Result<Self, SourceStageAdmissionError> {
        let admission = source_stage_limits()
            .decode::<Self>(bytes, SOURCE_STAGE_ADMISSION_SCHEMA)
            .map_err(SourceStageAdmissionError::Decode)?;
        if admission.schema != SOURCE_STAGE_ADMISSION_SCHEMA {
            return Err(SourceStageAdmissionError::UnsupportedSchema);
        }
        if admission.canonical_bytes()? != bytes {
            return Err(SourceStageAdmissionError::NoncanonicalEncoding);
        }
        Ok(admission)
    }

    /// Replays the admitted plan against an independently authenticated root view.
    ///
    /// The caller must freshly authenticate `current_observed`; equality with
    /// the retained observation prevents recovery from silently changing a
    /// transaction's provider assignments. Replay uses retained pure results
    /// and does not invoke a provider constructor.
    ///
    /// # Errors
    ///
    /// Returns an error when the record commitment, source template, live
    /// observation, constructor transcript, or effect graph differs.
    pub fn check(
        self,
        template: &SourceStageBundle,
        current_observed: EnvironmentDocument,
        expected_digest: Option<Sha256Digest>,
    ) -> Result<CheckedSourceStageAdmission, SourceStageAdmissionError> {
        let digest = self.digest()?;
        if expected_digest.is_some_and(|expected| expected != digest) {
            return Err(SourceStageAdmissionError::CommitmentMismatch);
        }
        if self.template != template.digest()? {
            return Err(SourceStageAdmissionError::TemplateMismatch);
        }
        if self.observed_environment != current_observed {
            return Err(SourceStageAdmissionError::ObservationMismatch);
        }

        let (context, binding) = template.runtime_binding(current_observed)?;
        let transition = TransitionPlanner::new(&context).verify_source_transcript(
            template.authority,
            &binding,
            &template.fixed_point,
            &self.evaluations,
            self.effect_plan,
        )?;
        let plan = transition.checked_effect().clone();
        if !plan.is_executable() || plan.document() != &self.effect_document {
            return Err(SourceStageAdmissionError::PlanMismatch);
        }

        Ok(CheckedSourceStageAdmission {
            admission: self,
            digest,
            plan,
        })
    }
}

impl CheckedSourceStageAdmission {
    /// Returns the retained admission record.
    #[must_use]
    pub const fn admission(&self) -> &SourceStageAdmission {
        &self.admission
    }

    /// Returns the canonical admission commitment.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// Returns the replayed executable effect plan.
    #[must_use]
    pub const fn plan(&self) -> &CheckedEffectPlan {
        &self.plan
    }
}
