//! Canonical transition snapshots and replay verification.
//!
//! The retained format commits verified planning inputs to the exact evaluator
//! transcript and checked effect document:
//!
//! ```text
//! {"schema":"aos.ability.transition-snapshot/v1",
//!  "desired_planning":"sha256:...","current_planning":null,
//!  "evaluations":[...],"effect_plan":"sha256:...","effect_document":{...}}
//! ```

use std::io::{self, Write};

use aos_ability_model::{
    ABILITY_LIMITS_V1, AbilityValue, EffectPlanDocument, InstanceId, LocalKey, PlanId,
    ProviderImplementationReference, VersionedDocument, encode_canonical,
};
use aos_ability_validate::CheckedEffectPlan;
use aos_ability_validate::CheckedTransitionAuthority;
use aos_contract::Sha256Digest;
use aos_contract::limits::JsonLimits;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{CompositionEvaluator, EvaluationError, VerifiedPlanningSnapshot};

use super::{TransitionError, TransitionInputs, TransitionPlanner};

/// Exact schema discriminator for retained transition-construction provenance.
pub const TRANSITION_SNAPSHOT_SCHEMA: &str = "aos.ability.transition-snapshot/v1";

const TRANSITION_SNAPSHOT_COMPONENT_LIMIT: usize = 4;

/// Maximum encoded byte length accepted for one retained transition snapshot.
pub const TRANSITION_SNAPSHOT_MAX_BYTES: usize = (ABILITY_LIMITS_V1.max_document_bytes as usize)
    .saturating_mul(TRANSITION_SNAPSHOT_COMPONENT_LIMIT);

/// Records one exact pure transition-constructor exchange.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionEvaluation {
    /// Identifies the provider whose implementation was evaluated.
    pub provider: InstanceId,
    /// Pins the exact selected implementation descriptor and artifact.
    pub implementation: ProviderImplementationReference,
    /// Names the exact pure transition entry point invoked.
    pub entry: LocalKey,
    /// Retains the canonical scoped before-and-after transition context.
    pub input: AbilityValue,
    /// Retains the exact returned value or bounded adapter failure.
    pub result: TransitionEvaluationResult,
}

/// Retains the exact result of one restricted pure transition evaluation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TransitionEvaluationResult {
    /// The evaluator returned one bounded fragment value.
    Returned {
        /// Carries the exact returned value before fragment decoding.
        value: AbilityValue,
    },
    /// The evaluator rejected the selected implementation.
    Failed {
        /// Carries the bounded deterministic adapter message.
        message: String,
    },
}

/// Owns bounded, replayable provenance for one verified transition plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionSnapshot {
    schema: String,
    desired_planning: Sha256Digest,
    current_planning: Option<Sha256Digest>,
    transition_authority: Option<Sha256Digest>,
    evaluations: Vec<TransitionEvaluation>,
    effect_plan: PlanId,
    effect_document: EffectPlanDocument,
}

/// Carries a checked effect graph reconstructed from authenticated planning inputs.
///
/// The wrapper cannot be constructed outside this module. Its planning and
/// transition digests therefore identify the exact verified inputs and pure
/// constructor transcript from which the checked graph was derived.
#[derive(Debug)]
pub struct VerifiedTransitionPlan {
    pub(super) snapshot_digest: Sha256Digest,
    pub(super) snapshot: TransitionSnapshot,
    pub(super) checked_effect: CheckedEffectPlan,
}

/// Supplies independently verified inputs for transition-snapshot replay.
pub struct TransitionReplayInputs<'a> {
    /// Carries the transition-snapshot commitment from an approved record.
    pub expected_digest: Sha256Digest,
    /// Supplies the exact verified desired planning snapshot.
    pub desired: &'a VerifiedPlanningSnapshot,
    /// Supplies the exact verified prior planning snapshot, when one existed.
    pub current: Option<&'a VerifiedPlanningSnapshot>,
    /// Supplies sealed fresh teardown authority when prior bindings are used.
    pub authority: Option<&'a CheckedTransitionAuthority>,
}

impl VerifiedTransitionPlan {
    /// Returns the transition-snapshot commitment checked or created by planning.
    #[must_use]
    pub const fn snapshot_digest(&self) -> Sha256Digest {
        self.snapshot_digest
    }

    /// Returns the verified desired planning-snapshot commitment.
    #[must_use]
    pub const fn desired_planning_digest(&self) -> Sha256Digest {
        self.snapshot.desired_planning
    }

    /// Returns the verified prior planning-snapshot commitment, when present.
    #[must_use]
    pub const fn current_planning_digest(&self) -> Option<Sha256Digest> {
        self.snapshot.current_planning
    }

    /// Returns the fresh transition-authority commitment, when supplied.
    #[must_use]
    pub const fn transition_authority_digest(&self) -> Option<Sha256Digest> {
        self.snapshot.transition_authority
    }

    /// Returns the checked effect-plan identity linked by the snapshot.
    #[must_use]
    pub const fn effect_plan(&self) -> PlanId {
        self.snapshot.effect_plan
    }

    /// Returns the retained portable transition snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &TransitionSnapshot {
        &self.snapshot
    }

    /// Returns the freshly validated effect plan.
    #[must_use]
    pub const fn checked_effect(&self) -> &CheckedEffectPlan {
        &self.checked_effect
    }

    /// Consumes the verified wrapper and returns the checked effect plan.
    #[must_use]
    pub fn into_checked_effect(self) -> CheckedEffectPlan {
        self.checked_effect
    }
}

/// Reports why retained transition provenance cannot be encoded or trusted.
#[derive(Debug, Error)]
pub enum TransitionSnapshotError {
    /// Canonical snapshot encoding failed.
    #[error("transition snapshot encoding failed: {0}")]
    Encode(#[source] anyhow::Error),
    /// Bounded strict snapshot decoding failed.
    #[error("transition snapshot decoding failed: {0}")]
    Decode(#[source] anyhow::Error),
    /// The snapshot carries an unsupported schema discriminator.
    #[error("transition snapshot has an unsupported schema discriminator")]
    UnsupportedSchema,
    /// The encoded bytes are valid JSON but not their canonical representation.
    #[error("transition snapshot is not canonically encoded")]
    NoncanonicalEncoding,
    /// A retained digest, transcript, or effect-plan link is inconsistent.
    #[error("transition snapshot linkage is invalid: {0}")]
    InvalidLinkage(&'static str),
    /// Transition reconstruction failed against the verified planning inputs.
    #[error("transition snapshot replay failed: {0}")]
    Replay(#[source] TransitionError),
    /// The retained evaluator transcript did not match the replayed call sequence.
    #[error("transition snapshot evaluator transcript is invalid: {0}")]
    InvalidTranscript(String),
    /// Fresh reconstruction produced a different transition snapshot.
    #[error("transition snapshot replay produced a different outcome")]
    ReplayMismatch,
    /// The snapshot differs from the independently supplied commitment.
    #[error("transition snapshot differs from the expected external commitment")]
    CommitmentMismatch,
    /// A verified planning input differs from the snapshot commitment.
    #[error("transition snapshot planning commitment differs from verified input")]
    PlanningCommitmentMismatch,
}

impl TransitionSnapshot {
    pub(super) fn from_construction(
        desired: &VerifiedPlanningSnapshot,
        current: Option<&VerifiedPlanningSnapshot>,
        authority: Option<&CheckedTransitionAuthority>,
        evaluations: Vec<TransitionEvaluation>,
        checked_effect: &CheckedEffectPlan,
    ) -> Result<Self, TransitionSnapshotError> {
        let snapshot = Self {
            schema: TRANSITION_SNAPSHOT_SCHEMA.to_string(),
            desired_planning: desired.snapshot_digest(),
            current_planning: current.map(VerifiedPlanningSnapshot::snapshot_digest),
            transition_authority: authority.map(CheckedTransitionAuthority::digest),
            evaluations,
            effect_plan: checked_effect.id(),
            effect_document: checked_effect.document().clone(),
        };
        snapshot.validate_linkage()?;
        snapshot.canonical_bytes()?;
        Ok(snapshot)
    }

    /// Returns the desired planning-snapshot commitment.
    #[must_use]
    pub const fn desired_planning_digest(&self) -> Sha256Digest {
        self.desired_planning
    }

    /// Returns the prior planning-snapshot commitment, when one existed.
    #[must_use]
    pub const fn current_planning_digest(&self) -> Option<Sha256Digest> {
        self.current_planning
    }

    /// Returns the fresh transition-authority commitment, when supplied.
    #[must_use]
    pub const fn transition_authority_digest(&self) -> Option<Sha256Digest> {
        self.transition_authority
    }

    /// Returns every retained transition-constructor exchange.
    #[must_use]
    pub fn evaluations(&self) -> &[TransitionEvaluation] {
        &self.evaluations
    }

    /// Returns the checked effect-plan identity linked by the snapshot.
    #[must_use]
    pub const fn effect_plan(&self) -> PlanId {
        self.effect_plan
    }

    /// Returns the portable effect-plan document linked by the snapshot.
    #[must_use]
    pub const fn effect_document(&self) -> &EffectPlanDocument {
        &self.effect_document
    }

    /// Encodes the transition snapshot in the canonical AOS JSON dialect.
    ///
    /// # Errors
    ///
    /// Returns an error if the snapshot is malformed or exceeds a version-1
    /// structural, collection, string, or byte bound.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, TransitionSnapshotError> {
        self.validate_linkage()?;
        self.validate_bounded_structure()?;

        let mut writer = SnapshotBoundedWriter::new(TRANSITION_SNAPSHOT_MAX_BYTES);
        serde_json::to_writer(&mut writer, self).map_err(|error| {
            if writer.exceeded {
                TransitionSnapshotError::InvalidLinkage(
                    "encoded snapshot exceeds the version-1 byte limit",
                )
            } else {
                TransitionSnapshotError::Encode(error.into())
            }
        })?;
        encode_canonical(&self.effect_document)
            .map_err(|error| TransitionSnapshotError::Encode(error.into()))?;

        let bytes =
            aos_contract::canonical::to_vec(self).map_err(TransitionSnapshotError::Encode)?;
        transition_snapshot_limits()
            .decode::<serde_json::Value>(&bytes, TRANSITION_SNAPSHOT_SCHEMA)
            .map_err(TransitionSnapshotError::Encode)?;
        Ok(bytes)
    }

    /// Computes the domain-separated identity of the canonical snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error if canonical encoding fails or exceeds its bound.
    pub fn digest(&self) -> Result<Sha256Digest, TransitionSnapshotError> {
        Ok(Sha256Digest::separated(
            TRANSITION_SNAPSHOT_SCHEMA,
            self.canonical_bytes()?,
        ))
    }

    /// Decodes and validates one strictly bounded canonical transition snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, structurally invalid, unknown,
    /// noncanonical, or internally inconsistent input.
    pub fn decode(bytes: &[u8]) -> Result<Self, TransitionSnapshotError> {
        let snapshot = transition_snapshot_limits()
            .decode::<Self>(bytes, TRANSITION_SNAPSHOT_SCHEMA)
            .map_err(TransitionSnapshotError::Decode)?;
        if snapshot.schema != TRANSITION_SNAPSHOT_SCHEMA {
            return Err(TransitionSnapshotError::UnsupportedSchema);
        }
        if snapshot.canonical_bytes()? != bytes {
            return Err(TransitionSnapshotError::NoncanonicalEncoding);
        }
        snapshot.validate_linkage()?;
        Ok(snapshot)
    }

    /// Reconstructs the effect plan from the retained constructor transcript.
    ///
    /// The caller must independently anchor `expected_digest` and supply sealed
    /// desired and prior planning snapshots. Provider code is not executed.
    ///
    /// # Errors
    ///
    /// Returns an error if a commitment differs, the transcript is missing or
    /// out of order, construction fails, or the reconstructed graph differs.
    pub fn verify_structure(
        &self,
        planner: &TransitionPlanner<'_>,
        inputs: TransitionReplayInputs<'_>,
    ) -> Result<VerifiedTransitionPlan, TransitionSnapshotError> {
        self.validate_replay_inputs(&inputs)?;
        let mut evaluator = TransitionTranscriptEvaluator::new(&self.evaluations);
        let transition_inputs = TransitionInputs {
            current: inputs.current,
            authority: inputs.authority,
        };
        let (checked_effect, evaluations) = planner
            .construct(inputs.desired, &transition_inputs, &mut evaluator)
            .map_err(TransitionSnapshotError::Replay)?;
        evaluator.finish()?;
        self.verify_reconstruction(inputs.expected_digest, evaluations, checked_effect)
    }

    /// Replays construction by invoking the supplied exact provider evaluator.
    ///
    /// # Errors
    ///
    /// Returns an error if an independent commitment differs, provider
    /// evaluation or validation fails, or fresh construction differs.
    pub fn replay_with(
        &self,
        planner: &TransitionPlanner<'_>,
        inputs: TransitionReplayInputs<'_>,
        evaluator: &mut impl CompositionEvaluator,
    ) -> Result<VerifiedTransitionPlan, TransitionSnapshotError> {
        self.validate_replay_inputs(&inputs)?;
        let transition_inputs = TransitionInputs {
            current: inputs.current,
            authority: inputs.authority,
        };
        let (checked_effect, evaluations) = planner
            .construct(inputs.desired, &transition_inputs, evaluator)
            .map_err(TransitionSnapshotError::Replay)?;
        self.verify_reconstruction(inputs.expected_digest, evaluations, checked_effect)
    }

    fn validate_replay_inputs(
        &self,
        inputs: &TransitionReplayInputs<'_>,
    ) -> Result<(), TransitionSnapshotError> {
        if self.digest()? != inputs.expected_digest {
            return Err(TransitionSnapshotError::CommitmentMismatch);
        }
        if self.desired_planning != inputs.desired.snapshot_digest()
            || self.current_planning
                != inputs
                    .current
                    .map(VerifiedPlanningSnapshot::snapshot_digest)
        {
            return Err(TransitionSnapshotError::PlanningCommitmentMismatch);
        }
        if self.transition_authority != inputs.authority.map(CheckedTransitionAuthority::digest) {
            return Err(TransitionSnapshotError::PlanningCommitmentMismatch);
        }
        Ok(())
    }

    fn verify_reconstruction(
        &self,
        snapshot_digest: Sha256Digest,
        evaluations: Vec<TransitionEvaluation>,
        checked_effect: CheckedEffectPlan,
    ) -> Result<VerifiedTransitionPlan, TransitionSnapshotError> {
        let reconstructed = Self {
            schema: TRANSITION_SNAPSHOT_SCHEMA.to_string(),
            desired_planning: self.desired_planning,
            current_planning: self.current_planning,
            transition_authority: self.transition_authority,
            evaluations,
            effect_plan: checked_effect.id(),
            effect_document: checked_effect.document().clone(),
        };
        if reconstructed != *self {
            return Err(TransitionSnapshotError::ReplayMismatch);
        }
        Ok(VerifiedTransitionPlan {
            snapshot_digest,
            snapshot: reconstructed,
            checked_effect,
        })
    }

    fn validate_linkage(&self) -> Result<(), TransitionSnapshotError> {
        if self.schema != TRANSITION_SNAPSHOT_SCHEMA {
            return Err(TransitionSnapshotError::UnsupportedSchema);
        }
        let document_id = self
            .effect_document
            .content_digest()
            .map(PlanId)
            .map_err(|error| TransitionSnapshotError::Encode(error.into()))?;
        if document_id != self.effect_plan {
            return Err(TransitionSnapshotError::InvalidLinkage(
                "effect-plan identity differs from its document",
            ));
        }
        if self.evaluations.iter().any(|evaluation| {
            matches!(evaluation.result, TransitionEvaluationResult::Failed { .. })
        }) {
            return Err(TransitionSnapshotError::InvalidLinkage(
                "successful transition snapshot retains a failed evaluation",
            ));
        }
        if self.evaluations.windows(2).any(|pair| {
            (&pair[0].provider, pair[0].implementation.descriptor)
                >= (&pair[1].provider, pair[1].implementation.descriptor)
        }) {
            return Err(TransitionSnapshotError::InvalidLinkage(
                "transition evaluations are not in strict provider order",
            ));
        }
        Ok(())
    }

    fn validate_bounded_structure(&self) -> Result<(), TransitionSnapshotError> {
        let maximum_nodes = ABILITY_LIMITS_V1.max_graph_nodes as usize;
        if self.evaluations.len() > maximum_nodes {
            return Err(TransitionSnapshotError::InvalidLinkage(
                "snapshot exceeds the version-1 evaluation bound",
            ));
        }
        self.effect_document
            .validate_structure(&ABILITY_LIMITS_V1)
            .map_err(|error| TransitionSnapshotError::Encode(error.into()))?;
        let maximum_string = ABILITY_LIMITS_V1.max_string_bytes as usize;
        if self
            .evaluations
            .iter()
            .any(|evaluation| match &evaluation.result {
                TransitionEvaluationResult::Failed { message } => message.len() > maximum_string,
                TransitionEvaluationResult::Returned { .. } => false,
            })
        {
            return Err(TransitionSnapshotError::InvalidLinkage(
                "snapshot contains an oversized evaluator failure",
            ));
        }
        Ok(())
    }
}

struct TransitionTranscriptEvaluator<'a> {
    evaluations: &'a [TransitionEvaluation],
    next: usize,
    mismatch: Option<String>,
}

impl<'a> TransitionTranscriptEvaluator<'a> {
    const fn new(evaluations: &'a [TransitionEvaluation]) -> Self {
        Self {
            evaluations,
            next: 0,
            mismatch: None,
        }
    }

    fn finish(self) -> Result<(), TransitionSnapshotError> {
        if let Some(message) = self.mismatch {
            return Err(TransitionSnapshotError::InvalidTranscript(message));
        }
        if self.next != self.evaluations.len() {
            return Err(TransitionSnapshotError::InvalidTranscript(
                "retained transcript has unused evaluator exchanges".to_string(),
            ));
        }
        Ok(())
    }
}

impl CompositionEvaluator for TransitionTranscriptEvaluator<'_> {
    fn evaluate(
        &mut self,
        implementation: &ProviderImplementationReference,
        entry: &LocalKey,
        input: &AbilityValue,
    ) -> Result<AbilityValue, EvaluationError> {
        let Some(retained) = self.evaluations.get(self.next) else {
            let message = "replay requested an evaluator exchange absent from the transcript";
            self.mismatch = Some(message.to_string());
            return Err(EvaluationError::new(message));
        };
        self.next = self.next.saturating_add(1);
        if retained.implementation != *implementation
            || retained.entry != *entry
            || retained.input != *input
        {
            let message =
                "retained evaluator provider, implementation, entry, or input differs from replay";
            self.mismatch = Some(message.to_string());
            return Err(EvaluationError::new(message));
        }
        match &retained.result {
            TransitionEvaluationResult::Returned { value } => Ok(value.clone()),
            TransitionEvaluationResult::Failed { message } => {
                Err(EvaluationError::new(message.clone()))
            }
        }
    }
}

const fn transition_snapshot_limits() -> JsonLimits {
    JsonLimits {
        max_bytes: TRANSITION_SNAPSHOT_MAX_BYTES,
        max_depth: ABILITY_LIMITS_V1.max_structural_depth as usize + 4,
        max_items: (ABILITY_LIMITS_V1.max_collection_items as usize)
            .saturating_mul(TRANSITION_SNAPSHOT_COMPONENT_LIMIT),
        max_string_bytes: ABILITY_LIMITS_V1.max_string_bytes as usize,
    }
}

struct SnapshotBoundedWriter {
    remaining: usize,
    exceeded: bool,
}

impl SnapshotBoundedWriter {
    const fn new(remaining: usize) -> Self {
        Self {
            remaining,
            exceeded: false,
        }
    }
}

impl Write for SnapshotBoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            self.exceeded = true;
            return Err(io::Error::other(
                "serialized transition snapshot exceeds its byte limit",
            ));
        }
        self.remaining -= bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
