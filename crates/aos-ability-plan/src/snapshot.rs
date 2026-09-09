//! Canonical retained snapshots of recursive planning provenance.
//!
//! A snapshot retains the complete authenticated policy set, every restricted
//! evaluator exchange (including discarded search branches), and the final
//! successful pass chain. Structural verification replays resolution and
//! fragment validation against the retained transcript without executing
//! provider code. An optional live replay can invoke the exact evaluator again.

use std::io::{self, Write};

use aos_ability_model::{
    ABILITY_LIMITS_V1, BindingPlanDocument, DesiredStateDocument, EnvironmentDocument,
    PackageDocument, PlanId, VersionedDocument, encode_canonical,
};
use aos_ability_validate::CheckedBindingPlan;
use aos_contract::Sha256Digest;
use aos_contract::limits::JsonLimits;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CandidateRejection, CompositionError, CompositionEvaluation, CompositionEvaluationResult,
    CompositionEvaluator, CompositionOutcome, CompositionPass, EvaluationError, RecursiveComposer,
    ResolutionDecision, ResolutionPolicyDocument,
};

/// Exact schema discriminator for retained recursive planning provenance.
pub const PLANNING_SNAPSHOT_SCHEMA: &str = "aos.ability.planning-snapshot/v1";

const PLANNING_SNAPSHOT_COMPONENT_LIMIT: usize = 8;

/// Maximum encoded byte length accepted for one retained planning snapshot.
pub const PLANNING_SNAPSHOT_MAX_BYTES: usize = (ABILITY_LIMITS_V1.max_document_bytes as usize)
    .saturating_mul(PLANNING_SNAPSHOT_COMPONENT_LIMIT);

/// Retains the final provider-resolution result without validator-private indexes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionSnapshot {
    policy: ResolutionPolicyDocument,
    policy_digest: Sha256Digest,
    decisions: Vec<ResolutionDecision>,
    rejections: Vec<CandidateRejection>,
    binding_plan: PlanId,
    binding_document: BindingPlanDocument,
}

impl ResolutionSnapshot {
    /// Returns the exact authenticated final resolution policy.
    #[must_use]
    pub const fn policy(&self) -> &ResolutionPolicyDocument {
        &self.policy
    }

    /// Returns the canonical final resolution-policy identity.
    #[must_use]
    pub const fn policy_digest(&self) -> Sha256Digest {
        self.policy_digest
    }

    /// Returns accepted final provider decisions in canonical request order.
    #[must_use]
    pub fn decisions(&self) -> &[ResolutionDecision] {
        &self.decisions
    }

    /// Returns bounded final candidate rejections in encounter order.
    #[must_use]
    pub fn rejections(&self) -> &[CandidateRejection] {
        &self.rejections
    }

    /// Returns the semantically checked final binding-plan identity.
    #[must_use]
    pub const fn binding_plan(&self) -> PlanId {
        self.binding_plan
    }

    /// Returns the portable final binding-plan document.
    #[must_use]
    pub const fn binding_document(&self) -> &BindingPlanDocument {
        &self.binding_document
    }
}

/// Owns the bounded, replayable provenance of one recursive planning fixed point.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanningSnapshot {
    schema: String,
    seed: DesiredStateDocument,
    seed_digest: Sha256Digest,
    desired_state: DesiredStateDocument,
    desired_state_digest: Sha256Digest,
    policies: Vec<ResolutionPolicyDocument>,
    evaluations: Vec<CompositionEvaluation>,
    passes: Vec<CompositionPass>,
    resolution: ResolutionSnapshot,
}

/// Carries a freshly reconstructed result under an external snapshot commitment.
///
/// Structural verification establishes that retained evaluator values reproduce
/// the resolver and validator result. It proves provider execution only when the
/// external commitment came from a trusted initial evaluation. [`PlanningSnapshot::replay_with`]
/// additionally reruns the supplied exact evaluator.
#[derive(Debug)]
pub struct VerifiedPlanningSnapshot {
    snapshot_digest: Sha256Digest,
    outcome: CompositionOutcome,
}

impl VerifiedPlanningSnapshot {
    /// Returns the independently supplied commitment checked during replay.
    #[must_use]
    pub const fn snapshot_digest(&self) -> Sha256Digest {
        self.snapshot_digest
    }

    /// Returns the reconstructed fixed-point planning result.
    #[must_use]
    pub const fn outcome(&self) -> &CompositionOutcome {
        &self.outcome
    }

    /// Returns the freshly checked final binding plan.
    #[must_use]
    pub const fn checked_binding(&self) -> &CheckedBindingPlan {
        &self.outcome.resolution.checked
    }

    /// Consumes the verified wrapper and returns the reconstructed outcome.
    #[must_use]
    pub fn into_outcome(self) -> CompositionOutcome {
        self.outcome
    }
}

/// Supplies the independent inputs needed to reconstruct a planning snapshot.
pub struct PlanningReplayInputs<'a> {
    /// Carries the snapshot commitment from an approved plan or durable record.
    pub expected_digest: Sha256Digest,
    /// Supplies the exact independently authenticated policy set.
    pub authenticated_policies: &'a [ResolutionPolicyDocument],
    /// Supplies the original normalized desired-state document.
    pub seed: DesiredStateDocument,
    /// Supplies the authenticated environment snapshot used during planning.
    pub environment: EnvironmentDocument,
    /// Supplies the exact package documents used during planning.
    pub packages: Vec<PackageDocument>,
}

/// Reports why retained planning provenance cannot be encoded or trusted.
#[derive(Debug, Error)]
pub enum PlanningSnapshotError {
    /// Canonical snapshot encoding failed.
    #[error("planning snapshot encoding failed: {0}")]
    Encode(#[source] anyhow::Error),
    /// Bounded strict snapshot decoding failed.
    #[error("planning snapshot decoding failed: {0}")]
    Decode(#[source] anyhow::Error),
    /// The snapshot carries an unsupported schema discriminator.
    #[error("planning snapshot has an unsupported schema discriminator")]
    UnsupportedSchema,
    /// The encoded bytes are valid JSON but not their canonical representation.
    #[error("planning snapshot is not canonically encoded")]
    NoncanonicalEncoding,
    /// A retained digest, pass sequence, policy set, or final linkage is inconsistent.
    #[error("planning snapshot linkage is invalid: {0}")]
    InvalidLinkage(&'static str),
    /// Resolution or fragment validation did not reproduce the retained outcome.
    #[error("planning snapshot replay failed: {0}")]
    Replay(#[source] CompositionError),
    /// The retained evaluator transcript did not match the replayed call sequence.
    #[error("planning snapshot evaluator transcript is invalid: {0}")]
    InvalidTranscript(String),
    /// Fresh replay produced a different policy, transcript, pass, or binding result.
    #[error("planning snapshot replay produced a different planning outcome")]
    ReplayMismatch,
    /// The snapshot differs from the independently retained exact commitment.
    #[error("planning snapshot differs from the expected external commitment")]
    CommitmentMismatch,
    /// The snapshot policy set differs from independently authenticated policy input.
    #[error("planning snapshot policy set differs from authenticated policy input")]
    PolicySetMismatch,
}

impl PlanningSnapshot {
    /// Captures owned portable provenance from a successful composition outcome.
    ///
    /// # Errors
    ///
    /// Returns an error if a retained document cannot be canonically digested,
    /// the outcome's final records disagree, or the encoded snapshot exceeds
    /// the version-1 snapshot bound.
    pub fn from_outcome(outcome: &CompositionOutcome) -> Result<Self, PlanningSnapshotError> {
        validate_outcome_counts(outcome)?;
        let seed_digest = document_digest(&outcome.seed)?;
        let desired_state_digest = document_digest(&outcome.desired_state)?;
        let checked = &outcome.resolution.checked;
        let snapshot = Self {
            schema: PLANNING_SNAPSHOT_SCHEMA.to_string(),
            seed: outcome.seed.clone(),
            seed_digest,
            desired_state: outcome.desired_state.clone(),
            desired_state_digest,
            policies: outcome.policies.clone(),
            evaluations: outcome.evaluations.clone(),
            passes: outcome.passes.clone(),
            resolution: ResolutionSnapshot {
                policy: outcome.resolution.policy.clone(),
                policy_digest: outcome.resolution.policy_digest,
                decisions: outcome.resolution.decisions.clone(),
                rejections: outcome.resolution.rejections.clone(),
                binding_plan: checked.id(),
                binding_document: checked.document().clone(),
            },
        };
        snapshot.validate_linkage()?;
        snapshot.canonical_bytes()?;
        Ok(snapshot)
    }

    /// Returns the original normalized desired-state input.
    #[must_use]
    pub const fn seed(&self) -> &DesiredStateDocument {
        &self.seed
    }

    /// Returns the normalized fixed-point desired state.
    #[must_use]
    pub const fn desired_state(&self) -> &DesiredStateDocument {
        &self.desired_state
    }

    /// Returns the complete canonical authenticated policy set.
    #[must_use]
    pub fn policies(&self) -> &[ResolutionPolicyDocument] {
        &self.policies
    }

    /// Returns every retained evaluator exchange, including discarded branches.
    #[must_use]
    pub fn evaluations(&self) -> &[CompositionEvaluation] {
        &self.evaluations
    }

    /// Returns the successful fixed-point resolution pass chain.
    #[must_use]
    pub fn passes(&self) -> &[CompositionPass] {
        &self.passes
    }

    /// Returns the retained final resolution result.
    #[must_use]
    pub const fn resolution(&self) -> &ResolutionSnapshot {
        &self.resolution
    }

    /// Returns the semantically checked binding-plan identity linked by the snapshot.
    #[must_use]
    pub const fn binding_plan(&self) -> PlanId {
        self.resolution.binding_plan
    }

    /// Encodes the snapshot in the canonical AOS JSON dialect.
    ///
    /// # Errors
    ///
    /// Returns an error if validation or serialization fails, or the snapshot
    /// exceeds a version-1 structural, collection, string, or byte bound.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PlanningSnapshotError> {
        self.validate_bounded_structure()?;

        let mut writer = BoundedWriter::new(PLANNING_SNAPSHOT_MAX_BYTES);
        serde_json::to_writer(&mut writer, self).map_err(|error| {
            if writer.exceeded {
                PlanningSnapshotError::InvalidLinkage(
                    "encoded snapshot exceeds the version-1 byte limit",
                )
            } else {
                PlanningSnapshotError::Encode(error.into())
            }
        })?;
        self.validate_component_documents()?;

        let bytes = aos_contract::canonical::to_vec(self).map_err(PlanningSnapshotError::Encode)?;
        snapshot_limits()
            .decode::<serde_json::Value>(&bytes, PLANNING_SNAPSHOT_SCHEMA)
            .map_err(PlanningSnapshotError::Encode)?;
        Ok(bytes)
    }

    /// Computes the domain-separated identity of the canonical snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error if canonical encoding fails or exceeds its bound.
    pub fn digest(&self) -> Result<Sha256Digest, PlanningSnapshotError> {
        Ok(Sha256Digest::separated(
            PLANNING_SNAPSHOT_SCHEMA,
            self.canonical_bytes()?,
        ))
    }

    /// Decodes and validates one strictly bounded canonical snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, structurally invalid, unknown,
    /// noncanonical, or internally inconsistent input.
    pub fn decode(bytes: &[u8]) -> Result<Self, PlanningSnapshotError> {
        let snapshot = snapshot_limits()
            .decode::<Self>(bytes, PLANNING_SNAPSHOT_SCHEMA)
            .map_err(PlanningSnapshotError::Decode)?;
        if snapshot.schema != PLANNING_SNAPSHOT_SCHEMA {
            return Err(PlanningSnapshotError::UnsupportedSchema);
        }
        if snapshot.canonical_bytes()? != bytes {
            return Err(PlanningSnapshotError::NoncanonicalEncoding);
        }
        snapshot.validate_linkage()?;
        Ok(snapshot)
    }

    /// Reconstructs resolution and fragment validation from the retained transcript.
    ///
    /// The caller supplies an independently retained snapshot commitment, the
    /// exact authenticated policy set in canonical desired-state order, the
    /// exact seed, an authenticated environment, an exact package set, and a
    /// composer built from the exact interface catalog. `expected_digest` must
    /// come from an approved plan or durable transaction record; computing it
    /// from the snapshot being checked supplies no external trust. Provider code
    /// is not executed.
    ///
    /// # Errors
    ///
    /// Returns an error if any independent input differs, a retained evaluator
    /// exchange is missing or out of order, planning fails, or the reconstructed
    /// policy, transcript, pass, desired-state, or binding result differs.
    pub fn verify_structure(
        &self,
        composer: &RecursiveComposer<'_>,
        inputs: PlanningReplayInputs<'_>,
    ) -> Result<VerifiedPlanningSnapshot, PlanningSnapshotError> {
        let PlanningReplayInputs {
            expected_digest,
            authenticated_policies,
            seed,
            environment,
            packages,
        } = inputs;
        self.validate_external_inputs(expected_digest, authenticated_policies, &seed)?;
        let mut evaluator = TranscriptEvaluator::new(&self.evaluations);
        let outcome = composer
            .compose(
                authenticated_policies,
                seed,
                environment,
                packages,
                &mut evaluator,
            )
            .map_err(PlanningSnapshotError::Replay)?;
        evaluator.finish()?;
        self.verify_replayed_outcome(expected_digest, outcome)
    }

    /// Replays planning by invoking the supplied exact provider evaluator.
    ///
    /// `expected_digest` and `authenticated_policies` have the same independent
    /// trust requirements as [`Self::verify_structure`].
    ///
    /// # Errors
    ///
    /// Returns an error if an independent input differs, provider evaluation or
    /// planning fails, or fresh evaluation produces a different retained outcome.
    pub fn replay_with(
        &self,
        composer: &RecursiveComposer<'_>,
        inputs: PlanningReplayInputs<'_>,
        evaluator: &mut impl CompositionEvaluator,
    ) -> Result<VerifiedPlanningSnapshot, PlanningSnapshotError> {
        let PlanningReplayInputs {
            expected_digest,
            authenticated_policies,
            seed,
            environment,
            packages,
        } = inputs;
        self.validate_external_inputs(expected_digest, authenticated_policies, &seed)?;
        let outcome = composer
            .compose(
                authenticated_policies,
                seed,
                environment,
                packages,
                evaluator,
            )
            .map_err(PlanningSnapshotError::Replay)?;
        self.verify_replayed_outcome(expected_digest, outcome)
    }

    fn validate_external_inputs(
        &self,
        expected_digest: Sha256Digest,
        authenticated_policies: &[ResolutionPolicyDocument],
        seed: &DesiredStateDocument,
    ) -> Result<(), PlanningSnapshotError> {
        if self.digest()? != expected_digest {
            return Err(PlanningSnapshotError::CommitmentMismatch);
        }
        if authenticated_policies != self.policies {
            return Err(PlanningSnapshotError::PolicySetMismatch);
        }
        if seed != &self.seed {
            return Err(PlanningSnapshotError::InvalidLinkage(
                "independently retained seed differs from the snapshot",
            ));
        }
        Ok(())
    }

    fn verify_replayed_outcome(
        &self,
        snapshot_digest: Sha256Digest,
        outcome: CompositionOutcome,
    ) -> Result<VerifiedPlanningSnapshot, PlanningSnapshotError> {
        if Self::from_outcome(&outcome)? != *self {
            return Err(PlanningSnapshotError::ReplayMismatch);
        }
        Ok(VerifiedPlanningSnapshot {
            snapshot_digest,
            outcome,
        })
    }

    fn validate_linkage(&self) -> Result<(), PlanningSnapshotError> {
        if self.schema != PLANNING_SNAPSHOT_SCHEMA {
            return Err(PlanningSnapshotError::UnsupportedSchema);
        }
        if document_digest(&self.seed)? != self.seed_digest {
            return Err(PlanningSnapshotError::InvalidLinkage(
                "seed desired-state digest differs from its document",
            ));
        }
        if document_digest(&self.desired_state)? != self.desired_state_digest {
            return Err(PlanningSnapshotError::InvalidLinkage(
                "fixed-point desired-state digest differs from its document",
            ));
        }
        if self.policies.is_empty() {
            return Err(PlanningSnapshotError::InvalidLinkage(
                "successful composition retains no authenticated policy",
            ));
        }
        if self
            .policies
            .windows(2)
            .any(|pair| pair[0].desired_state >= pair[1].desired_state)
        {
            return Err(PlanningSnapshotError::InvalidLinkage(
                "authenticated policies are not in strict desired-state order",
            ));
        }
        if self.passes.is_empty() {
            return Err(PlanningSnapshotError::InvalidLinkage(
                "successful composition contains no resolution pass",
            ));
        }
        if self.passes[0].desired_state != self.seed
            || self.passes[0].desired_state_digest != self.seed_digest
        {
            return Err(PlanningSnapshotError::InvalidLinkage(
                "first successful pass does not start at the retained seed",
            ));
        }
        for (index, pass) in self.passes.iter().enumerate() {
            if pass.round as usize != index {
                return Err(PlanningSnapshotError::InvalidLinkage(
                    "composition pass rounds are not contiguous",
                ));
            }
            if document_digest(&pass.desired_state)? != pass.desired_state_digest
                || pass.policy.desired_state != pass.desired_state_digest
            {
                return Err(PlanningSnapshotError::InvalidLinkage(
                    "composition pass desired-state linkage differs",
                ));
            }
            if document_digest(&pass.policy)? != pass.policy_digest {
                return Err(PlanningSnapshotError::InvalidLinkage(
                    "composition pass policy digest differs from its document",
                ));
            }
            if !self.policies.iter().any(|policy| policy == &pass.policy) {
                return Err(PlanningSnapshotError::InvalidLinkage(
                    "composition pass policy is absent from the retained policy set",
                ));
            }
        }
        let Some(final_pass) = self.passes.last() else {
            return Err(PlanningSnapshotError::InvalidLinkage(
                "successful composition contains no final pass",
            ));
        };
        if final_pass.desired_state != self.desired_state
            || final_pass.desired_state_digest != self.desired_state_digest
            || final_pass.policy != self.resolution.policy
            || final_pass.policy_digest != self.resolution.policy_digest
            || final_pass.decisions != self.resolution.decisions
            || final_pass.rejections != self.resolution.rejections
        {
            return Err(PlanningSnapshotError::InvalidLinkage(
                "final pass differs from the retained resolution outcome",
            ));
        }
        if document_digest(&self.resolution.policy)? != self.resolution.policy_digest {
            return Err(PlanningSnapshotError::InvalidLinkage(
                "final resolution policy digest differs from its document",
            ));
        }
        if self.resolution.policy.desired_state != self.desired_state_digest {
            return Err(PlanningSnapshotError::InvalidLinkage(
                "final resolution policy targets another desired state",
            ));
        }
        if PlanId(document_digest(&self.resolution.binding_document)?)
            != self.resolution.binding_plan
        {
            return Err(PlanningSnapshotError::InvalidLinkage(
                "binding plan identity differs from its document",
            ));
        }
        if self.resolution.binding_document.desired_state != self.desired_state_digest
            || self.resolution.binding_document.policy_revision
                != self.resolution.policy.policy_revision
        {
            return Err(PlanningSnapshotError::InvalidLinkage(
                "binding plan does not target the final desired state and policy revision",
            ));
        }
        Ok(())
    }

    fn validate_bounded_structure(&self) -> Result<(), PlanningSnapshotError> {
        let maximum_nodes = ABILITY_LIMITS_V1.max_graph_nodes as usize;
        if self.policies.len() > maximum_nodes
            || self.evaluations.len() > maximum_nodes
            || self.passes.len() > ABILITY_LIMITS_V1.max_resolver_rounds as usize
        {
            return Err(PlanningSnapshotError::InvalidLinkage(
                "snapshot exceeds a version-1 collection bound",
            ));
        }
        for desired in std::iter::once(&self.seed)
            .chain(std::iter::once(&self.desired_state))
            .chain(self.passes.iter().map(|pass| &pass.desired_state))
        {
            desired
                .validate_structure(&ABILITY_LIMITS_V1)
                .map_err(|error| PlanningSnapshotError::Encode(error.into()))?;
        }
        self.resolution
            .binding_document
            .validate_structure(&ABILITY_LIMITS_V1)
            .map_err(|error| PlanningSnapshotError::Encode(error.into()))?;
        let maximum_string = ABILITY_LIMITS_V1.max_string_bytes as usize;
        if self
            .evaluations
            .iter()
            .filter_map(|evaluation| match &evaluation.result {
                CompositionEvaluationResult::Failed { message } => Some(message),
                CompositionEvaluationResult::Returned { .. } => None,
            })
            .chain(
                self.passes
                    .iter()
                    .flat_map(|pass| &pass.rejections)
                    .map(|rejection| &rejection.constraint),
            )
            .chain(
                self.resolution
                    .rejections
                    .iter()
                    .map(|item| &item.constraint),
            )
            .any(|text| text.len() > maximum_string)
        {
            return Err(PlanningSnapshotError::InvalidLinkage(
                "snapshot contains a string exceeding the version-1 limit",
            ));
        }

        Ok(())
    }

    fn validate_component_documents(&self) -> Result<(), PlanningSnapshotError> {
        // Each component encoding applies its own depth, item, string, and byte limits.
        for policy in &self.policies {
            encode_canonical(policy)
                .map_err(|error| PlanningSnapshotError::Encode(error.into()))?;
        }
        for pass in &self.passes {
            encode_canonical(&pass.policy)
                .map_err(|error| PlanningSnapshotError::Encode(error.into()))?;
        }
        encode_canonical(&self.seed)
            .map_err(|error| PlanningSnapshotError::Encode(error.into()))?;
        encode_canonical(&self.desired_state)
            .map_err(|error| PlanningSnapshotError::Encode(error.into()))?;
        encode_canonical(&self.resolution.binding_document)
            .map_err(|error| PlanningSnapshotError::Encode(error.into()))?;
        Ok(())
    }
}

struct TranscriptEvaluator<'a> {
    evaluations: &'a [CompositionEvaluation],
    next: usize,
    mismatch: Option<String>,
}

impl<'a> TranscriptEvaluator<'a> {
    const fn new(evaluations: &'a [CompositionEvaluation]) -> Self {
        Self {
            evaluations,
            next: 0,
            mismatch: None,
        }
    }

    fn finish(self) -> Result<(), PlanningSnapshotError> {
        if let Some(message) = self.mismatch {
            return Err(PlanningSnapshotError::InvalidTranscript(message));
        }
        if self.next != self.evaluations.len() {
            return Err(PlanningSnapshotError::InvalidTranscript(
                "retained transcript has unused evaluator exchanges".to_string(),
            ));
        }
        Ok(())
    }
}

impl CompositionEvaluator for TranscriptEvaluator<'_> {
    fn evaluate(
        &mut self,
        implementation: &aos_ability_model::ProviderImplementationReference,
        entry: &aos_ability_model::LocalKey,
        input: &aos_ability_model::AbilityValue,
    ) -> Result<aos_ability_model::AbilityValue, EvaluationError> {
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
            let message = "retained evaluator implementation, entry, or input differs from replay";
            self.mismatch = Some(message.to_string());
            return Err(EvaluationError::new(message));
        }
        match &retained.result {
            CompositionEvaluationResult::Returned { value } => Ok(value.clone()),
            CompositionEvaluationResult::Failed { message } => {
                Err(EvaluationError::new(message.clone()))
            }
        }
    }
}

fn document_digest(
    document: &impl VersionedDocument,
) -> Result<Sha256Digest, PlanningSnapshotError> {
    document
        .content_digest()
        .map_err(|error| PlanningSnapshotError::Encode(error.into()))
}

fn validate_outcome_counts(outcome: &CompositionOutcome) -> Result<(), PlanningSnapshotError> {
    let maximum_nodes = ABILITY_LIMITS_V1.max_graph_nodes as usize;
    if outcome.policies.len() > maximum_nodes
        || outcome.evaluations.len() > maximum_nodes
        || outcome.passes.len() > ABILITY_LIMITS_V1.max_resolver_rounds as usize
    {
        return Err(PlanningSnapshotError::InvalidLinkage(
            "planning outcome exceeds a version-1 collection bound",
        ));
    }
    Ok(())
}

const fn snapshot_limits() -> JsonLimits {
    JsonLimits {
        max_bytes: PLANNING_SNAPSHOT_MAX_BYTES,
        max_depth: ABILITY_LIMITS_V1.max_structural_depth as usize + 4,
        max_items: (ABILITY_LIMITS_V1.max_collection_items as usize)
            .saturating_mul(PLANNING_SNAPSHOT_COMPONENT_LIMIT),
        max_string_bytes: ABILITY_LIMITS_V1.max_string_bytes as usize,
    }
}

struct BoundedWriter {
    remaining: usize,
    exceeded: bool,
}

impl BoundedWriter {
    const fn new(maximum_bytes: usize) -> Self {
        Self {
            remaining: maximum_bytes,
            exceeded: false,
        }
    }
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            self.exceeded = true;
            return Err(io::Error::other(
                "serialized planning snapshot exceeds its byte limit",
            ));
        }
        self.remaining -= bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
