//! Closed deterministic Beam planner over owner-replayed sibling cohorts.
//!
//! The coordinator supplies one exact cohort state for every frontier position.
//! A position becomes eligible only after its producing request has closed, all
//! sibling attempts have modeled or explicit terminal results, every modeled
//! sibling has a policy evaluation, and the position's configuration belongs to
//! the replayed survivor set. Portable state carries the least eligible offer
//! across bounded scan pages and issues it only at EOF.

use std::collections::{BTreeMap, BTreeSet};

use crucible_cas::content_store::ContentId;

use super::*;
use crate::{
    CampaignPolicyId, CampaignViewId, ChoiceDomainId, ChoiceValue, GuidanceEvidence,
    PlannerEngineId,
};

const ENGINE_NAME: &str = "crucible-canonical-beam";
const ENGINE_IMPLEMENTATION_VERSION: u32 = 1;
const ENGINE_PROTOCOL_VERSION: u32 = 1;
const STATE_FORMAT: &str = "canonical-beam-planner";
const STATE_FORMAT_VERSION: u32 = 1;
const STATE_SCHEMA_VERSION: u32 = 1;
const POLICY_ARTIFACT_ABI_VERSION: u32 = 1;
const POLICY_DEPENDENCY_LOCK_BYTES: &[u8] = b"crucible-canonical-beam-planner.v1";

/// Complete deterministic repository basis for the built-in Beam planner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalBeamPlannerBasis {
    engine: PlannerEngine,
    artifact: PolicyArtifact,
    initial_state: PlannerState,
}

impl CanonicalBeamPlannerBasis {
    /// Returns the exact built-in Beam engine descriptor.
    #[must_use]
    pub const fn engine(&self) -> &PlannerEngine {
        &self.engine
    }

    /// Returns the exact built-in Beam policy artifact.
    #[must_use]
    pub const fn artifact(&self) -> &PolicyArtifact {
        &self.artifact
    }

    /// Returns the empty portable Beam planner state.
    #[must_use]
    pub const fn initial_state(&self) -> &PlannerState {
        &self.initial_state
    }

    /// Consumes the basis into repository-driver values.
    #[must_use]
    pub fn into_parts(self) -> (PlannerEngine, PolicyArtifact, PlannerState) {
        (self.engine, self.artifact, self.initial_state)
    }
}

/// Closed deterministic planner for policy-bound Beam survivor decisions.
#[derive(Clone, Copy, Debug, Default)]
pub struct CanonicalBeamPlanner;

impl CanonicalBeamPlanner {
    /// Builds the exact engine descriptor accepted by this implementation.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if the closed descriptor unexpectedly
    /// violates the canonical planner-engine grammar.
    pub fn descriptor() -> Result<PlannerEngine, CampaignCodecError> {
        PlannerEngine::new(
            ENGINE_NAME,
            ENGINE_IMPLEMENTATION_VERSION,
            ENGINE_PROTOCOL_VERSION,
            BTreeSet::from([
                CANONICAL_FRONTIER_OFFERS_CAPABILITY.to_owned(),
                CANONICAL_BEAM_SURVIVORS_CAPABILITY.to_owned(),
                CANONICAL_FRONTIER_BUDGET_CAPABILITY.to_owned(),
                CANONICAL_FRONTIER_REQUEST_BUDGET_CAPABILITY.to_owned(),
            ]),
        )
    }

    /// Returns whether this implementation can replay the exact descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if the closed descriptor cannot be built.
    pub fn supports_descriptor(engine: &PlannerEngine) -> Result<bool, CampaignCodecError> {
        Ok(engine == &Self::descriptor()?)
    }

    /// Builds the empty portable state for the exact Beam engine.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if descriptor identity or state encoding
    /// violates a canonical bound.
    pub fn initial_state() -> Result<PlannerState, CampaignCodecError> {
        Self::initial_state_for_engine(&Self::descriptor()?)
    }

    pub(crate) fn initial_state_for_engine(
        engine: &PlannerEngine,
    ) -> Result<PlannerState, CampaignCodecError> {
        Self::encode_state(engine.id()?, &CanonicalBeamPlannerState::empty())
    }

    /// Builds the exact repository basis for the packaged Beam planner.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if a descriptor, identity, or initial
    /// state violates its canonical contract.
    pub fn basis() -> Result<CanonicalBeamPlannerBasis, CampaignCodecError> {
        let engine = Self::descriptor()?;
        let artifact = PolicyArtifact::new(
            engine.id()?,
            POLICY_ARTIFACT_ABI_VERSION,
            Self::dependency_lock_id(),
            BTreeSet::new(),
            BTreeMap::new(),
        )?;
        Ok(CanonicalBeamPlannerBasis {
            engine,
            artifact,
            initial_state: Self::initial_state()?,
        })
    }

    pub(crate) fn dependency_lock_id() -> ContentId {
        ContentId::for_bytes(
            crucible_cas::content_store::ObjectKind::Trace,
            1,
            POLICY_DEPENDENCY_LOCK_BYTES,
        )
    }

    pub(crate) const fn dependency_lock_bytes() -> &'static [u8] {
        POLICY_DEPENDENCY_LOCK_BYTES
    }

    fn encode_state(
        engine: PlannerEngineId,
        state: &CanonicalBeamPlannerState,
    ) -> Result<PlannerState, CampaignCodecError> {
        PlannerState::new(
            engine,
            STATE_FORMAT,
            STATE_FORMAT_VERSION,
            codec::encode(state),
        )
    }

    fn decode_state(
        request: &PlannerRequest,
    ) -> Result<CanonicalBeamPlannerState, CampaignCodecError> {
        let state = request.planner_state();
        if state.state_format() != STATE_FORMAT
            || state.state_format_version() != STATE_FORMAT_VERSION
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "canonical Beam planner state format mismatch",
            });
        }
        let decoded: CanonicalBeamPlannerState = codec::decode(state.bytes())?;
        if decoded.schema_version != STATE_SCHEMA_VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "canonical Beam state schema disagrees with its engine",
            });
        }
        Ok(decoded)
    }
}

impl PurePlannerEngine for CanonicalBeamPlanner {
    type Error = CampaignCodecError;

    fn plan(&mut self, request: &PlannerRequest) -> Result<PlannerEngineOutput, Self::Error> {
        let expected_engine_id = request.engine().id()?;
        if !Self::supports_descriptor(request.engine())?
            || request.invocation().engine() != expected_engine_id
            || request.planner_state().engine() != expected_engine_id
            || !matches!(
                request.policy().explorer(),
                crate::ExplorerPolicy::Beam { .. }
            )
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "canonical Beam planner basis mismatch",
            });
        }

        let view = request.invocation().input_view();
        let policy = request.invocation().policy();
        let page = request.invocation().scan_page();
        let prior = Self::decode_state(request)?;
        let continuing = prior.input_view == Some(view) && prior.policy == Some(policy);
        let mut budget_blocked = continuing && prior.budget_blocked;
        let mut best = if continuing {
            if prior.best.as_ref().is_some_and(|candidate| {
                page.after().is_none_or(|after| candidate.position > after)
            }) {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "canonical Beam planner state exceeds the scan cursor",
                });
            }
            prior.best
        } else {
            None
        };

        let inputs = request.input_bundle().candidate_inputs(request)?;
        let mut offered_on_page = 0_u64;
        let mut pending_cohorts = 0_u64;
        let mut filtered_on_page = 0_u64;
        let mut intervention_exclusions = BTreeMap::new();
        for (position, input) in inputs {
            if input
                .budget
                .as_ref()
                .is_some_and(|budget| !budget.request_can_issue())
            {
                continue;
            }
            if input
                .budget
                .as_ref()
                .is_some_and(|budget| !budget.can_issue())
            {
                budget_blocked = true;
                continue;
            }
            let (Some(offer), Some(beam)) = (input.offer, input.beam) else {
                continue;
            };
            let excluded = beam.cohort_state().intervention_exclusions();
            if excluded != 0
                && intervention_exclusions
                    .insert(*beam.barrier(), excluded)
                    .is_some_and(|current| current != excluded)
            {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "Beam cohort repeats inconsistent intervention exclusions",
                });
            }
            let Some(selection_id) = beam.selection() else {
                match beam.cohort_state() {
                    crate::PlannerBeamCohortState::CohortLimitExceeded(_) => {
                        return Err(CampaignCodecError::LimitExceeded {
                            limit: "beam-cohort-candidate-count",
                        });
                    }
                    crate::PlannerBeamCohortState::AwaitingRequestClosure(_)
                    | crate::PlannerBeamCohortState::AwaitingAttempts(_)
                    | crate::PlannerBeamCohortState::AwaitingEvaluations(_) => {
                        pending_cohorts = checked_evidence_increment(pending_cohorts)?;
                    }
                    crate::PlannerBeamCohortState::InterventionExcluded(_) => {}
                    crate::PlannerBeamCohortState::Settled(_)
                    | crate::PlannerBeamCohortState::SettledWithInterventionExclusions { .. } => {
                        return Err(CampaignCodecError::InvalidValue {
                            reason: "settled Beam cohort omits its selection",
                        });
                    }
                }
                continue;
            };
            let selection = request
                .input_bundle()
                .object(selection_id.content_id())?
                .ok_or(CampaignCodecError::InvalidValue {
                    reason: "Beam candidate omits its selection",
                })?;
            let selection = crate::SurvivorSelection::from_canonical_bytes(selection.body())?;
            if !selection.selected().contains(&beam.configuration()) {
                filtered_on_page = checked_evidence_increment(filtered_on_page)?;
                continue;
            }

            offered_on_page = checked_evidence_increment(offered_on_page)?;
            let candidate = BeamCarriedCandidate::from_offer(position, &offer);
            if best
                .as_ref()
                .is_none_or(|current| candidate.position < current.position)
            {
                best = Some(candidate);
            }
        }

        let fuel = u64::try_from(page.positions().len())
            .ok()
            .and_then(|positions| positions.checked_add(1))
            .ok_or(CampaignCodecError::LimitExceeded {
                limit: "canonical-beam-planner-fuel",
            })?;
        if fuel > request.invocation().budget().fuel() {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "canonical-beam-planner-fuel",
            });
        }

        let invocation = request.invocation_id()?;
        let (next_best, proposal_count, disposition) = if page.complete() {
            match best {
                Some(candidate) => {
                    let proposal = candidate.to_proposal(request, invocation)?;
                    let selected = candidate.position;
                    (
                        Some(candidate),
                        1,
                        PlannerProposalDisposition::Issue {
                            selected,
                            branch_requests: Vec::new(),
                            proposals: vec![proposal],
                        },
                    )
                }
                None => (None, 0, PlannerProposalDisposition::NoWork),
            }
        } else {
            (
                best,
                0,
                PlannerProposalDisposition::ContinueScan {
                    cursor: crate::PlanningScanCursor::new(view, page.last()),
                },
            )
        };
        let next_state = Self::encode_state(
            expected_engine_id,
            &CanonicalBeamPlannerState {
                schema_version: STATE_SCHEMA_VERSION,
                input_view: Some(view),
                policy: Some(policy),
                best: next_best.clone(),
                budget_blocked,
            },
        )?;
        let mut explanation_terms = BTreeMap::from([
            ("budget-blocked".to_owned(), i64::from(budget_blocked)),
            (
                "filtered-on-page".to_owned(),
                evidence_i64(filtered_on_page)?,
            ),
            ("offered-on-page".to_owned(), evidence_i64(offered_on_page)?),
            ("pending-cohorts".to_owned(), evidence_i64(pending_cohorts)?),
            ("selected".to_owned(), i64::from(next_best.is_some())),
        ]);
        if !intervention_exclusions.is_empty() {
            let excluded_observations = intervention_exclusions
                .values()
                .try_fold(0_u64, |total, count| total.checked_add(*count))
                .ok_or(CampaignCodecError::LimitExceeded {
                    limit: "canonical-beam-planner-evidence",
                })?;
            let excluded_cohorts = u64::try_from(intervention_exclusions.len()).map_err(|_| {
                CampaignCodecError::LimitExceeded {
                    limit: "canonical-beam-planner-evidence",
                }
            })?;
            explanation_terms.insert(
                "intervention-excluded-cohorts".to_owned(),
                evidence_i64(excluded_cohorts)?,
            );
            explanation_terms.insert(
                "intervention-excluded-observations".to_owned(),
                evidence_i64(excluded_observations)?,
            );
        }
        if matches!(
            request.policy().intervention_learning_policy(),
            crate::InterventionLearningPolicy::IncludeInGuidance
        ) {
            explanation_terms.insert("intervention-guidance-opt-in".to_owned(), 1);
        }
        let explanation = GuidanceEvidence::new(explanation_terms)?;
        Ok(PlannerEngineOutput::new(PlannerStepProposal::new(
            invocation,
            next_state,
            PlanningUsage {
                branch_requests: 0,
                proposals: proposal_count,
                input_objects: page.input_objects(),
                input_bytes: page.input_bytes(),
                fuel,
            },
            explanation,
            disposition,
        )?))
    }
}

fn checked_evidence_increment(value: u64) -> Result<u64, CampaignCodecError> {
    value
        .checked_add(1)
        .ok_or(CampaignCodecError::LimitExceeded {
            limit: "canonical-beam-planner-evidence",
        })
}

fn evidence_i64(value: u64) -> Result<i64, CampaignCodecError> {
    i64::try_from(value).map_err(|_| CampaignCodecError::LimitExceeded {
        limit: "canonical-beam-planner-evidence",
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CanonicalBeamPlannerState {
    schema_version: u32,
    input_view: Option<CampaignViewId>,
    policy: Option<CampaignPolicyId>,
    best: Option<BeamCarriedCandidate>,
    budget_blocked: bool,
}

impl CanonicalBeamPlannerState {
    const fn empty() -> Self {
        Self {
            schema_version: STATE_SCHEMA_VERSION,
            input_view: None,
            policy: None,
            best: None,
            budget_blocked: false,
        }
    }
}

impl Canonical for CanonicalBeamPlannerState {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.input_view.encode(encoder);
        self.policy.encode(encoder);
        self.best.encode(encoder);
        self.budget_blocked.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        if schema_version != STATE_SCHEMA_VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported canonical Beam planner state version",
            });
        }
        let input_view = Option::decode(decoder)?;
        let policy = Option::decode(decoder)?;
        let best = Option::decode(decoder)?;
        if input_view.is_some() != policy.is_some() || (best.is_some() && input_view.is_none()) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "canonical Beam planner state basis is partial",
            });
        }
        Ok(Self {
            schema_version,
            input_view,
            policy,
            best,
            budget_blocked: bool::decode(decoder)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BeamCarriedCandidate {
    position: PlanningScanPosition,
    domain: ChoiceDomainId,
    value: ChoiceValue,
    ordinal: u64,
}

impl BeamCarriedCandidate {
    fn from_offer(position: PlanningScanPosition, offer: &Proposal) -> Self {
        Self {
            position,
            domain: offer.domain(),
            value: offer.value().clone(),
            ordinal: offer.ordinal(),
        }
    }

    fn to_proposal(
        &self,
        request: &PlannerRequest,
        invocation: crate::PlannerInvocationId,
    ) -> Result<Proposal, CampaignCodecError> {
        Proposal::new(
            self.position.branch_point(),
            self.position.source(),
            self.domain,
            self.value.clone(),
            request.invocation().policy(),
            Some(invocation),
            self.ordinal,
            request.invocation().input_view(),
        )
    }
}

impl Canonical for BeamCarriedCandidate {
    fn encode(&self, encoder: &mut Encoder) {
        self.position.encode(encoder);
        self.domain.encode(encoder);
        self.value.encode(encoder);
        self.ordinal.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let value = Self {
            position: PlanningScanPosition::decode(decoder)?,
            domain: ChoiceDomainId::decode(decoder)?,
            value: ChoiceValue::decode(decoder)?,
            ordinal: u64::decode(decoder)?,
        };
        if value.ordinal == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "canonical Beam candidate ordinal is zero",
            });
        }
        Ok(value)
    }
}
