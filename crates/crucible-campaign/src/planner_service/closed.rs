//! Closed deterministic planner over coordinator-authenticated frontier offers.
//!
//! The engine never resolves repository records or generator algorithms. The
//! coordinator supplies exact continuation projections and Ready candidate
//! offers. Budget-aware engines also require an eligibility record for every
//! offer, including blocked offers. The engine scans
//! those bounded inputs in canonical order, carries the best offer in portable
//! state across pages, and issues only after reaching EOF.
//!
//! Current portable state appends a blocked-offer bit so an empty final page
//! does not erase an earlier budget blocker. Legacy engines retain v1 state.
//!
//! ```text
//! canonical-frontier-planner@2: v2 | input_view? | best? | budget_blocked
//! canonical-frontier-puct-planner@2: v2 | input_view? | policy? | best? | budget_blocked
//! ```

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
};

use super::*;
use crate::{
    CampaignPolicyId, CampaignViewId, ChoiceDomainId, ChoiceValue, GuidanceEvidence,
    PlannerEngineId,
};

const ENGINE_NAME: &str = "crucible-canonical-frontier";
const ENGINE_IMPLEMENTATION_VERSION: u32 = 3;
const ENGINE_PROTOCOL_VERSION: u32 = 1;
const STATE_FORMAT: &str = "canonical-frontier-planner";
const STATE_FORMAT_VERSION: u32 = 2;
const STATE_SCHEMA_VERSION: u32 = 2;
const POLICY_ARTIFACT_ABI_VERSION: u32 = 1;
const POLICY_DEPENDENCY_LOCK_BYTES: &[u8] = b"crucible-canonical-frontier-planner.v3";

/// Complete deterministic repository basis for the built-in planner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalFrontierPlannerBasis {
    engine: PlannerEngine,
    artifact: PolicyArtifact,
    initial_state: PlannerState,
}

impl CanonicalFrontierPlannerBasis {
    /// Returns the exact built-in engine descriptor.
    #[must_use]
    pub const fn engine(&self) -> &PlannerEngine {
        &self.engine
    }

    /// Returns the exact built-in policy-artifact descriptor.
    #[must_use]
    pub const fn artifact(&self) -> &PolicyArtifact {
        &self.artifact
    }

    /// Returns the empty portable state for the built-in engine.
    #[must_use]
    pub const fn initial_state(&self) -> &PlannerState {
        &self.initial_state
    }

    /// Consumes the basis into its driver-owned values.
    #[must_use]
    pub fn into_parts(self) -> (PlannerEngine, PolicyArtifact, PlannerState) {
        (self.engine, self.artifact, self.initial_state)
    }
}

/// Closed deterministic planner for coordinator-authenticated candidate offers.
#[derive(Clone, Copy, Debug, Default)]
pub struct CanonicalFrontierPlanner;

impl CanonicalFrontierPlanner {
    /// Builds the exact engine descriptor accepted by this implementation.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if the closed descriptor unexpectedly
    /// violates the canonical planner-engine grammar.
    pub fn descriptor() -> Result<PlannerEngine, CampaignCodecError> {
        Self::descriptor_for_budget(true)
    }

    /// Returns whether this implementation can replay the exact engine descriptor.
    ///
    /// Legacy version-1 inputs retain their original offer and selection semantics.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if a closed descriptor cannot be constructed.
    pub fn supports_descriptor(engine: &PlannerEngine) -> Result<bool, CampaignCodecError> {
        Ok(engine == &Self::descriptor()? || engine == &Self::descriptor_for_budget(false)?)
    }

    fn descriptor_for_budget(budget_aware: bool) -> Result<PlannerEngine, CampaignCodecError> {
        let mut capabilities = BTreeSet::from([CANONICAL_FRONTIER_OFFERS_CAPABILITY.to_owned()]);
        if budget_aware {
            capabilities.insert(CANONICAL_FRONTIER_BUDGET_CAPABILITY.to_owned());
        }
        PlannerEngine::new(
            ENGINE_NAME,
            if budget_aware {
                ENGINE_IMPLEMENTATION_VERSION
            } else {
                1
            },
            ENGINE_PROTOCOL_VERSION,
            capabilities,
        )
    }

    /// Builds an empty portable state for this exact engine descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if descriptor identity or state encoding
    /// unexpectedly violates a canonical bound.
    pub fn initial_state() -> Result<PlannerState, CampaignCodecError> {
        Self::initial_state_for_engine(&Self::descriptor()?)
    }

    pub(crate) fn initial_state_for_engine(
        engine: &PlannerEngine,
    ) -> Result<PlannerState, CampaignCodecError> {
        let mut state = CanonicalFrontierPlannerState::empty();
        if !engine
            .capabilities()
            .contains(CANONICAL_FRONTIER_BUDGET_CAPABILITY)
        {
            state.schema_version = 1;
        }
        Self::encode_state(engine.id()?, &state)
    }

    /// Builds the exact repository basis for the packaged built-in planner.
    ///
    /// The dependency lock is a fixed opaque content identity for this closed
    /// implementation. Repository publication places that leaf before the
    /// child-bearing artifact descriptor becomes reachable.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if a descriptor, identity, or initial
    /// state unexpectedly violates its canonical contract.
    pub fn basis() -> Result<CanonicalFrontierPlannerBasis, CampaignCodecError> {
        let engine = Self::descriptor()?;
        let engine_id = engine.id()?;
        let artifact = PolicyArtifact::new(
            engine_id,
            POLICY_ARTIFACT_ABI_VERSION,
            Self::dependency_lock_id(),
            BTreeSet::new(),
            BTreeMap::new(),
        )?;
        let initial_state = Self::initial_state()?;
        Ok(CanonicalFrontierPlannerBasis {
            engine,
            artifact,
            initial_state,
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
        state: &CanonicalFrontierPlannerState,
    ) -> Result<PlannerState, CampaignCodecError> {
        PlannerState::new(
            engine,
            STATE_FORMAT,
            if state.schema_version >= 2 {
                STATE_FORMAT_VERSION
            } else {
                1
            },
            codec::encode(state),
        )
    }

    fn decode_state(
        request: &PlannerRequest,
    ) -> Result<CanonicalFrontierPlannerState, CampaignCodecError> {
        let state = request.planner_state();
        let expected_format = if request
            .engine()
            .capabilities()
            .contains(CANONICAL_FRONTIER_BUDGET_CAPABILITY)
        {
            STATE_FORMAT_VERSION
        } else {
            1
        };
        if state.state_format() != STATE_FORMAT || state.state_format_version() != expected_format {
            return Err(CampaignCodecError::InvalidValue {
                reason: "canonical frontier planner state format mismatch",
            });
        }
        let decoded: CanonicalFrontierPlannerState = codec::decode(state.bytes())?;
        let budget_aware = request
            .engine()
            .capabilities()
            .contains(CANONICAL_FRONTIER_BUDGET_CAPABILITY);
        if decoded.schema_version
            != if budget_aware {
                STATE_SCHEMA_VERSION
            } else {
                1
            }
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "canonical frontier state schema disagrees with its engine",
            });
        }
        Ok(decoded)
    }
}

impl PurePlannerEngine for CanonicalFrontierPlanner {
    type Error = CampaignCodecError;

    fn plan(&mut self, request: &PlannerRequest) -> Result<PlannerEngineOutput, Self::Error> {
        let expected_engine_id = request.engine().id()?;
        if !Self::supports_descriptor(request.engine())?
            || request.invocation().engine() != expected_engine_id
            || request.planner_state().engine() != expected_engine_id
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "canonical frontier planner engine basis mismatch",
            });
        }

        let view = request.invocation().input_view();
        let page = request.invocation().scan_page();
        let prior = Self::decode_state(request)?;
        let budget_aware = request
            .engine()
            .capabilities()
            .contains(CANONICAL_FRONTIER_BUDGET_CAPABILITY);
        let mut budget_blocked = prior.input_view == Some(view) && prior.budget_blocked;
        let mut best = if prior.input_view == Some(view) {
            if prior.best.as_ref().is_some_and(|candidate| {
                page.after().is_none_or(|after| candidate.position > after)
            }) {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "canonical frontier planner state exceeds the scan cursor",
                });
            }
            prior.best
        } else {
            None
        };

        let inputs = request.input_bundle().candidate_inputs(request)?;
        let mut offered_on_page = 0_u64;
        for (position, input) in inputs {
            if input
                .budget
                .as_ref()
                .is_some_and(|budget| !budget.can_issue())
            {
                budget_blocked = true;
                continue;
            }
            let Some(offer) = input.offer else {
                continue;
            };
            offered_on_page =
                offered_on_page
                    .checked_add(1)
                    .ok_or(CampaignCodecError::LimitExceeded {
                        limit: "canonical-frontier-planner-eligible-count",
                    })?;
            let candidate = CarriedCandidate::from_offer(position, &offer);
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
                limit: "canonical-frontier-planner-fuel",
            })?;
        if fuel > request.invocation().budget().fuel() {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "canonical-frontier-planner-fuel",
            });
        }
        let input_objects = page.input_objects();
        let input_bytes = page.input_bytes();
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
            &CanonicalFrontierPlannerState {
                schema_version: if budget_aware {
                    STATE_SCHEMA_VERSION
                } else {
                    1
                },
                input_view: Some(view),
                best: next_best.clone(),
                budget_blocked,
            },
        )?;
        let mut terms = BTreeMap::from([
            (
                "offered-on-page".to_owned(),
                i64::try_from(offered_on_page).map_err(|_| CampaignCodecError::LimitExceeded {
                    limit: "canonical-frontier-planner-evidence",
                })?,
            ),
            ("selected".to_owned(), i64::from(next_best.is_some())),
        ]);
        if budget_aware {
            terms.insert("budget-blocked".to_owned(), i64::from(budget_blocked));
        }
        let explanation = GuidanceEvidence::new(terms)?;
        let usage = PlanningUsage {
            branch_requests: 0,
            proposals: proposal_count,
            input_objects,
            input_bytes,
            fuel,
        };
        Ok(PlannerEngineOutput::new(PlannerStepProposal::new(
            invocation,
            next_state,
            usage,
            explanation,
            disposition,
        )?))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CanonicalFrontierPlannerState {
    schema_version: u32,
    input_view: Option<CampaignViewId>,
    best: Option<CarriedCandidate>,
    budget_blocked: bool,
}

impl CanonicalFrontierPlannerState {
    const fn empty() -> Self {
        Self {
            schema_version: STATE_SCHEMA_VERSION,
            input_view: None,
            best: None,
            budget_blocked: false,
        }
    }
}

impl Canonical for CanonicalFrontierPlannerState {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.input_view.encode(encoder);
        self.best.encode(encoder);
        if self.schema_version >= 2 {
            self.budget_blocked.encode(encoder);
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        if !matches!(schema_version, 1 | STATE_SCHEMA_VERSION) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported canonical frontier planner state version",
            });
        }
        Ok(Self {
            schema_version,
            input_view: Option::decode(decoder)?,
            best: Option::decode(decoder)?,
            budget_blocked: schema_version >= 2 && bool::decode(decoder)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CarriedCandidate {
    position: PlanningScanPosition,
    domain: ChoiceDomainId,
    value: ChoiceValue,
    ordinal: u64,
}

impl CarriedCandidate {
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

impl Canonical for CarriedCandidate {
    fn encode(&self, encoder: &mut Encoder) {
        self.position.encode(encoder);
        self.domain.encode(encoder);
        self.value.encode(encoder);
        self.ordinal.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let candidate = Self {
            position: PlanningScanPosition::decode(decoder)?,
            domain: ChoiceDomainId::decode(decoder)?,
            value: ChoiceValue::decode(decoder)?,
            ordinal: u64::decode(decoder)?,
        };
        if candidate.ordinal == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "canonical frontier planner candidate ordinal is zero",
            });
        }
        Ok(candidate)
    }
}

const PUCT_ENGINE_IMPLEMENTATION_VERSION: u32 = 4;
const PUCT_STATE_FORMAT: &str = "canonical-frontier-puct-planner";
const PUCT_STATE_FORMAT_VERSION: u32 = 2;
const PUCT_STATE_SCHEMA_VERSION: u32 = 2;
const PUCT_POLICY_DEPENDENCY_LOCK_BYTES: &[u8] = b"crucible-canonical-frontier-planner.v4";

/// Complete deterministic repository basis for the PUCT-ranked planner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPuctPlannerBasis {
    engine: PlannerEngine,
    artifact: PolicyArtifact,
    initial_state: PlannerState,
}

impl CanonicalPuctPlannerBasis {
    /// Returns the exact budget-aware engine descriptor.
    #[must_use]
    pub const fn engine(&self) -> &PlannerEngine {
        &self.engine
    }

    /// Returns the exact budget-aware policy-artifact descriptor.
    #[must_use]
    pub const fn artifact(&self) -> &PolicyArtifact {
        &self.artifact
    }

    /// Returns the empty portable budget-aware planner state.
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

/// Closed deterministic planner ranked by owner-built fixed-point PUCT input.
#[derive(Clone, Copy, Debug, Default)]
pub struct CanonicalPuctPlanner;

impl CanonicalPuctPlanner {
    /// Builds the exact budget-aware engine descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if the closed descriptor unexpectedly
    /// violates the planner-engine grammar.
    pub fn descriptor() -> Result<PlannerEngine, CampaignCodecError> {
        Self::descriptor_for_budget(true)
    }

    /// Returns whether this implementation can replay the exact engine descriptor.
    ///
    /// Legacy version-2 inputs retain their original offer and ranking semantics.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if a closed descriptor cannot be constructed.
    pub fn supports_descriptor(engine: &PlannerEngine) -> Result<bool, CampaignCodecError> {
        Ok(engine == &Self::descriptor()? || engine == &Self::descriptor_for_budget(false)?)
    }

    fn descriptor_for_budget(budget_aware: bool) -> Result<PlannerEngine, CampaignCodecError> {
        let mut capabilities = BTreeSet::from([
            CANONICAL_FRONTIER_OFFERS_CAPABILITY.to_owned(),
            CANONICAL_FRONTIER_PUCT_CAPABILITY.to_owned(),
        ]);
        if budget_aware {
            capabilities.insert(CANONICAL_FRONTIER_BUDGET_CAPABILITY.to_owned());
        }
        PlannerEngine::new(
            ENGINE_NAME,
            if budget_aware {
                PUCT_ENGINE_IMPLEMENTATION_VERSION
            } else {
                2
            },
            ENGINE_PROTOCOL_VERSION,
            capabilities,
        )
    }

    /// Builds the empty portable state for this exact engine.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if descriptor identity or state encoding
    /// unexpectedly violates a canonical bound.
    pub fn initial_state() -> Result<PlannerState, CampaignCodecError> {
        Self::initial_state_for_engine(&Self::descriptor()?)
    }

    pub(crate) fn initial_state_for_engine(
        engine: &PlannerEngine,
    ) -> Result<PlannerState, CampaignCodecError> {
        let mut state = CanonicalPuctPlannerState::empty();
        if !engine
            .capabilities()
            .contains(CANONICAL_FRONTIER_BUDGET_CAPABILITY)
        {
            state.schema_version = 1;
        }
        Self::encode_state(engine.id()?, &state)
    }

    /// Builds the exact repository basis for the packaged PUCT planner.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if a descriptor, artifact, or initial
    /// state unexpectedly violates its canonical contract.
    pub fn basis() -> Result<CanonicalPuctPlannerBasis, CampaignCodecError> {
        let engine = Self::descriptor()?;
        let engine_id = engine.id()?;
        let artifact = PolicyArtifact::new(
            engine_id,
            POLICY_ARTIFACT_ABI_VERSION,
            Self::dependency_lock_id(),
            BTreeSet::new(),
            BTreeMap::new(),
        )?;
        Ok(CanonicalPuctPlannerBasis {
            engine,
            artifact,
            initial_state: Self::initial_state()?,
        })
    }

    pub(crate) fn dependency_lock_id() -> ContentId {
        ContentId::for_bytes(
            crucible_cas::content_store::ObjectKind::Trace,
            1,
            PUCT_POLICY_DEPENDENCY_LOCK_BYTES,
        )
    }

    pub(crate) const fn dependency_lock_bytes() -> &'static [u8] {
        PUCT_POLICY_DEPENDENCY_LOCK_BYTES
    }

    fn encode_state(
        engine: PlannerEngineId,
        state: &CanonicalPuctPlannerState,
    ) -> Result<PlannerState, CampaignCodecError> {
        PlannerState::new(
            engine,
            PUCT_STATE_FORMAT,
            if state.schema_version >= 2 {
                PUCT_STATE_FORMAT_VERSION
            } else {
                1
            },
            codec::encode(state),
        )
    }

    fn decode_state(
        request: &PlannerRequest,
    ) -> Result<CanonicalPuctPlannerState, CampaignCodecError> {
        let state = request.planner_state();
        let expected_format = if request
            .engine()
            .capabilities()
            .contains(CANONICAL_FRONTIER_BUDGET_CAPABILITY)
        {
            PUCT_STATE_FORMAT_VERSION
        } else {
            1
        };
        if state.state_format() != PUCT_STATE_FORMAT
            || state.state_format_version() != expected_format
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "canonical PUCT planner state format mismatch",
            });
        }
        let decoded: CanonicalPuctPlannerState = codec::decode(state.bytes())?;
        let budget_aware = request
            .engine()
            .capabilities()
            .contains(CANONICAL_FRONTIER_BUDGET_CAPABILITY);
        if decoded.schema_version
            != if budget_aware {
                PUCT_STATE_SCHEMA_VERSION
            } else {
                1
            }
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "canonical PUCT state schema disagrees with its engine",
            });
        }
        Ok(decoded)
    }
}

impl PurePlannerEngine for CanonicalPuctPlanner {
    type Error = CampaignCodecError;

    fn plan(&mut self, request: &PlannerRequest) -> Result<PlannerEngineOutput, Self::Error> {
        let expected_engine_id = request.engine().id()?;
        if !Self::supports_descriptor(request.engine())?
            || request.invocation().engine() != expected_engine_id
            || request.planner_state().engine() != expected_engine_id
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "canonical PUCT planner engine basis mismatch",
            });
        }

        let view = request.invocation().input_view();
        let policy_id = request.invocation().policy();
        let page = request.invocation().scan_page();
        let prior = Self::decode_state(request)?;
        let budget_aware = request
            .engine()
            .capabilities()
            .contains(CANONICAL_FRONTIER_BUDGET_CAPABILITY);
        let mut budget_blocked = prior.input_view == Some(view)
            && prior.policy == Some(policy_id)
            && prior.budget_blocked;
        let mut best = if prior.input_view == Some(view) && prior.policy == Some(policy_id) {
            if prior.best.as_ref().is_some_and(|candidate| {
                page.after()
                    .is_none_or(|after| candidate.guidance.position() > after)
            }) {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "canonical PUCT planner state exceeds the scan cursor",
                });
            }
            if let Some(candidate) = &prior.best {
                candidate
                    .guidance
                    .score_for_policy(request.policy(), view)?;
            }
            prior.best
        } else {
            None
        };

        let inputs = request.input_bundle().candidate_inputs(request)?;
        let mut offered_on_page = 0_u64;
        for input in inputs.into_values() {
            if input
                .budget
                .as_ref()
                .is_some_and(|budget| !budget.can_issue())
            {
                budget_blocked = true;
                continue;
            }
            let (Some(_offer), Some(guidance)) = (input.offer, input.guidance) else {
                continue;
            };
            offered_on_page =
                offered_on_page
                    .checked_add(1)
                    .ok_or(CampaignCodecError::LimitExceeded {
                        limit: "canonical-puct-planner-eligible-count",
                    })?;
            let candidate = PuctCarriedCandidate { guidance };
            let replace = match &best {
                Some(current) => {
                    candidate.cmp(current, request.policy(), view)? == Ordering::Greater
                }
                None => true,
            };
            if replace {
                best = Some(candidate);
            }
        }

        let fuel = u64::try_from(page.positions().len())
            .ok()
            .and_then(|positions| positions.checked_add(1))
            .ok_or(CampaignCodecError::LimitExceeded {
                limit: "canonical-puct-planner-fuel",
            })?;
        if fuel > request.invocation().budget().fuel() {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "canonical-puct-planner-fuel",
            });
        }
        let invocation = request.invocation_id()?;
        let (next_best, proposal_count, disposition) = if page.complete() {
            match best {
                Some(candidate) => {
                    let proposal = candidate.to_proposal(request, invocation)?;
                    let selected = candidate.guidance.position();
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
            &CanonicalPuctPlannerState {
                schema_version: if budget_aware {
                    PUCT_STATE_SCHEMA_VERSION
                } else {
                    1
                },
                input_view: Some(view),
                policy: Some(policy_id),
                best: next_best.clone(),
                budget_blocked,
            },
        )?;
        let explanation =
            puct_explanation(offered_on_page, next_best.as_ref(), request.policy(), view)?;
        let explanation = if budget_aware {
            let mut terms = explanation.terms_micros().clone();
            terms.insert("budget-blocked".to_owned(), i64::from(budget_blocked));
            GuidanceEvidence::new(terms)?
        } else {
            explanation
        };
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

fn puct_explanation(
    offered_on_page: u64,
    selected: Option<&PuctCarriedCandidate>,
    policy: &CampaignPolicy,
    view: CampaignViewId,
) -> Result<GuidanceEvidence, CampaignCodecError> {
    let mut terms = BTreeMap::from([
        ("offered-on-page".to_owned(), guidance_i64(offered_on_page)?),
        ("selected".to_owned(), i64::from(selected.is_some())),
    ]);
    if let Some(selected) = selected {
        let statistics = selected.guidance.statistics();
        let score = selected.guidance.score_for_policy(policy, view)?;
        for (name, value) in [
            ("selected-edge-visits", statistics.edge_visits()),
            ("selected-parent-visits", statistics.parent_visits()),
            ("selected-prior-micros", statistics.prior_micros()),
            (
                "selected-novelty-events",
                selected.guidance.novelty_events(),
            ),
            (
                "selected-finding-events",
                selected
                    .guidance
                    .finding_events()
                    .values()
                    .try_fold(0_u64, |total, count| total.checked_add(*count))
                    .ok_or(CampaignCodecError::LimitExceeded {
                        limit: "canonical-puct-planner-evidence",
                    })?,
            ),
        ] {
            terms.insert(name.to_owned(), guidance_i64(value)?);
        }
        terms.insert(
            "selected-reward-sum-micros".to_owned(),
            statistics.reward_sum_micros(),
        );
        terms.insert(
            "selected-mean-reward-micros".to_owned(),
            score.mean_reward_micros(),
        );
        terms.insert(
            "selected-exploration-micros".to_owned(),
            guidance_i64(score.exploration_bonus_micros())?,
        );
        terms.insert(
            "selected-novelty-micros".to_owned(),
            guidance_i64(score.novelty_bonus_micros())?,
        );
        terms.insert(
            "selected-fairness-micros".to_owned(),
            guidance_i64(score.fairness_bonus_micros())?,
        );
        terms.insert("selected-total-micros".to_owned(), score.total_micros());
    }
    GuidanceEvidence::new(terms)
}

fn guidance_i64(value: u64) -> Result<i64, CampaignCodecError> {
    i64::try_from(value).map_err(|_| CampaignCodecError::LimitExceeded {
        limit: "canonical-puct-planner-evidence",
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CanonicalPuctPlannerState {
    schema_version: u32,
    input_view: Option<CampaignViewId>,
    policy: Option<CampaignPolicyId>,
    best: Option<PuctCarriedCandidate>,
    budget_blocked: bool,
}

impl CanonicalPuctPlannerState {
    const fn empty() -> Self {
        Self {
            schema_version: PUCT_STATE_SCHEMA_VERSION,
            input_view: None,
            policy: None,
            best: None,
            budget_blocked: false,
        }
    }
}

impl Canonical for CanonicalPuctPlannerState {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.input_view.encode(encoder);
        self.policy.encode(encoder);
        self.best.encode(encoder);
        if self.schema_version >= 2 {
            self.budget_blocked.encode(encoder);
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        if !matches!(schema_version, 1 | PUCT_STATE_SCHEMA_VERSION) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported canonical PUCT planner state version",
            });
        }
        let input_view = Option::decode(decoder)?;
        let policy = Option::decode(decoder)?;
        let best = Option::decode(decoder)?;
        if input_view.is_some() != policy.is_some() || (best.is_some() && input_view.is_none()) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "canonical PUCT planner state basis is partial",
            });
        }
        Ok(Self {
            schema_version,
            input_view,
            policy,
            best,
            budget_blocked: schema_version >= 2 && bool::decode(decoder)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PuctCarriedCandidate {
    guidance: crate::PlannerCandidateGuidance,
}

impl PuctCarriedCandidate {
    fn cmp(
        &self,
        other: &Self,
        policy: &CampaignPolicy,
        view: CampaignViewId,
    ) -> Result<Ordering, CampaignCodecError> {
        let score = self.guidance.score_for_policy(policy, view)?;
        let other_score = other.guidance.score_for_policy(policy, view)?;
        Ok(compare_puct_selection_basis(
            score,
            self.guidance.edge(),
            self.guidance.position(),
            other_score,
            other.guidance.edge(),
            other.guidance.position(),
        ))
    }

    fn to_proposal(
        &self,
        request: &PlannerRequest,
        invocation: crate::PlannerInvocationId,
    ) -> Result<Proposal, CampaignCodecError> {
        Proposal::new(
            self.guidance.position().branch_point(),
            self.guidance.position().source(),
            self.guidance.domain(),
            self.guidance.value().clone(),
            request.invocation().policy(),
            Some(invocation),
            self.guidance.ordinal(),
            request.invocation().input_view(),
        )
    }
}

impl Canonical for PuctCarriedCandidate {
    fn encode(&self, encoder: &mut Encoder) {
        self.guidance.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self {
            guidance: crate::PlannerCandidateGuidance::decode(decoder)?,
        })
    }
}
