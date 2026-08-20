//! Closed deterministic planner over coordinator-authenticated frontier offers.
//!
//! The engine never resolves repository records or generator algorithms. The
//! coordinator supplies one exact continuation projection and, when eligible,
//! one exact candidate offer for every served scan position. The engine scans
//! those bounded inputs in canonical order, carries the best offer in portable
//! state across pages, and issues only after reaching EOF.

use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::{CampaignViewId, ChoiceDomainId, ChoiceValue, GuidanceEvidence, PlannerEngineId};

const ENGINE_NAME: &str = "crucible-canonical-frontier";
const ENGINE_IMPLEMENTATION_VERSION: u32 = 1;
const ENGINE_PROTOCOL_VERSION: u32 = 1;
const STATE_FORMAT: &str = "canonical-frontier-planner";
const STATE_FORMAT_VERSION: u32 = 1;
const STATE_SCHEMA_VERSION: u32 = 1;

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
        PlannerEngine::new(
            ENGINE_NAME,
            ENGINE_IMPLEMENTATION_VERSION,
            ENGINE_PROTOCOL_VERSION,
            BTreeSet::from([CANONICAL_FRONTIER_OFFERS_CAPABILITY.to_owned()]),
        )
    }

    /// Builds an empty portable state for this exact engine descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if descriptor identity or state encoding
    /// unexpectedly violates a canonical bound.
    pub fn initial_state() -> Result<PlannerState, CampaignCodecError> {
        let engine = Self::descriptor()?.id()?;
        Self::encode_state(engine, &CanonicalFrontierPlannerState::empty())
    }

    fn encode_state(
        engine: PlannerEngineId,
        state: &CanonicalFrontierPlannerState,
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
    ) -> Result<CanonicalFrontierPlannerState, CampaignCodecError> {
        let state = request.planner_state();
        if state.state_format() != STATE_FORMAT
            || state.state_format_version() != STATE_FORMAT_VERSION
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "canonical frontier planner state format mismatch",
            });
        }
        codec::decode(state.bytes())
    }
}

impl PurePlannerEngine for CanonicalFrontierPlanner {
    type Error = CampaignCodecError;

    fn plan(&mut self, request: &PlannerRequest) -> Result<PlannerEngineOutput, Self::Error> {
        let expected_engine = Self::descriptor()?;
        let expected_engine_id = expected_engine.id()?;
        if request.engine() != &expected_engine
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
                schema_version: STATE_SCHEMA_VERSION,
                input_view: Some(view),
                best: next_best.clone(),
            },
        )?;
        let explanation = GuidanceEvidence::new(BTreeMap::from([
            (
                "offered-on-page".to_owned(),
                i64::try_from(offered_on_page).map_err(|_| CampaignCodecError::LimitExceeded {
                    limit: "canonical-frontier-planner-evidence",
                })?,
            ),
            ("selected".to_owned(), i64::from(next_best.is_some())),
        ]))?;
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
}

impl CanonicalFrontierPlannerState {
    const fn empty() -> Self {
        Self {
            schema_version: STATE_SCHEMA_VERSION,
            input_view: None,
            best: None,
        }
    }
}

impl Canonical for CanonicalFrontierPlannerState {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.input_view.encode(encoder);
        self.best.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        if u32::decode(decoder)? != STATE_SCHEMA_VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported canonical frontier planner state version",
            });
        }
        Ok(Self {
            schema_version: STATE_SCHEMA_VERSION,
            input_view: Option::decode(decoder)?,
            best: Option::decode(decoder)?,
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
