//! Closed deterministic planners for breadth-first, depth-first, and seeded-priority search.
//!
//! The coordinator supplies every Ready offer with an authenticated prospective
//! branch path. The pure engine ranks only those projections, carries the best
//! candidate across bounded scan pages, and issues after reaching EOF.

use std::cmp::Ordering;

use super::*;
use crate::{GuidanceEvidence, PlannerEngineId};

const ENGINE_NAME: &str = "crucible-canonical-search-order";
const ENGINE_IMPLEMENTATION_VERSION: u32 = 1;
const ENGINE_PROTOCOL_VERSION: u32 = 1;
const STATE_FORMAT: &str = "canonical-search-order-planner";
const STATE_FORMAT_VERSION: u32 = 1;
const POLICY_ARTIFACT_ABI_VERSION: u32 = 1;
const POLICY_DEPENDENCY_LOCK_BYTES: &[u8] = b"crucible-canonical-search-order-planner.v1";
const PRIORITY_SCORE_DOMAIN: &[u8] = b"crucible.search.strategy.priority.v1";
const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

/// Authenticated graph-search ordering selected by the local campaign owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalSearchStrategy {
    /// Selects the shallowest prospective child first.
    BreadthFirst,
    /// Selects the deepest prospective child first.
    DepthFirst,
    /// Selects by the legacy depth score under an exact 32-byte seed.
    Priority {
        /// Exact strategy-local seed used by the legacy priority score.
        seed: [u8; 32],
    },
}

impl CanonicalSearchStrategy {
    fn artifact_arguments(self) -> BTreeMap<String, String> {
        match self {
            Self::BreadthFirst => {
                BTreeMap::from([("strategy".to_owned(), "breadth-first".to_owned())])
            }
            Self::DepthFirst => BTreeMap::from([("strategy".to_owned(), "depth-first".to_owned())]),
            Self::Priority { seed } => BTreeMap::from([
                ("strategy".to_owned(), "priority".to_owned()),
                ("seed".to_owned(), encode_hex(seed)),
            ]),
        }
    }

    fn compare(self, left: &CarriedSearchCandidate, right: &CarriedSearchCandidate) -> Ordering {
        match self {
            Self::BreadthFirst => left
                .depth
                .cmp(&right.depth)
                .then_with(|| left.path.cmp(&right.path)),
            Self::DepthFirst => right
                .depth
                .cmp(&left.depth)
                .then_with(|| left.path.cmp(&right.path)),
            Self::Priority { seed } => priority_score(seed, left.depth)
                .cmp(&priority_score(seed, right.depth))
                .then_with(|| left.path.cmp(&right.path)),
        }
    }
}

/// Complete deterministic repository basis for one canonical search strategy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalSearchPlannerBasis {
    engine: PlannerEngine,
    artifact: PolicyArtifact,
    initial_state: PlannerState,
}

impl CanonicalSearchPlannerBasis {
    /// Returns the exact built-in engine descriptor.
    #[must_use]
    pub const fn engine(&self) -> &PlannerEngine {
        &self.engine
    }

    /// Returns the strategy-bound policy artifact.
    #[must_use]
    pub const fn artifact(&self) -> &PolicyArtifact {
        &self.artifact
    }

    /// Returns the empty portable planner state.
    #[must_use]
    pub const fn initial_state(&self) -> &PlannerState {
        &self.initial_state
    }
}

/// Pure planner for one fixed authenticated graph-search ordering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalSearchPlanner {
    strategy: CanonicalSearchStrategy,
}

impl CanonicalSearchPlanner {
    /// Builds the pure planner for one fixed strategy.
    #[must_use]
    pub const fn new(strategy: CanonicalSearchStrategy) -> Self {
        Self { strategy }
    }

    /// Builds the closed engine descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if the fixed descriptor is invalid.
    pub fn descriptor() -> Result<PlannerEngine, CampaignCodecError> {
        PlannerEngine::new(
            ENGINE_NAME,
            ENGINE_IMPLEMENTATION_VERSION,
            ENGINE_PROTOCOL_VERSION,
            BTreeSet::from([
                CANONICAL_FRONTIER_OFFERS_CAPABILITY.to_owned(),
                CANONICAL_FRONTIER_BUDGET_CAPABILITY.to_owned(),
                CANONICAL_FRONTIER_REQUEST_BUDGET_CAPABILITY.to_owned(),
                CANONICAL_FRONTIER_SEARCH_ORDER_CAPABILITY.to_owned(),
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

    pub(crate) fn from_request(
        request: &PlannerRequest,
    ) -> Result<Option<Self>, CampaignCodecError> {
        if !Self::supports_descriptor(request.engine())? {
            return Ok(None);
        }

        let arguments = request.policy_artifact().arguments();
        let strategy = match arguments.get("strategy").map(String::as_str) {
            Some("breadth-first") if arguments.len() == 1 => CanonicalSearchStrategy::BreadthFirst,
            Some("depth-first") if arguments.len() == 1 => CanonicalSearchStrategy::DepthFirst,
            Some("priority") if arguments.len() == 2 => {
                let seed = arguments
                    .get("seed")
                    .ok_or(CampaignCodecError::InvalidValue {
                        reason: "canonical search priority artifact omits its seed",
                    })?;
                CanonicalSearchStrategy::Priority {
                    seed: decode_hex_seed(seed)?,
                }
            }
            _ => {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "canonical search planner artifact arguments are invalid",
                });
            }
        };
        Ok(Some(Self::new(strategy)))
    }

    pub(crate) fn initial_state_for_engine(
        engine: &PlannerEngine,
    ) -> Result<PlannerState, CampaignCodecError> {
        Self::encode_state(
            engine.id()?,
            &CanonicalSearchPlannerState {
                input_view: None,
                best: None,
                budget_blocked: false,
            },
        )
    }

    /// Builds the exact strategy-bound repository basis.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if a closed descriptor is invalid.
    pub fn basis(
        strategy: CanonicalSearchStrategy,
    ) -> Result<CanonicalSearchPlannerBasis, CampaignCodecError> {
        let engine = Self::descriptor()?;
        let engine_id = engine.id()?;
        let artifact = PolicyArtifact::new(
            engine_id,
            POLICY_ARTIFACT_ABI_VERSION,
            Self::dependency_lock_id(),
            BTreeSet::new(),
            strategy.artifact_arguments(),
        )?;
        let initial_state = Self::initial_state_for_engine(&engine)?;
        Ok(CanonicalSearchPlannerBasis {
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
        state: &CanonicalSearchPlannerState,
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
    ) -> Result<CanonicalSearchPlannerState, CampaignCodecError> {
        let state = request.planner_state();
        if state.state_format() != STATE_FORMAT
            || state.state_format_version() != STATE_FORMAT_VERSION
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "canonical search planner state format mismatch",
            });
        }
        codec::decode(state.bytes())
    }
}

impl PurePlannerEngine for CanonicalSearchPlanner {
    type Error = CampaignCodecError;

    fn plan(&mut self, request: &PlannerRequest) -> Result<PlannerEngineOutput, Self::Error> {
        let expected_basis = Self::basis(self.strategy)?;
        let expected_engine = expected_basis.engine().id()?;
        if request.engine() != expected_basis.engine()
            || request.policy_artifact() != expected_basis.artifact()
            || request.invocation().engine() != expected_engine
            || request.planner_state().engine() != expected_engine
            || !matches!(
                request.policy().explorer(),
                crate::ExplorerPolicy::Exhaustive { .. }
            )
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "canonical search planner engine or strategy basis mismatch",
            });
        }

        let view = request.invocation().input_view();
        let page = request.invocation().scan_page();
        let prior = Self::decode_state(request)?;
        let mut budget_blocked = prior.input_view == Some(view) && prior.budget_blocked;
        let mut best = if prior.input_view == Some(view) {
            if prior.best.as_ref().is_some_and(|candidate| {
                page.after().is_none_or(|after| candidate.position > after)
            }) {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "canonical search planner state exceeds the scan cursor",
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
            let (Some(offer), Some(search)) = (input.offer, input.search) else {
                continue;
            };
            offered_on_page =
                offered_on_page
                    .checked_add(1)
                    .ok_or(CampaignCodecError::LimitExceeded {
                        limit: "canonical-search-planner-eligible-count",
                    })?;
            let candidate = CarriedSearchCandidate::from_offer(position, &offer, &search);
            if best
                .as_ref()
                .is_none_or(|current| self.strategy.compare(&candidate, current).is_lt())
            {
                best = Some(candidate);
            }
        }

        let fuel = u64::try_from(page.positions().len())
            .ok()
            .and_then(|positions| positions.checked_add(1))
            .ok_or(CampaignCodecError::LimitExceeded {
                limit: "canonical-search-planner-fuel",
            })?;
        if fuel > request.invocation().budget().fuel() {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "canonical-search-planner-fuel",
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
            expected_engine,
            &CanonicalSearchPlannerState {
                input_view: Some(view),
                best: next_best.clone(),
                budget_blocked,
            },
        )?;
        let explanation = GuidanceEvidence::new(BTreeMap::from([
            (
                "offered-on-page".to_owned(),
                i64::try_from(offered_on_page).map_err(|_| CampaignCodecError::LimitExceeded {
                    limit: "canonical-search-planner-evidence",
                })?,
            ),
            ("selected".to_owned(), i64::from(next_best.is_some())),
            ("budget-blocked".to_owned(), i64::from(budget_blocked)),
        ]))?;
        let usage = PlanningUsage {
            branch_requests: 0,
            proposals: proposal_count,
            input_objects: page.input_objects(),
            input_bytes: page.input_bytes(),
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
struct CanonicalSearchPlannerState {
    input_view: Option<crate::CampaignViewId>,
    best: Option<CarriedSearchCandidate>,
    budget_blocked: bool,
}

impl Canonical for CanonicalSearchPlannerState {
    fn encode(&self, encoder: &mut Encoder) {
        1_u32.encode(encoder);
        self.input_view.encode(encoder);
        self.best.encode(encoder);
        self.budget_blocked.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        if u32::decode(decoder)? != 1 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported canonical search planner state version",
            });
        }
        Ok(Self {
            input_view: Option::decode(decoder)?,
            best: Option::decode(decoder)?,
            budget_blocked: bool::decode(decoder)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CarriedSearchCandidate {
    position: PlanningScanPosition,
    domain: crate::ChoiceDomainId,
    value: crate::ChoiceValue,
    ordinal: u64,
    statistical_evidence: Option<crate::StatisticalProposalEvidence>,
    path: crate::BranchPathId,
    depth: u64,
}

impl CarriedSearchCandidate {
    fn from_offer(
        position: PlanningScanPosition,
        offer: &Proposal,
        search: &PlannerSearchCandidate,
    ) -> Self {
        Self {
            position,
            domain: offer.domain(),
            value: offer.value().clone(),
            ordinal: offer.ordinal(),
            statistical_evidence: offer.statistical_evidence(),
            path: search.path(),
            depth: search.depth(),
        }
    }

    fn to_proposal(
        &self,
        request: &PlannerRequest,
        invocation: crate::PlannerInvocationId,
    ) -> Result<Proposal, CampaignCodecError> {
        match self.statistical_evidence {
            Some(evidence) => Proposal::new_with_statistical_evidence(
                self.position.branch_point(),
                self.position.source(),
                self.domain,
                self.value.clone(),
                request.invocation().policy(),
                Some(invocation),
                self.ordinal,
                request.invocation().input_view(),
                evidence,
            ),
            None => Proposal::new(
                self.position.branch_point(),
                self.position.source(),
                self.domain,
                self.value.clone(),
                request.invocation().policy(),
                Some(invocation),
                self.ordinal,
                request.invocation().input_view(),
            ),
        }
    }
}

impl Canonical for CarriedSearchCandidate {
    fn encode(&self, encoder: &mut Encoder) {
        self.position.encode(encoder);
        self.domain.encode(encoder);
        self.value.encode(encoder);
        self.ordinal.encode(encoder);
        self.statistical_evidence.encode(encoder);
        self.path.encode(encoder);
        self.depth.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let value = Self {
            position: PlanningScanPosition::decode(decoder)?,
            domain: crate::ChoiceDomainId::decode(decoder)?,
            value: crate::ChoiceValue::decode(decoder)?,
            ordinal: u64::decode(decoder)?,
            statistical_evidence: Option::decode(decoder)?,
            path: crate::BranchPathId::decode(decoder)?,
            depth: u64::decode(decoder)?,
        };
        if value.ordinal == 0 || value.depth == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "canonical search planner candidate has zero ordinal or depth",
            });
        }
        Ok(value)
    }
}

fn priority_score(seed: [u8; 32], depth: u64) -> u64 {
    let hash = fold_fnv_bytes(FNV_OFFSET_BASIS, PRIORITY_SCORE_DOMAIN);
    let hash = fold_fnv_bytes(hash, &seed);
    fold_fnv_bytes(hash, &depth.to_le_bytes())
}

fn fold_fnv_bytes(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn encode_hex(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        encoded.push(char::from(HEX[(byte >> 4) as usize]));
        encoded.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    encoded
}

fn decode_hex_seed(encoded: &str) -> Result<[u8; 32], CampaignCodecError> {
    if encoded.len() != 64 || !encoded.is_ascii() {
        return Err(CampaignCodecError::InvalidValue {
            reason: "canonical search priority seed is not 32-byte hexadecimal",
        });
    }
    let mut seed = [0_u8; 32];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_hex_nibble(pair[0])?;
        let low = decode_hex_nibble(pair[1])?;
        seed[index] = (high << 4) | low;
    }
    Ok(seed)
}

fn decode_hex_nibble(byte: u8) -> Result<u8, CampaignCodecError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(CampaignCodecError::InvalidValue {
            reason: "canonical search priority seed contains non-lowercase hexadecimal",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BooleanDomain, BranchBudget, BranchRequestCause, CampaignMode, CampaignSeed,
        CandidateSource, ChoiceDomain, FairnessPolicy, RetentionPolicy, StopCondition,
    };

    fn candidate(label: &'static [u8], depth: u64) -> CarriedSearchCandidate {
        CarriedSearchCandidate {
            position: PlanningScanPosition::new(
                crate::BranchPointId::from_hash(CampaignHash::derive(
                    "test.canonical-search.branch-point",
                    label,
                )),
                crate::BranchRequestId::from_content_id(ContentId::for_bytes(
                    crucible_cas::content_store::ObjectKind::CampaignFact,
                    1,
                    label,
                ))
                .expect("request id"),
            ),
            domain: crate::ChoiceDomainId::from_content_id(ContentId::for_bytes(
                crucible_cas::content_store::ObjectKind::CampaignFact,
                1,
                label,
            ))
            .expect("domain id"),
            value: crate::ChoiceValue::Boolean(false),
            ordinal: 1,
            statistical_evidence: None,
            path: crate::BranchPathId::from_content_id(ContentId::for_bytes(
                crucible_cas::content_store::ObjectKind::CampaignFact,
                1,
                label,
            ))
            .expect("path id"),
            depth,
        }
    }

    #[test]
    fn graph_search_strategies_use_depth_and_authenticated_path_ties() {
        let shallow = candidate(b"shallow", 1);
        let deep = candidate(b"deep", 3);

        assert!(
            CanonicalSearchStrategy::BreadthFirst
                .compare(&shallow, &deep)
                .is_lt()
        );
        assert!(
            CanonicalSearchStrategy::DepthFirst
                .compare(&deep, &shallow)
                .is_lt()
        );

        let same_depth_left = candidate(b"same-depth-left", 2);
        let same_depth_right = candidate(b"same-depth-right", 2);
        assert_eq!(
            CanonicalSearchStrategy::BreadthFirst.compare(&same_depth_left, &same_depth_right),
            same_depth_left.path.cmp(&same_depth_right.path)
        );
    }

    #[test]
    fn seeded_priority_score_matches_the_legacy_fnv_contract() {
        let seed = [0_u8; 32];

        assert_eq!(priority_score(seed, 1), 0xe226_78ea_f3c6_e89d);
        assert_eq!(priority_score(seed, 2), 0x0121_3ff3_feb6_32be);
        assert_eq!(priority_score(seed, 3), 0x201c_06fd_09a5_7cdf);
        assert_eq!(priority_score(seed, 10), 0x094b_07ab_a73b_e1b6);
    }

    #[test]
    fn graph_search_strategies_carry_their_winner_across_restart_pages() {
        let breadth = selected_across_pages(CanonicalSearchStrategy::BreadthFirst);
        assert_eq!(breadth.selected, breadth.first);

        let depth = selected_across_pages(CanonicalSearchStrategy::DepthFirst);
        assert_eq!(depth.selected, depth.second);

        let priority = selected_across_pages(CanonicalSearchStrategy::Priority { seed: [0; 32] });
        assert_eq!(priority.selected, priority.second);
    }

    struct SearchSelection {
        first: PlanningScanPosition,
        second: PlanningScanPosition,
        selected: PlanningScanPosition,
    }

    fn selected_across_pages(strategy: CanonicalSearchStrategy) -> SearchSelection {
        let basis = CanonicalSearchPlanner::basis(strategy).expect("search basis");
        let policy = search_policy();
        let view = search_view();
        let domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("boolean domain"));
        let domain_id = domain.id().expect("domain id");
        let mut branches = [
            search_branch_request(b"first", domain_id),
            search_branch_request(b"second", domain_id),
        ];
        branches.sort_by_key(|branch| {
            PlanningScanPosition::new(
                branch.branch_point(),
                branch.id().expect("branch request id"),
            )
        });
        let first_position = PlanningScanPosition::new(
            branches[0].branch_point(),
            branches[0].id().expect("first request id"),
        );
        let second_position = PlanningScanPosition::new(
            branches[1].branch_point(),
            branches[1].id().expect("second request id"),
        );

        let first_request = search_page_request(
            basis.engine(),
            basis.artifact(),
            basis.initial_state(),
            &policy,
            view,
            None,
            false,
            &branches[0],
            &domain,
            1,
        );
        let mut planner = CanonicalSearchPlanner::new(strategy);
        let first_output = planner
            .plan(&first_request)
            .expect("plan first search page");
        let PlannerProposalDisposition::ContinueScan { cursor } =
            first_output.proposal().disposition()
        else {
            panic!("first search page must continue")
        };
        assert_eq!(cursor.after(), Some(first_position));

        // Canonical state bytes are the only state carried into a restarted engine.
        let restarted_state =
            codec::decode::<PlannerState>(&codec::encode(first_output.proposal().next_state()))
                .expect("reopen search planner state");
        let final_request = search_page_request(
            basis.engine(),
            basis.artifact(),
            &restarted_state,
            &policy,
            view,
            cursor.after(),
            true,
            &branches[1],
            &domain,
            3,
        );
        let final_output = CanonicalSearchPlanner::new(strategy)
            .plan(&final_request)
            .expect("plan final search page after restart");
        let PlannerProposalDisposition::Issue { selected, .. } =
            final_output.proposal().disposition()
        else {
            panic!("final search page must issue")
        };
        SearchSelection {
            first: first_position,
            second: second_position,
            selected: *selected,
        }
    }

    fn search_page_request(
        engine: &PlannerEngine,
        artifact: &PolicyArtifact,
        state: &PlannerState,
        policy: &CampaignPolicy,
        view: CampaignPlanningView,
        after: Option<PlanningScanPosition>,
        complete: bool,
        branch: &BranchRequest,
        domain: &ChoiceDomain,
        depth: u64,
    ) -> PlannerRequest {
        let position = PlanningScanPosition::new(
            branch.branch_point(),
            branch.id().expect("branch request id"),
        );
        let input_bytes = u64::try_from(branch.canonical_bytes().len()).expect("request bytes");
        let page = crate::PlanningScanPage::new(after, 1, vec![position], complete, input_bytes)
            .expect("search scan page");
        let invocation = PlannerInvocation::new(
            engine.id().expect("engine id"),
            artifact.id().expect("artifact id"),
            policy.id().expect("policy id"),
            state.id().expect("state id"),
            view.id().expect("view id"),
            page,
            crate::PlanningBudget::new(1, 1, 16, 1_048_576, 100).expect("planning budget"),
        )
        .expect("planner invocation");
        let invocation_id = invocation.id().expect("invocation id");
        let offer = Proposal::new(
            branch.branch_point(),
            branch.id().expect("branch request id"),
            domain.id().expect("domain id"),
            crate::ChoiceValue::Boolean(false),
            policy.id().expect("policy id"),
            Some(invocation_id),
            1,
            view.id().expect("view id"),
        )
        .expect("candidate offer");
        let budget = crate::PlannerCandidateBudget::new(&offer, 1, 1, true)
            .expect("candidate budget")
            .with_request_attempts(1);
        let continuation = ContinuationProjection::new(
            branch.id().expect("branch request id"),
            branch.branch_point(),
            ContinuationState::Ready,
        );
        let parent_segments = (0..depth.saturating_sub(1))
            .map(|index| {
                crate::BranchPathSegment::new(
                    crate::BranchPointId::from_hash(CampaignHash::derive(
                        "test.canonical-search.parent-point",
                        &index.to_le_bytes(),
                    )),
                    crate::BranchEdgeId::from_hash(CampaignHash::derive(
                        "test.canonical-search.parent-edge",
                        &index.to_le_bytes(),
                    )),
                )
            })
            .collect::<Vec<_>>();
        let parent_path = crate::BranchPath::new(parent_segments.clone()).expect("parent path");
        let edge = crate::Selection::campaign_edge_id(
            branch.branch_point(),
            domain.semantic_id(),
            offer.value(),
        );
        let mut child_segments = parent_segments;
        child_segments.push(crate::BranchPathSegment::new(branch.branch_point(), edge));
        let path = crate::BranchPath::new(child_segments).expect("child path");
        let search = PlannerSearchCandidate::new(
            view.id().expect("view id"),
            policy.id().expect("policy id"),
            position,
            domain.id().expect("domain id"),
            domain.semantic_id(),
            offer.value().clone(),
            offer.ordinal(),
            edge,
            parent_path.id().expect("parent path id"),
            path.id().expect("child path id"),
            depth,
        )
        .expect("search candidate");
        let objects = vec![
            ObjectEnvelope::for_record_versioned(
                crate::CampaignRecordKind::BranchRequest,
                branch.schema_version(),
                crate::object::content_children(branch.content_children())
                    .expect("branch children"),
                branch.canonical_bytes(),
            )
            .expect("branch envelope"),
            ObjectEnvelope::for_record(
                crate::CampaignRecordKind::ChoiceDomain,
                BTreeSet::new(),
                domain.canonical_bytes(),
            )
            .expect("domain envelope"),
            ObjectEnvelope::for_record(
                crate::CampaignRecordKind::ContinuationProjection,
                crate::object::content_children(continuation.content_children())
                    .expect("continuation children"),
                continuation.canonical_bytes(),
            )
            .expect("continuation envelope"),
            ObjectEnvelope::for_record_versioned(
                crate::CampaignRecordKind::Proposal,
                offer.schema_version(),
                crate::object::content_children(offer.content_children()).expect("offer children"),
                offer.canonical_bytes(),
            )
            .expect("offer envelope"),
            ObjectEnvelope::for_candidate_budget(&budget).expect("budget envelope"),
            ObjectEnvelope::for_branch_path(&parent_path).expect("parent path envelope"),
            ObjectEnvelope::for_branch_path(&path).expect("child path envelope"),
            ObjectEnvelope::for_record(
                crate::CampaignRecordKind::PlannerSearchCandidate,
                crate::object::content_children(search.content_children())
                    .expect("search children"),
                search.canonical_bytes(),
            )
            .expect("search envelope"),
        ];
        PlannerRequest::new(
            crate::CampaignSnapshotId::from_content_id(ContentId::for_bytes(
                crucible_cas::content_store::ObjectKind::CampaignSnapshot,
                2,
                b"canonical search snapshot",
            ))
            .expect("snapshot id"),
            invocation,
            engine.clone(),
            artifact.clone(),
            policy.clone(),
            state.clone(),
            view,
            CampaignPlanningBundle::new(objects).expect("search bundle"),
        )
        .expect("search planner request")
    }

    fn search_branch_request(label: &[u8], domain: crate::ChoiceDomainId) -> BranchRequest {
        let branch_point = crate::BranchPointId::from_hash(CampaignHash::derive(
            "test.canonical-search.branch-point",
            label,
        ));
        BranchRequest::new(
            branch_point,
            crate::ConfigurationArtifactId::from_content_id(ContentId::for_bytes(
                crucible_cas::content_store::ObjectKind::Configuration,
                1,
                label,
            ))
            .expect("parent configuration"),
            crate::ChoiceOpportunityId::from_content_id(ContentId::for_bytes(
                crucible_cas::content_store::ObjectKind::CampaignFact,
                1,
                &[label, b" opportunity"].concat(),
            ))
            .expect("opportunity id"),
            domain,
            CandidateSource::finite(BTreeSet::from([crate::ChoiceValue::Boolean(false)]))
                .expect("finite source"),
            BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(
                CampaignHash::derive("test.canonical-search.command", label),
            )),
            BranchBudget::new(1, 1).expect("branch budget"),
            StopCondition::NextChoice,
        )
        .expect("branch request")
    }

    fn search_policy() -> CampaignPolicy {
        CampaignPolicy::new(
            crate::ScenarioDefId::from_hash(CampaignHash::derive(
                "test.canonical-search.scenario",
                b"scenario",
            )),
            CampaignSeed::from_bytes([0x44; 32]),
            CampaignMode::Strict,
            crate::ExplorerPolicy::Exhaustive {
                maximum_cardinality: u64::MAX,
            },
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            FairnessPolicy::new(0, 0).expect("fairness"),
            RetentionPolicy::new(true, 1, true, true),
            true,
        )
        .expect("search policy")
    }

    fn search_view() -> CampaignPlanningView {
        let root = |label: u8| {
            ContentId::for_bytes(
                crucible_cas::content_store::ObjectKind::MerkleNode,
                1,
                &[label],
            )
        };
        CampaignPlanningView::new(
            root(1),
            root(2),
            root(3),
            root(4),
            root(5),
            root(6),
            root(7),
        )
        .expect("planning view")
    }
}
