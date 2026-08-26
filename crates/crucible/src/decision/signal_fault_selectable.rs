//! Campaign normalization for promoted signal-fault search frontiers.
//!
//! Runtime signal evaluation exposes finite per-event candidates as exact
//! [`SearchRuntimeFrontier`] values. This module converts one homogeneous
//! signal-fault frontier into the campaign choice vocabulary and reconstructs
//! the exact scheduler prefix from repository-authenticated selection records.
//! It performs no repository mutation and deliberately does not decide when a
//! historical frontier is safe to publish as campaign knowledge.

use std::collections::BTreeSet;

use crucible_campaign::{
    CampaignCodecError, CampaignHash, ChoiceClassContext, ChoiceCoordinate, ChoiceDiscovery,
    ChoiceDomain, ChoiceSource, ChoiceValue, ConfigurationId, ExactRational, IntegerDomain,
    IntegerRepresentation, IntegerValue, ScenarioDefId, SelectableDeclaration, Selection,
};
use thiserror::Error;

use crate::model::{BindingSearchChoice, SearchChoiceId, SearchOverride};
use crate::{Configuration, Decision, SearchRuntimeFrontier, SelectionDecision, VirtualTime, step};

/// Stable environment-adapter identity for promoted signal-fault choices.
pub const SIGNAL_FAULT_CAMPAIGN_ADAPTER: &str = "crucible.signal-fault-search.v1";

/// Maximum finite candidates promoted from one signal-fault event.
pub const MAX_SIGNAL_FAULT_CAMPAIGN_CANDIDATES: usize = 4_096;

/// Maximum promoted signal-fault events retained in one replay plan.
pub const MAX_SIGNAL_FAULT_CAMPAIGN_BRANCHES: usize = 4_096;

const SIGNAL_FAULT_DOMAIN_VERSION: u32 = 1;
const SIGNAL_FAULT_DECLARATION_NAME: &str = "signal-fault-event-outcome";
const SIGNAL_FAULT_INSTANCE_PREFIX: &str = "frontier-";
const SIGNAL_FAULT_CANDIDATE_UNIT: &str = "candidate-index";

/// One exact finite signal-fault frontier expressed as a campaign selectable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignalFaultSelectable {
    parent: Configuration,
    frontier: VirtualTime,
    choice: SearchChoiceId,
    candidates_digest: crate::ContentHash,
    candidate_count: u32,
    declaration: SelectableDeclaration,
    domain: ChoiceDomain,
    opportunity: crucible_campaign::ChoiceOpportunity,
}

impl SignalFaultSelectable {
    /// Normalizes one homogeneous runtime signal-fault frontier.
    ///
    /// Candidate order is semantic: the frontier must contain the exact dense
    /// sequence `candidate/0..candidate_count` for one search-choice identity,
    /// candidate-set digest, parent configuration, and virtual-time boundary.
    /// The campaign domain adds one final sentinel value representing the
    /// unmodified model result.
    ///
    /// # Errors
    ///
    /// Returns [`SignalFaultSelectableError`] when the frontier is empty,
    /// exceeds the campaign cap, mixes producer contracts, contains a sparse
    /// candidate sequence, or cannot be represented canonically.
    pub fn from_frontier(
        frontier: &SearchRuntimeFrontier,
    ) -> Result<Self, SignalFaultSelectableError> {
        let choices = frontier.choices.choices();
        if choices.is_empty() {
            return Err(SignalFaultSelectableError::EmptyFrontier);
        }
        if choices.len() > MAX_SIGNAL_FAULT_CAMPAIGN_CANDIDATES {
            return Err(SignalFaultSelectableError::CandidateLimitExceeded);
        }

        let parent_id = frontier.configuration.id();
        let mut basis = None;
        for (expected_index, choice) in choices.iter().enumerate() {
            let [Decision::Override(decision)] = choice.decisions() else {
                return Err(SignalFaultSelectableError::InvalidFrontierDecision {
                    index: expected_index,
                });
            };
            let Some((choice_id, search_override)) =
                SearchOverride::from_override_decision(decision)
            else {
                return Err(SignalFaultSelectableError::InvalidFrontierDecision {
                    index: expected_index,
                });
            };
            if search_override.parent_branch != Some(parent_id) {
                return Err(SignalFaultSelectableError::FrontierParentMismatch);
            }
            if usize::try_from(search_override.candidate_index).ok() != Some(expected_index) {
                return Err(SignalFaultSelectableError::NonDenseCandidates);
            }
            match basis {
                None => basis = Some((choice_id, search_override.candidates_digest)),
                Some((expected_choice, expected_digest))
                    if expected_choice == choice_id
                        && expected_digest == search_override.candidates_digest => {}
                Some(_) => return Err(SignalFaultSelectableError::MixedCandidateBasis),
            }
        }

        let Some((choice, candidates_digest)) = basis else {
            return Err(SignalFaultSelectableError::EmptyFrontier);
        };
        let candidate_count = u32::try_from(choices.len())
            .map_err(|_| SignalFaultSelectableError::CandidateLimitExceeded)?;
        Self::from_basis(
            frontier.configuration.clone(),
            frontier.at,
            choice,
            candidates_digest,
            candidate_count,
        )
    }

    fn from_basis(
        parent: Configuration,
        frontier: VirtualTime,
        choice: SearchChoiceId,
        candidates_digest: crate::ContentHash,
        candidate_count: u32,
    ) -> Result<Self, SignalFaultSelectableError> {
        if candidate_count == 0 {
            return Err(SignalFaultSelectableError::EmptyFrontier);
        }
        if usize::try_from(candidate_count)
            .map_or(true, |count| count > MAX_SIGNAL_FAULT_CAMPAIGN_CANDIDATES)
        {
            return Err(SignalFaultSelectableError::CandidateLimitExceeded);
        }

        let domain = signal_fault_domain(candidate_count)?;
        let source = ChoiceSource::Environment {
            adapter: String::from(SIGNAL_FAULT_CAMPAIGN_ADAPTER),
            target: CampaignHash::from_bytes(choice.content_hash().bytes),
        };
        let default = ChoiceValue::Integer(IntegerValue::Unsigned(u64::from(candidate_count)));
        let class_context = ChoiceClassContext::new(BTreeSet::from([
            String::from("per-event"),
            String::from("signal-fault"),
        ]))?;
        let declaration = SelectableDeclaration::new(
            SIGNAL_FAULT_DECLARATION_NAME,
            source,
            domain.clone(),
            default,
            class_context,
            BTreeSet::from([
                String::from("event-outcome"),
                String::from("hierarchical-promotion"),
            ]),
            false,
        )?;
        let opportunity = crucible_campaign::ChoiceOpportunity::new(
            ScenarioDefId::from_hash(CampaignHash::from_bytes(parent.def.id().bytes)),
            &declaration,
            &domain,
            ChoiceCoordinate {
                scheduler: CampaignHash::from_bytes(parent.id().bytes),
                producer: CampaignHash::from_bytes(candidates_digest.bytes),
            },
            format!("{SIGNAL_FAULT_INSTANCE_PREFIX}{:016x}", frontier.ticks),
            None,
        )?;

        Ok(Self {
            parent,
            frontier,
            choice,
            candidates_digest,
            candidate_count,
            declaration,
            domain,
            opportunity,
        })
    }

    /// Reconstructs and validates the standardized producer contract.
    ///
    /// # Errors
    ///
    /// Returns [`SignalFaultSelectableError`] when the parent, declaration,
    /// domain, or opportunity differs from the exact standardized records.
    pub fn from_records(
        parent: &Configuration,
        declaration: &SelectableDeclaration,
        opportunity: &crucible_campaign::ChoiceOpportunity,
        domain: &ChoiceDomain,
    ) -> Result<Self, SignalFaultSelectableError> {
        let ChoiceSource::Environment { adapter, target } = opportunity.source() else {
            return Err(SignalFaultSelectableError::ProducerContractMismatch);
        };
        if adapter != SIGNAL_FAULT_CAMPAIGN_ADAPTER
            || opportunity.coordinate().scheduler != CampaignHash::from_bytes(parent.id().bytes)
            || opportunity.scenario()
                != ScenarioDefId::from_hash(CampaignHash::from_bytes(parent.def.id().bytes))
        {
            return Err(SignalFaultSelectableError::ProducerContractMismatch);
        }

        let candidate_count = signal_fault_candidate_count(domain)?;
        let frontier = parse_frontier_instance(opportunity.instance())?;
        let reconstructed = Self::from_basis(
            parent.clone(),
            frontier,
            SearchChoiceId::from_content_hash(crate::ContentHash {
                bytes: target.as_bytes(),
            }),
            crate::ContentHash {
                bytes: opportunity.coordinate().producer.as_bytes(),
            },
            candidate_count,
        )?;
        if reconstructed.declaration != *declaration
            || reconstructed.domain != *domain
            || reconstructed.opportunity != *opportunity
        {
            return Err(SignalFaultSelectableError::ProducerContractMismatch);
        }
        Ok(reconstructed)
    }

    /// Returns the exact configuration before the promoted event choice.
    #[must_use]
    pub const fn parent(&self) -> &Configuration {
        &self.parent
    }

    /// Returns the exact virtual-time boundary of the promoted event choice.
    #[must_use]
    pub const fn frontier(&self) -> VirtualTime {
        self.frontier
    }

    /// Returns the stable finite search-choice identity.
    #[must_use]
    pub const fn search_choice(&self) -> SearchChoiceId {
        self.choice
    }

    /// Returns the exact finite candidate-set digest.
    #[must_use]
    pub const fn candidates_digest(&self) -> crate::ContentHash {
        self.candidates_digest
    }

    /// Returns the number of override candidates, excluding the default sentinel.
    #[must_use]
    pub const fn candidate_count(&self) -> u32 {
        self.candidate_count
    }

    /// Returns the reusable standardized declaration.
    #[must_use]
    pub const fn declaration(&self) -> &SelectableDeclaration {
        &self.declaration
    }

    /// Returns the finite candidate-index domain plus default sentinel.
    #[must_use]
    pub const fn domain(&self) -> &ChoiceDomain {
        &self.domain
    }

    /// Returns the exact runtime opportunity.
    #[must_use]
    pub const fn opportunity(&self) -> &crucible_campaign::ChoiceOpportunity {
        &self.opportunity
    }

    /// Clones the immutable records needed for campaign publication.
    ///
    /// # Errors
    ///
    /// Returns [`SignalFaultSelectableError`] if canonical record identity
    /// construction unexpectedly fails.
    pub fn discovery(&self) -> Result<ChoiceDiscovery, SignalFaultSelectableError> {
        Ok(ChoiceDiscovery::new(
            self.declaration.clone(),
            self.domain.clone(),
            self.opportunity.clone(),
        )?)
    }

    /// Builds one exact campaign branch selection.
    ///
    /// `candidate_index == candidate_count` selects the unmodified model result;
    /// lower values select the corresponding finite override candidate.
    ///
    /// # Errors
    ///
    /// Returns [`SignalFaultSelectableError`] when the parent differs or the
    /// selected candidate lies outside the standardized domain.
    pub fn branch_selection(
        &self,
        parent: &Configuration,
        candidate_index: u32,
    ) -> Result<Selection, SignalFaultSelectableError> {
        if parent != &self.parent {
            return Err(SignalFaultSelectableError::FrontierParentMismatch);
        }
        if candidate_index > self.candidate_count {
            return Err(SignalFaultSelectableError::CandidateOutsideDomain);
        }
        let parent = ConfigurationId::from_hash(CampaignHash::from_bytes(parent.id().bytes));
        Ok(Selection::new_campaign_branch(
            &self.opportunity,
            &self.domain,
            ChoiceValue::Integer(IntegerValue::Unsigned(u64::from(candidate_index))),
            self.opportunity.branch_point_id(parent),
        )?)
    }

    /// Resolves an authenticated campaign selection into an exact replay plan.
    ///
    /// # Errors
    ///
    /// Returns [`SignalFaultSelectableError`] when the selection is not a legal
    /// campaign branch at this exact parent or names an invalid candidate.
    pub fn resolve_branch(
        &self,
        selection: &Selection,
    ) -> Result<SignalFaultCampaignBranch, SignalFaultSelectableError> {
        let parent_id =
            ConfigurationId::from_hash(CampaignHash::from_bytes(self.parent.id().bytes));
        selection.validate_branch_replay(
            &self.opportunity,
            &self.domain,
            self.opportunity.branch_point_id(parent_id),
        )?;
        let ChoiceValue::Integer(IntegerValue::Unsigned(index)) = selection.value() else {
            return Err(SignalFaultSelectableError::CandidateOutsideDomain);
        };
        let index = u32::try_from(*index)
            .map_err(|_| SignalFaultSelectableError::CandidateOutsideDomain)?;
        if index > self.candidate_count {
            return Err(SignalFaultSelectableError::CandidateOutsideDomain);
        }

        let mut decisions = vec![Decision::Selection(SelectionDecision::new(selection))];
        if index < self.candidate_count {
            let basis = BindingSearchChoice {
                id: self.choice,
                candidates_digest: self.candidates_digest,
                candidate_count: self.candidate_count,
                selected_index: Some(index),
                overridden: true,
            };
            let override_decision = basis
                .override_decisions(self.parent.id())
                .into_iter()
                .nth(index as usize)
                .ok_or(SignalFaultSelectableError::CandidateOutsideDomain)?;
            decisions.push(Decision::Override(override_decision));
        }
        let selected = decisions
            .iter()
            .cloned()
            .fold(self.parent.clone(), |configuration, decision| {
                step(&configuration, decision)
            });
        Ok(SignalFaultCampaignBranch {
            parent: self.parent.clone(),
            frontier: self.frontier,
            choice: self.choice,
            candidates_digest: self.candidates_digest,
            candidate_count: self.candidate_count,
            selected_candidate: (index < self.candidate_count).then_some(index),
            decisions,
            selected,
        })
    }
}

/// Validated scheduler prefix for one promoted signal-fault campaign branch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignalFaultCampaignBranch {
    parent: Configuration,
    frontier: VirtualTime,
    choice: SearchChoiceId,
    candidates_digest: crate::ContentHash,
    candidate_count: u32,
    selected_candidate: Option<u32>,
    decisions: Vec<Decision>,
    selected: Configuration,
}

/// Authenticated promoted signal-fault branches required by one configuration.
///
/// Branches remain in target-schedule order. Each branch names the exact
/// configuration and virtual-time boundary before its selection is injected;
/// the target contains the branch's selection and optional producer override
/// at that exact schedule position. This type is the only multi-event input
/// admitted by the production signal-fault replay path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignalFaultCampaignReplayPlan {
    target: Configuration,
    branches: Vec<SignalFaultCampaignBranch>,
}

impl SignalFaultCampaignReplayPlan {
    /// Builds a bounded exact replay plan for `target`.
    ///
    /// # Errors
    ///
    /// Returns [`SignalFaultSelectableError`] when the plan exceeds the event
    /// cap, branches are not in target-schedule order, a branch parent is not
    /// an exact target prefix, or its selected decisions differ from the
    /// target at that prefix.
    pub fn new(
        target: Configuration,
        branches: Vec<SignalFaultCampaignBranch>,
    ) -> Result<Self, SignalFaultSelectableError> {
        if branches.len() > MAX_SIGNAL_FAULT_CAMPAIGN_BRANCHES {
            return Err(SignalFaultSelectableError::ReplayPlanLimitExceeded);
        }

        let target_decisions = target.schedule.decisions();
        let mut prior_selected: Option<&Configuration> = None;
        let mut prior_frontier = None;
        for branch in &branches {
            if branch.parent.def != target.def {
                return Err(SignalFaultSelectableError::ReplayPlanMismatch);
            }
            if prior_frontier.is_some_and(|frontier| branch.frontier < frontier) {
                return Err(SignalFaultSelectableError::ReplayPlanMismatch);
            }
            let parent_len = branch.parent.schedule.len();
            let selected_len = branch.selected.schedule.len();
            if selected_len != parent_len.saturating_add(branch.decisions.len())
                || selected_len > target_decisions.len()
                || branch.parent.schedule.decisions() != &target_decisions[..parent_len]
                || branch.decisions.as_slice() != &target_decisions[parent_len..selected_len]
                || branch.selected.schedule.decisions() != &target_decisions[..selected_len]
            {
                return Err(SignalFaultSelectableError::ReplayPlanMismatch);
            }
            if let Some(prior) = prior_selected
                && (prior.schedule.len() > parent_len
                    || prior.schedule.decisions()
                        != &branch.parent.schedule.decisions()[..prior.schedule.len()])
            {
                return Err(SignalFaultSelectableError::ReplayPlanMismatch);
            }
            prior_selected = Some(&branch.selected);
            prior_frontier = Some(branch.frontier);
        }

        Ok(Self { target, branches })
    }

    /// Builds the empty replay plan for a target without promoted branches.
    #[must_use]
    pub const fn empty(target: Configuration) -> Self {
        Self {
            target,
            branches: Vec::new(),
        }
    }

    /// Returns the exact configuration reconstructed by the plan.
    #[must_use]
    pub const fn target(&self) -> &Configuration {
        &self.target
    }

    /// Returns promoted branches in exact target-schedule order.
    #[must_use]
    pub fn branches(&self) -> &[SignalFaultCampaignBranch] {
        &self.branches
    }

    /// Consumes the plan into its target and ordered branches.
    #[must_use]
    pub fn into_parts(self) -> (Configuration, Vec<SignalFaultCampaignBranch>) {
        (self.target, self.branches)
    }
}

impl SignalFaultCampaignBranch {
    /// Returns the exact configuration before branch-prefix injection.
    #[must_use]
    pub const fn parent(&self) -> &Configuration {
        &self.parent
    }

    /// Returns the exact virtual-time injection boundary.
    #[must_use]
    pub const fn frontier(&self) -> VirtualTime {
        self.frontier
    }

    /// Returns whether one runtime choice proves this branch's producer event.
    ///
    /// Candidate branches require the exact installed override to have been
    /// consumed. The sentinel branch instead requires an unmodified producer
    /// result and deliberately accepts whichever model-selected candidate the
    /// binding reports.
    #[must_use]
    pub fn matches_runtime_choice(
        &self,
        coordinate: crate::model::FaultCoordinate,
        choice: &BindingSearchChoice,
    ) -> bool {
        coordinate.virtual_nanos == self.frontier.ticks
            && choice.id == self.choice
            && choice.candidates_digest == self.candidates_digest
            && choice.candidate_count == self.candidate_count
            && match self.selected_candidate {
                Some(index) => choice.overridden && choice.selected_index == Some(index),
                None => !choice.overridden,
            }
    }

    /// Returns whether one scheduler frontier proves the unmodified producer event.
    ///
    /// Candidate branches are authenticated through their consumed runtime
    /// override instead and therefore never match this sentinel-only helper.
    #[must_use]
    pub fn matches_runtime_frontier(&self, frontier: &SearchRuntimeFrontier) -> bool {
        self.selected_candidate.is_none()
            && Self::runtime_frontier_basis(frontier).is_some_and(
                |(parent, at, choice, candidates_digest, candidate_count)| {
                    parent == self.parent
                        && at == self.frontier
                        && choice == self.choice
                        && candidates_digest == self.candidates_digest
                        && candidate_count == self.candidate_count
                },
            )
    }

    /// Returns the exact finite override required by a candidate branch.
    #[must_use]
    pub fn expected_search_override(&self) -> Option<(SearchChoiceId, SearchOverride)> {
        self.selected_candidate.map(|candidate_index| {
            (
                self.choice,
                SearchOverride {
                    candidate_index,
                    candidates_digest: self.candidates_digest,
                    parent_branch: Some(self.parent.id()),
                },
            )
        })
    }

    fn runtime_frontier_basis(
        frontier: &SearchRuntimeFrontier,
    ) -> Option<(
        Configuration,
        VirtualTime,
        SearchChoiceId,
        crate::ContentHash,
        u32,
    )> {
        let selectable = SignalFaultSelectable::from_frontier(frontier).ok()?;
        Some((
            selectable.parent,
            selectable.frontier,
            selectable.choice,
            selectable.candidates_digest,
            selectable.candidate_count,
        ))
    }

    /// Returns the validated selection and optional override decisions.
    #[must_use]
    pub fn decisions(&self) -> &[Decision] {
        &self.decisions
    }

    /// Returns the exact configuration after branch-prefix injection.
    #[must_use]
    pub const fn selected(&self) -> &Configuration {
        &self.selected
    }
}

/// Failure to normalize or replay one promoted signal-fault choice.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SignalFaultSelectableError {
    /// The runtime frontier supplied no finite candidates.
    #[error("signal-fault search frontier is empty")]
    EmptyFrontier,
    /// The runtime frontier exceeded the campaign per-event candidate cap.
    #[error("signal-fault search frontier exceeds the campaign candidate cap")]
    CandidateLimitExceeded,
    /// One frontier entry was not one canonical signal-fault override.
    #[error("signal-fault search frontier candidate {index} is invalid")]
    InvalidFrontierDecision {
        /// Zero-based frontier entry index.
        index: usize,
    },
    /// Candidate indexes were not the exact dense sequence from zero.
    #[error("signal-fault search frontier candidates are not dense")]
    NonDenseCandidates,
    /// Candidate decisions named different search identities or candidate sets.
    #[error("signal-fault search frontier mixes candidate bases")]
    MixedCandidateBasis,
    /// The decision parent differs from the promoted exact configuration.
    #[error("signal-fault search frontier parent is inconsistent")]
    FrontierParentMismatch,
    /// Authenticated records differ from the standardized producer contract.
    #[error("signal-fault campaign producer contract is inconsistent")]
    ProducerContractMismatch,
    /// The selected integer is outside the candidate plus sentinel domain.
    #[error("signal-fault campaign candidate is outside its domain")]
    CandidateOutsideDomain,
    /// One configuration retained too many promoted signal-fault events.
    #[error("signal-fault campaign replay plan exceeds its event cap")]
    ReplayPlanLimitExceeded,
    /// A promoted branch is not an exact ordered prefix of its target.
    #[error("signal-fault campaign replay plan is inconsistent with its target")]
    ReplayPlanMismatch,
    /// Canonical campaign record validation failed.
    #[error(transparent)]
    Campaign(#[from] CampaignCodecError),
}

fn signal_fault_domain(candidate_count: u32) -> Result<ChoiceDomain, CampaignCodecError> {
    Ok(ChoiceDomain::Integer(IntegerDomain::new(
        SIGNAL_FAULT_DOMAIN_VERSION,
        IntegerRepresentation::Unsigned64,
        IntegerValue::Unsigned(0),
        IntegerValue::Unsigned(u64::from(candidate_count)),
        1,
        Some(String::from(SIGNAL_FAULT_CANDIDATE_UNIT)),
        ExactRational::new(1, 1)?,
        Vec::new(),
    )?))
}

fn signal_fault_candidate_count(domain: &ChoiceDomain) -> Result<u32, SignalFaultSelectableError> {
    let ChoiceDomain::Integer(integer) = domain else {
        return Err(SignalFaultSelectableError::ProducerContractMismatch);
    };
    let IntegerValue::Unsigned(maximum) = integer.maximum() else {
        return Err(SignalFaultSelectableError::ProducerContractMismatch);
    };
    let candidate_count =
        u32::try_from(maximum).map_err(|_| SignalFaultSelectableError::CandidateLimitExceeded)?;
    if candidate_count == 0
        || usize::try_from(candidate_count)
            .map_or(true, |count| count > MAX_SIGNAL_FAULT_CAMPAIGN_CANDIDATES)
        || integer.semantic_version() != SIGNAL_FAULT_DOMAIN_VERSION
        || integer.representation() != IntegerRepresentation::Unsigned64
        || integer.minimum() != IntegerValue::Unsigned(0)
        || integer.step() != 1
        || integer.unit() != Some(SIGNAL_FAULT_CANDIDATE_UNIT)
        || integer.scale() != ExactRational::new(1, 1)?
        || !integer.landmarks().is_empty()
    {
        return Err(SignalFaultSelectableError::ProducerContractMismatch);
    }
    Ok(candidate_count)
}

fn parse_frontier_instance(instance: &str) -> Result<VirtualTime, SignalFaultSelectableError> {
    let encoded = instance
        .strip_prefix(SIGNAL_FAULT_INSTANCE_PREFIX)
        .ok_or(SignalFaultSelectableError::ProducerContractMismatch)?;
    if encoded.len() != 16 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SignalFaultSelectableError::ProducerContractMismatch);
    }
    let ticks = u64::from_str_radix(encoded, 16)
        .map_err(|_| SignalFaultSelectableError::ProducerContractMismatch)?;
    Ok(VirtualTime { ticks })
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts for exact failure localization.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{ScenarioDef, SearchFrontierChoices};

    fn fixture(candidate_count: u32) -> (SearchRuntimeFrontier, BindingSearchChoice) {
        let scenario = ScenarioDef::from_canonical_material(
            "crucible.test.signal-fault-selectable",
            "signal fault selectable",
        );
        let parent = Configuration::genesis(scenario);
        let choice = BindingSearchChoice {
            id: SearchChoiceId::from_content_hash(crate::ContentHash::from_bytes(b"choice")),
            candidates_digest: crate::ContentHash::from_bytes(b"candidates"),
            candidate_count,
            selected_index: None,
            overridden: false,
        };
        let decisions = choice
            .override_decisions(parent.id())
            .into_iter()
            .map(Decision::Override)
            .collect::<Vec<_>>();
        (
            SearchRuntimeFrontier {
                configuration: parent,
                at: VirtualTime { ticks: 0x1234 },
                choices: SearchFrontierChoices::from_decisions(decisions),
            },
            choice,
        )
    }

    #[test]
    fn promoted_frontier_round_trips_candidate_and_default_branches() {
        let (frontier, choice) = fixture(3);
        let selectable =
            SignalFaultSelectable::from_frontier(&frontier).expect("normalize frontier");
        let discovery = selectable.discovery().expect("build discovery");
        let reconstructed = SignalFaultSelectable::from_records(
            &frontier.configuration,
            discovery.declaration(),
            discovery.opportunity(),
            discovery.domain(),
        )
        .expect("reconstruct records");
        assert_eq!(reconstructed, selectable);

        let selection = selectable
            .branch_selection(&frontier.configuration, 1)
            .expect("candidate branch");
        let branch = selectable
            .resolve_branch(&selection)
            .expect("resolve branch");
        assert_eq!(branch.parent(), &frontier.configuration);
        assert_eq!(branch.frontier(), frontier.at);
        assert_eq!(branch.selected().schedule.len(), 2);
        assert_eq!(
            branch.decisions()[0],
            Decision::Selection(SelectionDecision::new(&selection))
        );
        assert_eq!(
            branch.decisions()[1],
            Decision::Override(choice.override_decisions(frontier.configuration.id())[1].clone())
        );
        let observed_candidate = BindingSearchChoice {
            selected_index: Some(1),
            overridden: true,
            ..choice.clone()
        };
        assert!(branch.matches_runtime_choice(
            crate::model::FaultCoordinate {
                virtual_nanos: frontier.at.ticks,
                retired_instructions: Some(99),
            },
            &observed_candidate,
        ));
        assert!(!branch.matches_runtime_frontier(&frontier));
        assert_eq!(
            branch.expected_search_override(),
            Some((
                choice.id,
                SearchOverride {
                    candidate_index: 1,
                    candidates_digest: choice.candidates_digest,
                    parent_branch: Some(frontier.configuration.id()),
                },
            ))
        );

        let selection = selectable
            .branch_selection(&frontier.configuration, 3)
            .expect("default branch");
        let branch = selectable
            .resolve_branch(&selection)
            .expect("resolve default");
        assert_eq!(branch.decisions().len(), 1);
        assert_eq!(branch.selected().schedule.len(), 1);
        assert!(branch.matches_runtime_frontier(&frontier));
        assert!(branch.matches_runtime_choice(
            crate::model::FaultCoordinate {
                virtual_nanos: frontier.at.ticks,
                retired_instructions: None,
            },
            &choice,
        ));
        assert_eq!(branch.expected_search_override(), None);
    }

    #[test]
    fn replay_plan_binds_nested_branches_to_exact_target_prefixes() {
        let (first_frontier, _) = fixture(2);
        let first_selectable =
            SignalFaultSelectable::from_frontier(&first_frontier).expect("first selectable");
        let first_selection = first_selectable
            .branch_selection(&first_frontier.configuration, 0)
            .expect("first selection");
        let first = first_selectable
            .resolve_branch(&first_selection)
            .expect("first branch");

        let between = step(
            first.selected(),
            Decision::RngDraw(crate::RngDecision {
                stream: crate::RngStreamId::from_name("between-promoted-frontiers"),
                value: 7,
            }),
        );
        let second_choice = BindingSearchChoice {
            id: SearchChoiceId::from_content_hash(crate::ContentHash::from_bytes(b"second-choice")),
            candidates_digest: crate::ContentHash::from_bytes(b"second-candidates"),
            candidate_count: 2,
            selected_index: None,
            overridden: false,
        };
        let second_frontier = SearchRuntimeFrontier {
            configuration: between.clone(),
            at: VirtualTime { ticks: 0x5678 },
            choices: SearchFrontierChoices::from_decisions(
                second_choice
                    .override_decisions(between.id())
                    .into_iter()
                    .map(Decision::Override),
            ),
        };
        let second_selectable =
            SignalFaultSelectable::from_frontier(&second_frontier).expect("second selectable");
        let second_selection = second_selectable
            .branch_selection(&second_frontier.configuration, 2)
            .expect("unmodified second selection");
        let second = second_selectable
            .resolve_branch(&second_selection)
            .expect("second branch");

        let plan = SignalFaultCampaignReplayPlan::new(
            second.selected().clone(),
            vec![first.clone(), second.clone()],
        )
        .expect("nested plan");
        assert_eq!(plan.target(), second.selected());
        assert_eq!(plan.branches(), &[first.clone(), second.clone()]);
        assert_eq!(
            SignalFaultCampaignReplayPlan::new(
                second.selected().clone(),
                vec![second.clone(), first],
            ),
            Err(SignalFaultSelectableError::ReplayPlanMismatch)
        );

        let missing_second = second.parent().clone();
        assert_eq!(
            SignalFaultCampaignReplayPlan::new(missing_second, vec![second]),
            Err(SignalFaultSelectableError::ReplayPlanMismatch)
        );
    }

    #[test]
    fn replay_plan_rejects_more_than_the_configuration_event_cap() {
        let (frontier, _) = fixture(1);
        let selectable = SignalFaultSelectable::from_frontier(&frontier).expect("selectable");
        let selection = selectable
            .branch_selection(&frontier.configuration, 1)
            .expect("default selection");
        let branch = selectable.resolve_branch(&selection).expect("branch");
        let branches = vec![branch.clone(); MAX_SIGNAL_FAULT_CAMPAIGN_BRANCHES + 1];

        assert_eq!(
            SignalFaultCampaignReplayPlan::new(branch.selected().clone(), branches),
            Err(SignalFaultSelectableError::ReplayPlanLimitExceeded)
        );
    }

    #[test]
    fn promoted_frontier_rejects_sparse_or_foreign_candidates() {
        let (frontier, choice) = fixture(3);
        let sparse = SearchRuntimeFrontier {
            configuration: frontier.configuration.clone(),
            at: frontier.at,
            choices: SearchFrontierChoices::from_decisions([Decision::Override(
                choice.override_decisions(frontier.configuration.id())[1].clone(),
            )]),
        };
        assert_eq!(
            SignalFaultSelectable::from_frontier(&sparse),
            Err(SignalFaultSelectableError::NonDenseCandidates)
        );

        let foreign_parent = Configuration::genesis(ScenarioDef::from_canonical_material(
            "crucible.test.signal-fault-selectable.foreign",
            "foreign",
        ));
        let foreign = SearchRuntimeFrontier {
            configuration: foreign_parent,
            at: frontier.at,
            choices: frontier.choices,
        };
        assert_eq!(
            SignalFaultSelectable::from_frontier(&foreign),
            Err(SignalFaultSelectableError::FrontierParentMismatch)
        );
    }

    #[test]
    fn promoted_frontier_rejects_mixed_bases_and_excess_candidates() {
        let (frontier, choice) = fixture(2);
        let other = BindingSearchChoice {
            id: SearchChoiceId::from_content_hash(crate::ContentHash::from_bytes(b"other-choice")),
            candidates_digest: crate::ContentHash::from_bytes(b"other-candidates"),
            candidate_count: 2,
            selected_index: None,
            overridden: false,
        };
        let mixed = SearchRuntimeFrontier {
            configuration: frontier.configuration.clone(),
            at: frontier.at,
            choices: SearchFrontierChoices::from_decisions([
                Decision::Override(
                    choice.override_decisions(frontier.configuration.id())[0].clone(),
                ),
                Decision::Override(
                    other.override_decisions(frontier.configuration.id())[1].clone(),
                ),
            ]),
        };
        assert_eq!(
            SignalFaultSelectable::from_frontier(&mixed),
            Err(SignalFaultSelectableError::MixedCandidateBasis)
        );

        let (excess, _) = fixture(
            u32::try_from(MAX_SIGNAL_FAULT_CAMPAIGN_CANDIDATES + 1)
                .expect("candidate cap fits u32"),
        );
        assert_eq!(
            SignalFaultSelectable::from_frontier(&excess),
            Err(SignalFaultSelectableError::CandidateLimitExceeded)
        );
    }

    #[test]
    fn authenticated_records_must_match_the_exact_frontier_basis() {
        let (frontier, _) = fixture(2);
        let selectable =
            SignalFaultSelectable::from_frontier(&frontier).expect("normalize frontier");
        let (other_frontier, _) = fixture(3);
        let other = SignalFaultSelectable::from_frontier(&other_frontier).expect("other frontier");

        assert_eq!(
            SignalFaultSelectable::from_records(
                &frontier.configuration,
                selectable.declaration(),
                selectable.opportunity(),
                other.domain(),
            ),
            Err(SignalFaultSelectableError::ProducerContractMismatch)
        );
        assert_eq!(
            selectable.branch_selection(&frontier.configuration, 3),
            Err(SignalFaultSelectableError::CandidateOutsideDomain)
        );
    }
}
