//! Scenario-owned network fault choices and exact campaign branch replay.
//!
//! Each disruption is one atomic tuple with typed member domains and
//! kind-dependent constraints. First and follow-up selections have distinct
//! phase identities and exact replay parents.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crucible_campaign::{
    AlternativeId, CampaignCodecError, CampaignHash, ChoiceClassContext, ChoiceCoordinate,
    ChoiceDiscovery, ChoiceDomain, ChoiceGroup, ChoiceGroupApplication, ChoiceGroupDomain,
    ChoiceRelationalConstraint, ChoiceSource, ChoiceTuple, ChoiceValue, ConfigurationId,
    DiscreteAlternative, DiscreteDomain, ExactRational, IntegerDomain, IntegerRepresentation,
    IntegerValue, ScenarioDefId, SelectableDeclaration, Selection,
};
use thiserror::Error;

use crate::model::{
    BindingActionCause, BindingActionKind, EFFECT_SEMANTIC_VERSION, EffectLifetime, EffectRequest,
    EffectSpecification, FaultContractError, FaultDirection, FaultObjectId, FaultOpportunity,
    FaultPhase, NetworkAvailabilityState, NetworkEffectSpecification, NetworkInFlightPolicy,
    PositiveU64, ProbabilityMillionths, ResolvedBindingAction, ResolvedFaultTarget,
    ResolvedMappingOutput, WorldFaultTargetRef, WorldFaultTopology,
};
use crate::{
    Configuration, ContentHash, Decision, EngineError, ScenarioDefForm, SelectionDecision,
    VirtualTime, try_step,
};

/// Stable environment adapter for the worked network fault contract.
pub const NETWORK_FAULT_CAMPAIGN_ADAPTER: &str = "crucible.worked-network-fault.v1";

mod group_schema;

use group_schema::{fault_context, fault_group, fault_source};

const MAX_NETWORK_FAULT_BRANCHES: usize = 2;
const FAULT_NETWORK: &str = "fault.network";
const FAULT_KIND: &str = "fault.kind";
const AFFECTED_PATH: &str = "fault.affected_path";
const DURATION_US: &str = "fault.duration_us";
const LOSS_BPS: &str = "fault.loss_bps";
const LATENCY_US: &str = "fault.latency_us";

/// Which scenario disruption a network fault choice configures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum NetworkFaultPhase {
    /// First transport disruption.
    First,
    /// Later disruption of a surviving run.
    Followup,
}

impl NetworkFaultPhase {
    fn label(self) -> &'static str {
        match self {
            Self::First => "first",
            Self::Followup => "followup",
        }
    }

    fn instance(self, at: VirtualTime) -> String {
        format!("{}-at-{:016x}", self.label(), at.ticks)
    }

    fn parse_instance(instance: &str) -> Result<(Self, VirtualTime), NetworkFaultSelectableError> {
        let (phase, coordinate) = instance
            .split_once("-at-")
            .ok_or(NetworkFaultSelectableError::ProducerContractMismatch)?;
        let phase = match phase {
            "first" => Self::First,
            "followup" => Self::Followup,
            _ => return Err(NetworkFaultSelectableError::ProducerContractMismatch),
        };
        if coordinate.len() != 16 {
            return Err(NetworkFaultSelectableError::ProducerContractMismatch);
        }
        let ticks = u64::from_str_radix(coordinate, 16)
            .map_err(|_| NetworkFaultSelectableError::ProducerContractMismatch)?;
        Ok((phase, VirtualTime { ticks }))
    }
}

/// One atomic fault opportunity in a scenario-owned network disruption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkFaultSelectable {
    parent: Configuration,
    phase: NetworkFaultPhase,
    at: VirtualTime,
    declaration: SelectableDeclaration,
    domain: ChoiceDomain,
    opportunity: crucible_campaign::ChoiceOpportunity,
}

impl NetworkFaultSelectable {
    /// Returns the single fault declaration with its complete member schema.
    ///
    /// # Errors
    ///
    /// Returns a canonical codec error if any member, constraint, or group is invalid.
    pub fn declaration() -> Result<SelectableDeclaration, CampaignCodecError> {
        let group = fault_group()?;
        let defaults = group
            .declarations()
            .iter()
            .map(|(id, declaration)| (*id, declaration.default().clone()))
            .collect();
        let default = ChoiceValue::Group(group.select(ChoiceTuple::new(defaults))?);
        SelectableDeclaration::new(
            FAULT_NETWORK,
            fault_source(),
            ChoiceDomain::Group(Box::new(group)),
            default,
            fault_context()?,
            BTreeSet::from([
                String::from("network-fault"),
                String::from("scenario-owned"),
            ]),
            false,
        )
    }

    /// Builds a complete, validated choice value for the fault declaration.
    ///
    /// Inactive loss and latency parameters must be zero. Duration and path
    /// are always present, and large integer values are checked by the group.
    ///
    /// # Errors
    ///
    /// Returns a codec error for an unknown kind or path, an out-of-domain
    /// integer, or a kind-dependent inactive parameter.
    pub fn selected_value(
        kind: &str,
        path: &str,
        duration_us: u64,
        loss_bps: u64,
        latency_us: u64,
    ) -> Result<ChoiceValue, CampaignCodecError> {
        let group = fault_group()?;
        let values = [
            (FAULT_KIND, discrete_value(FAULT_KIND, kind)),
            (AFFECTED_PATH, discrete_value(AFFECTED_PATH, path)),
            (
                DURATION_US,
                ChoiceValue::Integer(IntegerValue::Unsigned(duration_us)),
            ),
            (
                LOSS_BPS,
                ChoiceValue::Integer(IntegerValue::Unsigned(loss_bps)),
            ),
            (
                LATENCY_US,
                ChoiceValue::Integer(IntegerValue::Unsigned(latency_us)),
            ),
        ];
        let tuple = values
            .into_iter()
            .map(|(name, value)| {
                group
                    .declarations()
                    .iter()
                    .find(|(_, declaration)| declaration.name() == name)
                    .map(|(id, _)| (*id, value))
                    .ok_or(CampaignCodecError::InvalidValue {
                        reason: "network fault group is missing a member",
                    })
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        group
            .select(ChoiceTuple::new(tuple))
            .map(ChoiceValue::Group)
    }

    /// Returns one pending phase choice at an authenticated disruption boundary.
    ///
    /// # Errors
    ///
    /// Returns an error for mismatched declarations or replay prefixes.
    pub fn next(
        scenario: &ScenarioDefForm,
        parent: &Configuration,
        phase: NetworkFaultPhase,
        at: VirtualTime,
        prior: &[NetworkFaultCampaignBranch],
    ) -> Result<Option<Self>, NetworkFaultSelectableError> {
        let Some(_) = scenario.selectables().declaration(FAULT_NETWORK) else {
            if [FAULT_KIND, AFFECTED_PATH, DURATION_US, LOSS_BPS, LATENCY_US]
                .iter()
                .any(|name| scenario.selectables().declaration(name).is_some())
            {
                return Err(NetworkFaultSelectableError::ProducerContractMismatch);
            }
            return Ok(None);
        };
        validate_declarations(scenario)?;
        NetworkFaultCampaignReplayPlan::new(parent.clone(), prior.to_vec())?;
        if prior.iter().any(|branch| branch.phase == phase) {
            return Ok(None);
        }
        if phase == NetworkFaultPhase::Followup
            && !prior
                .iter()
                .any(|branch| branch.phase == NetworkFaultPhase::First && branch.at < at)
        {
            return Err(NetworkFaultSelectableError::ReplayPlanMismatch);
        }
        Self::for_phase(scenario, parent, phase, at).map(Some)
    }

    /// Reconstructs the exact standardized record for branch replay.
    ///
    /// # Errors
    ///
    /// Returns an error if scenario, declaration, domain, or opportunity differ.
    pub fn from_records(
        scenario: &ScenarioDefForm,
        parent: &Configuration,
        declaration: &SelectableDeclaration,
        opportunity: &crucible_campaign::ChoiceOpportunity,
        domain: &ChoiceDomain,
    ) -> Result<Self, NetworkFaultSelectableError> {
        validate_declarations(scenario)?;
        let (phase, at) = NetworkFaultPhase::parse_instance(opportunity.instance())?;
        let reconstructed = Self::for_phase(scenario, parent, phase, at)?;
        if reconstructed.declaration != *declaration
            || reconstructed.domain != *domain
            || reconstructed.opportunity != *opportunity
        {
            return Err(NetworkFaultSelectableError::ProducerContractMismatch);
        }
        Ok(reconstructed)
    }

    fn for_phase(
        scenario: &ScenarioDefForm,
        parent: &Configuration,
        phase: NetworkFaultPhase,
        at: VirtualTime,
    ) -> Result<Self, NetworkFaultSelectableError> {
        if parent.def != scenario.scenario_def() {
            return Err(NetworkFaultSelectableError::ProducerContractMismatch);
        }
        let declaration = scenario
            .selectables()
            .declaration(FAULT_NETWORK)
            .ok_or(NetworkFaultSelectableError::ProducerContractMismatch)?
            .clone();
        let domain = declaration.domain().clone();
        let opportunity = crucible_campaign::ChoiceOpportunity::new(
            ScenarioDefId::from_hash(CampaignHash::from_bytes(parent.def.id().bytes)),
            &declaration,
            &domain,
            ChoiceCoordinate {
                scheduler: CampaignHash::from_bytes(parent.id().bytes),
                producer: CampaignHash::derive(
                    "crucible.worked-network-fault.phase.v1",
                    phase.label().as_bytes(),
                ),
            },
            phase.instance(at),
            None,
        )?;
        Ok(Self {
            parent: parent.clone(),
            phase,
            at,
            declaration,
            domain,
            opportunity,
        })
    }

    /// Returns the scenario declaration for this fault.
    #[must_use]
    pub const fn declaration_ref(&self) -> &SelectableDeclaration {
        &self.declaration
    }

    /// Returns the exact group domain.
    #[must_use]
    pub const fn domain(&self) -> &ChoiceDomain {
        &self.domain
    }

    /// Returns the exact phase-specific opportunity.
    #[must_use]
    pub const fn opportunity(&self) -> &crucible_campaign::ChoiceOpportunity {
        &self.opportunity
    }

    /// Builds a public discovery for this atomic fault.
    ///
    /// # Errors
    ///
    /// Returns a codec error if canonical discovery addressing fails.
    pub fn discovery(&self) -> Result<ChoiceDiscovery, CampaignCodecError> {
        ChoiceDiscovery::new(
            self.declaration.clone(),
            self.domain.clone(),
            self.opportunity.clone(),
        )
    }

    /// Builds one campaign branch selection at this exact parent.
    ///
    /// # Errors
    ///
    /// Returns a codec error if the group value violates its member domains
    /// or kind-dependent constraints.
    pub fn branch_selection(&self, value: ChoiceValue) -> Result<Selection, CampaignCodecError> {
        let parent = ConfigurationId::from_hash(CampaignHash::from_bytes(self.parent.id().bytes));
        Selection::new_campaign_branch(
            &self.opportunity,
            &self.domain,
            value,
            self.opportunity.branch_point_id(parent),
        )
    }

    /// Resolves an authenticated tuple into its exact schedule child.
    ///
    /// # Errors
    ///
    /// Returns an error for a mismatched branch or invalid configuration step.
    pub fn resolve_branch(
        &self,
        selection: &Selection,
    ) -> Result<NetworkFaultCampaignBranch, NetworkFaultSelectableError> {
        let parent = ConfigurationId::from_hash(CampaignHash::from_bytes(self.parent.id().bytes));
        selection.validate_branch_replay(
            &self.opportunity,
            &self.domain,
            self.opportunity.branch_point_id(parent),
        )?;
        let parameters = selected_parameters(&self.domain, selection.value())?;
        let duration_nanos = parameters
            .duration_us
            .checked_mul(1_000)
            .ok_or(NetworkFaultSelectableError::ProducerContractMismatch)?;
        self.at
            .ticks
            .checked_add(duration_nanos)
            .ok_or(NetworkFaultSelectableError::ProducerContractMismatch)?;
        let decision = Decision::Selection(SelectionDecision::new(selection));
        let selected = try_step(&self.parent, decision.clone())?;
        Ok(NetworkFaultCampaignBranch {
            parent: self.parent.clone(),
            selected,
            phase: self.phase,
            at: self.at,
            value: selection.value().clone(),
            parameters,
            decision,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SelectedFaultParameters {
    kind: &'static str,
    path: &'static str,
    duration_us: u64,
    loss_bps: u64,
    latency_us: u64,
}

fn selected_parameters(
    domain: &ChoiceDomain,
    value: &ChoiceValue,
) -> Result<SelectedFaultParameters, NetworkFaultSelectableError> {
    let (ChoiceDomain::Group(group), ChoiceValue::Group(group_value)) = (domain, value) else {
        return Err(NetworkFaultSelectableError::ProducerContractMismatch);
    };
    if !domain.contains(value) {
        return Err(NetworkFaultSelectableError::ProducerContractMismatch);
    }
    let mut values = BTreeMap::new();
    for name in [FAULT_KIND, AFFECTED_PATH, DURATION_US, LOSS_BPS, LATENCY_US] {
        let id = group
            .declarations()
            .iter()
            .find(|(_, declaration)| declaration.name() == name)
            .map(|(id, _)| id)
            .ok_or(NetworkFaultSelectableError::ProducerContractMismatch)?;
        let member = group_value
            .tuple()
            .values()
            .get(id)
            .ok_or(NetworkFaultSelectableError::ProducerContractMismatch)?;
        values.insert(name, member.clone());
    }
    Ok(SelectedFaultParameters {
        kind: selected_discrete(&values, FAULT_KIND)?,
        path: selected_discrete(&values, AFFECTED_PATH)?,
        duration_us: selected_integer(&values, DURATION_US)?,
        loss_bps: selected_integer(&values, LOSS_BPS)?,
        latency_us: selected_integer(&values, LATENCY_US)?,
    })
}

/// One authenticated network fault branch with exact parent and child.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkFaultCampaignBranch {
    parent: Configuration,
    selected: Configuration,
    phase: NetworkFaultPhase,
    at: VirtualTime,
    value: ChoiceValue,
    parameters: SelectedFaultParameters,
    decision: Decision,
}

impl NetworkFaultCampaignBranch {
    /// Returns the configuration before this selection.
    #[must_use]
    pub const fn parent(&self) -> &Configuration {
        &self.parent
    }

    /// Returns the configuration after this selection.
    #[must_use]
    pub const fn selected(&self) -> &Configuration {
        &self.selected
    }

    /// Returns the selected disruption phase.
    #[must_use]
    pub const fn phase(&self) -> NetworkFaultPhase {
        self.phase
    }

    /// Returns the boundary time anchoring this disruption.
    #[must_use]
    pub const fn at(&self) -> VirtualTime {
        self.at
    }

    /// Returns the exact schedule decision.
    #[must_use]
    pub const fn decision(&self) -> &Decision {
        &self.decision
    }

    /// Returns the complete selected group value.
    #[must_use]
    pub const fn value(&self) -> &ChoiceValue {
        &self.value
    }
}

/// Exact selected network fault tuples required by one configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkFaultCampaignReplayPlan {
    target: Configuration,
    branches: Vec<NetworkFaultCampaignBranch>,
}

impl NetworkFaultCampaignReplayPlan {
    /// Validates branch order, inactive constraints, and exact schedule prefixes.
    ///
    /// # Errors
    ///
    /// Returns an error for reordered, repeated, or non-prefix records.
    pub fn new(
        target: Configuration,
        branches: Vec<NetworkFaultCampaignBranch>,
    ) -> Result<Self, NetworkFaultSelectableError> {
        if branches.len() > MAX_NETWORK_FAULT_BRANCHES {
            return Err(NetworkFaultSelectableError::ReplayPlanMismatch);
        }
        let mut phases = BTreeSet::new();
        let mut first_at = None;
        let mut previous_end = 0;
        for branch in &branches {
            let start = branch.parent.schedule.len();
            let end = branch.selected.schedule.len();
            if branch.parent.def != target.def
                || start < previous_end
                || end != start + 1
                || end > target.schedule.len()
                || branch.parent.schedule.decisions() != &target.schedule.decisions()[..start]
                || branch.decision != target.schedule.decisions()[start]
                || branch.selected.schedule.decisions() != &target.schedule.decisions()[..end]
                || !phases.insert(branch.phase)
                || (branch.phase == NetworkFaultPhase::Followup
                    && !first_at.is_some_and(|at| at < branch.at))
            {
                return Err(NetworkFaultSelectableError::ReplayPlanMismatch);
            }
            if branch.phase == NetworkFaultPhase::First {
                first_at = Some(branch.at);
            }
            previous_end = end;
        }
        Ok(Self { target, branches })
    }

    /// Returns the exact target configuration.
    #[must_use]
    pub const fn target(&self) -> &Configuration {
        &self.target
    }

    /// Returns ordered, authenticated network fault branches.
    #[must_use]
    pub fn branches(&self) -> &[NetworkFaultCampaignBranch] {
        &self.branches
    }

    /// Returns the stable identity of the exact selected fault branch prefix.
    #[must_use]
    pub fn identity(&self) -> ContentHash {
        let mut material = Vec::new();
        material.extend_from_slice(b"crucible.worked-network-fault.replay.v1");
        material.extend_from_slice(&(self.branches.len() as u64).to_be_bytes());
        for branch in &self.branches {
            material.extend_from_slice(&branch.selected.id().bytes);
            material.extend_from_slice(branch.phase.label().as_bytes());
            material.extend_from_slice(&branch.at.ticks.to_be_bytes());
        }
        ContentHash::from_bytes(&material)
    }

    /// Requires both scenario-owned path domains to address network segments.
    ///
    /// # Errors
    ///
    /// Returns an error when either path domain is absent or cannot affect a
    /// modeled frame.
    pub fn validate_topology(
        &self,
        topology: &WorldFaultTopology,
    ) -> Result<(), NetworkFaultSelectableError> {
        for name in ["primary", "backup"] {
            let domain = topology
                .fault_domains
                .iter()
                .find(|domain| domain.id.as_str() == name)
                .ok_or(NetworkFaultSelectableError::ProducerContractMismatch)?;
            if !domain
                .targets
                .iter()
                .any(|target| matches!(target, WorldFaultTargetRef::NetworkSegment { .. }))
            {
                return Err(NetworkFaultSelectableError::ProducerContractMismatch);
            }
        }
        Ok(())
    }

    /// Reports active selected outages against concrete World network segments.
    ///
    /// # Errors
    ///
    /// Returns an error if a selected duration overflows virtual time or its
    /// declared path cannot be resolved against the admitted topology.
    pub fn active_outages(
        &self,
        topology: &WorldFaultTopology,
        now: u64,
    ) -> Result<Vec<(ResolvedFaultTarget, u64)>, NetworkFaultSelectableError> {
        let mut outages = BTreeMap::new();
        for branch in &self.branches {
            if !matches!(branch.parameters.kind, "link_down" | "asymmetric_partition") {
                continue;
            }
            let until = branch
                .at
                .ticks
                .checked_add(
                    branch
                        .parameters
                        .duration_us
                        .checked_mul(1_000)
                        .ok_or(NetworkFaultSelectableError::ProducerContractMismatch)?,
                )
                .ok_or(NetworkFaultSelectableError::ProducerContractMismatch)?;
            if now < branch.at.ticks || now >= until {
                continue;
            }
            for domain in &topology.fault_domains {
                for member in &domain.targets {
                    let WorldFaultTargetRef::NetworkSegment { segment, direction } = member else {
                        continue;
                    };
                    if branch.parameters.kind == "asymmetric_partition"
                        && *direction != FaultDirection::AToB
                    {
                        continue;
                    }
                    let target = ResolvedFaultTarget::NetworkSegment {
                        segment: FaultObjectId::parse(segment.as_str())?,
                        direction: *direction,
                    };
                    if path_matches(topology, &target, branch.parameters.path)? {
                        let prior = outages.entry(target).or_insert(until);
                        *prior = (*prior).max(until);
                    }
                }
            }
        }
        Ok(outages.into_iter().collect())
    }

    /// Projects complete selected faults into the existing typed network action path.
    ///
    /// Only a resolve-phase network segment in a selected primary or backup
    /// fault domain receives an action. The action uses the same validated
    /// effect request, opportunity identity, and binding-action vocabulary as
    /// the signal-driven production adapter.
    ///
    /// # Errors
    ///
    /// Returns an error if a selected value cannot be represented by its
    /// declared typed effect or a required path domain is absent.
    pub fn actions_for_opportunity(
        &self,
        topology: &WorldFaultTopology,
        opportunity: &FaultOpportunity,
    ) -> Result<Vec<ResolvedBindingAction>, NetworkFaultSelectableError> {
        if opportunity.phase() != FaultPhase::Resolve
            || !matches!(
                opportunity.target(),
                ResolvedFaultTarget::NetworkSegment { .. }
            )
        {
            return Ok(Vec::new());
        }
        let mut actions = Vec::new();
        for branch in &self.branches {
            let parameters = &branch.parameters;
            let duration_nanos = parameters
                .duration_us
                .checked_mul(1_000)
                .ok_or(NetworkFaultSelectableError::ProducerContractMismatch)?;
            let until = branch
                .at
                .ticks
                .checked_add(duration_nanos)
                .ok_or(NetworkFaultSelectableError::ProducerContractMismatch)?;
            if opportunity.coordinate().virtual_nanos < branch.at.ticks
                || opportunity.coordinate().virtual_nanos >= until
            {
                continue;
            }
            if !path_matches(topology, opportunity.target(), parameters.path)? {
                continue;
            }
            let specification = match parameters.kind {
                "link_down" => Some(NetworkEffectSpecification::Availability {
                    state: NetworkAvailabilityState::Down,
                    queued_policy: NetworkInFlightPolicy::Drop,
                    in_flight_policy: NetworkInFlightPolicy::Drop,
                }),
                "asymmetric_partition"
                    if matches!(
                        opportunity.target(),
                        ResolvedFaultTarget::NetworkSegment {
                            direction: FaultDirection::AToB,
                            ..
                        }
                    ) =>
                {
                    Some(NetworkEffectSpecification::Availability {
                        state: NetworkAvailabilityState::Down,
                        queued_policy: NetworkInFlightPolicy::Drop,
                        in_flight_policy: NetworkInFlightPolicy::Drop,
                    })
                }
                "asymmetric_partition" => None,
                "packet_loss" => {
                    let millionths = parameters
                        .loss_bps
                        .checked_mul(100)
                        .ok_or(NetworkFaultSelectableError::ProducerContractMismatch)?;
                    let probability = u32::try_from(millionths)
                        .map_err(|_| NetworkFaultSelectableError::ProducerContractMismatch)?;
                    (probability != 0)
                        .then(|| {
                            ProbabilityMillionths::new(probability).map(|probability| {
                                NetworkEffectSpecification::FrameLoss {
                                    probability: Some(probability),
                                    outcome: None,
                                }
                            })
                        })
                        .transpose()?
                }
                "latency_step" => (parameters.latency_us != 0)
                    .then(|| {
                        parameters
                            .latency_us
                            .checked_mul(1_000)
                            .ok_or(NetworkFaultSelectableError::ProducerContractMismatch)
                            .and_then(|nanos| {
                                PositiveU64::new("campaign network latency", nanos)
                                    .map_err(Into::into)
                            })
                            .map(|delay_nanos| NetworkEffectSpecification::PropagationDelay {
                                delay_nanos: Some(delay_nanos),
                                distance_velocity_lookup: None,
                            })
                    })
                    .transpose()?,
                _ => return Err(NetworkFaultSelectableError::ProducerContractMismatch),
            };
            let Some(specification) = specification else {
                continue;
            };
            let persistent = matches!(
                specification,
                NetworkEffectSpecification::Availability { .. }
            );
            let effect = EffectRequest::new(
                EFFECT_SEMANTIC_VERSION,
                if persistent {
                    EffectLifetime::Persistent
                } else {
                    EffectLifetime::Opportunity
                },
                EffectSpecification::Network(specification),
            )?;
            let binding =
                FaultObjectId::parse(format!("campaign-network-{}", branch.phase.label()))?;
            let mut material = Vec::new();
            material.extend_from_slice(b"crucible.worked-network-fault.mapping.v1");
            material.extend_from_slice(branch.phase.label().as_bytes());
            material.extend_from_slice(&branch.at.ticks.to_be_bytes());
            material.extend_from_slice(&branch.value.canonical_bytes());
            let mapped_digest = ContentHash::from_bytes(&material);
            actions.push(ResolvedBindingAction {
                kind: if persistent {
                    BindingActionKind::UpsertPersistent
                } else {
                    BindingActionKind::Apply
                },
                binding,
                target: opportunity.target().clone(),
                phase: FaultPhase::Resolve,
                effect: Arc::new(effect),
                mapping_output: Arc::new(ResolvedMappingOutput::Activation { active: true }),
                mapped_digest,
                transition_sequence: 0,
                opportunity: Some(opportunity.id()),
                coordinate: opportunity.coordinate(),
                cause: BindingActionCause::Opportunity {
                    identity: opportunity.id(),
                    payload: opportunity.payload().clone(),
                },
                expected_precondition: None,
            });
        }
        Ok(actions)
    }

    /// Consumes the plan into its exact target and branches.
    #[must_use]
    pub fn into_parts(self) -> (Configuration, Vec<NetworkFaultCampaignBranch>) {
        (self.target, self.branches)
    }
}

/// Failure to construct or replay a network fault choice.
#[derive(Debug, Error)]
pub enum NetworkFaultSelectableError {
    /// A campaign record failed canonical validation.
    #[error(transparent)]
    Campaign(#[from] CampaignCodecError),
    /// Appending the selection exceeded a configuration limit.
    #[error(transparent)]
    Configuration(#[from] EngineError),
    /// A selected effect failed the closed network fault schema.
    #[error(transparent)]
    FaultContract(#[from] FaultContractError),
    /// Selected records differ from the scenario producer contract.
    #[error("network fault selection differs from its scenario producer contract")]
    ProducerContractMismatch,
    /// Branches do not form one legal exact replay prefix.
    #[error("network fault selections do not form a legal exact replay prefix")]
    ReplayPlanMismatch,
}

fn selected_integer(
    values: &BTreeMap<&str, ChoiceValue>,
    name: &str,
) -> Result<u64, NetworkFaultSelectableError> {
    match values.get(name) {
        Some(ChoiceValue::Integer(IntegerValue::Unsigned(value))) => Ok(*value),
        _ => Err(NetworkFaultSelectableError::ProducerContractMismatch),
    }
}

fn selected_discrete(
    values: &BTreeMap<&str, ChoiceValue>,
    name: &str,
) -> Result<&'static str, NetworkFaultSelectableError> {
    let choices: &[&str] = match name {
        FAULT_KIND => &[
            "link_down",
            "packet_loss",
            "latency_step",
            "asymmetric_partition",
        ],
        AFFECTED_PATH => &["primary", "backup", "both"],
        _ => return Err(NetworkFaultSelectableError::ProducerContractMismatch),
    };
    choices
        .iter()
        .copied()
        .find(|choice| values.get(name) == Some(&discrete_value(name, choice)))
        .ok_or(NetworkFaultSelectableError::ProducerContractMismatch)
}

fn path_matches(
    topology: &WorldFaultTopology,
    target: &ResolvedFaultTarget,
    selected: &str,
) -> Result<bool, NetworkFaultSelectableError> {
    let ResolvedFaultTarget::NetworkSegment { segment, direction } = target else {
        return Ok(false);
    };
    let selected_domains: &[&str] = match selected {
        "primary" => &["primary"],
        "backup" => &["backup"],
        "both" => &["primary", "backup"],
        _ => return Err(NetworkFaultSelectableError::ProducerContractMismatch),
    };
    selected_domains
        .iter()
        .try_fold(false, |matched, domain_name| {
            let domain = topology
                .fault_domains
                .iter()
                .find(|domain| domain.id.as_str() == *domain_name)
                .ok_or(NetworkFaultSelectableError::ProducerContractMismatch)?;
            Ok(matched
                || domain.targets.iter().any(|member| {
                    matches!(
                        member,
                        WorldFaultTargetRef::NetworkSegment {
                            segment: candidate,
                            direction: candidate_direction,
                        } if candidate.as_str() == segment.as_str()
                            && candidate_direction == direction
                    )
                }))
        })
}

fn validate_declarations(scenario: &ScenarioDefForm) -> Result<(), NetworkFaultSelectableError> {
    let expected = NetworkFaultSelectable::declaration()?;
    if scenario.selectables().declaration(expected.name()) != Some(&expected)
        || [FAULT_KIND, AFFECTED_PATH, DURATION_US, LOSS_BPS, LATENCY_US]
            .iter()
            .any(|name| scenario.selectables().declaration(name).is_some())
    {
        return Err(NetworkFaultSelectableError::ProducerContractMismatch);
    }
    Ok(())
}

fn discrete_domain(field: &str, values: &[&str]) -> Result<ChoiceDomain, CampaignCodecError> {
    let alternatives = values
        .iter()
        .map(|value| {
            let id = alternative_id(field, value);
            DiscreteAlternative::new(id, *value, None).map(|alternative| (id, alternative))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    DiscreteDomain::new(1, alternatives).map(ChoiceDomain::Discrete)
}

fn discrete_value(field: &str, value: &str) -> ChoiceValue {
    ChoiceValue::Discrete(alternative_id(field, value))
}

fn alternative_id(field: &str, value: &str) -> AlternativeId {
    AlternativeId::from_hash(CampaignHash::derive(
        "crucible.worked-network-fault.alternative.v1",
        format!("{field}/{value}").as_bytes(),
    ))
}

#[cfg(test)]
mod tests;
