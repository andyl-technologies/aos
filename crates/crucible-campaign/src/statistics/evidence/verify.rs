//! Pure semantic replay for authenticated statistical evidence.
//!
//! Replay is incremental. [`FiniteEvidenceReplay`] consumes stage-zero draws
//! in coordinate order and keeps one compact [`VerifiedDraw`] per planned
//! coordinate, which the policy bounds independently of campaign length.
//! [`SmcEvidenceReplay`] consumes those draws and then every transition in
//! stage and slot order. A particle can reference only an outcome of the stage
//! immediately before it, so the SMC replay keeps compact [`SmcSource`]
//! summaries for one previous stage, the current generation, and the current
//! stage's outcomes. Live memory is therefore `O(particle_count)`, not
//! proportional to the number of completed transitions.
//!
//! The chunked portable verifier feeds chunk items through these replays, and
//! the repository's internal estimates feed records read one execution at a
//! time from snapshot roots, so both paths apply identical checks. Proposal
//! membership and its content envelope authenticate the historical guidance and
//! planner-invocation identities; replay does not reconstruct historical
//! planner ranking decisions.

use std::collections::{BTreeMap, BTreeSet, btree_map};

use super::{
    SmcTransitionEvidence, StatisticalDrawEvidence, StatisticalExecutionEvidence,
    StatisticalOpportunityEvidence,
};
use crate::{
    AttemptAdmissionRole, AttemptId, AttemptStart, BranchBudget, BranchPath, BranchPathId,
    BranchPathSegment, BranchPointId, BranchRequest, BranchRequestCause, CampaignCodecError,
    CampaignLineage, CampaignMode, CampaignPlanningView, CampaignPolicy, CampaignPolicyId,
    CampaignSnapshot, CandidateSource, ChoiceDomainId, ChoiceOpportunityId,
    ConfigurationArtifactId, ConfigurationId, ObservationId, ProposalId, SelectionOrigin,
    SequentialMonteCarloDesign, SequentialMonteCarloEstimateReport, SmcOpportunitySelector,
    StatisticalDistribution, StatisticalDrawPlan, StatisticalEndpointEstimate,
    StatisticalEstimateReport, StatisticalGeneration, StatisticalGenerationSummary,
    StatisticalParticleOutcome, StatisticalProposalEvidence, StatisticalRational,
    StatisticalSamplingDesign, StatisticalWeightDiagnostics,
};

mod smc_replay;

pub(crate) use smc_replay::SmcEvidenceReplay;
use smc_replay::{SmcSource, SmcSourceKey};

/// Snapshot-bound records shared by every item of one evidence stream.
#[derive(Clone, Copy)]
pub(crate) struct EvidenceBasis<'a> {
    snapshot: &'a CampaignSnapshot,
    planning_view: &'a CampaignPlanningView,
    policy: &'a CampaignPolicy,
    lineage: &'a CampaignLineage,
}

impl<'a> EvidenceBasis<'a> {
    pub(crate) const fn new(
        snapshot: &'a CampaignSnapshot,
        planning_view: &'a CampaignPlanningView,
        policy: &'a CampaignPolicy,
        lineage: &'a CampaignLineage,
    ) -> Self {
        Self {
            snapshot,
            planning_view,
            policy,
            lineage,
        }
    }
}

/// Compact replay facts retained for one verified stage-zero draw.
struct VerifiedDraw {
    terminal: BranchPathSegment,
    child_content: ConfigurationArtifactId,
    child: ConfigurationId,
    probability: StatisticalProposalEvidence,
    proposal: ProposalId,
    attempt: AttemptId,
    observation: ObservationId,
    path: BranchPathId,
}

/// Incremental replay of one finite stage-zero flight in coordinate order.
pub(crate) struct FiniteEvidenceReplay<'a> {
    basis: EvidenceBasis<'a>,
    policy_id: CampaignPolicyId,
    design: &'a StatisticalSamplingDesign,
    planned: btree_map::Iter<'a, u64, StatisticalDrawPlan>,
    draws: BTreeMap<u64, VerifiedDraw>,
}

impl<'a> FiniteEvidenceReplay<'a> {
    /// Starts a replay after checking the snapshot, policy, and lineage basis.
    pub(crate) fn new(
        basis: EvidenceBasis<'a>,
        allow_smc: bool,
    ) -> Result<Self, CampaignCodecError> {
        let policy = basis.policy;
        let policy_id = policy.id()?;
        if basis.snapshot.active_policy() != policy_id
            || basis.snapshot.lineage() != basis.lineage.id()?
            || basis.snapshot.planning_view() != *basis.planning_view
            || policy.mode() != CampaignMode::Statistical
            || policy.sequential_monte_carlo_design().is_some() != allow_smc
        {
            return Err(invalid(
                "statistical evidence snapshot basis is inconsistent",
            ));
        }
        let design = policy
            .statistical_sampling_design()
            .ok_or_else(|| invalid("statistical evidence policy lacks a sampling design"))?;
        Ok(Self {
            basis,
            policy_id,
            design,
            planned: design.draws().iter(),
            draws: BTreeMap::new(),
        })
    }

    /// Verifies the next planned draw.
    pub(crate) fn push(
        &mut self,
        draw: &StatisticalDrawEvidence,
    ) -> Result<(), CampaignCodecError> {
        let (expected_coordinate, draw_plan) = self
            .planned
            .next()
            .ok_or_else(|| invalid("statistical evidence draw count is incomplete"))?;
        if draw.coordinate() != *expected_coordinate {
            return Err(invalid("statistical evidence draw coordinate has a gap"));
        }
        let execution = draw.execution();
        verify_execution_common(self.basis, execution)?;
        validate_finite_request(
            self.basis,
            *expected_coordinate,
            draw_plan,
            execution,
            &self.draws,
        )?;

        let segments = execution.path().segments();
        let terminal = segments
            .last()
            .copied()
            .ok_or_else(|| invalid("statistical evidence draw path is empty"))?;
        let mut expected_segments = Vec::new();
        let mut ancestry = draw_ancestry(self.design, *expected_coordinate)?;
        ancestry.pop();
        for ancestor in ancestry {
            expected_segments.push(
                self.draws
                    .get(&ancestor)
                    .ok_or_else(|| invalid("statistical evidence draw ancestry has a gap"))?
                    .terminal,
            );
        }
        expected_segments.push(terminal);
        if segments != expected_segments {
            return Err(invalid(
                "statistical evidence draw path ancestry is invalid",
            ));
        }

        let probability = execution
            .proposal()
            .statistical_evidence()
            .ok_or_else(|| invalid("statistical ancestry probability evidence is missing"))?;
        self.draws.insert(
            *expected_coordinate,
            VerifiedDraw {
                terminal,
                child_content: execution.observation().child_content(),
                child: execution.observation().child(),
                probability,
                proposal: execution.proposal().id()?,
                attempt: execution.attempt().id()?,
                observation: execution.observation().id()?,
                path: execution.path().id()?,
            },
        );
        Ok(())
    }

    /// Completes the replay and derives the endpoint estimate.
    pub(crate) fn finish(mut self) -> Result<StatisticalEstimateReport, CampaignCodecError> {
        if self.planned.next().is_some() {
            return Err(invalid("statistical evidence draw count is incomplete"));
        }

        let mut endpoints = Vec::with_capacity(self.design.estimand_endpoints().len());
        for coordinate in self.design.estimand_endpoints().iter().copied() {
            let draw = self
                .draws
                .get(&coordinate)
                .ok_or_else(|| invalid("statistical estimand endpoint is missing"))?;
            let mut target = StatisticalRational::one();
            let mut proposal = StatisticalRational::one();
            for ancestor in draw_ancestry(self.design, coordinate)? {
                let probability = self
                    .draws
                    .get(&ancestor)
                    .map(|draw| draw.probability)
                    .ok_or_else(|| {
                        invalid("statistical ancestry probability evidence is missing")
                    })?;
                target = target.checked_multiply(target_probability(probability)?)?;
                proposal = proposal.checked_multiply(proposal_probability(probability)?)?;
            }
            endpoints.push(StatisticalEndpointEstimate::new(
                coordinate,
                draw.proposal,
                draw.attempt,
                draw.observation,
                draw.path,
                target,
                proposal,
                target.checked_divide(proposal)?,
            ));
        }
        let diagnostics = endpoint_weight_diagnostics(&endpoints)?;
        Ok(StatisticalEstimateReport::new(
            self.basis.snapshot.id()?,
            self.policy_id,
            endpoints,
            diagnostics,
        ))
    }
}

fn verify_execution_common(
    stream: EvidenceBasis<'_>,
    execution: &StatisticalExecutionEvidence,
) -> Result<(), CampaignCodecError> {
    validate_opportunity(execution.request_opportunity())?;
    validate_opportunity(execution.choice().opportunity())?;
    for opportunity in execution.discovered_opportunities() {
        validate_opportunity(opportunity)?;
    }

    let request = execution.request();
    let proposal = execution.proposal();
    let attempt = execution.attempt();
    let observation = execution.observation();
    let choice = execution.choice();
    let request_id = request.id()?;
    let proposal_id = proposal.id()?;
    let attempt_id = attempt.id()?;

    request.validate_resolved(
        execution.parent(),
        execution.request_opportunity().opportunity(),
        execution.request_opportunity().domain(),
    )?;
    proposal.validate_resolved(request, execution.request_opportunity().domain())?;
    if proposal.policy() != stream.snapshot.active_policy()
        || proposal.request() != request_id
        || proposal.statistical_evidence().is_none()
    {
        return Err(invalid("statistical proposal campaign basis is invalid"));
    }

    let admitted_proposal = match execution.proposal_admission().role() {
        AttemptAdmissionRole::ExecutionBasis {
            proposal: Some(proposal),
            ..
        }
        | AttemptAdmissionRole::AdditionalCause { proposal } => proposal,
        AttemptAdmissionRole::ExecutionBasis { proposal: None, .. } => {
            return Err(invalid("statistical proposal admission lacks a proposal"));
        }
    };
    if admitted_proposal != proposal_id || execution.proposal_admission().attempt() != attempt_id {
        return Err(invalid("statistical proposal admission is inconsistent"));
    }

    let basis = execution.execution_basis();
    let AttemptAdmissionRole::ExecutionBasis {
        proposal: Some(basis_proposal),
        cause: basis_cause @ BranchRequestCause::Planner(_),
        ..
    } = basis.admission().role()
    else {
        return Err(invalid(
            "statistical attempt execution basis is an intervention",
        ));
    };
    if basis.admission().attempt() != attempt_id
        || basis_proposal != basis.proposal().id()?
        || basis.proposal().request() != basis.request().id()?
        || basis.proposal().policy() != stream.snapshot.active_policy()
        || basis.request().cause() != basis_cause
        || !matches!(
            basis.request().source(),
            CandidateSource::StatisticalFinite(_) | CandidateSource::StatisticalSmc(_)
        )
    {
        return Err(invalid(
            "statistical attempt execution basis is inconsistent",
        ));
    }
    basis
        .proposal()
        .validate_resolved(basis.request(), execution.choice().opportunity().domain())?;
    basis.request().validate_resolved(
        execution.parent(),
        execution.choice().opportunity().opportunity(),
        execution.choice().opportunity().domain(),
    )?;

    let AttemptStart::Branch {
        edge,
        parent,
        selection,
    } = attempt.start()
    else {
        return Err(invalid("statistical attempt is not a branch"));
    };
    if parent != request.parent()
        || selection != choice.selection().id()?
        || choice.selection().opportunity() != request.opportunity()
        || choice.selection().domain() != request.domain()
        || attempt.path() != execution.path().id()?
        || attempt.stop() != request.stop()
    {
        return Err(invalid(
            "statistical attempt request binding is inconsistent",
        ));
    }
    choice.selection().validate_resolved_references(
        choice.opportunity().opportunity(),
        choice.opportunity().domain(),
    )?;
    choice.selection().validate_branch_replay(
        choice.opportunity().opportunity(),
        choice.opportunity().domain(),
        proposal.branch_point(),
    )?;
    let SelectionOrigin::CampaignBranch {
        branch_point,
        edge: selected_edge,
    } = choice.selection().origin()
    else {
        return Err(invalid("statistical selection is not a campaign branch"));
    };
    if branch_point != proposal.branch_point()
        || selected_edge != edge
        || choice.selection().value() != proposal.value()
    {
        return Err(invalid("statistical selection disagrees with the proposal"));
    }

    let segments = execution.path().segments();
    let terminal = segments
        .last()
        .ok_or_else(|| invalid("statistical path is empty"))?;
    if terminal.branch_point() != proposal.branch_point() || terminal.edge() != edge {
        return Err(invalid("statistical path terminal is inconsistent"));
    }

    if observation.attempt() != attempt_id
        || observation.path() != execution.path().id()?
        || observation.child_content() != execution.child().id()?
        || observation.child() != execution.child().configuration()
    {
        return Err(invalid("statistical observation is inconsistent"));
    }
    let discovered = execution
        .discovered_opportunities()
        .iter()
        .map(|evidence| evidence.opportunity().id())
        .collect::<Result<BTreeSet<_>, _>>()?;
    let discovered_root =
        crate::observation::derive_choice_set_root(discovered.iter().map(|opportunity| {
            (
                crate::choice_set_key(*opportunity),
                opportunity.content_id(),
            )
        }))?;
    if discovered.len() != execution.discovered_opportunities().len()
        || discovered_root != observation.discovered_choices()
    {
        return Err(invalid(
            "statistical discovered opportunity closure is inexact",
        ));
    }
    Ok(())
}

fn validate_opportunity(
    evidence: &StatisticalOpportunityEvidence,
) -> Result<(), CampaignCodecError> {
    evidence
        .opportunity()
        .validate_references(evidence.declaration(), evidence.domain())
}

fn validate_finite_request(
    basis: EvidenceBasis<'_>,
    coordinate: u64,
    draw: &StatisticalDrawPlan,
    execution: &StatisticalExecutionEvidence,
    verified: &BTreeMap<u64, VerifiedDraw>,
) -> Result<(), CampaignCodecError> {
    let CandidateSource::StatisticalFinite(source) = execution.request().source() else {
        return Err(invalid("finite statistical request source is invalid"));
    };
    let distribution = basis
        .policy
        .statistical_sampling_design()
        .and_then(|design| design.distributions().get(&draw.model()))
        .ok_or_else(|| invalid("finite statistical request model is not planned"))?;
    let opportunity = execution.request_opportunity().opportunity();
    if source.coordinate() != coordinate
        || source.model() != draw.model()
        || source.target_masses() != distribution.target_masses()
        || source.proposal_masses() != distribution.proposal_masses()
        || execution.request().opportunity() != draw.opportunity()
        || opportunity.id()? != draw.opportunity()
        || opportunity.semantic_id() != draw.opportunity_semantics()
        || execution.request().domain() != draw.domain()
        || opportunity.domain() != draw.domain()
        || opportunity.model_prior() != Some(draw.model())
        || execution.request().stop() != draw.stop()
        || execution.request().budget() != BranchBudget::new(1, 1)?
        || !matches!(execution.request().cause(), BranchRequestCause::Planner(_))
    {
        return Err(invalid(
            "finite statistical request disagrees with its pinned draw",
        ));
    }

    match draw.parent() {
        None => {
            if execution.request().parent() != basis.lineage.genesis_content()
                || execution.parent().configuration() != basis.lineage.genesis()
            {
                return Err(invalid("finite root draw parent is not the genesis"));
            }
        }
        Some(parent_coordinate) => {
            let parent = verified
                .get(&parent_coordinate)
                .ok_or_else(|| invalid("finite parent draw evidence is missing"))?;
            if execution.request().parent() != parent.child_content
                || execution.parent().configuration() != parent.child
            {
                return Err(invalid("finite parent draw endpoint is inconsistent"));
            }
        }
    }
    Ok(())
}

fn validate_smc_request(
    basis: EvidenceBasis<'_>,
    generation: &StatisticalGeneration,
    particle: &crate::StatisticalParticleSlot,
    execution: &StatisticalExecutionEvidence,
    sources: &BTreeMap<SmcSourceKey, SmcSource>,
) -> Result<(), CampaignCodecError> {
    let CandidateSource::StatisticalSmc(source) = execution.request().source() else {
        return Err(invalid("SMC transition request source is invalid"));
    };
    if source.generation() != generation.id()
        || source.input_particle() != particle.id()
        || source.stage() != generation.next_stage()
        || source.slot() != particle.slot()
    {
        return Err(invalid("SMC transition generation basis is inconsistent"));
    }
    let design = basis
        .policy
        .sequential_monte_carlo_design()
        .ok_or_else(|| invalid("SMC transition policy lacks a design"))?;
    let stage = design
        .stage(generation.next_stage())
        .ok_or_else(|| invalid("SMC transition stage is not planned"))?;
    let selector = stage.selector();
    let distribution = design
        .distributions()
        .get(&selector.model())
        .ok_or_else(|| invalid("SMC selector model is not planned"))?;
    let source = sources
        .get(&(particle.observation(), particle.proposal()))
        .ok_or_else(|| invalid("SMC source observation evidence is missing"))?;
    if source.observation_path != particle.path()
        || !source.reaches_stop
        || execution.parent().id()? != source.child_content
        || execution.parent().configuration() != source.child
    {
        return Err(invalid("SMC source observation is inconsistent"));
    }

    // The source summary resolved this stage's selector when it was recorded.
    let selected = source.selected.map_err(invalid)?;
    if selected.opportunity != execution.request_opportunity().opportunity().id()?
        || selected.domain != execution.request_opportunity().domain().id()?
    {
        return Err(invalid("SMC selector opportunity closure drifted"));
    }
    let BranchRequestCause::Planner(invocation) = execution.request().cause() else {
        return Err(invalid("SMC transition request cause is not a planner"));
    };
    let expected = BranchRequest::new(
        BranchRequest::identity(
            selected.branch_point,
            execution.parent().id()?,
            selected.opportunity,
            selected.domain,
        ),
        CandidateSource::statistical_smc(
            generation.id(),
            particle.id(),
            generation.next_stage(),
            particle.slot(),
            selector.model(),
            distribution.target_masses().clone(),
            distribution.proposal_masses().clone(),
        )?,
        BranchRequestCause::Planner(invocation),
        BranchBudget::new(1, 1)?,
        selector.stop().clone(),
    )?;
    if execution.request() != &expected {
        return Err(invalid("SMC transition request disagrees with pure replay"));
    }
    Ok(())
}

fn select_smc_opportunity<'a>(
    source_execution: &'a StatisticalExecutionEvidence,
    selector: &crate::SmcOpportunitySelector,
    distribution: &crate::StatisticalDistribution,
) -> Result<&'a StatisticalOpportunityEvidence, CampaignCodecError> {
    let matches = source_execution
        .discovered_opportunities()
        .iter()
        .filter(|evidence| {
            let opportunity = evidence.opportunity();
            opportunity.declaration_semantics() == selector.declaration()
                && opportunity.domain_semantics() == selector.domain()
                && opportunity.instance() == selector.instance()
                && opportunity.model_prior() == Some(selector.model())
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(invalid(
            "SMC selector does not match exactly one opportunity",
        ));
    }
    let selected = matches[0];
    if selected.domain().cardinality() != distribution.target_masses().len() as u128
        || distribution
            .target_masses()
            .keys()
            .any(|value| !selected.domain().contains(value))
    {
        return Err(invalid("SMC selector support drifted"));
    }
    Ok(selected)
}

#[cfg(test)]
pub(crate) fn verify_smc_source_selector(
    source_execution: &StatisticalExecutionEvidence,
    selector: &crate::SmcOpportunitySelector,
    distribution: &crate::StatisticalDistribution,
) -> Result<(), CampaignCodecError> {
    select_smc_opportunity(source_execution, selector, distribution).map(|_| ())
}

fn validate_extended_path(
    source_segments: &[BranchPathSegment],
    child: &BranchPath,
) -> Result<(), CampaignCodecError> {
    let child_segments = child.segments();
    if child_segments.len() != source_segments.len().saturating_add(1)
        || !child_segments.starts_with(source_segments)
    {
        return Err(invalid("SMC transition path does not extend its source"));
    }
    Ok(())
}

fn draw_ancestry(
    design: &StatisticalSamplingDesign,
    coordinate: u64,
) -> Result<Vec<u64>, CampaignCodecError> {
    let mut ancestry = Vec::new();
    let mut cursor = Some(coordinate);
    while let Some(current) = cursor {
        let draw = design
            .draw(current)
            .ok_or_else(|| invalid("statistical ancestry coordinate is not planned"))?;
        ancestry.push(current);
        cursor = draw.parent();
    }
    ancestry.reverse();
    Ok(ancestry)
}

fn target_probability(
    evidence: StatisticalProposalEvidence,
) -> Result<StatisticalRational, CampaignCodecError> {
    StatisticalRational::new(
        u128::from(evidence.target_mass()),
        u128::from(evidence.target_total()),
    )
}

fn proposal_probability(
    evidence: StatisticalProposalEvidence,
) -> Result<StatisticalRational, CampaignCodecError> {
    StatisticalRational::new(
        u128::from(evidence.proposal_mass()),
        u128::from(evidence.proposal_total()),
    )
}

fn endpoint_weight_diagnostics(
    endpoints: &[StatisticalEndpointEstimate],
) -> Result<StatisticalWeightDiagnostics, CampaignCodecError> {
    weight_diagnostics(
        endpoints
            .iter()
            .map(StatisticalEndpointEstimate::importance_weight),
    )
}

fn particle_weight_diagnostics(
    particles: &[StatisticalParticleOutcome],
) -> Result<StatisticalWeightDiagnostics, CampaignCodecError> {
    weight_diagnostics(
        particles
            .iter()
            .map(StatisticalParticleOutcome::estimator_weight),
    )
}

fn weight_diagnostics(
    weights: impl IntoIterator<Item = StatisticalRational>,
) -> Result<StatisticalWeightDiagnostics, CampaignCodecError> {
    let mut sum = StatisticalRational::new(0, 1)?;
    let mut sum_squares = StatisticalRational::new(0, 1)?;
    let mut maximum = StatisticalRational::new(0, 1)?;
    for weight in weights {
        sum = sum.checked_add(weight)?;
        sum_squares = sum_squares.checked_add(weight.checked_multiply(weight)?)?;
        if weight.checked_cmp(maximum)?.is_gt() {
            maximum = weight;
        }
    }
    Ok(StatisticalWeightDiagnostics::new(
        maximum.checked_divide(sum)?,
        sum.checked_multiply(sum)?.checked_divide(sum_squares)?,
    ))
}

const fn invalid(reason: &'static str) -> CampaignCodecError {
    CampaignCodecError::InvalidValue { reason }
}
