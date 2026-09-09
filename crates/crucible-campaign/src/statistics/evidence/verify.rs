//! Pure semantic replay for authenticated statistical evidence.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    FiniteStatisticalEvidence, SequentialMonteCarloEvidence, StatisticalExecutionEvidence,
    StatisticalOpportunityEvidence,
};
use crate::{
    AttemptAdmissionRole, AttemptStart, BranchBudget, BranchPath, BranchPathSegment, BranchRequest,
    BranchRequestCause, CampaignCodecError, CampaignMode, CandidateSource, ObservationId,
    SelectionOrigin, SequentialMonteCarloEstimateReport, StatisticalEndpointEstimate,
    StatisticalEstimateReport, StatisticalGeneration, StatisticalParticleOutcome,
    StatisticalProposalEvidence, StatisticalRational, StatisticalWeightDiagnostics, StopOutcome,
};

/// Replays the semantics of a complete finite statistical evidence bundle.
///
/// The caller must first authenticate the snapshot and every membership from
/// [`FiniteStatisticalEvidence::required_root_lookups`].
/// Proposal membership and its content envelope authenticate the historical
/// guidance and planner-invocation identities; this estimator replay does not
/// reconstruct historical planner ranking decisions.
///
/// # Errors
///
/// Returns [`CampaignCodecError`] when any identity, cross-record binding,
/// coordinate, ancestry edge, probability, or report invariant is invalid.
pub fn verify_finite_statistical_evidence(
    evidence: &FiniteStatisticalEvidence,
) -> Result<StatisticalEstimateReport, CampaignCodecError> {
    verify_finite(evidence, false)
}

pub(crate) fn verify_initial_smc_statistical_evidence(
    evidence: &FiniteStatisticalEvidence,
) -> Result<StatisticalEstimateReport, CampaignCodecError> {
    verify_finite(evidence, true)
}

/// Replays the semantics of a complete sequential Monte Carlo evidence bundle.
///
/// The caller must first authenticate the snapshot and every membership from
/// [`SequentialMonteCarloEvidence::required_root_lookups`].
/// Proposal membership and its content envelope authenticate the historical
/// guidance and planner-invocation identities; this estimator replay does not
/// reconstruct historical planner ranking decisions.
///
/// # Errors
///
/// Returns [`CampaignCodecError`] when any initial draw, transition, selector,
/// support, genealogy, probability, or report invariant is invalid.
pub fn verify_sequential_monte_carlo_evidence(
    evidence: &SequentialMonteCarloEvidence,
) -> Result<SequentialMonteCarloEstimateReport, CampaignCodecError> {
    let initial = verify_finite(evidence.initial(), true)?;
    let policy = evidence.initial().policy();
    let policy_id = policy.id()?;
    let design = policy
        .sequential_monte_carlo_design()
        .ok_or_else(|| invalid("SMC evidence requires an SMC policy"))?;

    let mut source_executions = BTreeMap::new();
    for draw in evidence.initial().draws() {
        let execution = draw.execution();
        if execution.observation().stop()
            != &StopOutcome::Reached(execution.request().stop().clone())
        {
            return Err(invalid("SMC initial draw did not reach its declared stop"));
        }
        insert_source_execution(&mut source_executions, execution)?;
    }

    let mut transition_index = 0_usize;
    let mut generation = StatisticalGeneration::from_initial_report(
        policy_id,
        policy.campaign_seed(),
        design,
        &initial,
    )?;
    let mut generations = Vec::with_capacity(design.stages().len());
    let mut normalization_product = StatisticalRational::one();

    for stage in design.stages().keys().copied() {
        if generation.next_stage() != stage {
            return Err(invalid("SMC evidence generation stage is not canonical"));
        }
        normalization_product =
            normalization_product.checked_multiply(generation.normalization_factor())?;
        generations.push(generation.clone());

        let mut outcomes = Vec::with_capacity(generation.slots().len());
        for particle in generation.slots() {
            let transition = evidence
                .transitions()
                .get(transition_index)
                .ok_or_else(|| invalid("SMC evidence transition is missing"))?;
            transition_index = transition_index
                .checked_add(1)
                .ok_or_else(|| invalid("SMC evidence transition count overflows"))?;
            if transition.stage() != stage || transition.slot() != particle.slot() {
                return Err(invalid(
                    "SMC evidence transition coordinate is not canonical",
                ));
            }

            let execution = transition.execution();
            verify_execution_common(evidence.initial(), execution)?;
            validate_smc_request(
                evidence.initial(),
                &generation,
                particle,
                execution,
                &source_executions,
            )?;

            if design.stage(stage.saturating_add(1)).is_some()
                && execution.observation().stop()
                    != &StopOutcome::Reached(execution.request().stop().clone())
            {
                return Err(invalid(
                    "nonfinal SMC transition did not reach its declared stop",
                ));
            }

            let source = source_executions
                .get(&(particle.observation(), particle.proposal()))
                .ok_or_else(|| invalid("SMC source observation evidence is missing"))?;
            validate_extended_path(source.path(), execution.path())?;

            let proposal_id = execution.proposal().id()?;
            let attempt_id = execution.attempt().id()?;
            let observation_id = execution.observation().id()?;
            let proposal_evidence = execution
                .proposal()
                .statistical_evidence()
                .ok_or_else(|| invalid("SMC transition probability evidence is missing"))?;
            let cumulative_target_probability = particle
                .cumulative_target_probability()
                .checked_multiply(target_probability(proposal_evidence)?)?;
            let cumulative_proposal_probability = particle
                .cumulative_proposal_probability()
                .checked_multiply(proposal_probability(proposal_evidence)?)?;
            let branch_weight = target_probability(proposal_evidence)?
                .checked_divide(proposal_probability(proposal_evidence)?)?;
            let estimator_weight = particle
                .estimator_weight()
                .checked_multiply(branch_weight)?;

            outcomes.push(StatisticalParticleOutcome::new(
                stage,
                particle.slot(),
                particle.id(),
                particle.source_coordinate(),
                proposal_id,
                attempt_id,
                observation_id,
                execution.path().id()?,
                cumulative_target_probability,
                cumulative_proposal_probability,
                estimator_weight,
            )?);
            insert_source_execution(&mut source_executions, execution)?;
        }

        if design.stage(stage.saturating_add(1)).is_none() {
            if transition_index != evidence.transitions().len() {
                return Err(invalid(
                    "SMC evidence contains transitions after the final stage",
                ));
            }
            let diagnostics = particle_weight_diagnostics(&outcomes)?;
            return SequentialMonteCarloEstimateReport::new(
                evidence.initial().snapshot().id()?,
                policy_id,
                design.resampling().algorithm(),
                generations,
                normalization_product,
                outcomes,
                diagnostics,
            );
        }
        generation = StatisticalGeneration::from_completed_stage(
            policy_id,
            policy.campaign_seed(),
            design,
            stage,
            &outcomes,
        )?;
    }
    Err(invalid("SMC evidence policy has no transition stage"))
}

fn verify_finite(
    evidence: &FiniteStatisticalEvidence,
    allow_smc: bool,
) -> Result<StatisticalEstimateReport, CampaignCodecError> {
    let snapshot = evidence.snapshot();
    let policy = evidence.policy();
    let lineage = evidence.lineage();
    let policy_id = policy.id()?;
    if snapshot.active_policy() != policy_id
        || snapshot.lineage() != lineage.id()?
        || snapshot.planning_view() != *evidence.planning_view()
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
    if evidence.draws().len() != design.draws().len() {
        return Err(invalid("statistical evidence draw count is incomplete"));
    }

    let mut draws = BTreeMap::new();
    for ((expected_coordinate, draw_plan), evidence_draw) in
        design.draws().iter().zip(evidence.draws())
    {
        if evidence_draw.coordinate() != *expected_coordinate {
            return Err(invalid("statistical evidence draw coordinate has a gap"));
        }
        let execution = evidence_draw.execution();
        verify_execution_common(evidence, execution)?;
        validate_finite_request(evidence, *expected_coordinate, draw_plan, execution, &draws)?;

        let segments = execution
            .path()
            .segments()
            .ok_or_else(|| invalid("statistical evidence draw path is legacy"))?;
        let terminal = segments
            .last()
            .copied()
            .ok_or_else(|| invalid("statistical evidence draw path is empty"))?;
        let mut expected_segments = Vec::new();
        let mut ancestry = draw_ancestry(design, *expected_coordinate)?;
        ancestry.pop();
        for ancestor in ancestry {
            expected_segments.push(
                draws
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

        draws.insert(
            *expected_coordinate,
            VerifiedDraw {
                execution,
                terminal,
            },
        );
    }

    let mut endpoints = Vec::with_capacity(design.estimand_endpoints().len());
    for coordinate in design.estimand_endpoints().iter().copied() {
        let draw = draws
            .get(&coordinate)
            .ok_or_else(|| invalid("statistical estimand endpoint is missing"))?;
        let mut target = StatisticalRational::one();
        let mut proposal = StatisticalRational::one();
        for ancestor in draw_ancestry(design, coordinate)? {
            let proposal_evidence = draws
                .get(&ancestor)
                .and_then(|draw| draw.execution.proposal().statistical_evidence())
                .ok_or_else(|| invalid("statistical ancestry probability evidence is missing"))?;
            target = target.checked_multiply(target_probability(proposal_evidence)?)?;
            proposal = proposal.checked_multiply(proposal_probability(proposal_evidence)?)?;
        }
        let execution = draw.execution;
        endpoints.push(StatisticalEndpointEstimate::new(
            coordinate,
            execution.proposal().id()?,
            execution.attempt().id()?,
            execution.observation().id()?,
            execution.path().id()?,
            target,
            proposal,
            target.checked_divide(proposal)?,
        ));
    }
    let diagnostics = endpoint_weight_diagnostics(&endpoints)?;
    Ok(StatisticalEstimateReport::new(
        snapshot.id()?,
        policy_id,
        endpoints,
        diagnostics,
    ))
}

struct VerifiedDraw<'a> {
    execution: &'a StatisticalExecutionEvidence,
    terminal: BranchPathSegment,
}

fn verify_execution_common(
    bundle: &FiniteStatisticalEvidence,
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
    if proposal.policy() != bundle.snapshot().active_policy()
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
        || basis.proposal().policy() != bundle.snapshot().active_policy()
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

    let segments = execution
        .path()
        .segments()
        .ok_or_else(|| invalid("statistical path is legacy"))?;
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
    if discovered.len() != execution.discovered_opportunities().len()
        || discovered != *observation.discovered_choices()
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
    bundle: &FiniteStatisticalEvidence,
    coordinate: u64,
    draw: &crate::StatisticalDrawPlan,
    execution: &StatisticalExecutionEvidence,
    verified: &BTreeMap<u64, VerifiedDraw<'_>>,
) -> Result<(), CampaignCodecError> {
    let CandidateSource::StatisticalFinite(source) = execution.request().source() else {
        return Err(invalid("finite statistical request source is invalid"));
    };
    let distribution = bundle
        .policy()
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
            if execution.request().parent() != bundle.lineage().genesis_content()
                || execution.parent().configuration() != bundle.lineage().genesis()
            {
                return Err(invalid("finite root draw parent is not the genesis"));
            }
        }
        Some(parent_coordinate) => {
            let parent = verified
                .get(&parent_coordinate)
                .ok_or_else(|| invalid("finite parent draw evidence is missing"))?
                .execution;
            if execution.request().parent() != parent.observation().child_content()
                || execution.parent().configuration() != parent.observation().child()
            {
                return Err(invalid("finite parent draw endpoint is inconsistent"));
            }
        }
    }
    Ok(())
}

fn validate_smc_request(
    bundle: &FiniteStatisticalEvidence,
    generation: &StatisticalGeneration,
    particle: &crate::StatisticalParticleSlot,
    execution: &StatisticalExecutionEvidence,
    source_executions: &BTreeMap<(ObservationId, crate::ProposalId), &StatisticalExecutionEvidence>,
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
    let design = bundle
        .policy()
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
    let source_execution = source_executions
        .get(&(particle.observation(), particle.proposal()))
        .ok_or_else(|| invalid("SMC source observation evidence is missing"))?;
    if source_execution.observation().path() != particle.path()
        || source_execution.observation().stop()
            != &StopOutcome::Reached(source_execution.request().stop().clone())
        || execution.parent().id()? != source_execution.observation().child_content()
        || execution.parent().configuration() != source_execution.observation().child()
    {
        return Err(invalid("SMC source observation is inconsistent"));
    }

    let selected = select_smc_opportunity(source_execution, selector, distribution)?;
    if selected.opportunity().id()? != execution.request_opportunity().opportunity().id()?
        || selected.domain().id()? != execution.request_opportunity().domain().id()?
    {
        return Err(invalid("SMC selector opportunity closure drifted"));
    }
    let BranchRequestCause::Planner(invocation) = execution.request().cause() else {
        return Err(invalid("SMC transition request cause is not a planner"));
    };
    let expected = BranchRequest::new(
        selected
            .opportunity()
            .branch_point_id(execution.parent().configuration()),
        execution.parent().id()?,
        selected.opportunity().id()?,
        selected.domain().id()?,
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

fn insert_source_execution<'a>(
    sources: &mut BTreeMap<(ObservationId, crate::ProposalId), &'a StatisticalExecutionEvidence>,
    execution: &'a StatisticalExecutionEvidence,
) -> Result<(), CampaignCodecError> {
    let source = (execution.observation().id()?, execution.proposal().id()?);
    if sources
        .insert(source, execution)
        .is_some_and(|prior| prior != execution)
    {
        return Err(invalid(
            "one observation has conflicting statistical evidence",
        ));
    }
    Ok(())
}

fn validate_extended_path(
    source: &BranchPath,
    child: &BranchPath,
) -> Result<(), CampaignCodecError> {
    let source_segments = source
        .segments()
        .ok_or_else(|| invalid("SMC source path is legacy"))?;
    let child_segments = child
        .segments()
        .ok_or_else(|| invalid("SMC transition path is legacy"))?;
    if child_segments.len() != source_segments.len().saturating_add(1)
        || !child_segments.starts_with(source_segments)
    {
        return Err(invalid("SMC transition path does not extend its source"));
    }
    Ok(())
}

fn draw_ancestry(
    design: &crate::StatisticalSamplingDesign,
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
