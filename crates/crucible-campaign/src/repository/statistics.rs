//! Authenticated projection of complete statistical sampling flights.

use super::*;
use crate::{
    StatisticalEndpointEstimate, StatisticalEstimateReport, StatisticalProposalEvidence,
    StatisticalRational, StatisticalWeightDiagnostics,
};

struct StatisticalDrawRecord {
    proposal_id: ProposalId,
    proposal: Proposal,
    attempt_id: AttemptId,
    observation_id: ObservationId,
    path_id: BranchPathId,
    terminal: crate::BranchPathSegment,
}

impl CampaignRepository {
    pub(super) fn statistical_request_basis(
        &self,
        snapshot: &LoadedSnapshot,
        policy: &CampaignPolicy,
    ) -> Result<Option<crate::StatisticalRequestBasis>, CampaignRepositoryError> {
        let Some(design) = policy.statistical_sampling_design() else {
            return Ok(None);
        };
        let mut coordinate = None;
        for candidate in design.draws().keys().copied() {
            if self
                .merkle
                .get(
                    snapshot.snapshot.roots().exploration,
                    statistical_draw_request_key(candidate),
                )?
                .is_none()
            {
                coordinate = Some(candidate);
                break;
            }
        }
        let Some(coordinate) = coordinate else {
            return Ok(None);
        };
        for prior_coordinate in 0..coordinate {
            if self
                .merkle
                .get(
                    snapshot.snapshot.roots().accounting,
                    statistical_draw_proposal_key(prior_coordinate),
                )?
                .is_none()
            {
                return Ok(None);
            }
        }
        let draw = design
            .draw(coordinate)
            .ok_or_else(|| integrity("statistical-request-coordinate-is-not-planned"))?;
        let lineage = self.read_lineage(required_child(&snapshot.envelope, "lineage")?)?;
        let (parent, configuration) = match draw.parent() {
            None => (lineage.genesis_content(), lineage.genesis()),
            Some(parent_coordinate) => {
                let Some(proposal_content) = self.merkle.get(
                    snapshot.snapshot.roots().accounting,
                    statistical_draw_proposal_key(parent_coordinate),
                )?
                else {
                    return Ok(None);
                };
                let proposal = self.read_proposal(proposal_content)?;
                let parent_request = self.read_branch_request(proposal.request().content_id())?;
                let CandidateSource::StatisticalFinite(parent_source) = parent_request.source()
                else {
                    return Err(integrity("statistical-parent-draw-source-mismatch"));
                };
                if parent_source.coordinate() != parent_coordinate {
                    return Err(integrity("statistical-parent-draw-coordinate-mismatch"));
                }
                let admission_content = self
                    .merkle
                    .get(
                        snapshot.snapshot.roots().accounting,
                        map_key_content("accounting.proposal-admission", proposal_content),
                    )?
                    .ok_or_else(|| integrity("statistical-parent-draw-admission-is-missing"))?;
                let admission = self.read_attempt_admission(admission_content)?;
                self.validate_statistical_attempt_basis(snapshot, admission.attempt())?;
                let Some(observation_content) = self.merkle.get(
                    snapshot.snapshot.roots().observations,
                    map_key_content("observations.attempt", admission.attempt().content_id()),
                )?
                else {
                    return Ok(None);
                };
                let observation = self.read_observation(observation_content)?;
                if observation.attempt() != admission.attempt()
                    || observation.stop() != &StopOutcome::Reached(parent_request.stop().clone())
                {
                    return Err(integrity("statistical-parent-draw-cannot-continue"));
                }
                (observation.child_content(), observation.child())
            }
        };
        let parent_artifact = self.read_configuration_artifact(parent.content_id())?;
        if parent_artifact.configuration() != configuration
            || self.merkle.get(
                snapshot.snapshot.roots().graph,
                map_key_hash("graph.configuration", configuration.as_hash()),
            )? != Some(parent.content_id())
        {
            return Err(integrity("statistical-request-parent-is-not-authoritative"));
        }
        let opportunity = self.read_opportunity(draw.opportunity().content_id())?;
        if opportunity.id()? != draw.opportunity()
            || opportunity.semantic_id() != draw.opportunity_semantics()
            || opportunity.domain() != draw.domain()
            || opportunity.model_prior() != Some(draw.model())
        {
            return Err(integrity("statistical-design-opportunity-basis-mismatch"));
        }
        let branch_point = opportunity.branch_point_id(configuration);
        if self.merkle.get(
            snapshot.snapshot.roots().graph,
            branch_point_opportunity_key(branch_point, draw.opportunity()),
        )? != Some(draw.opportunity().content_id())
        {
            return Err(integrity(
                "statistical-draw-opportunity-is-not-authoritative",
            ));
        }
        Ok(Some(crate::StatisticalRequestBasis::new(
            coordinate,
            parent,
            configuration,
        )))
    }

    /// Projects exact importance weights for a complete pinned sampling design.
    ///
    /// The endpoint population is the equal-weight mixture declared by the
    /// policy's terminal coordinates. Every planned coordinate, including
    /// shared prefixes, must have one admitted proposal and a canonical
    /// observation. Shared ancestry is retained, so diagnostics describe
    /// weights without claiming independent samples.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale snapshot, a non-statistical or legacy
    /// policy, an incomplete/reordered/forged draw, intervention ancestry,
    /// legacy paths, inconsistent endpoint ancestry, or exact arithmetic
    /// overflow.
    pub fn project_statistical_estimate(
        &self,
        name: &str,
        expected_snapshot: CampaignSnapshotId,
    ) -> Result<StatisticalEstimateReport, CampaignRepositoryError> {
        let head = self.head(name)?;
        if head.snapshot_id() != expected_snapshot {
            return Err(CampaignRepositoryError::Stale {
                expected: expected_snapshot,
                current: head.snapshot_id(),
            });
        }
        let snapshot = self.read_snapshot(expected_snapshot.content_id())?;
        self.validate_complete_head(expected_snapshot.content_id())?;
        let policy_id = snapshot.snapshot.active_policy();
        let policy = self.read_policy(policy_id.content_id())?;
        if policy.mode() != CampaignMode::Statistical {
            return Err(integrity("statistical-report-requires-statistical-policy"));
        }
        let design = policy
            .statistical_sampling_design()
            .ok_or_else(|| integrity("statistical-report-policy-lacks-design"))?;
        let lineage = self.read_lineage(required_child(&snapshot.envelope, "lineage")?)?;
        let mut draws: BTreeMap<u64, StatisticalDrawRecord> = BTreeMap::new();

        for coordinate in design.draws().keys().copied() {
            let request_content = self
                .merkle
                .get(
                    snapshot.snapshot.roots().exploration,
                    statistical_draw_request_key(coordinate),
                )?
                .ok_or_else(|| integrity("statistical-report-draw-request-is-missing"))?;
            let request = self.read_branch_request(request_content)?;
            let CandidateSource::StatisticalFinite(source) = request.source() else {
                return Err(integrity("statistical-report-draw-request-source-mismatch"));
            };
            if source.coordinate() != coordinate {
                return Err(integrity(
                    "statistical-report-draw-request-coordinate-mismatch",
                ));
            }
            self.validate_statistical_request_policy(&snapshot, &lineage, &policy, &request)?;

            let proposal_content = self
                .merkle
                .get(
                    snapshot.snapshot.roots().accounting,
                    statistical_draw_proposal_key(coordinate),
                )?
                .ok_or_else(|| integrity("statistical-report-draw-proposal-is-missing"))?;
            let proposal_id = ProposalId::from_content_id(proposal_content)?;
            let proposal = self.read_proposal(proposal_content)?;
            if proposal.request().content_id() != request_content
                || proposal.statistical_evidence().is_none()
            {
                return Err(integrity("statistical-report-draw-proposal-mismatch"));
            }
            let admission_content = self
                .merkle
                .get(
                    snapshot.snapshot.roots().accounting,
                    map_key_content("accounting.proposal-admission", proposal_content),
                )?
                .ok_or_else(|| integrity("statistical-report-draw-admission-is-missing"))?;
            let admission = self.read_attempt_admission(admission_content)?;
            let admitted_proposal = match admission.role() {
                AttemptAdmissionRole::ExecutionBasis {
                    proposal: Some(proposal),
                    ..
                }
                | AttemptAdmissionRole::AdditionalCause { proposal } => proposal,
                AttemptAdmissionRole::ExecutionBasis { proposal: None, .. } => {
                    return Err(integrity(
                        "statistical-report-draw-admission-has-no-proposal",
                    ));
                }
            };
            if admitted_proposal != proposal_id {
                return Err(integrity("statistical-report-draw-admission-mismatch"));
            }
            self.validate_statistical_attempt_basis(&snapshot, admission.attempt())?;

            let observation_content = self
                .merkle
                .get(
                    snapshot.snapshot.roots().observations,
                    map_key_content("observations.attempt", admission.attempt().content_id()),
                )?
                .ok_or_else(|| integrity("statistical-report-draw-observation-is-missing"))?;
            let observation_id = ObservationId::from_content_id(observation_content)?;
            let observation = self.read_observation(observation_content)?;
            let attempt = self.read_attempt(admission.attempt().content_id())?;
            if observation.attempt() != admission.attempt() || observation.path() != attempt.path()
            {
                return Err(integrity("statistical-report-draw-observation-mismatch"));
            }
            let AttemptStart::Branch {
                edge,
                parent,
                selection,
            } = attempt.start()
            else {
                return Err(integrity("statistical-report-draw-attempt-is-not-a-branch"));
            };
            if parent != request.parent() {
                return Err(integrity("statistical-report-draw-attempt-parent-mismatch"));
            }
            let selection = self.resolve_selection(selection)?;
            let crate::SelectionOrigin::CampaignBranch {
                branch_point,
                edge: selected_edge,
            } = selection.selection().origin()
            else {
                return Err(integrity(
                    "statistical-report-draw-selection-origin-mismatch",
                ));
            };
            if branch_point != proposal.branch_point()
                || edge != selected_edge
                || selection.selection().value() != proposal.value()
            {
                return Err(integrity("statistical-report-draw-selection-mismatch"));
            }
            let path = self.read_branch_path(attempt.path().content_id())?;
            let segments = path
                .segments()
                .ok_or_else(|| integrity("statistical-report-draw-path-is-legacy"))?;
            let Some(terminal) = segments.last().copied() else {
                return Err(integrity("statistical-report-draw-path-is-empty"));
            };
            if terminal.branch_point() != proposal.branch_point() || terminal.edge() != edge {
                return Err(integrity("statistical-report-draw-path-terminal-mismatch"));
            }

            let mut expected_segments = Vec::new();
            let mut ancestry = statistical_draw_ancestry(design, coordinate)?;
            ancestry.pop();
            for ancestor in ancestry {
                expected_segments.push(
                    draws
                        .get(&ancestor)
                        .ok_or_else(|| integrity("statistical-report-draw-ancestry-gap"))?
                        .terminal,
                );
            }
            expected_segments.push(terminal);
            if segments != expected_segments {
                return Err(integrity("statistical-report-draw-path-ancestry-mismatch"));
            }

            draws.insert(
                coordinate,
                StatisticalDrawRecord {
                    proposal_id,
                    proposal,
                    attempt_id: admission.attempt(),
                    observation_id,
                    path_id: attempt.path(),
                    terminal,
                },
            );
        }

        let mut endpoints = Vec::with_capacity(design.estimand_endpoints().len());
        for coordinate in design.estimand_endpoints().iter().copied() {
            let draw = draws
                .get(&coordinate)
                .ok_or_else(|| integrity("statistical-report-estimand-endpoint-is-missing"))?;
            let mut target_probability = StatisticalRational::one();
            let mut proposal_probability = StatisticalRational::one();
            for ancestor in statistical_draw_ancestry(design, coordinate)? {
                let evidence = draws
                    .get(&ancestor)
                    .and_then(|record| record.proposal.statistical_evidence())
                    .ok_or_else(|| integrity("statistical-report-ancestry-evidence-is-missing"))?;
                target_probability = target_probability
                    .checked_multiply(statistical_target_probability(evidence)?)?;
                proposal_probability = proposal_probability
                    .checked_multiply(statistical_proposal_probability(evidence)?)?;
            }
            let importance_weight = target_probability.checked_divide(proposal_probability)?;
            endpoints.push(StatisticalEndpointEstimate::new(
                coordinate,
                draw.proposal_id,
                draw.attempt_id,
                draw.observation_id,
                draw.path_id,
                target_probability,
                proposal_probability,
                importance_weight,
            ));
        }
        let diagnostics = statistical_weight_diagnostics(&endpoints)?;
        Ok(StatisticalEstimateReport::new(
            expected_snapshot,
            policy_id,
            endpoints,
            diagnostics,
        ))
    }
}

fn statistical_draw_ancestry(
    design: &crate::StatisticalSamplingDesign,
    coordinate: u64,
) -> Result<Vec<u64>, CampaignRepositoryError> {
    let mut ancestry = Vec::new();
    let mut cursor = Some(coordinate);
    while let Some(current) = cursor {
        let draw = design
            .draw(current)
            .ok_or_else(|| integrity("statistical-report-ancestry-coordinate-is-missing"))?;
        ancestry.push(current);
        cursor = draw.parent();
    }
    ancestry.reverse();
    Ok(ancestry)
}

fn statistical_target_probability(
    evidence: StatisticalProposalEvidence,
) -> Result<StatisticalRational, CampaignRepositoryError> {
    StatisticalRational::new(
        u128::from(evidence.target_mass()),
        u128::from(evidence.target_total()),
    )
    .map_err(Into::into)
}

fn statistical_proposal_probability(
    evidence: StatisticalProposalEvidence,
) -> Result<StatisticalRational, CampaignRepositoryError> {
    StatisticalRational::new(
        u128::from(evidence.proposal_mass()),
        u128::from(evidence.proposal_total()),
    )
    .map_err(Into::into)
}

fn statistical_weight_diagnostics(
    endpoints: &[StatisticalEndpointEstimate],
) -> Result<StatisticalWeightDiagnostics, CampaignRepositoryError> {
    let mut sum = StatisticalRational::new(0, 1)?;
    let mut sum_squares = StatisticalRational::new(0, 1)?;
    let mut maximum = StatisticalRational::new(0, 1)?;
    for endpoint in endpoints {
        let weight = endpoint.importance_weight();
        sum = sum.checked_add(weight)?;
        sum_squares = sum_squares.checked_add(weight.checked_multiply(weight)?)?;
        if weight.checked_cmp(maximum)?.is_gt() {
            maximum = weight;
        }
    }
    let concentration = maximum.checked_divide(sum)?;
    let effective_sample_size = sum.checked_multiply(sum)?.checked_divide(sum_squares)?;
    Ok(StatisticalWeightDiagnostics::new(
        concentration,
        effective_sample_size,
    ))
}
