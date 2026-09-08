//! Snapshot-bound branch-request acceptance computation.

use super::*;

// This bound determines exact-versus-range v7 fact bytes and cold replay.
// Changing it or the bounded scan requires explicit schema compatibility.
const MAX_ACCEPTANCE_EDGE_LOOKUPS: u64 = 65_536;

impl CampaignRepository {
    pub(super) fn branch_acceptance_summary(
        &self,
        graph: ContentId,
        request: &BranchRequest,
    ) -> Result<BranchAcceptanceSummary, CampaignRepositoryError> {
        let domain = self.read_choice_domain(request.domain().content_id())?;
        let static_cardinality = self.static_candidate_count(request, &domain)?;
        let profile = self.candidate_source_profile(request, &domain)?;
        let budget = request.budget();
        let validated_cardinality = match (static_cardinality, profile) {
            (Some(count), _) => BranchAcceptanceCount::Exact(count),
            (
                None,
                Some(super::projection::CandidateSourceProfile::ProgressiveInteger {
                    count, ..
                }),
            ) => BranchAcceptanceCount::Exact(count),
            (None, Some(super::projection::CandidateSourceProfile::CorpusMutation)) => {
                let upper = u64::try_from(
                    domain
                        .cardinality()
                        .min(u128::from(crate::CORPUS_MUTATION_GENERATOR_MAX_PROPOSALS)),
                )
                .map_err(|_| integrity("branch-acceptance-cardinality-overflow"))?;
                BranchAcceptanceCount::between(0, upper)?
            }
            (None, None) => {
                // Every proposal position is a nonzero u64 ordinal, so a source
                // can expose at most u64::MAX addressable candidates even when
                // its semantic domain contains 2^64 values.
                let upper = u64::try_from(domain.cardinality().min(u128::from(u64::MAX)))
                    .map_err(|_| integrity("branch-acceptance-cardinality-overflow"))?;
                BranchAcceptanceCount::between(0, upper)?
            }
            (None, Some(super::projection::CandidateSourceProfile::Static { .. })) => {
                return Err(integrity("static-candidate-profile-has-no-cardinality"));
            }
        };
        let proposal_window = validated_cardinality
            .maximum()
            .min(budget.maximum_proposals());

        let (deduplicated, remaining) = if static_cardinality.is_some() {
            self.static_acceptance_counts(graph, request, &domain, proposal_window)?
        } else {
            (
                BranchAcceptanceCount::between(0, proposal_window)?,
                BranchAcceptanceCount::between(0, proposal_window)?,
            )
        };

        BranchAcceptanceSummary::new(
            validated_cardinality,
            deduplicated,
            remaining,
            budget.maximum_proposals(),
            budget.maximum_attempts(),
        )
        .map_err(CampaignRepositoryError::from)
    }

    fn static_acceptance_counts(
        &self,
        graph: ContentId,
        request: &BranchRequest,
        domain: &ChoiceDomain,
        proposal_window: u64,
    ) -> Result<(BranchAcceptanceCount, BranchAcceptanceCount), CampaignRepositoryError> {
        let inspected = proposal_window.min(MAX_ACCEPTANCE_EDGE_LOOKUPS);
        let mut deduplicated = 0_u64;

        let candidates = self.static_candidate_prefix(request, domain, inspected)?;
        if u64::try_from(candidates.len()) != Ok(inspected) {
            return Err(integrity("static-acceptance-candidate-prefix-is-short"));
        }
        for value in candidates {
            let edge =
                Selection::campaign_edge_id(request.branch_point(), domain.semantic_id(), &value);
            if self
                .merkle
                .get(
                    graph,
                    map_key_hash("graph.branch-edge-child", edge.as_hash()),
                )?
                .is_some()
            {
                deduplicated = deduplicated
                    .checked_add(1)
                    .ok_or_else(|| integrity("branch-acceptance-deduplication-overflow"))?;
            }
        }

        let unchecked = proposal_window
            .checked_sub(inspected)
            .ok_or_else(|| integrity("branch-acceptance-inspection-overflow"))?;
        let known_remaining = inspected
            .checked_sub(deduplicated)
            .ok_or_else(|| integrity("branch-acceptance-remaining-underflow"))?;
        Ok((
            BranchAcceptanceCount::between(deduplicated, deduplicated + unchecked)?,
            BranchAcceptanceCount::between(known_remaining, known_remaining + unchecked)?,
        ))
    }
}
