//! Checked candidate guidance over one owner-built branch projection.

use super::*;

impl ClosureSemanticRead<'_, '_> {
    pub(in crate::repository) fn planner_candidate_guidance(
        &mut self,
        loaded: &LoadedSnapshot,
        projection: &crate::BranchPuctProjection,
        offer: &Proposal,
        cache: &mut PlannerCandidateProjectionCache,
    ) -> Result<crate::PlannerCandidateGuidance, CampaignRepositoryError> {
        let _operation = self.enter_operation();
        if projection.branch_point() != offer.branch_point()
            || projection.policy() != loaded.snapshot.active_policy()
        {
            return Err(integrity(
                "planner-candidate-guidance-projection-basis-mismatch",
            ));
        }

        let domain_id = offer.domain();
        if !cache.checked_domains.contains_key(&domain_id) {
            let domain = self.read_choice_domain(domain_id.content_id())?;
            if domain.id()? != domain_id {
                return Err(integrity("planner-candidate-guidance-domain-mismatch"));
            }
            cache.domain_bytes = charge_planner_guidance_domain_work(
                cache.domain_bytes,
                domain.canonical_bytes().len(),
            )?;
            self.insert_map(&mut cache.checked_domains, domain_id, domain)?;
        }
        let semantic_id = cache
            .checked_domains
            .get(&domain_id)
            .ok_or_else(|| integrity("planner-candidate-guidance-domain-cache-mismatch"))?
            .semantic_id();
        let edge =
            crate::Selection::campaign_edge_id(offer.branch_point(), semantic_id, offer.value());

        let request_id = offer.request();
        if !cache.checked_requests.contains_key(&request_id) {
            let request = self.read_branch_request(request_id)?;
            self.insert_map(&mut cache.checked_requests, request_id, request)?;
        }
        let request = cache
            .checked_requests
            .get(&request_id)
            .ok_or_else(|| integrity("planner-candidate-guidance-request-cache-mismatch"))?;
        let raw_prior_weight = request
            .source()
            .prior_weight(offer.value())
            .ok_or_else(|| integrity("planner-offer-is-not-in-prior-source"))?;

        let (statistics, novelty_events, objective_reward_micros, finding_events) =
            if let Some(statistics) = projection.edge_statistics().get(&edge).copied() {
                let mut finding_events = BTreeMap::new();
                if let Some(events) = projection.edge_finding_events().get(&edge) {
                    for (kind, count) in events {
                        self.insert_map(&mut finding_events, *kind, *count)?;
                    }
                }
                (
                    statistics,
                    projection
                        .edge_novelty_events()
                        .get(&edge)
                        .copied()
                        .unwrap_or(0),
                    projection
                        .edge_objective_reward_micros()
                        .get(&edge)
                        .copied()
                        .unwrap_or(0),
                    finding_events,
                )
            } else {
                let cache_key = (projection.branch_point(), raw_prior_weight);
                let basis = match cache.prospective_priors.get(&cache_key).copied() {
                    Some(basis) => basis,
                    None => {
                        cache.prior_normalization_visits =
                            charge_branch_prior_normalization_visits(
                                cache.prior_normalization_visits,
                                projection.edge_prior_weights().len(),
                            )?;
                        let basis = projection.prospective_prior_basis(raw_prior_weight)?;
                        self.insert_map(&mut cache.prospective_priors, cache_key, basis)?;
                        basis
                    }
                };
                let evidence = projection.candidate_evidence_with_prior_basis(edge, basis)?;
                (
                    evidence.statistics,
                    evidence.novelty_events,
                    evidence.objective_reward_micros,
                    evidence.finding_events,
                )
            };

        crate::PlannerCandidateGuidance::new(
            loaded.snapshot.planning_view().id()?,
            loaded.snapshot.active_policy(),
            crate::PlanningScanPosition::new(offer.branch_point(), offer.request()),
            offer.domain(),
            semantic_id,
            offer.value().clone_admitted()?,
            offer.ordinal(),
            edge,
            statistics,
            novelty_events,
            objective_reward_micros,
            finding_events,
        )
        .map_err(Into::into)
    }
}
