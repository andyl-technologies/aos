//! Snapshot-bound finite expansion and branch-guidance projections.

use super::*;

impl CampaignRepository {
    /// Projects and publishes one bounded static-continuation page.
    ///
    /// The page is derived from one authenticated historical or current
    /// snapshot. Its cursor is meaningful only for that immutable snapshot and
    /// branch point. Implementation-version 2 `all` generators and
    /// implementation-version 3 boundary-integer generators share the
    /// finite-source path. Static continuation state is independent of modeled
    /// observations, but every page still binds the source view's exact
    /// observation root. History-dependent generators remain fail-closed until
    /// their feedback owners are implemented.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid snapshot closure, fabricated or
    /// cross-branch cursor, invalid page size, unsupported generated request or
    /// inconsistent proposal/admission indexes, or store failure.
    pub fn project_finite_expansion(
        &self,
        source_snapshot: CampaignSnapshotId,
        branch_point: crate::BranchPointId,
        page_after: Option<BranchRequestId>,
        page_size: u32,
    ) -> Result<ExpansionStateId, CampaignRepositoryError> {
        self.validate_complete_head(source_snapshot.content_id())?;
        let state =
            self.recompute_finite_expansion(source_snapshot, branch_point, page_after, page_size)?;
        let state_id = state.id()?;
        let content = self.put_expansion_state(&state)?;
        if content != state_id.content_id() {
            return Err(integrity("expansion-state-publication-id-mismatch"));
        }
        self.read_expansion_state(content)?;
        Ok(state_id)
    }

    pub(in crate::repository) fn recompute_finite_expansion(
        &self,
        source_snapshot: CampaignSnapshotId,
        branch_point: crate::BranchPointId,
        page_after: Option<BranchRequestId>,
        page_size: u32,
    ) -> Result<ExpansionState, CampaignRepositoryError> {
        let loaded = self.read_snapshot(source_snapshot.content_id())?;
        let view = loaded.snapshot.planning_view();
        let view_id = view.id()?;
        let view_content = self.put_planning_view(&view)?;
        if view_content != view_id.content_id() {
            return Err(integrity("expansion-state-planning-view-id-mismatch"));
        }
        let inputs = self.derive_finite_expansion_inputs(&view, branch_point)?;
        let (continuations, next_after) = self.finite_continuation_page(
            CandidateViewRoots::from_planning_view(&view),
            inputs.requests,
            page_after,
            page_size,
        )?;
        ExpansionState::new(
            source_snapshot,
            view_id,
            branch_point,
            inputs.requests,
            inputs.proposals,
            inputs.admissions,
            view.observations(),
            crate::ExpansionStatistics {
                admitted_children: inputs.admitted_children,
                completed_visits: inputs.completed_visits,
                ..crate::ExpansionStatistics::default()
            },
            page_after,
            page_size,
            next_after,
            continuations,
        )
        .map_err(Into::into)
    }

    fn derive_finite_expansion_inputs(
        &self,
        view: &CampaignPlanningView,
        branch_point: crate::BranchPointId,
    ) -> Result<FiniteExpansionInputs, CampaignRepositoryError> {
        let mut requests = self.merkle.empty()?.content_id();
        let mut proposals = self.merkle.empty()?.content_id();
        let mut admissions = self.merkle.empty()?.content_id();

        let mut after = None;
        loop {
            let page = self
                .merkle
                .scan(view.exploration(), after, PROJECTION_SCAN_PAGE_ITEMS)?;
            for (key, value) in page.entries() {
                if *key == map_key_content("exploration.branch-request", *value) {
                    let request = self.read_branch_request(*value)?;
                    if request.branch_point() == branch_point {
                        let domain = self.read_choice_domain(request.domain().content_id())?;
                        if self.candidate_source_profile(&request, &domain)?.is_none() {
                            return Err(integrity(
                                "generated-expansion-projector-is-not-implemented",
                            ));
                        }
                        requests = self
                            .merkle
                            .insert(requests, projection_order_key(*value), *value)?
                            .content_id();
                    }
                } else if *key == map_key_content("exploration.proposal", *value) {
                    let proposal = self.read_proposal(*value)?;
                    if proposal.branch_point() == branch_point {
                        proposals = self
                            .merkle
                            .insert(proposals, projection_order_key(*value), *value)?
                            .content_id();
                    }
                }
            }
            let Some(next) = page.next_after() else {
                break;
            };
            after = Some(next);
        }

        let mut admitted_children = 0_u64;
        after = None;
        loop {
            let page = self
                .merkle
                .scan(view.accounting(), after, PROJECTION_SCAN_PAGE_ITEMS)?;
            for (key, value) in page.entries() {
                if *key != map_key_content("accounting.attempt-admission", *value) {
                    continue;
                }
                let admission = self.read_attempt_admission(*value)?;
                let (proposal, is_execution_basis) = match admission.role() {
                    AttemptAdmissionRole::ExecutionBasis {
                        proposal: Some(proposal),
                        ..
                    } => (proposal, true),
                    AttemptAdmissionRole::AdditionalCause { proposal } => (proposal, false),
                    AttemptAdmissionRole::ExecutionBasis { proposal: None, .. } => continue,
                };
                if self.read_proposal(proposal.content_id())?.branch_point() != branch_point {
                    continue;
                }
                admissions = self
                    .merkle
                    .insert(admissions, projection_order_key(*value), *value)?
                    .content_id();
                if is_execution_basis {
                    admitted_children = admitted_children
                        .checked_add(1)
                        .ok_or_else(|| integrity("expansion-admitted-child-count-overflow"))?;
                }
            }
            let Some(next) = page.next_after() else {
                break;
            };
            after = Some(next);
        }

        Ok(FiniteExpansionInputs {
            requests,
            proposals,
            admissions,
            admitted_children,
            completed_visits: self.branch_completed_visits(view.observations(), branch_point)?,
        })
    }

    pub(in crate::repository) fn branch_completed_visits(
        &self,
        observation_root: ContentId,
        branch_point: crate::BranchPointId,
    ) -> Result<u64, CampaignRepositoryError> {
        let Some(index) = self
            .merkle
            .get(observation_root, branch_credit_index_key(branch_point))?
        else {
            return Ok(0);
        };
        Ok(self.merkle.inspect_shallow(index)?.entry_count())
    }

    /// Rebuilds exact completed visits partitioned by semantic branch edge.
    ///
    /// The projection authenticates the complete supplied snapshot first, then
    /// follows the branch point's idempotent observation-credit index. Every
    /// credited observation must contain exactly one scoped path segment for
    /// `branch_point`, so duplicate observations and convergent causes cannot
    /// receive additional credit.
    ///
    /// # Errors
    ///
    /// Returns an error when the snapshot closure or ancestry is invalid, a
    /// credit/path basis is inconsistent, more than 65,536 credits are present,
    /// more than 128 MiB of canonical evidence would be inspected, or storage
    /// access fails.
    pub fn project_branch_edge_visits(
        &self,
        snapshot: crate::CampaignSnapshotId,
        branch_point: crate::BranchPointId,
    ) -> Result<crate::BranchEdgeVisitStatistics, CampaignRepositoryError> {
        self.validate_complete_head(snapshot.content_id())?;
        let loaded = self.read_snapshot(snapshot.content_id())?;
        self.project_branch_edge_visit_evidence(&loaded, branch_point)
            .map(|evidence| evidence.statistics)
    }

    /// Rebuilds the active policy's bounded PUCT scores for one branch point.
    ///
    /// The projection authenticates the exact snapshot once, derives its
    /// completed edge-visit partition, assigns canonical proposal priors,
    /// projects globally unique coverage identities and inverse-frequency
    /// rarity onto credited edges, folds policy-weighted verified finding
    /// occurrences into reward, and reserves fairness for the least-visited
    /// edge. The active policy must select tree search.
    ///
    /// # Errors
    ///
    /// Returns an error when the snapshot or edge evidence is invalid, the
    /// active policy is not tree search, a projection bound is exceeded, or
    /// storage access fails.
    pub fn project_branch_puct(
        &self,
        snapshot: crate::CampaignSnapshotId,
        branch_point: crate::BranchPointId,
    ) -> Result<crate::BranchPuctProjection, CampaignRepositoryError> {
        self.validate_complete_head(snapshot.content_id())?;
        let loaded = self.read_snapshot(snapshot.content_id())?;
        self.project_branch_puct_loaded(&loaded, branch_point)
    }

    pub(in crate::repository) fn project_branch_puct_loaded(
        &self,
        loaded: &LoadedSnapshot,
        branch_point: crate::BranchPointId,
    ) -> Result<crate::BranchPuctProjection, CampaignRepositoryError> {
        let policy = self.read_policy(loaded.snapshot.active_policy().content_id())?;
        let crate::ExplorerPolicy::TreeSearch { puct, .. } = policy.explorer() else {
            return Err(integrity(
                "branch-puct-projection-requires-tree-search-policy",
            ));
        };
        let evidence = self.project_branch_edge_visit_evidence(loaded, branch_point)?;
        let coverage = self.project_branch_coverage_guidance(loaded, &evidence)?;
        let finding_weights = [
            crate::FindingKind::PropertyViolation,
            crate::FindingKind::Divergence,
            crate::FindingKind::Timeout,
        ]
        .into_iter()
        .filter_map(|kind| {
            policy
                .guidance()
                .get(kind.guidance_signal())
                .map(|weight| (kind, weight.weight_micros()))
        })
        .collect::<BTreeMap<_, _>>();
        let finding_events =
            self.project_branch_finding_events(loaded, &evidence, &finding_weights)?;
        let mut objective_rewards = self.project_branch_objective_rewards(
            loaded,
            &policy,
            std::iter::once((branch_point, &evidence)),
        )?;
        crate::BranchPuctProjection::new_with_evidence(
            loaded.snapshot.active_policy(),
            *puct,
            evidence.statistics,
            crate::exploration::BranchPuctProjectedEvidence {
                prior_weights: evidence.prior_weights,
                novelty_events: coverage.novelty_events,
                rarity_weights: coverage.rarity_weights,
                finding_weights,
                finding_events,
                objective_reward_micros: objective_rewards
                    .remove(&branch_point)
                    .unwrap_or_default(),
            },
        )
        .map_err(Into::into)
    }

    pub(in crate::repository) fn project_branch_puct_batch_loaded(
        &self,
        loaded: &LoadedSnapshot,
        branch_points: impl IntoIterator<Item = crate::BranchPointId>,
    ) -> Result<BTreeMap<crate::BranchPointId, crate::BranchPuctProjection>, CampaignRepositoryError>
    {
        let policy = self.read_policy(loaded.snapshot.active_policy().content_id())?;
        let crate::ExplorerPolicy::TreeSearch { puct, .. } = policy.explorer() else {
            return Err(integrity(
                "branch-puct-projection-requires-tree-search-policy",
            ));
        };
        let branch_points = branch_points.into_iter().collect::<BTreeSet<_>>();
        let evidence = self.project_branch_edge_visit_evidence_batch(loaded, &branch_points)?;
        let mut coverage = self.project_branch_coverage_guidance_batch(loaded, &evidence)?;
        let finding_weights = [
            crate::FindingKind::PropertyViolation,
            crate::FindingKind::Divergence,
            crate::FindingKind::Timeout,
        ]
        .into_iter()
        .filter_map(|kind| {
            policy
                .guidance()
                .get(kind.guidance_signal())
                .map(|weight| (kind, weight.weight_micros()))
        })
        .collect::<BTreeMap<_, _>>();
        let mut finding_events =
            self.project_branch_finding_events_batch(loaded, &evidence, &finding_weights)?;
        let mut objective_rewards = self.project_branch_objective_rewards(
            loaded,
            &policy,
            evidence
                .iter()
                .map(|(branch_point, evidence)| (*branch_point, evidence)),
        )?;
        evidence
            .into_iter()
            .map(|(branch_point, evidence)| {
                let coverage = coverage.remove(&branch_point).unwrap_or_default();
                crate::BranchPuctProjection::new_with_evidence(
                    loaded.snapshot.active_policy(),
                    *puct,
                    evidence.statistics,
                    crate::exploration::BranchPuctProjectedEvidence {
                        prior_weights: evidence.prior_weights,
                        novelty_events: coverage.novelty_events,
                        rarity_weights: coverage.rarity_weights,
                        finding_weights: finding_weights.clone(),
                        finding_events: finding_events.remove(&branch_point).unwrap_or_default(),
                        objective_reward_micros: objective_rewards
                            .remove(&branch_point)
                            .unwrap_or_default(),
                    },
                )
                .map(|projection| (branch_point, projection))
                .map_err(Into::into)
            })
            .collect()
    }

    pub(in crate::repository) fn planner_candidate_guidance(
        &self,
        loaded: &LoadedSnapshot,
        projection: &crate::BranchPuctProjection,
        offer: &Proposal,
        schema_version: u32,
        cache: &mut PlannerCandidateProjectionCache,
    ) -> Result<crate::PlannerCandidateGuidance, CampaignRepositoryError> {
        if projection.branch_point() != offer.branch_point()
            || projection.policy() != loaded.snapshot.active_policy()
        {
            return Err(integrity(
                "planner-candidate-guidance-projection-basis-mismatch",
            ));
        }
        let semantic_id = self
            .read_planner_guidance_domain(
                offer.domain(),
                &mut cache.domains,
                &mut cache.domain_bytes,
            )?
            .semantic_id();
        let edge =
            crate::Selection::campaign_edge_id(offer.branch_point(), semantic_id, offer.value());
        let request = match cache.requests.get(&offer.request()) {
            Some(request) => Arc::clone(request),
            None => {
                let request = Arc::new(self.read_branch_request(offer.request().content_id())?);
                cache.requests.insert(offer.request(), Arc::clone(&request));
                request
            }
        };
        let raw_prior_weight = request
            .source()
            .prior_weight(offer.value())
            .ok_or_else(|| integrity("planner-offer-is-not-in-prior-source"))?;
        let evidence = if projection.edge_statistics().contains_key(&edge) {
            projection.candidate_evidence_with_prior(edge, raw_prior_weight)?
        } else {
            let cache_key = (projection.branch_point(), raw_prior_weight);
            let basis = match cache.prospective_priors.get(&cache_key).copied() {
                Some(basis) => basis,
                None => {
                    cache.prior_normalization_visits = charge_branch_prior_normalization_visits(
                        cache.prior_normalization_visits,
                        projection.edge_prior_weights().len(),
                    )?;
                    let basis = projection.prospective_prior_basis(raw_prior_weight)?;
                    cache.prospective_priors.insert(cache_key, basis);
                    basis
                }
            };
            projection.candidate_evidence_with_prior_basis(edge, basis)?
        };
        crate::PlannerCandidateGuidance::new_for_schema(
            schema_version,
            loaded.snapshot.planning_view().id()?,
            loaded.snapshot.active_policy(),
            crate::PlanningScanPosition::new(offer.branch_point(), offer.request()),
            offer.domain(),
            semantic_id,
            offer.value().clone(),
            offer.ordinal(),
            edge,
            evidence.statistics,
            evidence.novelty_events,
            evidence.objective_reward_micros,
            evidence.finding_events,
        )
        .map_err(Into::into)
    }

    fn project_branch_edge_visit_evidence(
        &self,
        loaded: &LoadedSnapshot,
        branch_point: crate::BranchPointId,
    ) -> Result<BranchEdgeVisitEvidence, CampaignRepositoryError> {
        self.project_branch_edge_visit_evidence_bounded(
            loaded,
            branch_point,
            &mut BranchEdgeProjectionWork::default(),
        )
    }

    fn project_branch_edge_visit_evidence_batch(
        &self,
        loaded: &LoadedSnapshot,
        branch_points: &BTreeSet<crate::BranchPointId>,
    ) -> Result<BTreeMap<crate::BranchPointId, BranchEdgeVisitEvidence>, CampaignRepositoryError>
    {
        let mut work = BranchEdgeProjectionWork::default();
        branch_points
            .iter()
            .map(|branch_point| {
                self.project_branch_edge_visit_evidence_bounded(loaded, *branch_point, &mut work)
                    .map(|evidence| (*branch_point, evidence))
            })
            .collect()
    }

    fn project_branch_edge_visit_evidence_bounded(
        &self,
        loaded: &LoadedSnapshot,
        branch_point: crate::BranchPointId,
        work: &mut BranchEdgeProjectionWork,
    ) -> Result<BranchEdgeVisitEvidence, CampaignRepositoryError> {
        let Some(index) = self.merkle.get(
            loaded.snapshot.roots().observations,
            branch_credit_index_key(branch_point),
        )?
        else {
            return Ok(BranchEdgeVisitEvidence {
                statistics: crate::BranchEdgeVisitStatistics::new(
                    branch_point,
                    0,
                    BTreeMap::new(),
                )?,
                prior_weights: BTreeMap::new(),
                observations: Vec::new(),
            });
        };
        let parent_visits = self.merkle.inspect_shallow(index)?.entry_count();
        work.total_credits = charge_branch_edge_visit_credits(work.total_credits, parent_visits)?;

        let mut after = None;
        let mut edge_visits = BTreeMap::<crate::BranchEdgeId, u64>::new();
        let mut edge_prior_basis = BTreeMap::<crate::BranchEdgeId, AttemptProposalPrior>::new();
        let mut observations = Vec::new();
        observations
            .try_reserve_exact(
                usize::try_from(parent_visits)
                    .map_err(|_| integrity("branch-edge-visit-projection-count"))?,
            )
            .map_err(|_| integrity("branch-edge-visit-projection-count"))?;
        let mut visited = 0_u64;
        loop {
            let page = self.merkle.scan(index, after, PROJECTION_SCAN_PAGE_ITEMS)?;
            for (key, content) in page.entries() {
                let credit = self.read_expansion_credit(*content)?;
                work.evidence_bytes = charge_branch_edge_visit_evidence(
                    work.evidence_bytes,
                    credit.canonical_bytes().len(),
                )?;
                if credit.id().as_hash() != *key || credit.branch_point() != branch_point {
                    return Err(integrity("branch-edge-visit-credit-index-mismatch"));
                }

                let observation = self.decode_observation(credit.observation().content_id())?;
                work.evidence_bytes = charge_branch_edge_visit_evidence(
                    work.evidence_bytes,
                    observation.canonical_bytes().len(),
                )?;
                let attempt = self.read_attempt(observation.attempt().content_id())?;
                work.evidence_bytes = charge_branch_edge_visit_evidence(
                    work.evidence_bytes,
                    attempt.canonical_bytes().len(),
                )?;
                let path = self.read_branch_path(attempt.path().content_id())?;
                work.evidence_bytes = charge_branch_edge_visit_evidence(
                    work.evidence_bytes,
                    path.canonical_bytes().len(),
                )?;
                if observation.path() != attempt.path() {
                    return Err(integrity("branch-edge-visit-observation-path-mismatch"));
                }
                let mut matching = path
                    .segments()
                    .ok_or_else(|| integrity("branch-edge-visits-require-scoped-paths"))?
                    .iter()
                    .filter(|segment| segment.branch_point() == branch_point);
                let edge = matching
                    .next()
                    .ok_or_else(|| integrity("branch-edge-visit-path-missing-branch-point"))?
                    .edge();
                if matching.next().is_some() {
                    return Err(integrity("branch-edge-visit-path-repeats-branch-point"));
                }
                let prior = self.attempt_proposal_prior(
                    loaded.snapshot.roots().accounting,
                    observation.attempt(),
                    &mut work.evidence_bytes,
                    &mut work.prior_cache,
                    &mut work.prior_request_cache,
                    &mut work.charged_prior_records,
                )?;
                match edge_prior_basis.entry(edge) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(prior);
                    }
                    std::collections::btree_map::Entry::Occupied(mut entry) => {
                        let current = *entry.get();
                        if prior.admission_ordinal < current.admission_ordinal {
                            entry.insert(prior);
                        } else if prior.admission_ordinal == current.admission_ordinal
                            && prior.raw_weight != current.raw_weight
                        {
                            return Err(integrity("branch-edge-prior-basis-conflict"));
                        }
                    }
                }
                let visits = edge_visits.entry(edge).or_default();
                *visits = visits
                    .checked_add(1)
                    .ok_or_else(|| integrity("branch-edge-visit-count-overflow"))?;
                observations.push(BranchCreditedObservation {
                    observation: credit.observation(),
                    edge,
                    coverage: observation.coverage(),
                });
                visited = visited
                    .checked_add(1)
                    .ok_or_else(|| integrity("branch-edge-visit-count-overflow"))?;
            }
            let Some(next) = page.next_after() else {
                break;
            };
            after = Some(next);
        }
        if visited != parent_visits {
            return Err(integrity("branch-edge-visit-credit-scan-mismatch"));
        }
        let prior_weights = edge_prior_basis
            .into_iter()
            .map(|(edge, prior)| (edge, prior.raw_weight))
            .collect::<BTreeMap<_, _>>();
        if prior_weights.keys().ne(edge_visits.keys()) {
            return Err(integrity("branch-edge-prior-partition-mismatch"));
        }
        Ok(BranchEdgeVisitEvidence {
            statistics: crate::BranchEdgeVisitStatistics::new(
                branch_point,
                parent_visits,
                edge_visits,
            )?,
            prior_weights,
            observations,
        })
    }

    fn attempt_proposal_prior(
        &self,
        accounting: ContentId,
        attempt: AttemptId,
        evidence_bytes: &mut usize,
        cache: &mut BTreeMap<AttemptId, AttemptProposalPrior>,
        request_cache: &mut BTreeMap<BranchRequestId, Arc<BranchRequest>>,
        charged_records: &mut BTreeSet<ContentId>,
    ) -> Result<AttemptProposalPrior, CampaignRepositoryError> {
        if let Some(prior) = cache.get(&attempt).copied() {
            return Ok(prior);
        }

        let admission_content = self
            .merkle
            .get(
                accounting,
                map_key_content("accounting.attempt-execution-basis", attempt.content_id()),
            )?
            .ok_or_else(|| integrity("branch-edge-prior-attempt-is-not-admitted"))?;
        let admission = self.decode_attempt_admission(admission_content)?;
        charge_unique_branch_prior_record(
            charged_records,
            admission_content,
            || admission.canonical_bytes().len(),
            evidence_bytes,
        )?;
        if admission.attempt() != attempt {
            return Err(integrity("branch-edge-prior-attempt-basis-mismatch"));
        }
        let AttemptAdmissionRole::ExecutionBasis {
            proposal: Some(proposal_id),
            cause,
            admission_ordinal,
        } = admission.role()
        else {
            return Err(integrity("branch-edge-prior-requires-proposal-basis"));
        };

        let proposal = self.decode_proposal(proposal_id.content_id())?;
        charge_unique_branch_prior_record(
            charged_records,
            proposal_id.content_id(),
            || proposal.canonical_bytes().len(),
            evidence_bytes,
        )?;
        let request = match request_cache.get(&proposal.request()) {
            Some(request) => Arc::clone(request),
            None => {
                let request = Arc::new(self.read_branch_request(proposal.request().content_id())?);
                request_cache.insert(proposal.request(), Arc::clone(&request));
                request
            }
        };
        charge_unique_branch_prior_record(
            charged_records,
            proposal.request().content_id(),
            || request.canonical_bytes().len(),
            evidence_bytes,
        )?;
        if proposal.branch_point() != request.branch_point()
            || proposal.domain() != request.domain()
            || request.cause() != cause
        {
            return Err(integrity("branch-edge-prior-proposal-basis-mismatch"));
        }
        let raw_weight = request
            .source()
            .prior_weight(proposal.value())
            .ok_or_else(|| integrity("branch-edge-prior-proposal-is-not-in-source"))?;
        let prior = AttemptProposalPrior {
            admission_ordinal,
            raw_weight,
        };
        cache.insert(attempt, prior);
        Ok(prior)
    }

    fn project_branch_coverage_guidance(
        &self,
        loaded: &LoadedSnapshot,
        evidence: &BranchEdgeVisitEvidence,
    ) -> Result<BranchCoverageGuidance, CampaignRepositoryError> {
        if evidence.observations.is_empty() {
            return Ok(BranchCoverageGuidance::default());
        }

        let mut work_bytes = 0_usize;
        let mut identity_visits = 0_u64;
        let mut targets = BTreeSet::new();
        let mut coverage_targets =
            BTreeMap::<crate::CoverageProjectionId, Vec<crate::CampaignHash>>::new();
        for credited in &evidence.observations {
            if coverage_targets.contains_key(&credited.coverage) {
                continue;
            }
            let coverage = self.read_coverage_projection(credited.coverage.content_id())?;
            work_bytes = charge_branch_novelty_work(work_bytes, coverage.canonical_bytes().len())?;
            identity_visits = charge_branch_novelty_identity_visits(
                identity_visits,
                coverage.identities().len(),
            )?;
            targets.extend(coverage.identities().iter().copied());
            if targets.len() > crate::MAX_BRANCH_NOVELTY_IDENTITIES {
                return Err(integrity("branch-novelty-identity-count"));
            }
            coverage_targets.insert(
                credited.coverage,
                coverage.identities().iter().copied().collect(),
            );
        }
        if targets.is_empty() {
            return Ok(BranchCoverageGuidance::default());
        }

        let observation_root = loaded.snapshot.roots().observations;
        let root_entries = self.merkle.inspect_shallow(observation_root)?.entry_count();
        if root_entries > crate::MAX_BRANCH_NOVELTY_ROOT_ENTRIES {
            return Err(integrity("branch-novelty-observation-root-entry-count"));
        }
        let mut frequencies = targets
            .iter()
            .copied()
            .map(|identity| (identity, 0_u64))
            .collect::<BTreeMap<_, _>>();
        let mut canonical_observations = 0_u64;
        let mut scanned_entries = 0_u64;
        let mut after = None;
        loop {
            let page = self
                .merkle
                .scan(observation_root, after, PROJECTION_SCAN_PAGE_ITEMS)?;
            for (key, content) in page.entries() {
                scanned_entries = scanned_entries
                    .checked_add(1)
                    .ok_or_else(|| integrity("branch-novelty-observation-root-entry-count"))?;
                if *key != map_key_content("observations.observation", *content) {
                    continue;
                }
                canonical_observations = canonical_observations
                    .checked_add(1)
                    .ok_or_else(|| integrity("branch-novelty-observation-count"))?;
                if canonical_observations > crate::MAX_BRANCH_NOVELTY_OBSERVATIONS {
                    return Err(integrity("branch-novelty-observation-count"));
                }
                let observation = self.decode_observation(*content)?;
                work_bytes =
                    charge_branch_novelty_work(work_bytes, observation.canonical_bytes().len())?;
                let coverage_id = observation.coverage();
                if let std::collections::btree_map::Entry::Vacant(entry) =
                    coverage_targets.entry(coverage_id)
                {
                    let coverage = self.read_coverage_projection(coverage_id.content_id())?;
                    work_bytes =
                        charge_branch_novelty_work(work_bytes, coverage.canonical_bytes().len())?;
                    identity_visits = charge_branch_novelty_identity_visits(
                        identity_visits,
                        coverage.identities().len(),
                    )?;
                    entry.insert(
                        coverage
                            .identities()
                            .intersection(&targets)
                            .copied()
                            .collect(),
                    );
                }
                for identity in &coverage_targets[&coverage_id] {
                    let frequency = frequencies
                        .get_mut(identity)
                        .ok_or_else(|| integrity("branch-novelty-target-cache-mismatch"))?;
                    *frequency = frequency
                        .checked_add(1)
                        .ok_or_else(|| integrity("branch-novelty-frequency-overflow"))?;
                }
            }
            let Some(next) = page.next_after() else {
                break;
            };
            after = Some(next);
        }
        if scanned_entries != root_entries || frequencies.values().any(|frequency| *frequency == 0)
        {
            return Err(integrity("branch-novelty-observation-scan-mismatch"));
        }

        let mut edge_events = BTreeMap::<crate::BranchEdgeId, u64>::new();
        let mut edge_rarity = BTreeMap::<crate::BranchEdgeId, u64>::new();
        for credited in &evidence.observations {
            let (events, rarity) = coverage_guidance_for_identities(
                &coverage_targets[&credited.coverage],
                &frequencies,
            )?;
            if events != 0 {
                let total = edge_events.entry(credited.edge).or_default();
                *total = total
                    .checked_add(events)
                    .ok_or_else(|| integrity("branch-novelty-event-count-overflow"))?;
            }
            if rarity != 0 {
                let total = edge_rarity.entry(credited.edge).or_default();
                *total = total
                    .checked_add(rarity)
                    .ok_or_else(|| integrity("branch-rarity-weight-overflow"))?;
            }
        }
        Ok(BranchCoverageGuidance {
            novelty_events: edge_events,
            rarity_weights: edge_rarity,
        })
    }

    fn project_branch_coverage_guidance_batch(
        &self,
        loaded: &LoadedSnapshot,
        evidence: &BTreeMap<crate::BranchPointId, BranchEdgeVisitEvidence>,
    ) -> Result<BTreeMap<crate::BranchPointId, BranchCoverageGuidance>, CampaignRepositoryError>
    {
        if evidence
            .values()
            .all(|branch| branch.observations.is_empty())
        {
            return Ok(BTreeMap::new());
        }

        let mut work_bytes = 0_usize;
        let mut identity_visits = 0_u64;
        let mut targets = BTreeSet::new();
        let mut coverage_targets =
            BTreeMap::<crate::CoverageProjectionId, Vec<crate::CampaignHash>>::new();
        for branch in evidence.values() {
            for credited in &branch.observations {
                if coverage_targets.contains_key(&credited.coverage) {
                    continue;
                }
                let coverage = self.read_coverage_projection(credited.coverage.content_id())?;
                work_bytes =
                    charge_branch_novelty_work(work_bytes, coverage.canonical_bytes().len())?;
                identity_visits = charge_branch_novelty_identity_visits(
                    identity_visits,
                    coverage.identities().len(),
                )?;
                targets.extend(coverage.identities().iter().copied());
                if targets.len() > crate::MAX_BRANCH_NOVELTY_IDENTITIES {
                    return Err(integrity("branch-novelty-identity-count"));
                }
                coverage_targets.insert(
                    credited.coverage,
                    coverage.identities().iter().copied().collect(),
                );
            }
        }
        if targets.is_empty() {
            return Ok(BTreeMap::new());
        }

        let observation_root = loaded.snapshot.roots().observations;
        let root_entries = self.merkle.inspect_shallow(observation_root)?.entry_count();
        if root_entries > crate::MAX_BRANCH_NOVELTY_ROOT_ENTRIES {
            return Err(integrity("branch-novelty-observation-root-entry-count"));
        }
        let mut frequencies = targets
            .iter()
            .copied()
            .map(|identity| (identity, 0_u64))
            .collect::<BTreeMap<_, _>>();
        let mut canonical_observations = 0_u64;
        let mut scanned_entries = 0_u64;
        let mut after = None;
        loop {
            let page = self
                .merkle
                .scan(observation_root, after, PROJECTION_SCAN_PAGE_ITEMS)?;
            for (key, content) in page.entries() {
                scanned_entries = scanned_entries
                    .checked_add(1)
                    .ok_or_else(|| integrity("branch-novelty-observation-root-entry-count"))?;
                if *key != map_key_content("observations.observation", *content) {
                    continue;
                }
                canonical_observations = canonical_observations
                    .checked_add(1)
                    .ok_or_else(|| integrity("branch-novelty-observation-count"))?;
                if canonical_observations > crate::MAX_BRANCH_NOVELTY_OBSERVATIONS {
                    return Err(integrity("branch-novelty-observation-count"));
                }
                let observation = self.decode_observation(*content)?;
                work_bytes =
                    charge_branch_novelty_work(work_bytes, observation.canonical_bytes().len())?;
                let coverage_id = observation.coverage();
                if let std::collections::btree_map::Entry::Vacant(entry) =
                    coverage_targets.entry(coverage_id)
                {
                    let coverage = self.read_coverage_projection(coverage_id.content_id())?;
                    work_bytes =
                        charge_branch_novelty_work(work_bytes, coverage.canonical_bytes().len())?;
                    identity_visits = charge_branch_novelty_identity_visits(
                        identity_visits,
                        coverage.identities().len(),
                    )?;
                    entry.insert(
                        coverage
                            .identities()
                            .intersection(&targets)
                            .copied()
                            .collect(),
                    );
                }
                for identity in &coverage_targets[&coverage_id] {
                    let frequency = frequencies
                        .get_mut(identity)
                        .ok_or_else(|| integrity("branch-novelty-target-cache-mismatch"))?;
                    *frequency = frequency
                        .checked_add(1)
                        .ok_or_else(|| integrity("branch-novelty-frequency-overflow"))?;
                }
            }
            let Some(next) = page.next_after() else {
                break;
            };
            after = Some(next);
        }
        if scanned_entries != root_entries || frequencies.values().any(|frequency| *frequency == 0)
        {
            return Err(integrity("branch-novelty-observation-scan-mismatch"));
        }

        let mut branch_events =
            BTreeMap::<crate::BranchPointId, BTreeMap<crate::BranchEdgeId, u64>>::new();
        let mut branch_rarity =
            BTreeMap::<crate::BranchPointId, BTreeMap<crate::BranchEdgeId, u64>>::new();
        for (branch_point, branch) in evidence {
            for credited in &branch.observations {
                let (events, rarity) = coverage_guidance_for_identities(
                    &coverage_targets[&credited.coverage],
                    &frequencies,
                )?;
                if events != 0 {
                    let total = branch_events
                        .entry(*branch_point)
                        .or_default()
                        .entry(credited.edge)
                        .or_default();
                    *total = total
                        .checked_add(events)
                        .ok_or_else(|| integrity("branch-novelty-event-count-overflow"))?;
                }
                if rarity != 0 {
                    let total = branch_rarity
                        .entry(*branch_point)
                        .or_default()
                        .entry(credited.edge)
                        .or_default();
                    *total = total
                        .checked_add(rarity)
                        .ok_or_else(|| integrity("branch-rarity-weight-overflow"))?;
                }
            }
        }
        let branch_points = branch_events
            .keys()
            .chain(branch_rarity.keys())
            .copied()
            .collect::<BTreeSet<_>>();
        Ok(branch_points
            .into_iter()
            .map(|branch_point| {
                (
                    branch_point,
                    BranchCoverageGuidance {
                        novelty_events: branch_events.remove(&branch_point).unwrap_or_default(),
                        rarity_weights: branch_rarity.remove(&branch_point).unwrap_or_default(),
                    },
                )
            })
            .collect())
    }

    fn project_branch_finding_events(
        &self,
        loaded: &LoadedSnapshot,
        evidence: &BranchEdgeVisitEvidence,
        finding_weights: &BTreeMap<crate::FindingKind, u64>,
    ) -> Result<
        BTreeMap<crate::BranchEdgeId, BTreeMap<crate::FindingKind, u64>>,
        CampaignRepositoryError,
    > {
        if evidence.observations.is_empty() || finding_weights.is_empty() {
            return Ok(BTreeMap::new());
        }

        let mut targets = BTreeMap::new();
        for credited in &evidence.observations {
            if targets
                .insert(credited.observation, credited.edge)
                .is_some()
            {
                return Err(integrity("branch-finding-credited-observation-duplicate"));
            }
        }

        let finding_root = loaded.snapshot.roots().findings;
        let root_entries = self.merkle.inspect_shallow(finding_root)?.entry_count();
        if root_entries > crate::MAX_BRANCH_FINDING_ROOT_ENTRIES {
            return Err(integrity("branch-finding-root-entry-count"));
        }
        let mut work_bytes = 0_usize;
        let mut occurrence_visits = 0_u64;
        let mut scanned_findings = 0_u64;
        let mut edge_events =
            BTreeMap::<crate::BranchEdgeId, BTreeMap<crate::FindingKind, u64>>::new();
        let mut after = None;
        loop {
            let page = self
                .merkle
                .scan(finding_root, after, PROJECTION_SCAN_PAGE_ITEMS)?;
            for (key, content) in page.entries() {
                scanned_findings = scanned_findings
                    .checked_add(1)
                    .ok_or_else(|| integrity("branch-finding-root-entry-count"))?;
                let finding = self.decode_finding(*content)?;
                work_bytes =
                    charge_branch_finding_work(work_bytes, finding.canonical_bytes().len())?;
                if *key != finding_signature_key(finding.signature().cluster_key()) {
                    return Err(integrity("branch-finding-root-index-mismatch"));
                }
                let kind = finding.signature().kind();
                if !finding_weights.contains_key(&kind) {
                    continue;
                }

                let occurrence_count = u64::from(finding.occurrence_count());
                occurrence_visits =
                    charge_branch_finding_occurrence_visits(occurrence_visits, occurrence_count)?;
                let mut scanned_occurrences = 0_u64;
                let mut occurrence_after = None;
                loop {
                    let occurrences = self.merkle.scan(
                        finding.occurrences(),
                        occurrence_after,
                        PROJECTION_SCAN_PAGE_ITEMS,
                    )?;
                    for (occurrence_key, occurrence_content) in occurrences.entries() {
                        scanned_occurrences = scanned_occurrences
                            .checked_add(1)
                            .ok_or_else(|| integrity("branch-finding-occurrence-visit-limit"))?;
                        if scanned_occurrences > occurrence_count {
                            return Err(integrity("branch-finding-occurrence-scan-mismatch"));
                        }
                        let observation = ObservationId::from_content_id(*occurrence_content)?;
                        if *occurrence_key != finding_occurrence_key(observation) {
                            return Err(integrity("branch-finding-occurrence-index-mismatch"));
                        }
                        let Some(edge) = targets.get(&observation) else {
                            continue;
                        };
                        let count = edge_events
                            .entry(*edge)
                            .or_default()
                            .entry(kind)
                            .or_default();
                        *count = count
                            .checked_add(1)
                            .ok_or_else(|| integrity("branch-finding-event-count-overflow"))?;
                    }
                    let Some(next) = occurrences.next_after() else {
                        break;
                    };
                    occurrence_after = Some(next);
                }
                if scanned_occurrences != occurrence_count {
                    return Err(integrity("branch-finding-occurrence-scan-mismatch"));
                }
            }
            let Some(next) = page.next_after() else {
                break;
            };
            after = Some(next);
        }
        if scanned_findings != root_entries {
            return Err(integrity("branch-finding-root-scan-mismatch"));
        }
        Ok(edge_events)
    }

    fn project_branch_objective_rewards<'a>(
        &self,
        loaded: &LoadedSnapshot,
        policy_value: &crate::CampaignPolicy,
        evidence: impl IntoIterator<Item = (crate::BranchPointId, &'a BranchEdgeVisitEvidence)>,
    ) -> Result<BranchObjectiveRewards, CampaignRepositoryError> {
        let mut targets =
            BTreeMap::<ObservationId, Vec<(crate::BranchPointId, crate::BranchEdgeId)>>::new();
        for (branch_point, branch) in evidence {
            for credited in &branch.observations {
                targets
                    .entry(credited.observation)
                    .or_default()
                    .push((branch_point, credited.edge));
            }
        }
        if targets.is_empty() {
            return Ok(BTreeMap::new());
        }

        let policy = loaded.snapshot.active_policy();
        if policy_value.id()? != policy {
            return Err(integrity("branch-objective-policy-basis-mismatch"));
        }
        let objective_contract = policy_value.objective_contract_hash();
        let observation_root = loaded.snapshot.roots().observations;
        let mut decoded = BTreeMap::<ContentId, (ObservationId, i64)>::new();
        let mut properties =
            BTreeMap::<crate::PropertyVerdictSetId, Arc<crate::PropertyVerdictSet>>::new();
        let mut charged = BTreeSet::<ContentId>::new();
        let mut evaluation_count = 0_usize;
        let mut work_bytes = 0_usize;
        let mut reward_sums =
            BTreeMap::<crate::BranchPointId, BTreeMap<crate::BranchEdgeId, i128>>::new();
        for (observation, edges) in targets {
            let Some(content) = self.merkle.get(
                observation_root,
                objective_evaluation_key(policy, observation),
            )?
            else {
                continue;
            };
            let reward = if let Some((retained_observation, reward)) = decoded.get(&content) {
                if *retained_observation != observation {
                    return Err(integrity(
                        "branch-objective-evaluation-index-reuses-content",
                    ));
                }
                *reward
            } else {
                evaluation_count = charge_branch_objective_evaluations(evaluation_count)?;
                let evaluation_envelope = self
                    .require_record_kind(content, crate::CampaignRecordKind::ObjectiveEvaluation)?;
                work_bytes = charge_branch_objective_record(
                    work_bytes,
                    content,
                    evaluation_envelope.body().len(),
                    &mut charged,
                )?;
                let evaluation =
                    crate::ObjectiveEvaluation::from_canonical_bytes(evaluation_envelope.body())?;
                if evaluation.id()?.content_id() != content {
                    return Err(integrity("objective-evaluation-envelope-shape"));
                }
                if evaluation.policy() != policy || evaluation.observation() != observation {
                    return Err(integrity("branch-objective-evaluation-index-mismatch"));
                }
                let observation_envelope = self.require_record_kind(
                    observation.content_id(),
                    crate::CampaignRecordKind::Observation,
                )?;
                work_bytes = charge_branch_objective_record(
                    work_bytes,
                    observation.content_id(),
                    observation_envelope.body().len(),
                    &mut charged,
                )?;
                let observation_value =
                    crate::Observation::from_canonical_bytes(observation_envelope.body())?;
                if observation_value.id()? != observation {
                    return Err(integrity("observation-envelope-shape"));
                }
                let properties_id = observation_value.properties();
                let properties_value = if let Some(value) = properties.get(&properties_id) {
                    Arc::clone(value)
                } else {
                    let envelope = self.require_record_kind(
                        properties_id.content_id(),
                        crate::CampaignRecordKind::PropertyVerdictSet,
                    )?;
                    work_bytes = charge_branch_objective_record(
                        work_bytes,
                        properties_id.content_id(),
                        envelope.body().len(),
                        &mut charged,
                    )?;
                    let value = Arc::new(crate::PropertyVerdictSet::from_canonical_bytes(
                        envelope.body(),
                    )?);
                    if value.id()? != properties_id {
                        return Err(integrity("property-verdict-set-envelope-shape"));
                    }
                    properties.insert(properties_id, Arc::clone(&value));
                    value
                };
                evaluation.validate_compact_basis(
                    policy,
                    objective_contract,
                    &observation_value,
                    properties_value.as_ref(),
                )?;
                let reward = evaluation
                    .scalar_reward()
                    .map_or(0, crate::FixedReward::to_micros_saturating);
                decoded.insert(content, (observation, reward));
                reward
            };
            if reward == 0 {
                continue;
            }
            for (branch_point, edge) in edges {
                let total = reward_sums
                    .entry(branch_point)
                    .or_default()
                    .entry(edge)
                    .or_default();
                *total += i128::from(reward);
            }
        }
        Ok(reward_sums
            .into_iter()
            .filter_map(|(branch_point, edge_sums)| {
                let rewards = edge_sums
                    .into_iter()
                    .filter_map(|(edge, total)| {
                        let reward = total.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64;
                        (reward != 0).then_some((edge, reward))
                    })
                    .collect::<BTreeMap<_, _>>();
                (!rewards.is_empty()).then_some((branch_point, rewards))
            })
            .collect())
    }

    fn project_branch_finding_events_batch(
        &self,
        loaded: &LoadedSnapshot,
        evidence: &BTreeMap<crate::BranchPointId, BranchEdgeVisitEvidence>,
        finding_weights: &BTreeMap<crate::FindingKind, u64>,
    ) -> Result<BranchPointFindingEvents, CampaignRepositoryError> {
        if finding_weights.is_empty()
            || evidence
                .values()
                .all(|branch| branch.observations.is_empty())
        {
            return Ok(BTreeMap::new());
        }

        let mut targets =
            BTreeMap::<ObservationId, Vec<(crate::BranchPointId, crate::BranchEdgeId)>>::new();
        for (branch_point, branch) in evidence {
            for credited in &branch.observations {
                targets
                    .entry(credited.observation)
                    .or_default()
                    .push((*branch_point, credited.edge));
            }
        }

        let finding_root = loaded.snapshot.roots().findings;
        let root_entries = self.merkle.inspect_shallow(finding_root)?.entry_count();
        if root_entries > crate::MAX_BRANCH_FINDING_ROOT_ENTRIES {
            return Err(integrity("branch-finding-root-entry-count"));
        }
        let mut work_bytes = 0_usize;
        let mut occurrence_visits = 0_u64;
        let mut scanned_findings = 0_u64;
        let mut branch_events = BranchPointFindingEvents::new();
        let mut after = None;
        loop {
            let page = self
                .merkle
                .scan(finding_root, after, PROJECTION_SCAN_PAGE_ITEMS)?;
            for (key, content) in page.entries() {
                scanned_findings = scanned_findings
                    .checked_add(1)
                    .ok_or_else(|| integrity("branch-finding-root-entry-count"))?;
                let finding = self.decode_finding(*content)?;
                work_bytes =
                    charge_branch_finding_work(work_bytes, finding.canonical_bytes().len())?;
                if *key != finding_signature_key(finding.signature().cluster_key()) {
                    return Err(integrity("branch-finding-root-index-mismatch"));
                }
                let kind = finding.signature().kind();
                if !finding_weights.contains_key(&kind) {
                    continue;
                }

                let occurrence_count = u64::from(finding.occurrence_count());
                occurrence_visits =
                    charge_branch_finding_occurrence_visits(occurrence_visits, occurrence_count)?;
                let mut scanned_occurrences = 0_u64;
                let mut occurrence_after = None;
                loop {
                    let occurrences = self.merkle.scan(
                        finding.occurrences(),
                        occurrence_after,
                        PROJECTION_SCAN_PAGE_ITEMS,
                    )?;
                    for (occurrence_key, occurrence_content) in occurrences.entries() {
                        scanned_occurrences = scanned_occurrences
                            .checked_add(1)
                            .ok_or_else(|| integrity("branch-finding-occurrence-visit-limit"))?;
                        if scanned_occurrences > occurrence_count {
                            return Err(integrity("branch-finding-occurrence-scan-mismatch"));
                        }
                        let observation = ObservationId::from_content_id(*occurrence_content)?;
                        if *occurrence_key != finding_occurrence_key(observation) {
                            return Err(integrity("branch-finding-occurrence-index-mismatch"));
                        }
                        let Some(edges) = targets.get(&observation) else {
                            continue;
                        };
                        for (branch_point, edge) in edges {
                            let count = branch_events
                                .entry(*branch_point)
                                .or_default()
                                .entry(*edge)
                                .or_default()
                                .entry(kind)
                                .or_default();
                            *count = count
                                .checked_add(1)
                                .ok_or_else(|| integrity("branch-finding-event-count-overflow"))?;
                        }
                    }
                    let Some(next) = occurrences.next_after() else {
                        break;
                    };
                    occurrence_after = Some(next);
                }
                if scanned_occurrences != occurrence_count {
                    return Err(integrity("branch-finding-occurrence-scan-mismatch"));
                }
            }
            let Some(next) = page.next_after() else {
                break;
            };
            after = Some(next);
        }
        if scanned_findings != root_entries {
            return Err(integrity("branch-finding-root-scan-mismatch"));
        }
        Ok(branch_events)
    }

    fn finite_continuation_page(
        &self,
        view: CandidateViewRoots,
        request_root: ContentId,
        page_after: Option<BranchRequestId>,
        page_size: u32,
    ) -> Result<
        (
            BTreeMap<BranchRequestId, crate::ContinuationState>,
            Option<BranchRequestId>,
        ),
        CampaignRepositoryError,
    > {
        let limit =
            usize::try_from(page_size).map_err(|_| integrity("expansion-page-size-is-invalid"))?;
        let after_key = page_after.map(|request| projection_order_key(request.content_id()));
        if let Some(request) = page_after
            && self
                .merkle
                .get(request_root, projection_order_key(request.content_id()))?
                != Some(request.content_id())
        {
            return Err(integrity("expansion-page-cursor-is-not-in-request-root"));
        }

        let page = self.merkle.scan(request_root, after_key, limit)?;
        let mut continuations = BTreeMap::new();
        for (key, value) in page.entries() {
            if *key != projection_order_key(*value) {
                return Err(integrity("expansion-request-order-index-mismatch"));
            }
            let request_id = BranchRequestId::from_content_id(*value)?;
            let request = self.read_branch_request(*value)?;
            let state = self.continuation_state(view, request_id, &request)?;
            continuations.insert(request_id, state);
        }
        let next_after = if page.next_after().is_some() {
            continuations.last_key_value().map(|entry| *entry.0)
        } else {
            None
        };
        Ok((continuations, next_after))
    }

    pub(in crate::repository) fn continuation_state(
        &self,
        view: CandidateViewRoots,
        request_id: BranchRequestId,
        request: &BranchRequest,
    ) -> Result<crate::ContinuationState, CampaignRepositoryError> {
        let completed_visits =
            self.branch_completed_visits(view.observations, request.branch_point())?;
        self.continuation_state_with_completed_visits(view, request_id, request, completed_visits)
    }

    pub(in crate::repository) fn continuation_state_with_completed_visits(
        &self,
        view: CandidateViewRoots,
        request_id: BranchRequestId,
        request: &BranchRequest,
        completed_visits: u64,
    ) -> Result<crate::ContinuationState, CampaignRepositoryError> {
        let domain = self.read_choice_domain(request.domain().content_id())?;
        let progress = self.continuation_progress(view, request_id, request, &domain)?;
        continuation_state_after_progress(
            progress.profile,
            progress.proposed,
            progress.pending,
            progress.next_candidate.is_some(),
            request.budget().maximum_proposals(),
            completed_visits,
        )
    }

    pub(in crate::repository) fn continuation_state_after_observation(
        &self,
        view: CandidateViewRoots,
        request_id: BranchRequestId,
        request: &BranchRequest,
        observation: &Observation,
        completed_visits: u64,
    ) -> Result<crate::ContinuationState, CampaignRepositoryError> {
        let domain = self.read_choice_domain(request.domain().content_id())?;
        let progress = self.continuation_progress(view, request_id, request, &domain)?;
        if progress.profile != CandidateSourceProfile::CorpusMutation {
            return continuation_state_after_progress(
                progress.profile,
                progress.proposed,
                progress.pending,
                progress.next_candidate.is_some(),
                request.budget().maximum_proposals(),
                completed_visits,
            );
        }
        if progress.proposed >= request.budget().maximum_proposals() {
            return continuation_state_after_progress(
                progress.profile,
                progress.proposed,
                progress.pending,
                false,
                request.budget().maximum_proposals(),
                completed_visits,
            );
        }

        let attempt = self.read_attempt(observation.attempt().content_id())?;
        let additional_selection = match attempt.start() {
            AttemptStart::Branch { selection, .. } => Some(selection),
            AttemptStart::Discover { .. } => None,
        };
        let proposed = self.proposed_values_before(
            view.exploration,
            request_id,
            progress
                .proposed
                .checked_add(1)
                .ok_or_else(|| integrity("planner-candidate-ordinal-overflow"))?,
        )?;
        let has_next_candidate = self
            .corpus_mutation_candidates(request, &domain, view, additional_selection)?
            .into_iter()
            .any(|candidate| !proposed.contains(&candidate));
        continuation_state_after_progress(
            progress.profile,
            progress.proposed,
            progress.pending,
            has_next_candidate,
            request.budget().maximum_proposals(),
            completed_visits,
        )
    }

    pub(super) fn continuation_progress(
        &self,
        view: CandidateViewRoots,
        request_id: BranchRequestId,
        request: &BranchRequest,
        domain: &ChoiceDomain,
    ) -> Result<ContinuationProgress, CampaignRepositoryError> {
        let profile = self
            .candidate_source_profile(request, domain)?
            .ok_or_else(|| integrity("generated-expansion-projector-is-not-implemented"))?;
        let maximum_proposals = request.budget().maximum_proposals();
        let check_count = profile
            .count()
            .unwrap_or(maximum_proposals)
            .min(maximum_proposals);
        let mut proposed = 0_u64;
        let mut pending = false;

        for ordinal in 1..=check_count {
            let Some(proposal_content) = self
                .merkle
                .get(view.exploration, proposal_ordinal_key(request_id, ordinal))?
            else {
                break;
            };
            let proposal = self.read_proposal(proposal_content)?;
            if proposal.request() != request_id
                || proposal.ordinal() != ordinal
                || self.merkle.get(
                    view.exploration,
                    map_key_content("exploration.proposal", proposal_content),
                )? != Some(proposal_content)
            {
                return Err(integrity("finite-expansion-proposal-index-mismatch"));
            }
            proposed = ordinal;

            let Some(admission_content) = self.merkle.get(
                view.accounting,
                map_key_content("accounting.proposal-admission", proposal_content),
            )?
            else {
                pending = true;
                continue;
            };
            if self.merkle.get(
                view.accounting,
                map_key_content("accounting.attempt-admission", admission_content),
            )? != Some(admission_content)
            {
                return Err(integrity("finite-expansion-admission-index-mismatch"));
            }
            let admission = self.read_attempt_admission(admission_content)?;
            let admitted_proposal = match admission.role() {
                AttemptAdmissionRole::ExecutionBasis {
                    proposal: Some(proposal),
                    ..
                }
                | AttemptAdmissionRole::AdditionalCause { proposal } => proposal,
                AttemptAdmissionRole::ExecutionBasis { proposal: None, .. } => {
                    return Err(integrity("finite-expansion-discovery-admission"));
                }
            };
            if admitted_proposal.content_id() != proposal_content {
                return Err(integrity("finite-expansion-proposal-admission-mismatch"));
            }
        }

        Ok(ContinuationProgress {
            profile,
            proposed,
            pending,
            next_candidate: if profile == CandidateSourceProfile::CorpusMutation
                && proposed < maximum_proposals
            {
                self.corpus_mutation_next_candidate(
                    request,
                    domain,
                    view,
                    proposed
                        .checked_add(1)
                        .ok_or_else(|| integrity("planner-candidate-ordinal-overflow"))?,
                )?
            } else {
                None
            },
        })
    }

    /// Returns whether the next exact ordinal requires version-11 PUCT input.
    pub(in crate::repository) fn next_candidate_scores_intervals(
        &self,
        view: CandidateViewRoots,
        request_id: BranchRequestId,
        request: &BranchRequest,
        domain: &ChoiceDomain,
    ) -> Result<bool, CampaignRepositoryError> {
        let Some(CandidateSourceProfile::ProgressiveInteger {
            initial_count,
            score_intervals: true,
            ..
        }) = self.candidate_source_profile(request, domain)?
        else {
            return Ok(false);
        };
        Ok(self
            .merkle
            .get(
                view.exploration,
                proposal_ordinal_key(request_id, initial_count),
            )?
            .is_some())
    }

    pub(in crate::repository) fn put_expansion_state(
        &self,
        state: &ExpansionState,
    ) -> Result<ContentId, CampaignRepositoryError> {
        self.put_envelope(ObjectEnvelope::for_record(
            crate::CampaignRecordKind::ExpansionState,
            crate::object::content_children(state.content_children())?,
            state.canonical_bytes(),
        )?)
    }
}
