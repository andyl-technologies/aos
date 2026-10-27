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
            CandidateViewRoots::from_roots(loaded.snapshot.roots())
                .with_request_admissions(self.parent_budget_ledger(&loaded)?.request_admissions()),
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
    /// credit/path basis is inconsistent, the branch point has more than
    /// [`MAX_BRANCH_PROJECTION_EDGES`](crate::MAX_BRANCH_PROJECTION_EDGES)
    /// completed edges, or storage access fails.
    pub fn project_branch_edge_visits(
        &self,
        snapshot: crate::CampaignSnapshotId,
        branch_point: crate::BranchPointId,
    ) -> Result<crate::BranchEdgeVisitStatistics, CampaignRepositoryError> {
        self.validate_complete_head(snapshot.content_id())?;
        let loaded = self.read_snapshot(snapshot.content_id())?;
        self.fold_branch_credits(
            &loaded,
            branch_point,
            None,
            &mut BranchCreditFoldCaches::new(),
        )
        .map(|fold| fold.statistics)
    }

    /// Rebuilds the active policy's bounded PUCT scores for one branch point.
    ///
    /// The projection authenticates the exact snapshot once, then streams the
    /// branch point's credit index in one pass: it derives the completed
    /// edge-visit partition, assigns canonical proposal priors, projects
    /// globally unique coverage identities and inverse-frequency rarity onto
    /// credited edges from the snapshot's coverage-identity frequency index,
    /// folds policy-weighted verified finding occurrences and objective
    /// rewards into reward, and reserves fairness for the least-visited edge.
    /// The active policy must select tree search.
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
        self.project_branch_puct_batch_loaded(loaded, [branch_point])?
            .remove(&branch_point)
            .ok_or_else(|| integrity("branch-puct-projection-batch-missing-branch-point"))
    }

    /// Projects PUCT scores for a batch of branch points from one snapshot.
    ///
    /// Each branch point's credit index is streamed once. The batch shares one
    /// finding-root scan and bounded caches of priors, coverage terms, and
    /// objective rewards, so shared records are not reread per branch point.
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
        let policy_id = loaded.snapshot.active_policy();
        if policy.id()? != policy_id {
            return Err(integrity("branch-objective-policy-basis-mismatch"));
        }
        let branch_points = branch_points.into_iter().collect::<BTreeSet<_>>();
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

        // The finding root is scanned only when some branch point has credits
        // that a weighted occurrence could name.
        let mut has_credits = false;
        for branch_point in &branch_points {
            has_credits |= self
                .merkle
                .get(
                    loaded.snapshot.roots().observations,
                    branch_credit_index_key(*branch_point),
                )?
                .is_some();
        }
        let finding_occurrences = if has_credits && !finding_weights.is_empty() {
            self.weighted_finding_occurrences(loaded, &finding_weights)?
        } else {
            BTreeMap::new()
        };
        let guidance = BranchGuidanceBasis {
            policy: &policy,
            policy_id,
            finding_occurrences,
        };

        let mut caches = BranchCreditFoldCaches::new();
        let mut projections = BTreeMap::new();
        for branch_point in branch_points {
            let fold =
                self.fold_branch_credits(loaded, branch_point, Some(&guidance), &mut caches)?;
            let projection = crate::BranchPuctProjection::new_with_evidence(
                policy_id,
                *puct,
                fold.statistics,
                crate::exploration::BranchPuctProjectedEvidence {
                    prior_weights: fold.prior_weights,
                    novelty_events: fold.guidance.novelty_events,
                    rarity_weights: fold.guidance.rarity_weights,
                    finding_weights: finding_weights.clone(),
                    finding_events: fold.guidance.finding_events,
                    objective_reward_micros: fold.guidance.objective_reward_micros,
                },
            )?;
            projections.insert(branch_point, projection);
        }
        Ok(projections)
    }

    pub(in crate::repository) fn planner_candidate_guidance(
        &self,
        loaded: &LoadedSnapshot,
        projection: &crate::BranchPuctProjection,
        offer: &Proposal,
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
        crate::PlannerCandidateGuidance::new(
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

    /// Streams one branch point's credit index into per-edge accumulators.
    ///
    /// Every credit is authenticated against its observation, attempt, and
    /// path, and charged to the single scoped segment that names
    /// `branch_point`. With a guidance basis, credits whose execution basis
    /// the policy excludes from learning are skipped, and each remaining
    /// credit adds its coverage novelty and rarity, weighted finding
    /// occurrences, and objective reward to its edge. Memory is one
    /// accumulator per completed edge plus the shared bounded caches, however
    /// many credits the branch point has.
    fn fold_branch_credits(
        &self,
        loaded: &LoadedSnapshot,
        branch_point: crate::BranchPointId,
        guidance: Option<&BranchGuidanceBasis<'_>>,
        caches: &mut BranchCreditFoldCaches,
    ) -> Result<BranchCreditFold, CampaignRepositoryError> {
        let roots = loaded.snapshot.roots();
        let Some(index) = self
            .merkle
            .get(roots.observations, branch_credit_index_key(branch_point))?
        else {
            return Ok(BranchCreditFold {
                statistics: crate::BranchEdgeVisitStatistics::new(
                    branch_point,
                    0,
                    BTreeMap::new(),
                )?,
                prior_weights: BTreeMap::new(),
                guidance: BranchGuidanceTerms::default(),
            });
        };
        let indexed_visits = self.merkle.inspect_shallow(index)?.entry_count();

        let mut edge_visits = BTreeMap::<crate::BranchEdgeId, u64>::new();
        let mut edge_prior_basis = BTreeMap::<crate::BranchEdgeId, AttemptProposalPrior>::new();
        let mut terms = BranchGuidanceTerms::default();
        let mut reward_sums = BTreeMap::<crate::BranchEdgeId, i128>::new();
        let mut scanned = 0_u64;
        let mut eligible_visits = 0_u64;
        let mut after = None;
        loop {
            let page = self.merkle.scan(index, after, PROJECTION_SCAN_PAGE_ITEMS)?;
            for (key, content) in page.entries() {
                let credit = self.read_expansion_credit(*content)?;
                if credit.id().as_hash() != *key || credit.branch_point() != branch_point {
                    return Err(integrity("branch-edge-visit-credit-index-mismatch"));
                }
                let observation = self.decode_observation(credit.observation().content_id())?;
                let edge = self.credited_branch_edge(&observation, branch_point)?;
                let prior =
                    self.attempt_proposal_prior(roots.accounting, observation.attempt(), caches)?;
                scanned = scanned
                    .checked_add(1)
                    .ok_or_else(|| integrity("branch-edge-visit-count-overflow"))?;
                if guidance.is_some_and(|guidance| {
                    !execution_basis_is_guidance_eligible(guidance.policy, prior.cause)
                }) {
                    continue;
                }

                merge_edge_prior_basis(&mut edge_prior_basis, edge, prior)?;
                add_edge_count(
                    &mut edge_visits,
                    edge,
                    1,
                    "branch-edge-visit-count-overflow",
                )?;
                if edge_visits.len() > crate::MAX_BRANCH_PROJECTION_EDGES {
                    return Err(integrity("branch-edge-visit-projection-count"));
                }
                eligible_visits = eligible_visits
                    .checked_add(1)
                    .ok_or_else(|| integrity("branch-edge-visit-count-overflow"))?;

                let Some(guidance) = guidance else {
                    continue;
                };
                let (events, rarity) =
                    self.coverage_guidance_terms(roots.coverage, observation.coverage(), caches)?;
                add_edge_count(
                    &mut terms.novelty_events,
                    edge,
                    events,
                    "branch-novelty-event-count-overflow",
                )?;
                add_edge_count(
                    &mut terms.rarity_weights,
                    edge,
                    rarity,
                    "branch-rarity-weight-overflow",
                )?;
                if let Some(kinds) = guidance.finding_occurrences.get(&credit.observation()) {
                    let edge_findings = terms.finding_events.entry(edge).or_default();
                    for (kind, occurrences) in kinds {
                        add_edge_count(
                            edge_findings,
                            *kind,
                            *occurrences,
                            "branch-finding-event-count-overflow",
                        )?;
                    }
                }
                let reward = self.objective_reward_micros(
                    roots.observations,
                    guidance.policy_id,
                    credit.observation(),
                    caches,
                )?;
                if reward != 0 {
                    // Exact per-edge sums are clamped once, after the fold.
                    *reward_sums.entry(edge).or_default() += i128::from(reward);
                }
            }
            let Some(next) = page.next_after() else {
                break;
            };
            after = Some(next);
        }
        if scanned != indexed_visits {
            return Err(integrity("branch-edge-visit-credit-scan-mismatch"));
        }

        let prior_weights = edge_prior_basis
            .into_iter()
            .map(|(edge, prior)| (edge, prior.raw_weight))
            .collect::<BTreeMap<_, _>>();
        if prior_weights.keys().ne(edge_visits.keys()) {
            return Err(integrity("branch-edge-prior-partition-mismatch"));
        }
        terms.objective_reward_micros = reward_sums
            .into_iter()
            .filter_map(|(edge, total)| {
                let reward = total.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64;
                (reward != 0).then_some((edge, reward))
            })
            .collect();
        Ok(BranchCreditFold {
            statistics: crate::BranchEdgeVisitStatistics::new(
                branch_point,
                eligible_visits,
                edge_visits,
            )?,
            prior_weights,
            guidance: terms,
        })
    }

    /// Returns the semantic edge one credited observation took at `branch_point`.
    fn credited_branch_edge(
        &self,
        observation: &Observation,
        branch_point: crate::BranchPointId,
    ) -> Result<crate::BranchEdgeId, CampaignRepositoryError> {
        let attempt = self.read_attempt(observation.attempt().content_id())?;
        if observation.path() != attempt.path() {
            return Err(integrity("branch-edge-visit-observation-path-mismatch"));
        }
        let path = self.read_branch_path(attempt.path().content_id())?;
        let mut matching = path
            .segments()
            .iter()
            .filter(|segment| segment.branch_point() == branch_point);
        let edge = matching
            .next()
            .ok_or_else(|| integrity("branch-edge-visit-path-missing-branch-point"))?
            .edge();
        if matching.next().is_some() {
            return Err(integrity("branch-edge-visit-path-repeats-branch-point"));
        }
        Ok(edge)
    }

    fn attempt_proposal_prior(
        &self,
        accounting: ContentId,
        attempt: AttemptId,
        caches: &mut BranchCreditFoldCaches,
    ) -> Result<AttemptProposalPrior, CampaignRepositoryError> {
        if let Some(prior) = caches.priors.get(&attempt).copied() {
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
        let request = match caches.requests.get(&proposal.request()) {
            Some(request) => Arc::clone(request),
            None => {
                let request = Arc::new(self.read_branch_request(proposal.request().content_id())?);
                caches
                    .requests
                    .insert(proposal.request(), Arc::clone(&request));
                request
            }
        };
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
            cause,
        };
        caches.priors.insert(attempt, prior);
        Ok(prior)
    }

    /// Returns one coverage projection's novelty events and rarity mass.
    ///
    /// Each identity's global frequency is a point lookup in the snapshot's
    /// coverage-identity frequency index. An identity is a novelty event when
    /// its frequency is one, and contributes [`branch_rarity_contribution`] to
    /// rarity. A credited identity without an index entry fails closed.
    fn coverage_guidance_terms(
        &self,
        coverage_root: ContentId,
        coverage: crate::CoverageProjectionId,
        caches: &mut BranchCreditFoldCaches,
    ) -> Result<(u64, u64), CampaignRepositoryError> {
        if let Some(terms) = caches.coverage_terms.get(&coverage).copied() {
            return Ok(terms);
        }

        let projection = self.read_coverage_projection(coverage.content_id())?;
        let mut events = 0_u64;
        let mut rarity = 0_u64;
        for identity in projection.identities() {
            let record = self
                .merkle
                .get(coverage_root, coverage_identity_frequency_key(*identity))?
                .ok_or_else(|| integrity("branch-novelty-frequency-index-missing"))?;
            let frequency = match caches.frequencies.get(&record).copied() {
                Some(frequency) => frequency,
                None => {
                    let frequency = self.read_coverage_identity_frequency(record)?.count();
                    caches.frequencies.insert(record, frequency);
                    frequency
                }
            };
            if frequency == 1 {
                events = events
                    .checked_add(1)
                    .ok_or_else(|| integrity("branch-novelty-event-count-overflow"))?;
            }
            rarity = rarity
                .checked_add(branch_rarity_contribution(frequency))
                .ok_or_else(|| integrity("branch-rarity-weight-overflow"))?;
        }
        caches.coverage_terms.insert(coverage, (events, rarity));
        Ok((events, rarity))
    }

    /// Returns the active policy's scalar objective reward for one observation.
    ///
    /// Absence of an evaluation is neutral. A present evaluation must name
    /// exactly this policy and observation. Its compact basis was checked when
    /// the evaluation was published and again by the snapshot closure walk
    /// that precedes every projection, so it is not re-derived here.
    fn objective_reward_micros(
        &self,
        observation_root: ContentId,
        policy: crate::CampaignPolicyId,
        observation: ObservationId,
        caches: &mut BranchCreditFoldCaches,
    ) -> Result<i64, CampaignRepositoryError> {
        if let Some(reward) = caches.rewards.get(&observation).copied() {
            return Ok(reward);
        }

        let reward = match self.merkle.get(
            observation_root,
            objective_evaluation_key(policy, observation),
        )? {
            None => 0,
            Some(content) => {
                let envelope = self
                    .require_record_kind(content, crate::CampaignRecordKind::ObjectiveEvaluation)?;
                let evaluation = crate::ObjectiveEvaluation::from_canonical_bytes(envelope.body())?;
                if evaluation.id()?.content_id() != content {
                    return Err(integrity("objective-evaluation-envelope-shape"));
                }
                if evaluation.policy() != policy || evaluation.observation() != observation {
                    return Err(integrity("branch-objective-evaluation-index-mismatch"));
                }
                evaluation
                    .scalar_reward()
                    .map_or(0, crate::FixedReward::to_micros_saturating)
            }
        };
        caches.rewards.insert(observation, reward);
        Ok(reward)
    }

    /// Collects weighted finding occurrences by observation for one batch.
    ///
    /// The finding root is a public, proof-paged map of finding clusters, so it
    /// holds no reverse index. One bounded scan per batch serves every branch
    /// point; the retained map is bounded by the occurrence-visit ceiling.
    fn weighted_finding_occurrences(
        &self,
        loaded: &LoadedSnapshot,
        finding_weights: &BTreeMap<crate::FindingKind, u64>,
    ) -> Result<BranchFindingOccurrences, CampaignRepositoryError> {
        let finding_root = loaded.snapshot.roots().findings;
        let root_entries = self.merkle.inspect_shallow(finding_root)?.entry_count();
        if root_entries > crate::MAX_BRANCH_FINDING_ROOT_ENTRIES {
            return Err(integrity("branch-finding-root-entry-count"));
        }

        let mut work_bytes = 0_usize;
        let mut occurrence_visits = 0_u64;
        let mut scanned_findings = 0_u64;
        let mut occurrences_by_observation = BranchFindingOccurrences::new();
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
                        add_edge_count(
                            occurrences_by_observation.entry(observation).or_default(),
                            kind,
                            1,
                            "branch-finding-event-count-overflow",
                        )?;
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
        Ok(occurrences_by_observation)
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
            AttemptStart::Discover { .. } | AttemptStart::AfterAttempt { .. } => None,
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
            .first_unproposed_corpus_mutation(
                request,
                &domain,
                view,
                additional_selection,
                &proposed,
            )?
            .is_some();
        continuation_state_after_progress(
            progress.profile,
            progress.proposed,
            progress.pending,
            has_next_candidate,
            request.budget().maximum_proposals(),
            completed_visits,
        )
    }

    pub(in crate::repository) fn continuation_progress(
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
        // Snapshot-bound callers supply the ledger index that each successor
        // recomputes from admitted proposals. Cold ancestry checks every
        // predecessor and exact root delta, so the head ordinal and indexed
        // admission count replace a history-wide scan without losing density.
        let (proposed, pending) =
            if let ContinuationProgressBasis::Indexed(admissions_root) = view.progress_basis {
                let head = self
                    .merkle
                    .get(view.exploration, proposal_head_key(request_id))?;
                let proposed = match head {
                    Some(content) => {
                        let proposal = self.read_proposal(content)?;
                        let ordinal = proposal.ordinal();
                        if proposal.request() != request_id
                            || ordinal == 0
                            || ordinal > check_count
                            || self
                                .merkle
                                .get(view.exploration, proposal_ordinal_key(request_id, ordinal))?
                                != Some(content)
                            || self.merkle.get(
                                view.exploration,
                                map_key_content("exploration.proposal", content),
                            )? != Some(content)
                        {
                            return Err(integrity("finite-expansion-proposal-index-mismatch"));
                        }
                        if ordinal < check_count
                            && self
                                .merkle
                                .get(
                                    view.exploration,
                                    proposal_ordinal_key(request_id, ordinal + 1),
                                )?
                                .is_some()
                        {
                            return Err(integrity("finite-expansion-proposal-head-is-stale"));
                        }
                        ordinal
                    }
                    None => {
                        if self
                            .merkle
                            .get(view.exploration, proposal_ordinal_key(request_id, 1))?
                            .is_some()
                        {
                            return Err(integrity("finite-expansion-proposal-head-is-missing"));
                        }
                        0
                    }
                };
                let admitted = match self
                    .merkle
                    .get(admissions_root, request_admissions_key(request_id))?
                {
                    Some(root) => self.merkle.inspect_shallow(root)?.entry_count(),
                    None => 0,
                };
                if admitted > proposed {
                    return Err(integrity("finite-expansion-admission-index-mismatch"));
                }
                (proposed, admitted != proposed)
            } else if matches!(
                view.progress_basis,
                ContinuationProgressBasis::UnpublishedAccounting
            ) {
                self.scan_continuation_progress(view, request_id, check_count)?
            } else {
                return Err(integrity("continuation-progress-requires-admissions-basis"));
            };

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

    fn scan_continuation_progress(
        &self,
        view: CandidateViewRoots,
        request_id: BranchRequestId,
        check_count: u64,
    ) -> Result<(u64, bool), CampaignRepositoryError> {
        let mut proposed = 0_u64;
        let mut pending = false;
        for ordinal in 1..=check_count {
            let Some(content) = self
                .merkle
                .get(view.exploration, proposal_ordinal_key(request_id, ordinal))?
            else {
                break;
            };
            let proposal = self.read_proposal(content)?;
            if proposal.request() != request_id
                || proposal.ordinal() != ordinal
                || self.merkle.get(
                    view.exploration,
                    map_key_content("exploration.proposal", content),
                )? != Some(content)
            {
                return Err(integrity("finite-expansion-proposal-index-mismatch"));
            }
            proposed = ordinal;

            let Some(admission_content) = self.merkle.get(
                view.accounting,
                map_key_content("accounting.proposal-admission", content),
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
            if admitted_proposal.content_id() != content {
                return Err(integrity("finite-expansion-proposal-admission-mismatch"));
            }
        }
        Ok((proposed, pending))
    }

    /// Returns whether the next exact ordinal requires progressive PUCT input.
    pub(in crate::repository) fn next_candidate_scores_intervals(
        &self,
        view: CandidateViewRoots,
        request_id: BranchRequestId,
        request: &BranchRequest,
        domain: &ChoiceDomain,
    ) -> Result<bool, CampaignRepositoryError> {
        let Some(CandidateSourceProfile::ProgressiveInteger { initial_count, .. }) =
            self.candidate_source_profile(request, domain)?
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
