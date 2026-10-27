//! Checked semantic reads for one snapshot-bound PUCT projection.

use super::*;
use crate::repository::closure::read::ClosureSemanticRead;

mod guidance;

#[derive(Default)]
struct CheckedBranchEdgeProjectionWork {
    total_credits: u64,
    evidence_bytes: usize,
    prior_cache: BTreeMap<AttemptId, AttemptProposalPrior>,
    prior_request_cache: BTreeMap<BranchRequestId, BranchRequest>,
    charged_prior_records: BTreeSet<ContentId>,
}

impl ClosureSemanticRead<'_, '_> {
    pub(in crate::repository) fn project_branch_puct_loaded(
        &mut self,
        loaded: &LoadedSnapshot,
        branch_point: crate::BranchPointId,
    ) -> Result<crate::BranchPuctProjection, CampaignRepositoryError> {
        let _operation = self.enter_operation();
        let policy = self.read_policy(loaded.snapshot.active_policy().content_id())?;
        let crate::ExplorerPolicy::TreeSearch { puct, .. } = policy.explorer() else {
            return Err(integrity(
                "branch-puct-projection-requires-tree-search-policy",
            ));
        };
        let evidence =
            self.project_branch_edge_visit_evidence(loaded, branch_point, Some(&policy))?;
        let coverage = self.project_branch_coverage_guidance(loaded, &evidence)?;

        let mut finding_weights = BTreeMap::new();
        for kind in [
            crate::FindingKind::PropertyViolation,
            crate::FindingKind::Divergence,
            crate::FindingKind::Timeout,
        ] {
            if let Some(weight) = policy.guidance().get(kind.guidance_signal()) {
                self.insert_map(&mut finding_weights, kind, weight.weight_micros())?;
            }
        }
        let finding_events =
            self.project_branch_finding_events(loaded, &evidence, &finding_weights)?;
        let objective_reward_micros =
            self.project_branch_objective_rewards(loaded, &policy, &evidence)?;

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
                objective_reward_micros,
            },
        )
        .map_err(Into::into)
    }

    fn project_branch_edge_visit_evidence(
        &mut self,
        loaded: &LoadedSnapshot,
        branch_point: crate::BranchPointId,
        guidance_policy: Option<&CampaignPolicy>,
    ) -> Result<BranchEdgeVisitEvidence, CampaignRepositoryError> {
        self.project_branch_edge_visit_evidence_bounded(
            loaded,
            branch_point,
            guidance_policy,
            &mut CheckedBranchEdgeProjectionWork::default(),
        )
    }

    fn project_branch_edge_visit_evidence_bounded(
        &mut self,
        loaded: &LoadedSnapshot,
        branch_point: crate::BranchPointId,
        guidance_policy: Option<&CampaignPolicy>,
        work: &mut CheckedBranchEdgeProjectionWork,
    ) -> Result<BranchEdgeVisitEvidence, CampaignRepositoryError> {
        let Some(index) = self.merkle_get(
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
        let indexed_visits = self.merkle_inspect_shallow(index)?.entry_count();
        work.total_credits = charge_branch_edge_visit_credits(work.total_credits, indexed_visits)?;

        let mut after = None;
        let mut edge_visits = BTreeMap::<crate::BranchEdgeId, u64>::new();
        let mut edge_prior_basis = BTreeMap::<crate::BranchEdgeId, AttemptProposalPrior>::new();
        let mut observations = Vec::new();
        let mut scanned = 0_u64;
        let mut eligible_visits = 0_u64;
        loop {
            let page = self.merkle_scan(index, after, PROJECTION_SCAN_PAGE_ITEMS)?;
            for (key, content) in page.entries() {
                self.poll()?;
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
                let attempt = self.read_attempt_cached(
                    observation.attempt().content_id(),
                    &mut ChoiceValidationCache::default(),
                )?;
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
                    work,
                )?;
                scanned = scanned
                    .checked_add(1)
                    .ok_or_else(|| integrity("branch-edge-visit-count-overflow"))?;
                if guidance_policy.is_some_and(|policy| {
                    !execution_basis_is_guidance_eligible(policy, prior.cause)
                }) {
                    continue;
                }

                match edge_prior_basis.get_mut(&edge) {
                    Some(current) if prior.admission_ordinal < current.admission_ordinal => {
                        *current = prior;
                    }
                    Some(current)
                        if prior.admission_ordinal == current.admission_ordinal
                            && prior.raw_weight != current.raw_weight =>
                    {
                        return Err(integrity("branch-edge-prior-basis-conflict"));
                    }
                    Some(_) => {}
                    None => {
                        self.insert_map(&mut edge_prior_basis, edge, prior)?;
                    }
                }
                if let Some(visits) = edge_visits.get_mut(&edge) {
                    *visits = visits
                        .checked_add(1)
                        .ok_or_else(|| integrity("branch-edge-visit-count-overflow"))?;
                } else {
                    self.insert_map(&mut edge_visits, edge, 1)?;
                }
                self.push(
                    &mut observations,
                    BranchCreditedObservation {
                        observation: credit.observation(),
                        edge,
                        coverage: observation.coverage(),
                    },
                )?;
                eligible_visits = eligible_visits
                    .checked_add(1)
                    .ok_or_else(|| integrity("branch-edge-visit-count-overflow"))?;
            }
            let Some(next) = page.next_after() else {
                break;
            };
            after = Some(next);
        }
        if scanned != indexed_visits {
            return Err(integrity("branch-edge-visit-credit-scan-mismatch"));
        }

        let mut prior_weights = BTreeMap::new();
        for (edge, prior) in edge_prior_basis {
            self.insert_map(&mut prior_weights, edge, prior.raw_weight)?;
        }
        if prior_weights.keys().ne(edge_visits.keys()) {
            return Err(integrity("branch-edge-prior-partition-mismatch"));
        }
        Ok(BranchEdgeVisitEvidence {
            statistics: crate::BranchEdgeVisitStatistics::new(
                branch_point,
                eligible_visits,
                edge_visits,
            )?,
            prior_weights,
            observations,
        })
    }

    fn attempt_proposal_prior(
        &mut self,
        accounting: ContentId,
        attempt: AttemptId,
        work: &mut CheckedBranchEdgeProjectionWork,
    ) -> Result<AttemptProposalPrior, CampaignRepositoryError> {
        if let Some(prior) = work.prior_cache.get(&attempt).copied() {
            return Ok(prior);
        }

        let admission_content = self
            .merkle_get(
                accounting,
                map_key_content("accounting.attempt-execution-basis", attempt.content_id()),
            )?
            .ok_or_else(|| integrity("branch-edge-prior-attempt-is-not-admitted"))?;
        let admission = self.decode_attempt_admission(admission_content)?;
        self.charge_unique_prior_record(
            &mut work.charged_prior_records,
            admission_content,
            admission.canonical_bytes().len(),
            &mut work.evidence_bytes,
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
        self.charge_unique_prior_record(
            &mut work.charged_prior_records,
            proposal_id.content_id(),
            proposal.canonical_bytes().len(),
            &mut work.evidence_bytes,
        )?;
        let request_id = proposal.request();
        if !work.prior_request_cache.contains_key(&request_id) {
            let request = self.read_branch_request(request_id)?;
            self.insert_map(&mut work.prior_request_cache, request_id, request)?;
        }
        let request = work
            .prior_request_cache
            .get(&request_id)
            .ok_or_else(|| integrity("branch-edge-prior-request-cache-mismatch"))?;
        self.charge_unique_prior_record(
            &mut work.charged_prior_records,
            request_id.content_id(),
            request.canonical_bytes().len(),
            &mut work.evidence_bytes,
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
            cause,
        };
        self.insert_map(&mut work.prior_cache, attempt, prior)?;
        Ok(prior)
    }

    fn charge_unique_prior_record(
        &self,
        charged: &mut BTreeSet<ContentId>,
        content: ContentId,
        encoded_len: usize,
        evidence_bytes: &mut usize,
    ) -> Result<(), CampaignRepositoryError> {
        if charged.contains(&content) {
            return Ok(());
        }
        self.insert_set(charged, content)?;
        *evidence_bytes = charge_branch_edge_visit_evidence(*evidence_bytes, encoded_len)?;
        Ok(())
    }

    fn project_branch_coverage_guidance(
        &mut self,
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
            self.poll()?;
            if coverage_targets.contains_key(&credited.coverage) {
                continue;
            }
            let coverage = self.read_coverage_projection(credited.coverage.content_id())?;
            work_bytes = charge_branch_novelty_work(work_bytes, coverage.canonical_bytes().len())?;
            identity_visits = charge_branch_novelty_identity_visits(
                identity_visits,
                coverage.identities().len(),
            )?;
            let mut identities = Vec::new();
            for identity in coverage.identities().iter().copied() {
                self.insert_set(&mut targets, identity)?;
                self.push(&mut identities, identity)?;
            }
            if targets.len() > crate::MAX_BRANCH_NOVELTY_IDENTITIES {
                return Err(integrity("branch-novelty-identity-count"));
            }
            self.insert_map(&mut coverage_targets, credited.coverage, identities)?;
        }
        if targets.is_empty() {
            return Ok(BranchCoverageGuidance::default());
        }

        let observation_root = loaded.snapshot.roots().observations;
        let root_entries = self.merkle_inspect_shallow(observation_root)?.entry_count();
        if root_entries > crate::MAX_BRANCH_NOVELTY_ROOT_ENTRIES {
            return Err(integrity("branch-novelty-observation-root-entry-count"));
        }
        let mut frequencies = BTreeMap::new();
        for identity in targets.iter().copied() {
            self.insert_map(&mut frequencies, identity, 0_u64)?;
        }
        let mut canonical_observations = 0_u64;
        let mut scanned_entries = 0_u64;
        let mut after = None;
        loop {
            let page = self.merkle_scan(observation_root, after, PROJECTION_SCAN_PAGE_ITEMS)?;
            for (key, content) in page.entries() {
                self.poll()?;
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
                if !coverage_targets.contains_key(&coverage_id) {
                    let coverage = self.read_coverage_projection(coverage_id.content_id())?;
                    work_bytes =
                        charge_branch_novelty_work(work_bytes, coverage.canonical_bytes().len())?;
                    identity_visits = charge_branch_novelty_identity_visits(
                        identity_visits,
                        coverage.identities().len(),
                    )?;
                    let mut matching = Vec::new();
                    for identity in coverage.identities().intersection(&targets).copied() {
                        self.push(&mut matching, identity)?;
                    }
                    self.insert_map(&mut coverage_targets, coverage_id, matching)?;
                }
                let identities = coverage_targets
                    .get(&coverage_id)
                    .ok_or_else(|| integrity("branch-novelty-target-cache-mismatch"))?;
                for identity in identities {
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
            let identities = coverage_targets
                .get(&credited.coverage)
                .ok_or_else(|| integrity("branch-novelty-target-cache-mismatch"))?;
            let (events, rarity) = coverage_guidance_for_identities(identities, &frequencies)?;
            self.add_edge_total(
                &mut edge_events,
                credited.edge,
                events,
                "branch-novelty-event-count-overflow",
            )?;
            self.add_edge_total(
                &mut edge_rarity,
                credited.edge,
                rarity,
                "branch-rarity-weight-overflow",
            )?;
        }
        Ok(BranchCoverageGuidance {
            novelty_events: edge_events,
            rarity_weights: edge_rarity,
        })
    }

    fn add_edge_total(
        &self,
        totals: &mut BTreeMap<crate::BranchEdgeId, u64>,
        edge: crate::BranchEdgeId,
        value: u64,
        overflow: &'static str,
    ) -> Result<(), CampaignRepositoryError> {
        if value == 0 {
            return Ok(());
        }
        if let Some(total) = totals.get_mut(&edge) {
            *total = total
                .checked_add(value)
                .ok_or_else(|| integrity(overflow))?;
        } else {
            self.insert_map(totals, edge, value)?;
        }
        Ok(())
    }

    fn read_coverage_projection(
        &mut self,
        id: ContentId,
    ) -> Result<CoverageProjection, CampaignRepositoryError> {
        let envelope =
            self.require_record_kind(id, crate::CampaignRecordKind::CoverageProjection)?;
        self.repository()
            .decode_coverage_projection_envelope(id, &envelope)
    }

    fn project_branch_finding_events(
        &mut self,
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
            if targets.contains_key(&credited.observation) {
                return Err(integrity("branch-finding-credited-observation-duplicate"));
            }
            self.insert_map(&mut targets, credited.observation, credited.edge)?;
        }

        let finding_root = loaded.snapshot.roots().findings;
        let root_entries = self.merkle_inspect_shallow(finding_root)?.entry_count();
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
            let page = self.merkle_scan(finding_root, after, PROJECTION_SCAN_PAGE_ITEMS)?;
            for (key, content) in page.entries() {
                self.poll()?;
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
                    let occurrences = self.merkle_scan(
                        finding.occurrences(),
                        occurrence_after,
                        PROJECTION_SCAN_PAGE_ITEMS,
                    )?;
                    for (occurrence_key, occurrence_content) in occurrences.entries() {
                        self.poll()?;
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
                        let Some(edge) = targets.get(&observation).copied() else {
                            continue;
                        };
                        self.increment_finding_event(&mut edge_events, edge, kind)?;
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

    fn increment_finding_event(
        &self,
        events: &mut BTreeMap<crate::BranchEdgeId, BTreeMap<crate::FindingKind, u64>>,
        edge: crate::BranchEdgeId,
        kind: crate::FindingKind,
    ) -> Result<(), CampaignRepositoryError> {
        if !events.contains_key(&edge) {
            self.insert_map(events, edge, BTreeMap::new())?;
        }
        let edge_events = events
            .get_mut(&edge)
            .ok_or_else(|| integrity("branch-finding-event-cache-mismatch"))?;
        if let Some(count) = edge_events.get_mut(&kind) {
            *count = count
                .checked_add(1)
                .ok_or_else(|| integrity("branch-finding-event-count-overflow"))?;
        } else {
            self.insert_map(edge_events, kind, 1)?;
        }
        Ok(())
    }

    fn decode_finding(&mut self, id: ContentId) -> Result<Finding, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::Finding)?;
        self.repository().decode_finding_envelope(id, &envelope)
    }

    fn project_branch_objective_rewards(
        &mut self,
        loaded: &LoadedSnapshot,
        policy_value: &crate::CampaignPolicy,
        evidence: &BranchEdgeVisitEvidence,
    ) -> Result<BTreeMap<crate::BranchEdgeId, i64>, CampaignRepositoryError> {
        let mut targets = BTreeMap::<ObservationId, Vec<crate::BranchEdgeId>>::new();
        for credited in &evidence.observations {
            if !targets.contains_key(&credited.observation) {
                self.insert_map(&mut targets, credited.observation, Vec::new())?;
            }
            let edges = targets
                .get_mut(&credited.observation)
                .ok_or_else(|| integrity("branch-objective-target-cache-mismatch"))?;
            self.push(edges, credited.edge)?;
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
            BTreeMap::<crate::PropertyVerdictSetId, crate::PropertyVerdictSet>::new();
        let mut charged = BTreeSet::<ContentId>::new();
        let mut evaluation_count = 0_usize;
        let mut work_bytes = 0_usize;
        let mut reward_sums = BTreeMap::<crate::BranchEdgeId, i128>::new();
        for (observation, edges) in targets {
            self.poll()?;
            let Some(content) = self.merkle_get(
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
                work_bytes = self.charge_objective_record(
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
                work_bytes = self.charge_objective_record(
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
                if !properties.contains_key(&properties_id) {
                    let envelope = self.require_record_kind(
                        properties_id.content_id(),
                        crate::CampaignRecordKind::PropertyVerdictSet,
                    )?;
                    work_bytes = self.charge_objective_record(
                        work_bytes,
                        properties_id.content_id(),
                        envelope.body().len(),
                        &mut charged,
                    )?;
                    let value = crate::PropertyVerdictSet::from_canonical_bytes(envelope.body())?;
                    if value.id()? != properties_id {
                        return Err(integrity("property-verdict-set-envelope-shape"));
                    }
                    self.insert_map(&mut properties, properties_id, value)?;
                }
                let properties_value = properties
                    .get(&properties_id)
                    .ok_or_else(|| integrity("branch-objective-properties-cache-mismatch"))?;
                evaluation.validate_compact_basis(
                    policy,
                    objective_contract,
                    &observation_value,
                    properties_value,
                )?;
                let reward = evaluation
                    .scalar_reward()
                    .map_or(0, crate::FixedReward::to_micros_saturating);
                self.insert_map(&mut decoded, content, (observation, reward))?;
                reward
            };
            if reward == 0 {
                continue;
            }
            for edge in edges {
                if let Some(total) = reward_sums.get_mut(&edge) {
                    *total += i128::from(reward);
                } else {
                    self.insert_map(&mut reward_sums, edge, i128::from(reward))?;
                }
            }
        }

        let mut rewards = BTreeMap::new();
        for (edge, total) in reward_sums {
            let reward = total.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64;
            if reward != 0 {
                self.insert_map(&mut rewards, edge, reward)?;
            }
        }
        Ok(rewards)
    }

    fn charge_objective_record(
        &self,
        prior: usize,
        id: ContentId,
        bytes: usize,
        charged: &mut BTreeSet<ContentId>,
    ) -> Result<usize, CampaignRepositoryError> {
        if charged.contains(&id) {
            return Ok(prior);
        }
        self.insert_set(charged, id)?;
        charge_branch_objective_work(prior, bytes)
    }
}
