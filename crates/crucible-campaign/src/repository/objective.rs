//! Immutable objective-evaluation and survivor-decision publication.

use super::*;

/// Maximum admission ordinals inspected by one objective-input scan page.
pub const MAX_OBJECTIVE_EVALUATION_SCAN_PAGE_ITEMS: u32 = 10_000;
const MAX_OBJECTIVE_CURSOR_DELTA_SNAPSHOTS: usize = 10_000;
const MAX_OBJECTIVE_CURSOR_PENDING_ORDINALS: usize = 10_000;

/// Stable result of publishing one policy-bound objective evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectiveEvaluationPublicationResult {
    /// Snapshot that owned the canonical observation and active policy.
    pub prior_snapshot: CampaignSnapshotId,
    /// Snapshot that first indexed the exact evaluation.
    pub new_snapshot: CampaignSnapshotId,
    /// Exact immutable evaluation made authoritative.
    pub evaluation: ObjectiveEvaluationId,
    /// Whether this evaluation was already authoritative.
    pub replayed: bool,
}

/// Complete immutable input for the next policy evaluation in admission order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectiveEvaluationInput {
    snapshot: CampaignSnapshotId,
    policy: CampaignPolicy,
    observation: Observation,
    properties: PropertyVerdictSet,
    measurements: MeasurementSet,
    configuration: ConfigurationArtifact,
    scenario: ScenarioArtifact,
}

/// Restartable position in the objective-evaluation admission scan.
///
/// The cursor is bound to one named campaign, authenticated snapshot, and
/// active policy. When accounting advances, the repository replays only the
/// bounded snapshot delta and records newly completed ordinals below the scan
/// position for direct visits. Append-only admissions, higher-ordinal
/// completions, and evaluation-only successors retain the high-water mark.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectiveEvaluationCursor {
    campaign: CampaignHash,
    snapshot: CampaignSnapshotId,
    policy: CampaignPolicyId,
    accounting: ContentId,
    after_ordinal: u64,
    pending_ordinals: BTreeSet<u64>,
}

impl ObjectiveEvaluationCursor {
    /// Returns the authenticated snapshot at which this position was emitted.
    #[must_use]
    pub const fn snapshot(&self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns the active policy that owns this scan position.
    #[must_use]
    pub const fn policy(&self) -> CampaignPolicyId {
        self.policy
    }

    /// Returns the exact accounting root that owns this scan position.
    #[must_use]
    pub const fn accounting(&self) -> ContentId {
        self.accounting
    }

    /// Returns the last admission ordinal inspected by the scan.
    #[must_use]
    pub const fn after_ordinal(&self) -> u64 {
        self.after_ordinal
    }
}

/// One bounded page from the admission-ordered objective-evaluation scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectiveEvaluationScanPage {
    input: Option<ObjectiveEvaluationInput>,
    cursor: ObjectiveEvaluationCursor,
    complete: bool,
    visited_ordinals: u32,
}

impl ObjectiveEvaluationScanPage {
    /// Returns the first unevaluated observation found on this page.
    #[must_use]
    pub const fn input(&self) -> Option<&ObjectiveEvaluationInput> {
        self.input.as_ref()
    }

    /// Consumes the page and returns its first unevaluated observation.
    #[must_use]
    pub fn into_input(self) -> Option<ObjectiveEvaluationInput> {
        self.input
    }

    /// Returns the restartable position after this page's inspected ordinals.
    #[must_use]
    pub fn cursor(&self) -> ObjectiveEvaluationCursor {
        self.cursor.clone()
    }

    /// Returns whether the page reached the exact admission upper bound.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }

    /// Returns the number of admission ordinals inspected for this page.
    #[must_use]
    pub const fn visited_ordinals(&self) -> u32 {
        self.visited_ordinals
    }
}

impl ObjectiveEvaluationInput {
    /// Returns the exact snapshot on which publication must compare-and-swap.
    #[must_use]
    pub const fn snapshot(&self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns the active policy to evaluate.
    #[must_use]
    pub const fn policy(&self) -> &CampaignPolicy {
        &self.policy
    }

    /// Returns the canonical observation awaiting evaluation.
    #[must_use]
    pub const fn observation(&self) -> &Observation {
        &self.observation
    }

    /// Returns the observation's property-verdict set.
    #[must_use]
    pub const fn properties(&self) -> &PropertyVerdictSet {
        &self.properties
    }

    /// Returns the observation's retained measurement set.
    #[must_use]
    pub const fn measurements(&self) -> &MeasurementSet {
        &self.measurements
    }

    /// Returns the exact observed configuration artifact.
    #[must_use]
    pub const fn configuration(&self) -> &ConfigurationArtifact {
        &self.configuration
    }

    /// Returns the configuration's execution-model scenario artifact.
    #[must_use]
    pub const fn scenario(&self) -> &ScenarioArtifact {
        &self.scenario
    }
}

impl CampaignRepository {
    /// Scans for the next canonical observation lacking an active-policy evaluation.
    ///
    /// Available observations are visited in admission order. A later
    /// lower-ordinal completion is retained as direct pending work without
    /// rewinding the cursor's high-water mark. Explicitly closed non-modeled
    /// attempts are skipped because they have no observation to evaluate.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero or excessive page limit, missing campaign,
    /// malformed admission-order index, unreadable observation closure, or
    /// failed repository authentication.
    pub fn scan_objective_evaluation_inputs(
        &self,
        name: &str,
        cursor: Option<ObjectiveEvaluationCursor>,
        limit: u32,
    ) -> Result<ObjectiveEvaluationScanPage, CampaignRepositoryError> {
        if limit == 0 || limit > MAX_OBJECTIVE_EVALUATION_SCAN_PAGE_ITEMS {
            return Err(CampaignRepositoryError::InvalidRequest {
                reason: "objective-evaluation-scan-limit",
            });
        }

        let head = self.head(name)?;
        let campaign = CampaignHash::derive(
            "crucible.campaign.objective-evaluation-cursor-campaign.v1",
            name.as_bytes(),
        );
        let snapshot = head.snapshot_id();
        let roots = head.snapshot().roots();
        let active_policy = head.snapshot().active_policy();
        let policy = self.read_policy(active_policy.content_id())?;
        if policy.id()? != active_policy {
            return Err(integrity("objective-input-active-policy-id-mismatch"));
        }
        let admitted = self.accounted_attempts(roots.accounting)?;
        let mut cursor = match cursor {
            Some(cursor) if cursor.policy == active_policy && cursor.campaign == campaign => {
                self.reconcile_objective_cursor(head.snapshot(), cursor)?
            }
            Some(_) | None => ObjectiveEvaluationCursor {
                campaign,
                snapshot,
                policy: active_policy,
                accounting: roots.accounting,
                after_ordinal: 0,
                pending_ordinals: BTreeSet::new(),
            },
        };
        cursor.snapshot = snapshot;
        cursor.accounting = roots.accounting;

        let mut visited_ordinals = 0u32;
        while let Some(ordinal) = cursor.pending_ordinals.pop_first() {
            visited_ordinals = visited_ordinals
                .checked_add(1)
                .ok_or_else(|| integrity("objective-input-scan-count-overflow"))?;
            if let Some(input) = self.objective_evaluation_input_at(
                snapshot,
                &policy,
                roots,
                AdmissionOrdinal::new(ordinal),
            )? {
                return Ok(ObjectiveEvaluationScanPage {
                    input: Some(input),
                    cursor,
                    complete: false,
                    visited_ordinals,
                });
            }
            if visited_ordinals == limit {
                return Ok(ObjectiveEvaluationScanPage {
                    input: None,
                    cursor,
                    complete: false,
                    visited_ordinals,
                });
            }
        }

        if cursor.after_ordinal >= admitted {
            return Ok(ObjectiveEvaluationScanPage {
                input: None,
                cursor,
                complete: true,
                visited_ordinals,
            });
        }

        let remaining = limit - visited_ordinals;
        let page_end = cursor
            .after_ordinal
            .checked_add(u64::from(remaining))
            .unwrap_or(u64::MAX)
            .min(admitted);

        for ordinal in (cursor.after_ordinal + 1)..=page_end {
            visited_ordinals = visited_ordinals
                .checked_add(1)
                .ok_or_else(|| integrity("objective-input-scan-count-overflow"))?;
            cursor.after_ordinal = ordinal;
            if let Some(input) = self.objective_evaluation_input_at(
                snapshot,
                &policy,
                roots,
                AdmissionOrdinal::new(ordinal),
            )? {
                return Ok(ObjectiveEvaluationScanPage {
                    input: Some(input),
                    cursor,
                    complete: ordinal == admitted,
                    visited_ordinals,
                });
            }
        }

        cursor.after_ordinal = page_end;
        Ok(ObjectiveEvaluationScanPage {
            input: None,
            cursor,
            complete: page_end == admitted,
            visited_ordinals,
        })
    }

    fn reconcile_objective_cursor(
        &self,
        head: &CampaignSnapshot,
        mut cursor: ObjectiveEvaluationCursor,
    ) -> Result<ObjectiveEvaluationCursor, CampaignRepositoryError> {
        let mut current = head.clone();
        for _ in 0..MAX_OBJECTIVE_CURSOR_DELTA_SNAPSHOTS {
            let current_id = current.id()?;
            if current_id == cursor.snapshot {
                if current.roots().accounting != cursor.accounting {
                    return Err(integrity("objective-cursor-accounting-root-mismatch"));
                }
                return Ok(cursor);
            }
            if current.active_policy() != cursor.policy {
                return self.fresh_objective_cursor(head, cursor.campaign);
            }

            let Some(parent_id) = current.parent() else {
                return self.fresh_objective_cursor(head, cursor.campaign);
            };
            let parent = self.read_snapshot(parent_id.content_id())?;
            if current.roots().accounting != parent.snapshot.roots().accounting {
                let transition = current
                    .transition()
                    .ok_or_else(|| integrity("objective-cursor-accounting-transition-missing"))?;
                match self.read_fact(transition.content_id())? {
                    CampaignFact::ObservationPublished(observation)
                    | CampaignFact::ObservationCredited(observation) => {
                        let observation = self.read_observation(observation.content_id())?;
                        let (_, ordinal) = self.observation_execution_basis(
                            current.roots().accounting,
                            &observation,
                        )?;
                        if ordinal.value() <= cursor.after_ordinal {
                            cursor.pending_ordinals.insert(ordinal.value());
                            if cursor.pending_ordinals.len() > MAX_OBJECTIVE_CURSOR_PENDING_ORDINALS
                            {
                                // Pending ordinals only accelerate scanning; excess valid work
                                // restarts the bounded scan instead of rejecting campaign history.
                                return self.fresh_objective_cursor(head, cursor.campaign);
                            }
                        }
                    }
                    CampaignFact::ChoiceOpportunityDiscovered { .. }
                    | CampaignFact::BranchRequestIssued(_)
                    | CampaignFact::BranchRequestAccepted { .. }
                    | CampaignFact::PlannerAdvanced(_)
                    | CampaignFact::ProposalIssued(_)
                    | CampaignFact::AttemptAdmitted(_)
                    | CampaignFact::AttemptClosed { .. }
                    | CampaignFact::FindingPublished(_)
                    | CampaignFact::ObjectiveEvaluationPublished(_)
                    | CampaignFact::BudgetGranted(_)
                    | CampaignFact::ControlRequested(_)
                    | CampaignFact::PinChanged(_)
                    | CampaignFact::PinCommandAccepted(_)
                    | CampaignFact::DiscoveryRequested(_)
                    | CampaignFact::SavepointCaptureRequested(_)
                    | CampaignFact::SavepointCaptureResolved(_)
                    | CampaignFact::SavepointContinuationSelected(_) => {}
                    CampaignFact::CampaignDerived(_) | CampaignFact::PolicyActivated(_) => {
                        return self.fresh_objective_cursor(head, cursor.campaign);
                    }
                }
            }
            current = parent.snapshot;
        }

        // The ancestry walk is cursor bookkeeping, so exhausting its budget
        // discards the optimization rather than classifying valid history as corrupt.
        self.fresh_objective_cursor(head, cursor.campaign)
    }

    fn fresh_objective_cursor(
        &self,
        head: &CampaignSnapshot,
        campaign: CampaignHash,
    ) -> Result<ObjectiveEvaluationCursor, CampaignRepositoryError> {
        Ok(ObjectiveEvaluationCursor {
            campaign,
            snapshot: head.id()?,
            policy: head.active_policy(),
            accounting: head.roots().accounting,
            after_ordinal: 0,
            pending_ordinals: BTreeSet::new(),
        })
    }

    fn objective_evaluation_input_at(
        &self,
        snapshot: CampaignSnapshotId,
        policy: &CampaignPolicy,
        roots: crate::CampaignRoots,
        ordinal: AdmissionOrdinal,
    ) -> Result<Option<ObjectiveEvaluationInput>, CampaignRepositoryError> {
        let Some(content) = self
            .merkle
            .get(roots.accounting, observation_ordinal_key(ordinal))?
        else {
            return Ok(None);
        };
        let observation = self.read_observation(content)?;
        let observation_id = observation.id()?;
        if self
            .merkle
            .get(
                roots.observations,
                objective_evaluation_key(policy.id()?, observation_id),
            )?
            .is_some()
        {
            return Ok(None);
        }
        if self
            .observation_execution_basis(roots.accounting, &observation)?
            .1
            != ordinal
        {
            return Err(integrity("objective-input-observation-ordinal-mismatch"));
        }
        let properties = self.read_property_verdict_set(observation.properties().content_id())?;
        let measurements = self.read_measurement_set(observation.measurements().content_id())?;
        let configuration =
            self.read_configuration_artifact(observation.child_content().content_id())?;
        let scenario =
            self.read_scenario_artifact(configuration.scenario_artifact().content_id())?;

        Ok(Some(ObjectiveEvaluationInput {
            snapshot,
            policy: policy.clone(),
            observation,
            properties,
            measurements,
            configuration,
            scenario,
        }))
    }

    /// Reads one authenticated raw measurement-evidence leaf owned by an input.
    ///
    /// # Errors
    ///
    /// Returns an error when the measurement set does not name the leaf, the
    /// leaf is not trace content, its declared size exceeds `max_bytes`, or the
    /// backend cannot complete an authenticated read.
    pub fn read_objective_evidence_leaf(
        &self,
        input: &ObjectiveEvaluationInput,
        evidence: ContentId,
        max_bytes: u64,
    ) -> Result<Vec<u8>, CampaignRepositoryError> {
        let retained = input
            .measurements
            .evaluation()
            .ok_or_else(|| integrity("objective-input-measurement-set-has-no-evaluation"))?;
        if evidence.kind() != ObjectKind::Trace || !retained.evidence().contains(&evidence) {
            return Err(integrity("objective-input-evidence-leaf-is-not-owned"));
        }
        self.blobs
            .read(evidence, None)?
            .read_all(max_bytes)
            .map_err(Into::into)
    }

    /// Publishes one verified objective evaluation into a named campaign.
    ///
    /// The execution-model adapter must already have proven that every retained
    /// component came from the observation's verified measurement payload. This
    /// owner boundary validates the active policy, canonical observation,
    /// property filtering, deterministic scalar reward, and exact snapshot
    /// precondition before its first write.
    ///
    /// # Errors
    ///
    /// Returns an error without writing when the snapshot is stale, the
    /// evaluation is absent from the active policy/observation basis, another
    /// evaluation already owns the same basis, or repository validation fails.
    /// Storage failure after preflight may leave unreachable immutable objects
    /// before the final ref compare-and-swap.
    pub fn publish_objective_evaluation(
        &self,
        name: &str,
        expected_snapshot: CampaignSnapshotId,
        evaluation: &ObjectiveEvaluation,
    ) -> Result<ObjectiveEvaluationPublicationResult, CampaignRepositoryError> {
        let _guard = self.lock_mutation()?;
        let campaign_ref = campaign_ref(name)?;
        let current_content = self
            .refs
            .read_ref(&campaign_ref)?
            .ok_or(CampaignRepositoryError::NotFound)?;
        let current = self.read_snapshot(current_content)?;
        self.validate_complete_head(current_content)?;
        let current_id = CampaignSnapshotId::from_content_id(current_content)?;
        let evaluation_id = evaluation.id()?;
        if let Some(replayed) =
            self.find_objective_evaluation_result(current_content, evaluation_id)?
        {
            return Ok(replayed);
        }
        if expected_snapshot != current_id {
            return Err(CampaignRepositoryError::Stale {
                expected: expected_snapshot,
                current: current_id,
            });
        }

        self.validate_objective_evaluation_basis(&current, evaluation)?;
        let key = objective_evaluation_key(evaluation.policy(), evaluation.observation());
        match self
            .merkle
            .get(current.snapshot.roots().observations, key)?
        {
            Some(existing) if existing == evaluation_id.content_id() => {
                return Ok(ObjectiveEvaluationPublicationResult {
                    prior_snapshot: current_id,
                    new_snapshot: current_id,
                    evaluation: evaluation_id,
                    replayed: true,
                });
            }
            Some(_) => return Err(CampaignRepositoryError::AlreadyExists),
            None => {}
        }

        if self.put_objective_evaluation(evaluation)? != evaluation_id.content_id() {
            return Err(integrity("objective-evaluation-publication-id-mismatch"));
        }
        let mut roots = current.snapshot.roots();
        roots.observations = self
            .merkle
            .insert(roots.observations, key, evaluation_id.content_id())?
            .content_id();
        roots.coordination = self.coordination_with_parent_result(current_content, &current)?;
        let transition =
            self.put_fact(&CampaignFact::ObjectiveEvaluationPublished(evaluation_id))?;
        let next = self.budgeted_successor(
            current_id,
            current.snapshot.lineage(),
            current.snapshot.active_policy(),
            roots,
            CampaignFactId::from_content_id(transition)?,
        )?;
        let next_content = self.put_snapshot(&next)?;
        let checkpoint = self.prepare_local_successor_checkpoint(
            current_content,
            next_content,
            None,
            MAX_SIMPLE_SUCCESSOR_GROWTH,
        )?;

        match self
            .refs
            .compare_exchange(&campaign_ref, Some(current_content), next_content)?
        {
            RefCasOutcome::Advanced { .. } => {
                self.promote_local_successor(current_content, next_content, checkpoint);
                Ok(ObjectiveEvaluationPublicationResult {
                    prior_snapshot: current_id,
                    new_snapshot: CampaignSnapshotId::from_content_id(next_content)?,
                    evaluation: evaluation_id,
                    replayed: false,
                })
            }
            RefCasOutcome::Conflict { current, .. } => {
                Err(CampaignRepositoryError::RefConflict { current })
            }
        }
    }

    fn validate_objective_evaluation_basis(
        &self,
        snapshot: &LoadedSnapshot,
        evaluation: &ObjectiveEvaluation,
    ) -> Result<(), CampaignRepositoryError> {
        if evaluation.policy() != snapshot.snapshot.active_policy() {
            return Err(integrity("objective-evaluation-active-policy-mismatch"));
        }
        let policy = self.read_policy(evaluation.policy().content_id())?;
        let observation = self.read_observation(evaluation.observation().content_id())?;
        if self.merkle.get(
            snapshot.snapshot.roots().observations,
            attempt_observation_key(observation.attempt()),
        )? != Some(evaluation.observation().content_id())
        {
            return Err(integrity(
                "objective-evaluation-observation-is-not-canonical",
            ));
        }
        let properties = self.read_property_verdict_set(observation.properties().content_id())?;
        evaluation.validate_basis(&policy, &observation, &properties)?;
        Ok(())
    }

    pub(super) fn validate_objective_evaluation_successor(
        &self,
        parent: &LoadedSnapshot,
        child: &LoadedSnapshot,
        evaluation_id: ObjectiveEvaluationId,
        choice_cache: &mut ChoiceValidationCache,
    ) -> Result<(), CampaignRepositoryError> {
        if child.snapshot.lineage() != parent.snapshot.lineage()
            || child.snapshot.active_policy() != parent.snapshot.active_policy()
        {
            return Err(integrity(
                "objective-evaluation-transition-changed-campaign-basis",
            ));
        }
        let prior = parent.snapshot.roots();
        let next = child.snapshot.roots();
        if prior.graph != next.graph
            || prior.exploration != next.exploration
            || prior.corpus != next.corpus
            || prior.coverage != next.coverage
            || prior.findings != next.findings
            || prior.pins != next.pins
            || prior.accounting != next.accounting
        {
            return Err(integrity(
                "objective-evaluation-transition-changed-unrelated-root",
            ));
        }

        let evaluation =
            self.read_objective_evaluation_cached(evaluation_id.content_id(), choice_cache)?;
        self.validate_objective_evaluation_basis(parent, &evaluation)?;
        let key = objective_evaluation_key(evaluation.policy(), evaluation.observation());
        if self.merkle.get(prior.observations, key)?.is_some() {
            return Err(integrity(
                "objective-evaluation-transition-replaced-existing-basis",
            ));
        }
        let expected = self.merkle.root_after_upserts(
            prior.observations,
            &BTreeMap::from([(key, evaluation_id.content_id())]),
        )?;
        if next.observations != expected || next.observations == prior.observations {
            return Err(integrity(
                "objective-evaluation-transition-observation-root",
            ));
        }
        if !self.coordination_matches_parent_result(parent, next.coordination)? {
            return Err(integrity(
                "objective-evaluation-transition-coordination-root",
            ));
        }
        Ok(())
    }

    /// Publishes one complete deterministic survivor decision without advancing a campaign.
    ///
    /// The execution-model adapter must already have proven that every retained
    /// objective component came from its observation's verified measurement
    /// payload. This repository boundary authenticates observation/property/
    /// policy ownership, exact ranking replay, and the complete dependency
    /// closure before storing any new decision member.
    ///
    /// # Errors
    ///
    /// Returns an error without writing a decision member when a dependency is
    /// absent, corrupt, mismatched, or the retained selection differs from exact
    /// deterministic replay. A storage failure during final immutable writes may
    /// leave harmless content-addressed members for ordinary garbage collection.
    pub fn publish_survivor_selection(
        &self,
        bundle: &SurvivorSelectionBundle,
    ) -> Result<SurvivorSelectionId, CampaignRepositoryError> {
        let replayed = self.validate_survivor_selection_bundle(bundle)?;
        if &replayed != bundle {
            return Err(integrity("survivor-selection-bundle-replay-mismatch"));
        }

        for evaluation in bundle.evaluations().values() {
            self.put_objective_evaluation(evaluation)?;
        }
        for explanation in bundle.explanations().values() {
            self.put_ranking_explanation(explanation)?;
        }
        let content = self.put_survivor_selection(bundle.selection())?;
        if content != bundle.selection().id()?.content_id() {
            return Err(integrity("survivor-selection-publication-id-mismatch"));
        }
        self.verify_campaign_closure(content)?;
        SurvivorSelectionId::from_content_id(content).map_err(Into::into)
    }

    fn validate_survivor_selection_bundle(
        &self,
        bundle: &SurvivorSelectionBundle,
    ) -> Result<SurvivorSelectionBundle, CampaignRepositoryError> {
        let selection = bundle.selection();
        let policy = self.read_policy(selection.policy().content_id())?;
        if bundle.evaluations().len() != selection.considered().len()
            || bundle.explanations().len() != selection.explanations().len()
        {
            return Err(integrity("survivor-selection-bundle-member-count"));
        }

        let mut roots = BTreeSet::from([selection.policy().content_id()]);
        let mut candidates = Vec::with_capacity(bundle.evaluations().len());
        let mut evidence_bytes = 0;
        for (configuration, evaluation) in bundle.evaluations() {
            crate::objective::charge_survivor_evidence_bytes(
                &mut evidence_bytes,
                evaluation.canonical_bytes().len(),
            )?;
            let evaluation_id = evaluation.id()?;
            if selection.considered().get(configuration) != Some(&evaluation_id) {
                return Err(integrity("survivor-selection-evaluation-map-mismatch"));
            }
            let observation = self.decode_observation(evaluation.observation().content_id())?;
            let properties =
                self.read_property_verdict_set(observation.properties().content_id())?;
            evaluation.validate_basis(&policy, &observation, &properties)?;
            roots.insert(evaluation.observation().content_id());

            let explanation = bundle
                .explanations()
                .get(configuration)
                .ok_or_else(|| integrity("survivor-selection-explanation-missing"))?;
            if explanation.evaluation() != evaluation_id
                || selection.explanations().get(configuration) != Some(&explanation.id()?)
            {
                return Err(integrity("survivor-selection-explanation-map-mismatch"));
            }
            crate::objective::charge_survivor_evidence_bytes(
                &mut evidence_bytes,
                explanation.canonical_bytes().len(),
            )?;
            candidates.push(crate::RankingCandidate::new(
                evaluation.clone(),
                explanation.novelty_score(),
                explanation.breadth_ordinal(),
            ));
        }
        self.verify_campaign_closures_anchored_cached(
            roots,
            &BTreeSet::new(),
            &mut ChoiceValidationCache::default(),
        )?;
        crate::rank_survivors(&policy, selection.rule(), candidates).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use crucible_cas::content_store::{ContentId, MemoryBlobBackend, MemoryRefBackend, ObjectKind};

    use super::*;
    use crate::CampaignRoots;

    #[test]
    fn excessive_valid_cursor_delta_falls_back_to_a_fresh_position() {
        let repository = CampaignRepository::new(
            Arc::new(MemoryBlobBackend::new(
                "objective-cursor-cap",
                128 * 1024 * 1024,
            )),
            Arc::new(MemoryRefBackend::new()),
        );
        let root = ContentId::for_bytes(ObjectKind::MerkleNode, 1, b"empty-root");
        let roots = CampaignRoots {
            graph: root,
            exploration: root,
            observations: root,
            corpus: root,
            coverage: root,
            findings: root,
            pins: root,
            accounting: root,
            coordination: root,
        };
        let lineage = CampaignLineageId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignFact,
            1,
            b"lineage",
        ))
        .expect("synthetic lineage ID");
        let policy = CampaignPolicyId::from_content_id(ContentId::for_bytes(
            ObjectKind::Policy,
            1,
            b"policy",
        ))
        .expect("synthetic policy ID");
        let transition = CampaignFactId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignFact,
            2,
            b"transition",
        ))
        .expect("synthetic transition ID");

        let genesis = CampaignSnapshot::genesis(lineage, policy, roots).expect("genesis");
        let genesis_id = CampaignSnapshotId::from_content_id(
            repository.put_snapshot(&genesis).expect("publish genesis"),
        )
        .expect("genesis ID");
        let campaign = CampaignHash::derive("objective-cursor-cap-test", b"campaign");
        let cursor = ObjectiveEvaluationCursor {
            campaign,
            snapshot: genesis_id,
            policy,
            accounting: root,
            after_ordinal: 37,
            pending_ordinals: BTreeSet::from([11]),
        };

        let mut parent = genesis_id;
        let mut head = genesis;
        for _ in 0..=MAX_OBJECTIVE_CURSOR_DELTA_SNAPSHOTS {
            head = CampaignSnapshot::successor(parent, lineage, policy, roots, transition)
                .expect("successor");
            parent = CampaignSnapshotId::from_content_id(
                repository.put_snapshot(&head).expect("publish successor"),
            )
            .expect("successor ID");
        }

        let reconciled = repository
            .reconcile_objective_cursor(&head, cursor)
            .expect("valid excessive delta falls back");
        assert_eq!(reconciled.snapshot(), parent);
        assert_eq!(reconciled.policy(), policy);
        assert_eq!(reconciled.accounting(), root);
        assert_eq!(reconciled.after_ordinal(), 0);
        assert!(reconciled.pending_ordinals.is_empty());
    }
}
