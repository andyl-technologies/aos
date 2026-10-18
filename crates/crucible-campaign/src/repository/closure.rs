//! Complete snapshot ancestry and reachable-object closure validation.

use super::budget::ExpectedBudgetSuccessor;
use super::*;

/// Bounded process-local validation state exposed to conformance tests.
#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignValidationCheckpointMetrics {
    /// Number of validated heads retained across all campaigns in this repository.
    pub retained_heads: usize,
    /// Number of snapshots in the authenticated ancestry of the selected head.
    pub ancestry_depth: usize,
    /// Conservative count of authenticated objects reachable from the selected head.
    pub closure_objects: usize,
    /// Fixed in-memory size of one retained checkpoint value.
    pub checkpoint_bytes: usize,
}

mod delta;
mod successors;
mod walk;

pub(in crate::repository) use delta::HistoryClosure;
use delta::TransitionStep;
pub(in crate::repository) use walk::{
    ClosureSink, MAX_CLOSURE_WALK_OBJECTS, WalkContext, WalkEntry, WalkStart,
};

impl CampaignRepository {
    pub(super) fn simple_planner_issue_growth_upper(
        &self,
        parent: &LoadedSnapshot,
        child: &CampaignSnapshot,
    ) -> Result<usize, CampaignRepositoryError> {
        // Bounded finite Issues may publish several admissions at once. Charge
        // the actual changed trie positions and their newly linked leaf closure.
        let prior = parent.snapshot.roots();
        let next = child.roots();
        if prior.graph != next.graph
            || prior.observations != next.observations
            || prior.corpus != next.corpus
            || prior.coverage != next.coverage
            || prior.findings != next.findings
            || prior.pins != next.pins
        {
            return Err(integrity("simple-planner-issue-unexpected-root-change"));
        }
        let prior_ledger = self.parent_budget_ledger(parent)?;
        let next_ledger = self.read_budget_ledger(child.budget_ledger())?;
        let mut positions = BTreeSet::new();
        let mut roots = BTreeSet::new();
        let mut values = BTreeMap::new();
        for (old, new) in [
            (prior.exploration, next.exploration),
            (prior.accounting, next.accounting),
            (prior.coordination, next.coordination),
            (
                prior_ledger.request_spending(),
                next_ledger.request_spending(),
            ),
            (
                prior_ledger.request_admissions(),
                next_ledger.request_admissions(),
            ),
        ] {
            self.merkle.collect_changed_node_positions(
                old,
                new,
                &mut positions,
                &mut roots,
                &mut values,
                MAX_CLOSURE_WALK_OBJECTS,
            )?;
        }

        let transition = child
            .transition()
            .ok_or_else(|| integrity("local-successor-checkpoint-shape"))?
            .content_id();
        let mut anchors = self.incremental_closure_anchors(parent, transition)?;
        let mut linked_ids = BTreeSet::new();
        self.walk_campaign_closures(
            [transition],
            &anchors,
            false,
            &mut ChoiceValidationCache::default(),
            Some(&mut |id, _exact_leaf| {
                linked_ids.insert(id);
                Ok(())
            }),
        )?;
        anchors.extend(linked_ids);
        let leaf_growth = self.verify_campaign_closures_anchored_cached(
            values.into_keys(),
            &anchors,
            &mut ChoiceValidationCache::default(),
        )?;

        // A root is visited once as an object and once at its trie position.
        // The snapshot and changed ledger are the remaining owner records.
        positions
            .len()
            .checked_add(roots.len())
            .and_then(|count| count.checked_add(leaf_growth))
            .and_then(|count| count.checked_add(1))
            .and_then(|count| count.checked_add(usize::from(prior_ledger != next_ledger)))
            .ok_or_else(|| integrity("campaign-closure-object-limit"))
    }

    /// Reports the bounded acceleration checkpoint for one campaign head.
    ///
    /// This diagnostic exists only with the `test-support` feature. It exposes
    /// counts rather than mutable cache state so conformance gates can verify
    /// bounds without acquiring repository internals or changing semantics.
    ///
    /// # Errors
    ///
    /// Returns an error when the campaign head is absent or fails complete
    /// ancestry and closure validation.
    #[cfg(feature = "test-support")]
    pub fn validation_checkpoint_metrics(
        &self,
        campaign: &str,
    ) -> Result<CampaignValidationCheckpointMetrics, CampaignRepositoryError> {
        let head = self.head(campaign)?;
        let checkpoint = self.load_validation_checkpoint(head.snapshot_id().content_id())?;

        Ok(CampaignValidationCheckpointMetrics {
            retained_heads: self.validation_checkpoints().len(),
            ancestry_depth: checkpoint.ancestry_depth,
            closure_objects: checkpoint.closure_objects,
            checkpoint_bytes: std::mem::size_of::<ValidationCheckpoint>(),
        })
    }

    /// Reports whether a content ID is present in the validation cache.
    ///
    /// This diagnostic performs no object or ref read and never validates or
    /// inserts a checkpoint. It exists so conformance tests can observe the
    /// failure-atomic cache state before any later read repairs a cache miss.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn has_retained_validation_checkpoint(&self, content: ContentId) -> bool {
        self.validation_checkpoints().contains_key(&content)
    }

    pub(super) fn validate_complete_head(
        &self,
        head: ContentId,
    ) -> Result<(), CampaignRepositoryError> {
        self.load_validation_checkpoint(head).map(|_| ())
    }

    pub(super) fn load_validation_checkpoint(
        &self,
        head: ContentId,
    ) -> Result<ValidationCheckpoint, CampaignRepositoryError> {
        let mut planner_context = PlannerValidationContext::default();
        self.load_validation_checkpoint_with_planner_context(head, &mut planner_context)
    }

    /// Validates a complete head inductively with bounded attempt-local reuse.
    ///
    /// # Errors
    ///
    /// Returns any original ancestry or fresh closure failure without promoting
    /// a checkpoint, and clears retained tuples on every result.
    pub(super) fn load_validation_checkpoint_with_planner_context(
        &self,
        head: ContentId,
        planner_context: &mut PlannerValidationContext,
    ) -> Result<ValidationCheckpoint, CampaignRepositoryError> {
        let mut merkle_reads = MerkleValidationReads::default();
        self.load_validation_checkpoint_with_contexts(head, planner_context, &mut merkle_reads)
    }

    /// Ends both attempt-local contexts before returning or promoting a head.
    ///
    /// Complete validation is one backward walk from the head to genesis. Each
    /// step validates the owner transition and then authenticates only the
    /// objects newly reachable from the child relative to its parent; genesis
    /// authenticates its own small closure. Every object reachable from the
    /// head first becomes reachable at genesis or at exactly one transition,
    /// so the union of these deltas is the complete head closure while the
    /// walk retains one transition's state at a time.
    ///
    /// # Errors
    ///
    /// Returns every original ancestry or fresh closure validation error.
    pub(super) fn load_validation_checkpoint_with_contexts(
        &self,
        head: ContentId,
        planner_context: &mut PlannerValidationContext,
        merkle_reads: &mut MerkleValidationReads,
    ) -> Result<ValidationCheckpoint, CampaignRepositoryError> {
        planner_context.clear();
        merkle_reads.clear();
        let result = (|| {
            if let Some(checkpoint) = self.validation_checkpoints().get(&head).copied() {
                return Ok(checkpoint);
            }

            let checkpoint = self.validate_history_with_closure(
                head,
                Some(planner_context),
                Some(merkle_reads),
                None,
            )?;
            self.remember_validation_checkpoint(head, checkpoint);
            Ok(checkpoint)
        })();
        // A failed attempt must not lend authenticated tuples to a later read.
        // Successful reuse also ends here; only the original head checkpoint
        // is promoted after every transition and its closure delta succeed.
        planner_context.clear();
        merkle_reads.clear();
        result
    }

    /// Runs the inductive history walk and returns its checkpoint.
    ///
    /// `sink` receives every object of the genesis closure and of every
    /// transition delta. The checkpoint is not promoted here.
    ///
    /// # Errors
    ///
    /// Returns every original ancestry, transition, or closure error, or the
    /// first error returned by `sink`.
    fn validate_history_with_closure(
        &self,
        head: ContentId,
        planner_context: Option<&mut PlannerValidationContext>,
        merkle_reads: Option<&mut MerkleValidationReads>,
        sink: Option<&mut ClosureSink<'_>>,
    ) -> Result<ValidationCheckpoint, CampaignRepositoryError> {
        let mut choice_cache = ChoiceValidationCache::default();
        let mut closure = HistoryClosure {
            objects: 0,
            sink,
            peak_resident: 0,
        };
        let (ancestry_depth, lifecycle, genesis, derived_branch) = self.validate_snapshot_history(
            head,
            &mut choice_cache,
            MAX_CAMPAIGN_SNAPSHOT_ANCESTRY,
            planner_context,
            merkle_reads,
            Some(&mut closure),
        )?;
        Ok(ValidationCheckpoint {
            ancestry_depth,
            closure_objects: closure.objects,
            lifecycle,
            genesis,
            derived_branch,
        })
    }

    pub(super) fn prepare_local_successor_checkpoint(
        &self,
        parent: ContentId,
        child: ContentId,
        action: Option<&CampaignControlAction>,
        closure_growth_upper: usize,
        budget_witness: &ExpectedBudgetSuccessor,
    ) -> Result<ValidationCheckpoint, CampaignRepositoryError> {
        // Transaction helpers have already authenticated their inputs and
        // constructed the exact owner delta. This final shape check prevents a
        // future caller from promoting an unrelated object while avoiding a
        // second walk over the immutable parent closure.
        let loaded = self.read_snapshot(child)?;
        if loaded.snapshot.parent().map(CampaignSnapshotId::content_id) != Some(parent)
            || optional_child(&loaded.envelope, "parent") != Some(parent)
            || loaded.snapshot.transition().is_none()
            || optional_child(&loaded.envelope, "transition").is_none()
        {
            return Err(integrity("local-successor-checkpoint-shape"));
        }
        let transition_content = optional_child(&loaded.envelope, "transition")
            .ok_or_else(|| integrity("local-successor-checkpoint-shape"))?;
        let parent_checkpoint = self.load_validation_checkpoint(parent)?;
        let (fact, budget_growth) =
            self.validate_local_budget_witness(parent, child, &loaded, budget_witness)?;
        let derived_branch = match fact {
            CampaignFact::CampaignDerived(derivation) => Some(DerivedBranchCheckpoint {
                snapshot: child,
                derivation: *derivation,
            }),
            _ => parent_checkpoint.derived_branch,
        };
        let parent_snapshot = self.read_snapshot(parent)?;
        let ancestry_depth = parent_checkpoint
            .ancestry_depth
            .checked_add(1)
            .ok_or_else(|| integrity("snapshot-ancestry-limit"))?;
        if ancestry_depth > MAX_CAMPAIGN_SNAPSHOT_ANCESTRY {
            return Err(integrity("snapshot-ancestry-limit"));
        }
        let mut lifecycle = parent_checkpoint.lifecycle;
        if let Some(action) = action {
            lifecycle.apply(action)?;
        }
        // A transition may make a large, already-published object graph newly
        // reachable. Relative to exact parent-owned anchors, authenticate and
        // charge that complete new closure in addition to the conservative
        // bound for constructed snapshot and Merkle nodes, so a local
        // checkpoint never understates restart validation.
        let anchors = self.incremental_closure_anchors(&parent_snapshot, transition_content)?;
        let linked_objects = self.verify_transition_closure_anchored(
            transition_content,
            &anchors,
            &parent_snapshot,
        )?;
        // The transaction's indexed admission delta bounds its new trie paths.
        // Cold ancestry validation independently reconstructs both index roots.
        let scan_growth = self.planner_scan_closure_growth(&loaded, fact)?;
        let closure_growth_upper = closure_growth_upper
            .checked_add(linked_objects)
            .and_then(|growth| growth.checked_add(budget_growth))
            .and_then(|growth| growth.checked_add(scan_growth))
            .ok_or_else(|| integrity("campaign-closure-object-limit"))?;
        let closure_objects = parent_checkpoint
            .closure_objects
            .checked_add(closure_growth_upper)
            .ok_or_else(|| integrity("campaign-closure-object-limit"))?;
        Ok(ValidationCheckpoint {
            ancestry_depth,
            closure_objects,
            lifecycle,
            genesis: parent_checkpoint.genesis,
            derived_branch,
        })
    }

    pub(super) fn promote_local_successor(
        &self,
        parent: ContentId,
        child: ContentId,
        checkpoint: ValidationCheckpoint,
    ) {
        let mut checkpoints = self.validation_checkpoints();
        checkpoints.remove(&parent);
        if checkpoints.len() >= MAX_VALIDATED_HEADS {
            checkpoints.clear();
        }
        checkpoints.insert(child, checkpoint);
    }

    pub(super) fn promote_local_branch(&self, child: ContentId, checkpoint: ValidationCheckpoint) {
        self.remember_validation_checkpoint(child, checkpoint);
    }

    pub(super) fn evict_local_checkpoint(&self, content: ContentId) {
        self.validation_checkpoints().remove(&content);
    }

    pub(super) fn current_lifecycle(
        &self,
        head: ContentId,
    ) -> Result<ProjectedState, CampaignRepositoryError> {
        Ok(self.load_validation_checkpoint(head)?.lifecycle)
    }

    fn remember_validation_checkpoint(&self, head: ContentId, checkpoint: ValidationCheckpoint) {
        let mut checkpoints = self.validation_checkpoints();
        if checkpoints.len() >= MAX_VALIDATED_HEADS {
            checkpoints.clear();
        }
        checkpoints.insert(head, checkpoint);
    }

    fn validation_checkpoints(
        &self,
    ) -> std::sync::MutexGuard<'_, BTreeMap<ContentId, ValidationCheckpoint>> {
        match self.validated_heads.lock() {
            Ok(checkpoints) => checkpoints,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    #[cfg(test)]
    pub(super) fn validate_snapshot_ancestry(
        &self,
        content_id: ContentId,
        choice_cache: &mut ChoiceValidationCache,
        maximum_depth: usize,
    ) -> Result<
        (
            usize,
            ProjectedState,
            ContentId,
            Option<DerivedBranchCheckpoint>,
        ),
        CampaignRepositoryError,
    > {
        self.validate_snapshot_ancestry_with_planner_context(
            content_id,
            choice_cache,
            maximum_depth,
            None,
        )
    }

    /// Validates original ancestry and owner transitions using checked tuples.
    ///
    /// # Errors
    ///
    /// Returns the original missing-object, corruption, depth, lifecycle, lineage,
    /// transition, root, budget, cursor, or exact Issue validation errors.
    #[cfg(test)]
    pub(super) fn validate_snapshot_ancestry_with_planner_context(
        &self,
        content_id: ContentId,
        choice_cache: &mut ChoiceValidationCache,
        maximum_depth: usize,
        planner_context: Option<&mut PlannerValidationContext>,
    ) -> Result<
        (
            usize,
            ProjectedState,
            ContentId,
            Option<DerivedBranchCheckpoint>,
        ),
        CampaignRepositoryError,
    > {
        self.validate_snapshot_ancestry_with_validation_reads(
            content_id,
            choice_cache,
            maximum_depth,
            planner_context,
            None,
        )
    }

    /// Preserves ancestry checks while sharing only strict Issue node reads.
    ///
    /// This validates transitions only; it does not authenticate closures.
    ///
    /// # Errors
    ///
    /// Returns the original ancestry bound, object, successor, or owner error.
    #[cfg(test)]
    pub(super) fn validate_snapshot_ancestry_with_validation_reads(
        &self,
        content_id: ContentId,
        choice_cache: &mut ChoiceValidationCache,
        maximum_depth: usize,
        planner_context: Option<&mut PlannerValidationContext>,
        merkle_reads: Option<&mut MerkleValidationReads>,
    ) -> Result<
        (
            usize,
            ProjectedState,
            ContentId,
            Option<DerivedBranchCheckpoint>,
        ),
        CampaignRepositoryError,
    > {
        self.validate_snapshot_history(
            content_id,
            choice_cache,
            maximum_depth,
            planner_context,
            merkle_reads,
            None,
        )
    }

    /// Validates every transition from `content_id` back to genesis.
    ///
    /// With `closure`, each step also authenticates the objects that the child
    /// makes newly reachable relative to its parent, and genesis authenticates
    /// its own closure. Resident state is one step's: the previous step's
    /// roots, one delta walk, and operator-bounded lifecycle actions.
    ///
    /// A cycle is impossible because a child's canonical bytes embed its
    /// parent's content ID. Mutation-command uniqueness needs no history set:
    /// every command-bearing successor proves its command absent from the
    /// parent's grow-only `accounting.command` index and inserts it.
    ///
    /// # Errors
    ///
    /// Returns the original ancestry bound, object, successor, owner, or
    /// closure error, or the first error returned by the closure sink.
    pub(super) fn validate_snapshot_history(
        &self,
        mut content_id: ContentId,
        choice_cache: &mut ChoiceValidationCache,
        maximum_depth: usize,
        mut planner_context: Option<&mut PlannerValidationContext>,
        mut merkle_reads: Option<&mut MerkleValidationReads>,
        mut closure: Option<&mut HistoryClosure<'_, '_>>,
    ) -> Result<
        (
            usize,
            ProjectedState,
            ContentId,
            Option<DerivedBranchCheckpoint>,
        ),
        CampaignRepositoryError,
    > {
        let mut verified_roots = BTreeSet::new();
        let mut expected_lineage = None;
        let mut actions = Vec::new();
        let mut derived_branch = None;
        // Older snapshots named by delta objects; each ancestor discharges its
        // own entry when the walk reaches it.
        let mut deferred_snapshots = BTreeSet::new();

        for depth in 1..=maximum_depth.min(MAX_CAMPAIGN_SNAPSHOT_ANCESTRY) {
            deferred_snapshots.remove(&content_id);
            let loaded = self.read_snapshot(content_id)?;
            self.validate_snapshot_references_once(&loaded, &mut verified_roots)?;
            // Only the previous step's roots can repeat in its parent.
            let current_roots = snapshot_roots(&loaded.snapshot);
            verified_roots.retain(|root| current_roots.contains(root));

            match expected_lineage {
                None => expected_lineage = Some(loaded.snapshot.lineage()),
                Some(lineage) if lineage != loaded.snapshot.lineage() => {
                    return Err(integrity("snapshot-ancestry-lineage-mismatch"));
                }
                Some(_) => {}
            }

            match (loaded.snapshot.parent(), loaded.snapshot.transition()) {
                (None, None) => {
                    self.validate_genesis_snapshot(&loaded)?;
                    if let Some(closure) = closure.as_deref_mut() {
                        let (objects, peak) = self.authenticate_genesis_closure(
                            &loaded,
                            choice_cache,
                            planner_context.as_deref_mut(),
                            closure.sink.as_deref_mut(),
                            &mut deferred_snapshots,
                        )?;
                        closure.add(objects, peak)?;
                        // A named snapshot that is not an ancestor still needs
                        // its own complete history and closure validation.
                        for snapshot in std::mem::take(&mut deferred_snapshots) {
                            self.delegated_snapshot_closure(snapshot, closure.sink.as_deref_mut())?;
                        }
                    }
                    actions.reverse();
                    let mut projected = ProjectedState::new();
                    for action in &actions {
                        match action {
                            LifecycleValidationAction::Control(action) => {
                                projected.apply(action)?;
                            }
                            LifecycleValidationAction::RequireRunning(reason) => {
                                if projected.visible != CampaignState::Running {
                                    return Err(integrity(reason));
                                }
                            }
                        }
                    }
                    return Ok((depth, projected, content_id, derived_branch));
                }
                (Some(parent), Some(transition)) => {
                    let (transition_fact, validated_planner_step) = self
                        .read_fact_with_planner_context(
                            transition.content_id(),
                            planner_context.as_deref_mut(),
                        )?;
                    let parent_snapshot = self.read_snapshot(parent.content_id())?;
                    let budget_fact = transition_fact.clone();
                    match transition_fact {
                        CampaignFact::CampaignDerived(derivation) => {
                            self.validate_derivation_successor(
                                &parent_snapshot,
                                &loaded,
                                derivation,
                                &mut BTreeSet::new(),
                            )?;
                            if derived_branch.is_none() {
                                derived_branch = Some(DerivedBranchCheckpoint {
                                    snapshot: content_id,
                                    derivation,
                                });
                            }
                        }
                        CampaignFact::ChoiceOpportunityDiscovered {
                            parent,
                            branch_point,
                            opportunity,
                        } => {
                            self.validate_choice_discovery_successor(
                                &parent_snapshot,
                                &loaded,
                                parent,
                                branch_point,
                                opportunity,
                            )?;
                        }
                        CampaignFact::ControlRequested(request) => {
                            if request.expected_snapshot != parent {
                                return Err(integrity("transition-precondition-parent-mismatch"));
                            }
                            self.validate_control_successor(
                                &parent_snapshot,
                                &loaded,
                                transition.content_id(),
                                &request,
                            )?;
                            actions.push(LifecycleValidationAction::Control(request.action));
                        }
                        CampaignFact::PinCommandAccepted(request) => {
                            if request.expected_snapshot != parent {
                                return Err(integrity("transition-precondition-parent-mismatch"));
                            }
                            self.validate_pin_successor(
                                &parent_snapshot,
                                &loaded,
                                transition.content_id(),
                                &request,
                            )?;
                        }
                        CampaignFact::DiscoveryRequested(request) => {
                            if request.expected_snapshot != parent {
                                return Err(integrity("transition-precondition-parent-mismatch"));
                            }
                            self.validate_discovery_request_successor(
                                &parent_snapshot,
                                &loaded,
                                transition.content_id(),
                                &request,
                            )?;
                        }
                        CampaignFact::SavepointCaptureRequested(request) => {
                            if request.expected_snapshot != parent {
                                return Err(integrity("transition-precondition-parent-mismatch"));
                            }
                            self.validate_savepoint_capture_successor(
                                &parent_snapshot,
                                &loaded,
                                transition.content_id(),
                                &request,
                                choice_cache,
                            )?;
                            push_require_running(
                                &mut actions,
                                "savepoint-capture-parent-is-not-running",
                            );
                        }
                        CampaignFact::SavepointCaptureResolved(resolution) => {
                            if resolution.expected_snapshot != parent {
                                return Err(integrity("transition-precondition-parent-mismatch"));
                            }
                            self.validate_savepoint_capture_resolution_successor(
                                &parent_snapshot,
                                &loaded,
                                transition.content_id(),
                                &resolution,
                                choice_cache,
                            )?;
                        }
                        CampaignFact::SavepointContinuationSelected(selection) => {
                            if selection.expected_snapshot != parent {
                                return Err(integrity("transition-precondition-parent-mismatch"));
                            }
                            self.validate_savepoint_continuation_successor(
                                &parent_snapshot,
                                &loaded,
                                transition.content_id(),
                                &selection,
                                choice_cache,
                            )?;
                            push_require_running(
                                &mut actions,
                                "savepoint-continuation-parent-is-not-running",
                            );
                        }
                        CampaignFact::BranchRequestAccepted { request, summary } => {
                            let request_record = self.read_branch_request(request.content_id())?;
                            let expected_summary = self.branch_acceptance_summary(
                                parent_snapshot.snapshot.roots().graph,
                                &request_record,
                            )?;
                            if summary != expected_summary {
                                return Err(integrity(
                                    "branch-request-acceptance-summary-mismatch",
                                ));
                            }
                            self.validate_branch_request_successor(
                                &parent_snapshot,
                                &loaded,
                                request,
                                transition.content_id(),
                            )?;
                        }
                        CampaignFact::ProposalIssued(proposal) => {
                            self.validate_proposal_successor(&parent_snapshot, &loaded, proposal)?;
                        }
                        CampaignFact::AttemptAdmitted(admission) => {
                            self.validate_attempt_admission_successor(
                                &parent_snapshot,
                                &loaded,
                                admission,
                            )?;
                        }
                        CampaignFact::PlannerAdvanced(step) => {
                            let validated_step =
                                validated_planner_step.as_ref().ok_or_else(|| {
                                    integrity("planner-step-transition-fact-was-not-validated")
                                })?;
                            match merkle_reads.as_deref_mut() {
                                Some(reads) => self
                                    .validate_planner_step_successor_with_validation_reads(
                                        &parent_snapshot,
                                        &loaded,
                                        step,
                                        validated_step,
                                        Some(reads),
                                    )?,
                                None => self.validate_planner_step_successor(
                                    &parent_snapshot,
                                    &loaded,
                                    step,
                                    validated_step,
                                )?,
                            }
                        }
                        CampaignFact::ObservationCredited(observation) => {
                            self.validate_credited_observation_successor(
                                &parent_snapshot,
                                &loaded,
                                observation,
                                choice_cache,
                            )?;
                        }
                        CampaignFact::FindingPublished(finding) => {
                            self.validate_finding_successor(
                                &parent_snapshot,
                                &loaded,
                                finding,
                                choice_cache,
                            )?;
                        }
                        CampaignFact::ObjectiveEvaluationPublished(evaluation) => {
                            self.validate_objective_evaluation_successor(
                                &parent_snapshot,
                                &loaded,
                                evaluation,
                                choice_cache,
                            )?;
                        }
                        CampaignFact::AttemptClosed {
                            attempt,
                            ordinal,
                            disposition,
                        } => {
                            self.validate_attempt_closed_successor(
                                &parent_snapshot,
                                &loaded,
                                transition.content_id(),
                                attempt,
                                ordinal,
                                disposition,
                            )?;
                        }
                        _ => {
                            return Err(integrity("snapshot-transition-type-is-not-implemented"));
                        }
                    }
                    self.validate_budget_successor(&parent_snapshot, &loaded, &budget_fact)?;
                    if let Some(closure) = closure.as_deref_mut() {
                        let (objects, peak) = self.authenticate_transition_delta(
                            TransitionStep {
                                parent: &parent_snapshot,
                                child: &loaded,
                                transition: &budget_fact,
                            },
                            choice_cache,
                            planner_context.as_deref_mut(),
                            closure.sink.as_deref_mut(),
                            &mut deferred_snapshots,
                        )?;
                        closure.add(objects, peak)?;
                    }
                    content_id = parent.content_id();
                }
                _ => return Err(integrity("snapshot-parent-transition-shape")),
            }
        }
        Err(integrity("snapshot-ancestry-limit"))
    }

    pub(super) fn validate_genesis_snapshot(
        &self,
        loaded: &LoadedSnapshot,
    ) -> Result<(), CampaignRepositoryError> {
        self.validate_genesis_budget(&loaded.snapshot)?;
        let lineage = self.read_lineage(required_child(&loaded.envelope, "lineage")?)?;
        let roots = loaded.snapshot.roots();
        let expected_genesis = lineage.genesis_content().content_id();
        let corpus = self.merkle.inspect_shallow(roots.corpus)?;
        if corpus.entry_count() != 1
            || self.merkle.get(
                roots.corpus,
                map_key_hash("corpus.configuration", lineage.genesis().as_hash()),
            )? != Some(expected_genesis)
        {
            return Err(integrity("genesis-configuration-root-mismatch"));
        }
        let graph = self.merkle.inspect_shallow(roots.graph)?;
        if graph.entry_count() != 2
            || self.merkle.get(
                roots.graph,
                map_key_hash("graph.configuration", lineage.genesis().as_hash()),
            )? != Some(expected_genesis)
        {
            return Err(integrity("genesis-configuration-root-mismatch"));
        }
        let choice_index = self
            .merkle
            .get(roots.graph, choice_index_anchor_key())?
            .ok_or_else(|| integrity("genesis-choice-index-root-mismatch"))?;
        if self.merkle.inspect_shallow(choice_index)?.entry_count() != 0 {
            return Err(integrity("genesis-choice-index-root-mismatch"));
        }

        let exploration = self.merkle.inspect_shallow(roots.exploration)?;
        if exploration.entry_count() != 3 {
            return Err(integrity("genesis-exploration-index-root-mismatch"));
        }
        for (anchor, reason) in [
            (
                frontier_index_anchor_key(),
                "genesis-frontier-index-root-mismatch",
            ),
            (
                branch_request_index_anchor_key(),
                "genesis-branch-request-index-root-mismatch",
            ),
            (
                planner_scan_index_anchor_key(),
                "genesis-planner-scan-index-root-mismatch",
            ),
        ] {
            let index = self
                .merkle
                .get(roots.exploration, anchor)?
                .ok_or_else(|| integrity(reason))?;
            if self.merkle.inspect_shallow(index)?.entry_count() != 0 {
                return Err(integrity(reason));
            }
        }

        let observations = self.merkle.inspect_shallow(roots.observations)?;
        // Genesis observations hold exactly the two empty index anchors.
        if observations.entry_count() != 2 {
            return Err(integrity("genesis-observation-index-root-mismatch"));
        }
        let choice_sources = self
            .merkle
            .get(roots.observations, choice_source_index_anchor_key())?
            .ok_or_else(|| integrity("genesis-choice-source-index-root-mismatch"))?;
        if self.merkle.inspect_shallow(choice_sources)?.entry_count() != 0 {
            return Err(integrity("genesis-choice-source-index-root-mismatch"));
        }
        let direct_selection_index = self
            .merkle
            .get(roots.observations, direct_selection_index_anchor_key())?
            .ok_or_else(|| integrity("genesis-direct-selection-index-root-mismatch"))?;
        if self
            .merkle
            .inspect_shallow(direct_selection_index)?
            .entry_count()
            != 0
        {
            return Err(integrity("genesis-direct-selection-index-root-mismatch"));
        }

        let empty_roots = [
            roots.coverage,
            roots.findings,
            roots.pins,
            roots.accounting,
            roots.coordination,
        ];
        for root in empty_roots {
            if self.merkle.inspect_shallow(root)?.entry_count() != 0 {
                return Err(integrity("genesis-nonconfiguration-root-is-not-empty"));
            }
        }
        if empty_roots.windows(2).any(|pair| pair[0] != pair[1]) {
            return Err(integrity("genesis-empty-roots-are-not-canonical"));
        }
        Ok(())
    }

    pub(super) fn validate_snapshot_references_once(
        &self,
        loaded: &LoadedSnapshot,
        verified_roots: &mut BTreeSet<ContentId>,
    ) -> Result<(), CampaignRepositoryError> {
        let lineage = self.read_lineage(required_child(&loaded.envelope, "lineage")?)?;
        if lineage.id()? != loaded.snapshot.lineage() {
            return Err(integrity("snapshot-lineage-logical-id"));
        }
        let policy = self.read_policy(required_child(&loaded.envelope, "active-policy")?)?;
        if policy.id()? != loaded.snapshot.active_policy()
            || policy.scenario() != lineage.scenario()
        {
            return Err(integrity("snapshot-policy-logical-id-or-scenario"));
        }
        for root in snapshot_roots(&loaded.snapshot) {
            if verified_roots.insert(root) {
                self.merkle.inspect_shallow(root)?;
            }
        }
        let roots = loaded.snapshot.roots();
        for (root, key, reason) in [
            (
                roots.graph,
                choice_index_anchor_key(),
                "current-campaign-choice-index-is-missing",
            ),
            (
                roots.observations,
                choice_source_index_anchor_key(),
                "current-campaign-choice-source-index-is-missing",
            ),
            (
                roots.exploration,
                frontier_index_anchor_key(),
                "current-campaign-frontier-index-is-missing",
            ),
            (
                roots.exploration,
                branch_request_index_anchor_key(),
                "current-campaign-branch-request-index-is-missing",
            ),
            (
                roots.exploration,
                planner_scan_index_anchor_key(),
                "current-campaign-planner-scan-index-is-missing",
            ),
            (
                roots.observations,
                direct_selection_index_anchor_key(),
                "current-campaign-direct-selection-index-is-missing",
            ),
        ] {
            self.merkle
                .get(root, key)?
                .ok_or_else(|| integrity(reason))?;
        }
        Ok(())
    }

    pub(super) fn verify_campaign_closure(
        &self,
        root: ContentId,
    ) -> Result<usize, CampaignRepositoryError> {
        self.verify_campaign_closure_anchored(root, &BTreeSet::new())
    }
}

/// Lifecycle obligation collected while walking backward and replayed forward.
enum LifecycleValidationAction {
    Control(CampaignControlAction),
    RequireRunning(&'static str),
}

/// Records that the parent of a savepoint transition must be running.
///
/// Consecutive running requirements between the same two controls observe the
/// same projected state, so only the oldest one, which forward replay checks
/// first, is retained. The list therefore grows with operator controls rather
/// than with savepoint traffic.
fn push_require_running(actions: &mut Vec<LifecycleValidationAction>, reason: &'static str) {
    if let Some(LifecycleValidationAction::RequireRunning(prior)) = actions.last_mut() {
        *prior = reason;
        return;
    }
    actions.push(LifecycleValidationAction::RequireRunning(reason));
}

mod incremental;
