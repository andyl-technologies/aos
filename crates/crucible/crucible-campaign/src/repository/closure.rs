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
    /// Authenticated campaign metadata work, with RAM graphs charged separately.
    pub closure_objects: usize,
    /// Fixed in-memory size of one retained checkpoint value.
    pub checkpoint_bytes: usize,
}

mod ancestry;
mod planner;
pub(in crate::repository) mod read;
mod successors;

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
        let mut values = BTreeSet::new();
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
                MAX_CAMPAIGN_CLOSURE_OBJECTS,
            )?;
        }

        let transition = child
            .transition()
            .ok_or_else(|| integrity("local-successor-checkpoint-shape"))?
            .content_id();
        let mut anchors = self.incremental_closure_anchors(parent, transition)?;
        let mut linked_ids = BTreeSet::new();
        self.verify_campaign_closures_anchored_cached_collect(
            [transition],
            &anchors,
            &mut ChoiceValidationCache::default(),
            incremental::ClosureCollection {
                objects: Some(&mut linked_ids),
                ..incremental::ClosureCollection::default()
            },
            &mut || Ok(()),
        )?;
        anchors.extend(linked_ids);
        let leaf_growth = self.verify_campaign_closures_anchored_cached(
            values,
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

    pub(in crate::repository) fn validate_complete_head_with_boundary(
        &self,
        head: ContentId,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<(), CampaignRepositoryError> {
        self.load_validation_checkpoint_with_boundary(head, boundary)
            .map(|_| ())
    }

    pub(super) fn load_validation_checkpoint(
        &self,
        head: ContentId,
    ) -> Result<ValidationCheckpoint, CampaignRepositoryError> {
        self.load_validation_checkpoint_with_boundary(head, &mut || Ok(()))
    }

    fn load_validation_checkpoint_with_boundary(
        &self,
        head: ContentId,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<ValidationCheckpoint, CampaignRepositoryError> {
        boundary().map_err(CampaignRepositoryError::Ram)?;
        if let Some(checkpoint) = self.validation_checkpoints().get(&head).copied() {
            return Ok(checkpoint);
        }

        let mut choice_cache = ChoiceValidationCache::default();
        let (ancestry_depth, lifecycle, genesis, derived_branch) = self
            .validate_snapshot_ancestry_with_boundary(
                head,
                &mut choice_cache,
                MAX_SNAPSHOT_ANCESTRY,
                boundary,
            )?;
        let closure_objects = self.verify_campaign_closures_anchored_cached_collect(
            [head],
            &BTreeSet::new(),
            &mut choice_cache,
            incremental::ClosureCollection::default(),
            boundary,
        )?;
        let checkpoint = ValidationCheckpoint {
            ancestry_depth,
            closure_objects,
            lifecycle,
            genesis,
            derived_branch,
        };
        self.remember_validation_checkpoint(head, checkpoint);
        Ok(checkpoint)
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
        if ancestry_depth > MAX_SNAPSHOT_ANCESTRY {
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
        let linked_objects = self.verify_campaign_closure_anchored(transition_content, &anchors)?;
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
        if closure_objects <= MAX_CAMPAIGN_CLOSURE_OBJECTS {
            return Ok(ValidationCheckpoint {
                ancestry_depth,
                closure_objects,
                lifecycle,
                genesis: parent_checkpoint.genesis,
                derived_branch,
            });
        }

        let mut choice_cache = ChoiceValidationCache::default();
        let (ancestry_depth, lifecycle, genesis, derived_branch) =
            self.validate_snapshot_ancestry(child, &mut choice_cache, MAX_SNAPSHOT_ANCESTRY)?;
        let closure_objects = self.verify_campaign_closures_anchored_cached(
            [child],
            &BTreeSet::new(),
            &mut choice_cache,
        )?;
        Ok(ValidationCheckpoint {
            ancestry_depth,
            closure_objects,
            lifecycle,
            genesis,
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
        self.validate_snapshot_ancestry_with_boundary(
            content_id,
            choice_cache,
            maximum_depth,
            &mut || Ok(()),
        )
    }

    fn validate_snapshot_ancestry_with_boundary(
        &self,
        content_id: ContentId,
        choice_cache: &mut ChoiceValidationCache,
        maximum_depth: usize,
        boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    ) -> Result<
        (
            usize,
            ProjectedState,
            ContentId,
            Option<DerivedBranchCheckpoint>,
        ),
        CampaignRepositoryError,
    > {
        let reader = read::ClosureRead::Compatibility(self);
        reader.semantic(boundary).validate_snapshot_ancestry(
            content_id,
            choice_cache,
            maximum_depth,
        )
    }

    pub(super) fn verify_campaign_closure(
        &self,
        root: ContentId,
    ) -> Result<usize, CampaignRepositoryError> {
        self.verify_campaign_closure_anchored(root, &BTreeSet::new())
    }

    /// Reuses exact immutable roots only after complete head authentication.
    pub(super) fn authenticated_head_closure_anchors(
        &self,
        parent: &LoadedSnapshot,
    ) -> Result<BTreeSet<ContentId>, CampaignRepositoryError> {
        let mut anchors = BTreeSet::from([
            parent.envelope.content_id(),
            parent.snapshot.lineage().content_id(),
            parent.snapshot.active_policy().content_id(),
        ]);
        anchors.extend(snapshot_roots(&parent.snapshot));

        // These immutable basis records were authenticated with the parent.
        // Anchor their direct reusable roots as well because a new transition
        // can reference them without passing through the basis record itself.
        for basis in [
            parent.snapshot.lineage().content_id(),
            parent.snapshot.active_policy().content_id(),
        ] {
            let handle = self.blobs.read(basis, None)?;
            let envelope =
                ObjectEnvelope::from_canonical_bytes(&handle.read_all(MAX_ENVELOPE_BYTES)?)?;
            if envelope.content_id() != basis {
                return Err(integrity("incremental-closure-anchor-envelope-id"));
            }
            anchors.extend(envelope.children().iter().map(crate::ChildReference::id));
        }

        let roots = parent.snapshot.roots();
        if let Some(step) = self.merkle.get(roots.coordination, planner_head_key())? {
            anchors.insert(step);
            let envelope =
                self.require_record_kind(step, crate::CampaignRecordKind::PlannerStep)?;
            anchors.extend(envelope.children().iter().map(crate::ChildReference::id));
        }
        Ok(anchors)
    }
}

mod incremental;
pub use incremental::CampaignStorageClosure;
