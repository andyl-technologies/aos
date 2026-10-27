//! Inductive closure-delta authentication for complete history validation.
//!
//! Walking a head's ancestry backward, genesis authenticates its own closure
//! and every transition authenticates only the objects its child makes newly
//! reachable relative to exact parent-owned anchors. [`HistoryClosure`]
//! accumulates the per-step counts and the largest per-step resident state,
//! and forwards every authenticated object to an optional sink.

use super::*;

/// Closure accounting and observer for one inductive history walk.
pub(in crate::repository) struct HistoryClosure<'w, 's> {
    /// Sum of every transition's newly reachable object count.
    pub(in crate::repository) objects: usize,
    /// Receives every authenticated object of every transition delta.
    pub(in crate::repository) sink: Option<&'w mut ClosureSink<'s>>,
    /// Largest resident entry total reached by any genesis or delta walk.
    pub(in crate::repository) peak_resident: usize,
}

impl HistoryClosure<'_, '_> {
    pub(super) fn add(
        &mut self,
        objects: usize,
        peak_resident: usize,
    ) -> Result<(), CampaignRepositoryError> {
        self.peak_resident = self.peak_resident.max(peak_resident);
        self.objects = self
            .objects
            .checked_add(objects)
            .ok_or_else(|| integrity("campaign-closure-object-limit"))?;
        Ok(())
    }
}

/// One authenticated parent-to-child transition whose closure delta is walked.
#[derive(Clone, Copy)]
pub(super) struct TransitionStep<'a> {
    pub(super) parent: &'a LoadedSnapshot,
    pub(super) child: &'a LoadedSnapshot,
    /// Decoded transition fact, already authenticated by the successor check.
    pub(super) transition: &'a CampaignFact,
}

impl CampaignRepository {
    /// Repeats complete cold validation of one head and reports its peak walk state.
    ///
    /// The result is the largest number of visited objects, traversed trie
    /// positions, and pending walk entries that any single genesis or
    /// transition walk retained. It exists so conformance gates can verify
    /// that cold validation memory does not grow with ancestry length. No
    /// checkpoint is read, promoted, or evicted.
    ///
    /// # Errors
    ///
    /// Returns an error when the campaign head is absent or fails complete
    /// ancestry and closure validation.
    #[cfg(any(test, feature = "test-support"))]
    pub fn cold_validation_peak_resident(
        &self,
        campaign: &str,
    ) -> Result<usize, CampaignRepositoryError> {
        let head = self.head(campaign)?;
        let mut closure = HistoryClosure {
            objects: 0,
            sink: None,
            peak_resident: 0,
        };
        self.validate_snapshot_history(
            head.snapshot_id().content_id(),
            &mut ChoiceValidationCache::default(),
            MAX_CAMPAIGN_SNAPSHOT_ANCESTRY,
            Some(&mut PlannerValidationContext::default()),
            None,
            Some(&mut closure),
        )?;
        Ok(closure.peak_resident)
    }

    /// Streams the complete authenticated closure of one validated head.
    ///
    /// This always runs the inductive history walk, even when a checkpoint is
    /// retained, because a checkpoint does not carry the closure itself. Each
    /// object is delivered at least once; the delta walks deduplicate only
    /// within one transition. A successful walk promotes the head checkpoint.
    ///
    /// # Errors
    ///
    /// Returns every original ancestry, transition, or closure error, or the
    /// first error returned by `sink`. Objects delivered before an error must
    /// be discarded.
    pub(in crate::repository) fn visit_validated_head_closure(
        &self,
        head: ContentId,
        sink: &mut ClosureSink<'_>,
    ) -> Result<usize, CampaignRepositoryError> {
        let mut planner_context = PlannerValidationContext::default();
        let checkpoint =
            self.validate_history_with_closure(head, Some(&mut planner_context), None, Some(sink))?;
        self.remember_validation_checkpoint(head, checkpoint);
        Ok(checkpoint.closure_objects)
    }

    /// Authenticates a snapshot reached inside another closure walk.
    ///
    /// Without a sink, a retained checkpoint already proves the complete
    /// closure. With a sink, the closure itself must be produced.
    ///
    /// # Errors
    ///
    /// Returns every original ancestry, transition, or closure error.
    pub(in crate::repository) fn delegated_snapshot_closure(
        &self,
        snapshot: ContentId,
        sink: Option<&mut ClosureSink<'_>>,
    ) -> Result<(), CampaignRepositoryError> {
        match sink {
            None => self.load_validation_checkpoint(snapshot).map(|_| ()),
            Some(sink) => self
                .visit_validated_head_closure(snapshot, sink)
                .map(|_| ()),
        }
    }

    /// Reuses exact immutable roots only after complete head authentication.
    pub(in crate::repository) fn authenticated_head_closure_anchors(
        &self,
        parent: &LoadedSnapshot,
    ) -> Result<BTreeSet<ContentId>, CampaignRepositoryError> {
        // Every direct child of the authenticated parent envelope is owned by
        // its closure. A successor's coordination index names the parent's
        // transition fact as its result, so that fact is an anchor as well.
        let mut anchors = BTreeSet::from([parent.envelope.content_id()]);
        anchors.extend(
            parent
                .envelope
                .children()
                .iter()
                .map(crate::ChildReference::id),
        );

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

    /// Authenticates the complete closure of a genesis snapshot.
    ///
    /// Genesis has no parent, so every child is walked. Its roots are the
    /// canonical genesis indexes, which keeps this closure small.
    ///
    /// # Errors
    ///
    /// Returns original store, codec, closure-bound, child, record, or trie
    /// integrity errors, or the first error returned by `sink`.
    pub(super) fn authenticate_genesis_closure(
        &self,
        genesis: &LoadedSnapshot,
        choice_cache: &mut ChoiceValidationCache,
        planner_context: Option<&mut PlannerValidationContext>,
        sink: Option<&mut ClosureSink<'_>>,
        deferred_snapshots: &mut BTreeSet<ContentId>,
    ) -> Result<(usize, usize), CampaignRepositoryError> {
        let mut context = WalkContext {
            anchors: &BTreeSet::new(),
            exact_roots: false,
            choice_cache,
            planner_context,
            sink,
            deferred_snapshots: Some(deferred_snapshots),
            parent_accounting: None,
            peak_resident: 0,
        };
        let objects = self.walk_campaign_closure(
            WalkStart::Snapshot {
                loaded: genesis,
                predecessor: None,
            },
            &mut context,
        )?;
        Ok((objects, context.peak_resident))
    }

    /// Authenticates the objects one transition makes newly reachable.
    ///
    /// Anchors are exact parent-owned objects. Children shared with the parent
    /// snapshot are covered, and each changed root, including the budget
    /// ledger's request indexes, is authenticated as a diff of changed trie
    /// positions followed by walks of its changed values. The transition fact
    /// and any newly linked graph are walked relative to the same anchors.
    /// Every skipped object is owned by the parent closure, which the parent
    /// step or genesis authenticates, so walking backward is sound.
    ///
    /// # Errors
    ///
    /// Returns original store, codec, closure-bound, child, record, or trie
    /// integrity errors, or the first error returned by `sink`.
    pub(super) fn authenticate_transition_delta(
        &self,
        TransitionStep {
            parent,
            child,
            transition,
        }: TransitionStep<'_>,
        choice_cache: &mut ChoiceValidationCache,
        planner_context: Option<&mut PlannerValidationContext>,
        sink: Option<&mut ClosureSink<'_>>,
        deferred_snapshots: &mut BTreeSet<ContentId>,
    ) -> Result<(usize, usize), CampaignRepositoryError> {
        // The transition fact was authenticated and decoded by the successor
        // check; the walk still reads its bytes again as a closure object.
        let anchors = self.incremental_closure_anchors_for_fact(parent, transition)?;
        let mut context = WalkContext {
            anchors: &anchors,
            exact_roots: false,
            choice_cache,
            planner_context,
            sink,
            deferred_snapshots: Some(deferred_snapshots),
            parent_accounting: Some(parent.snapshot.roots().accounting),
            peak_resident: 0,
        };
        let objects = self.walk_campaign_closure(
            WalkStart::Snapshot {
                loaded: child,
                predecessor: Some(parent),
            },
            &mut context,
        )?;
        Ok((objects, context.peak_resident))
    }
}
