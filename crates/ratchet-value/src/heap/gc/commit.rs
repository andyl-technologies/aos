//! The minor-GC commit plan: staged buffers, the ordered commit pipeline,
//! and its report.
//!
//! Moved verbatim from `heap/gc.rs` under the RFC-0007 §2 file-size cap; the
//! parent re-exports every public path.

use super::*;

/// A metadata commit plan for the ordered side effects of one minor collection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MinorGcCommitPlan {
    object_copies: MinorGcObjectCopyPlan,
    forwarding_pointers: MinorGcForwardingPointerPlan,
    reference_rewrites: MinorGcReferenceRewritePlan,
    remembered_set_refresh: MinorGcRememberedSetRefreshPlan,
    next_remembered_set: RememberedSet,
}

/// Caller-owned mutation buffers for applying one minor-GC commit plan.
pub struct MinorGcCommitBuffers<'a, 'bytes> {
    object_byte_copies: &'a mut [MinorGcObjectByteCopyBuffer<'bytes>],
    forwarding_slots: &'a mut [MinorGcForwardingSlot],
    references: &'a mut [ResolvedValueGeneration],
    remembered_set: &'a mut RememberedSet,
    card_table: Option<&'a mut GcCardTable>,
}

impl<'a, 'bytes> MinorGcCommitBuffers<'a, 'bytes> {
    /// Creates caller-owned buffers for a minor-GC commit application.
    pub fn new(
        object_byte_copies: &'a mut [MinorGcObjectByteCopyBuffer<'bytes>],
        forwarding_slots: &'a mut [MinorGcForwardingSlot],
        references: &'a mut [ResolvedValueGeneration],
        remembered_set: &'a mut RememberedSet,
    ) -> Self {
        Self {
            object_byte_copies,
            forwarding_slots,
            references,
            remembered_set,
            card_table: None,
        }
    }

    /// Creates caller-owned buffers plus a card table to clear after commit.
    pub fn with_card_table(
        object_byte_copies: &'a mut [MinorGcObjectByteCopyBuffer<'bytes>],
        forwarding_slots: &'a mut [MinorGcForwardingSlot],
        references: &'a mut [ResolvedValueGeneration],
        remembered_set: &'a mut RememberedSet,
        card_table: &'a mut GcCardTable,
    ) -> Self {
        Self {
            object_byte_copies,
            forwarding_slots,
            references,
            remembered_set,
            card_table: Some(card_table),
        }
    }
}

/// Caller-owned state for applying one minor-GC commit into owned destination storage.
pub struct MinorGcOwnedCommitBuffers<'a, 'bytes> {
    destination_storage: &'a mut MinorGcOwnedDestinationStorage,
    source_bytes: &'a [MinorGcSourceObjectBytes<'bytes>],
    forwarding_slots: &'a mut [MinorGcForwardingSlot],
    references: &'a mut [ResolvedValueGeneration],
    remembered_set: &'a mut RememberedSet,
    card_table: Option<&'a mut GcCardTable>,
}

impl<'a, 'bytes> MinorGcOwnedCommitBuffers<'a, 'bytes> {
    /// Creates caller-owned state for a minor-GC commit using owned destination storage.
    pub fn new(
        destination_storage: &'a mut MinorGcOwnedDestinationStorage,
        source_bytes: &'a [MinorGcSourceObjectBytes<'bytes>],
        forwarding_slots: &'a mut [MinorGcForwardingSlot],
        references: &'a mut [ResolvedValueGeneration],
        remembered_set: &'a mut RememberedSet,
    ) -> Self {
        Self {
            destination_storage,
            source_bytes,
            forwarding_slots,
            references,
            remembered_set,
            card_table: None,
        }
    }

    /// Creates caller-owned state plus a card table to clear after commit.
    pub fn with_card_table(
        destination_storage: &'a mut MinorGcOwnedDestinationStorage,
        source_bytes: &'a [MinorGcSourceObjectBytes<'bytes>],
        forwarding_slots: &'a mut [MinorGcForwardingSlot],
        references: &'a mut [ResolvedValueGeneration],
        remembered_set: &'a mut RememberedSet,
        card_table: &'a mut GcCardTable,
    ) -> Self {
        Self {
            destination_storage,
            source_bytes,
            forwarding_slots,
            references,
            remembered_set,
            card_table: Some(card_table),
        }
    }
}

/// A summary of mutations applied by a minor-GC commit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MinorGcCommitReport {
    object_copies: usize,
    copied_to_nursery: usize,
    promoted_to_old: usize,
    forwarding_pointers: usize,
    reference_rewrites: usize,
    remembered_set_source_epoch: RememberedSetEpoch,
    remembered_set_next_epoch: RememberedSetEpoch,
    remembered_set_source_edges: usize,
    remembered_set_published_edges: usize,
    card_table_dirty_cards_cleared: usize,
}

impl MinorGcCommitReport {
    fn from_commit_parts(
        object_copies: &MinorGcObjectCopyPlan,
        forwarding_pointers: &MinorGcForwardingPointerPlan,
        reference_rewrites: &MinorGcReferenceRewritePlan,
        remembered_set_refresh: &MinorGcRememberedSetRefreshPlan,
        next_remembered_set: &RememberedSet,
    ) -> Self {
        let mut copied_to_nursery = 0;
        let mut promoted_to_old = 0;
        for copy in object_copies.copies() {
            match copy.action() {
                MinorGcSurvivorAction::CopyToNursery => copied_to_nursery += 1,
                MinorGcSurvivorAction::PromoteToOld => promoted_to_old += 1,
            }
        }

        Self {
            object_copies: object_copies.len(),
            copied_to_nursery,
            promoted_to_old,
            forwarding_pointers: forwarding_pointers.len(),
            reference_rewrites: reference_rewrites.len(),
            remembered_set_source_epoch: remembered_set_refresh.source_epoch(),
            remembered_set_next_epoch: next_remembered_set.epoch(),
            remembered_set_source_edges: remembered_set_refresh.len(),
            remembered_set_published_edges: next_remembered_set.len(),
            card_table_dirty_cards_cleared: 0,
        }
    }

    /// Returns the number of object byte copies committed.
    pub const fn object_copies(self) -> usize {
        self.object_copies
    }

    /// Returns the number of survivors copied to the next nursery.
    pub const fn copied_to_nursery(self) -> usize {
        self.copied_to_nursery
    }

    /// Returns the number of survivors promoted to old generation.
    pub const fn promoted_to_old(self) -> usize {
        self.promoted_to_old
    }

    /// Returns the number of forwarding pointers installed.
    pub const fn forwarding_pointers(self) -> usize {
        self.forwarding_pointers
    }

    /// Returns the number of root or field references rewritten.
    pub const fn reference_rewrites(self) -> usize {
        self.reference_rewrites
    }

    /// Returns the remembered-set epoch consumed by the commit.
    pub const fn remembered_set_source_epoch(self) -> RememberedSetEpoch {
        self.remembered_set_source_epoch
    }

    /// Returns the remembered-set epoch published by the commit.
    pub const fn remembered_set_next_epoch(self) -> RememberedSetEpoch {
        self.remembered_set_next_epoch
    }

    /// Returns the number of remembered edges examined from the source epoch.
    pub const fn remembered_set_source_edges(self) -> usize {
        self.remembered_set_source_edges
    }

    /// Returns the number of remembered edges published for the next epoch.
    pub const fn remembered_set_published_edges(self) -> usize {
        self.remembered_set_published_edges
    }

    /// Returns the number of dirty-card markers cleared after commit.
    pub const fn card_table_dirty_cards_cleared(self) -> usize {
        self.card_table_dirty_cards_cleared
    }
}

impl MinorGcCommitPlan {
    /// Builds a minor-GC commit plan from already validated subplans.
    ///
    /// The commit plan records the deterministic order a later collector
    /// implementation will use: copy/promote object bytes, install forwarding
    /// pointers, rewrite roots and fields, then publish the rebuilt remembered
    /// set for the next minor epoch. This remains metadata only and does not
    /// perform those mutations.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if any subplan does not match
    /// `object_copies`, if the remembered-set epoch cannot advance, or if
    /// rebuilding the next remembered set cannot reserve storage.
    pub fn from_parts(
        object_copies: MinorGcObjectCopyPlan,
        forwarding_pointers: MinorGcForwardingPointerPlan,
        reference_rewrites: MinorGcReferenceRewritePlan,
        remembered_set_refresh: MinorGcRememberedSetRefreshPlan,
    ) -> Result<Self, GenerationalGcError> {
        validate_forwarding_plan_matches_object_copies(&object_copies, &forwarding_pointers)?;
        validate_reference_rewrites_match_object_copies(&object_copies, &reference_rewrites)?;
        validate_remembered_set_refresh_matches_object_copies(
            &object_copies,
            &remembered_set_refresh,
        )?;
        let next_remembered_set = remembered_set_refresh.rebuild_remembered_set()?;

        Ok(Self {
            object_copies,
            forwarding_pointers,
            reference_rewrites,
            remembered_set_refresh,
            next_remembered_set,
        })
    }

    /// Builds a minor-GC commit plan that includes dirty old-field rescans.
    ///
    /// This validates the ordinary commit subplans, validates each dirty
    /// old/permanent field rescan decision against the object-copy schedule,
    /// and precomputes the next remembered set from both retained source
    /// snapshot edges and retained dirty-card rescan edges.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if any subplan or old-field rescan does
    /// not match `object_copies`, if the remembered-set epoch cannot advance, or
    /// if rebuilding the next remembered set cannot reserve storage.
    pub fn from_parts_with_old_field_rescan(
        object_copies: MinorGcObjectCopyPlan,
        forwarding_pointers: MinorGcForwardingPointerPlan,
        reference_rewrites: MinorGcReferenceRewritePlan,
        remembered_set_refresh: MinorGcRememberedSetRefreshPlan,
        old_field_rescan: &MinorGcOldFieldRescanPlan,
    ) -> Result<Self, GenerationalGcError> {
        validate_forwarding_plan_matches_object_copies(&object_copies, &forwarding_pointers)?;
        validate_reference_rewrites_match_object_copies(&object_copies, &reference_rewrites)?;
        validate_remembered_set_refresh_matches_object_copies(
            &object_copies,
            &remembered_set_refresh,
        )?;
        validate_old_field_rescan_matches_object_copies(&object_copies, old_field_rescan)?;
        let next_remembered_set = remembered_set_refresh
            .rebuild_remembered_set_with_old_field_rescan(old_field_rescan)?;

        Ok(Self {
            object_copies,
            forwarding_pointers,
            reference_rewrites,
            remembered_set_refresh,
            next_remembered_set,
        })
    }

    /// Returns object-copy metadata for the commit.
    pub fn object_copies(&self) -> &MinorGcObjectCopyPlan {
        &self.object_copies
    }

    /// Returns forwarding-pointer metadata for the commit.
    pub fn forwarding_pointers(&self) -> &MinorGcForwardingPointerPlan {
        &self.forwarding_pointers
    }

    /// Returns reference-rewrite metadata for the commit.
    pub fn reference_rewrites(&self) -> &MinorGcReferenceRewritePlan {
        &self.reference_rewrites
    }

    /// Returns remembered-set refresh metadata for the commit.
    pub fn remembered_set_refresh(&self) -> &MinorGcRememberedSetRefreshPlan {
        &self.remembered_set_refresh
    }

    /// Returns the rebuilt remembered set for the next minor-GC epoch.
    pub fn next_remembered_set(&self) -> &RememberedSet {
        &self.next_remembered_set
    }

    /// Applies this commit plan to caller-owned mutation buffers.
    ///
    /// The method validates every supplied buffer before making any mutation:
    /// object byte buffers must match the object-copy schedule, forwarding
    /// slots must match and be empty, planned reference slots must still contain
    /// the expected young from-space values, no unplanned young reference may be
    /// present, and the remembered set must still match the refresh source
    /// snapshot. If validation succeeds, mutations are applied in commit order:
    /// copy object bytes, install forwarding values, rewrite references, publish
    /// the next remembered set, then clear the card table when one is supplied.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if any caller-owned buffer no longer
    /// matches this commit plan.
    pub fn apply_to_buffers(
        self,
        buffers: MinorGcCommitBuffers<'_, '_>,
    ) -> Result<(), GenerationalGcError> {
        self.apply_to_buffers_with_report(buffers).map(|_| ())
    }

    /// Applies this commit plan and reports the committed mutation counts.
    ///
    /// This has the same validation and mutation order as
    /// [`Self::apply_to_buffers`], but returns a summary after the byte-copy,
    /// forwarding-pointer, reference-rewrite, remembered-set publication, and
    /// optional card-table clearing steps have all succeeded.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if any caller-owned buffer no longer
    /// matches this commit plan.
    pub fn apply_to_buffers_with_report(
        self,
        buffers: MinorGcCommitBuffers<'_, '_>,
    ) -> Result<MinorGcCommitReport, GenerationalGcError> {
        let Self {
            object_copies,
            forwarding_pointers,
            reference_rewrites,
            remembered_set_refresh,
            next_remembered_set,
        } = self;
        let MinorGcCommitBuffers {
            object_byte_copies,
            forwarding_slots,
            references,
            remembered_set,
            card_table,
        } = buffers;

        let mut report = MinorGcCommitReport::from_commit_parts(
            &object_copies,
            &forwarding_pointers,
            &reference_rewrites,
            &remembered_set_refresh,
            &next_remembered_set,
        );

        validate_object_byte_copy_buffers_match_plan(&object_copies, object_byte_copies)?;
        validate_forwarding_slots_match_plan(&forwarding_pointers, forwarding_slots)?;
        validate_reference_rewrite_commit_slots_match_plan(&reference_rewrites, references)?;
        validate_remembered_set_publication_source(&remembered_set_refresh, remembered_set)?;

        copy_object_byte_buffers(object_byte_copies);
        install_forwarding_slots(&forwarding_pointers, forwarding_slots);
        apply_reference_rewrites(&reference_rewrites, references);
        *remembered_set = next_remembered_set;
        if let Some(card_table) = card_table {
            report.card_table_dirty_cards_cleared = card_table.clear_dirty_cards().dirty_cards();
        }
        Ok(report)
    }

    /// Applies this commit plan to owned destination storage and caller-owned metadata slots.
    ///
    /// This is the owned-storage counterpart to [`Self::apply_to_buffers`].
    /// It validates the source-byte inventory against the destination storage
    /// and object-copy schedule, then validates forwarding slots, reference
    /// rewrites, unplanned young references, and remembered-set publication
    /// before making any mutation.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if the owned destination storage,
    /// source-byte inventory, forwarding slots, reference slots, or
    /// remembered-set state no longer match this commit plan.
    pub fn apply_to_owned_destination_storage(
        self,
        buffers: MinorGcOwnedCommitBuffers<'_, '_>,
    ) -> Result<(), GenerationalGcError> {
        self.apply_to_owned_destination_storage_with_report(buffers)
            .map(|_| ())
    }

    /// Applies this commit plan to owned destination storage and reports mutation counts.
    ///
    /// This has the same validation and mutation order as
    /// [`Self::apply_to_owned_destination_storage`], but returns a summary after
    /// destination byte copying, forwarding-pointer installation, reference
    /// rewriting, remembered-set publication, and optional card-table clearing.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if the owned destination storage,
    /// source-byte inventory, forwarding slots, reference slots, or
    /// remembered-set state no longer match this commit plan.
    pub fn apply_to_owned_destination_storage_with_report(
        self,
        buffers: MinorGcOwnedCommitBuffers<'_, '_>,
    ) -> Result<MinorGcCommitReport, GenerationalGcError> {
        let Self {
            object_copies,
            forwarding_pointers,
            reference_rewrites,
            remembered_set_refresh,
            next_remembered_set,
        } = self;
        let MinorGcOwnedCommitBuffers {
            destination_storage,
            source_bytes,
            forwarding_slots,
            references,
            remembered_set,
            card_table,
        } = buffers;

        let mut report = MinorGcCommitReport::from_commit_parts(
            &object_copies,
            &forwarding_pointers,
            &reference_rewrites,
            &remembered_set_refresh,
            &next_remembered_set,
        );

        destination_storage.validate_copy_from_sources(&object_copies, source_bytes)?;
        validate_forwarding_slots_match_plan(&forwarding_pointers, forwarding_slots)?;
        validate_reference_rewrite_commit_slots_match_plan(&reference_rewrites, references)?;
        validate_remembered_set_publication_source(&remembered_set_refresh, remembered_set)?;

        let _storage_report =
            destination_storage.copy_from_sources(&object_copies, source_bytes)?;
        install_forwarding_slots(&forwarding_pointers, forwarding_slots);
        apply_reference_rewrites(&reference_rewrites, references);
        *remembered_set = next_remembered_set;
        if let Some(card_table) = card_table {
            report.card_table_dirty_cards_cleared = card_table.clear_dirty_cards().dirty_cards();
        }
        Ok(report)
    }

    /// Publishes the rebuilt remembered set into caller-owned collector state.
    ///
    /// This consumes the commit plan because remembered-set publication is the
    /// final plan-owned metadata mutation represented by this helper. The
    /// method validates that `remembered_set` still matches the source epoch
    /// and edge sequence consumed by the refresh plan before replacing it with
    /// the precomputed next-epoch set.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError::MinorGcCommitRememberedSetPublicationEpochMismatch`]
    /// if the caller-owned remembered set is no longer on the epoch consumed by
    /// this commit plan. Returns [`GenerationalGcError`] if the caller-owned
    /// remembered-set edges no longer match the snapshot consumed by the plan.
    pub fn publish_next_remembered_set(
        self,
        remembered_set: &mut RememberedSet,
    ) -> Result<(), GenerationalGcError> {
        validate_remembered_set_publication_source(&self.remembered_set_refresh, remembered_set)?;
        *remembered_set = self.next_remembered_set;
        Ok(())
    }
}
