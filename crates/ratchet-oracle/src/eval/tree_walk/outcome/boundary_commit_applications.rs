//! Commit dry-run summary, aggregated commit-application types, and boundary slot snapshots.

use super::*;

/// Aggregate counts and payload bytes from owned boundary minor-GC dry runs.
///
/// The summary is telemetry for the synthetic dry-run boundary only. It does
/// not imply that live roots, heap fields, object bytes, forwarding headers,
/// remembered sets, card-table storage, or semispace storage were mutated. It
/// includes dirty-card clearing totals from each tier-owned daemon-card-table
/// clone, so those counts describe owned dry-run applications rather than live
/// daemon card-table storage.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcCommitDryRunSummary {
    tiers: usize,
    object_copies: usize,
    copied_to_nursery: usize,
    promoted_to_old: usize,
    copy_to_nursery_bytes: usize,
    promote_to_old_bytes: usize,
    forwarding_pointers: usize,
    reference_rewrites: usize,
    root_writebacks: usize,
    heap_field_writebacks: usize,
    remembered_set_source_edges: usize,
    remembered_set_published_edges: usize,
    card_table_dirty_cards_cleared: usize,
}

impl EvalGcStressBoundaryMinorGcCommitDryRunSummary {
    pub(crate) fn from_preflights_and_applications(
        preflights: &EvalGcStressBoundaryMinorGcCommitPreflights,
        reference_writebacks: &EvalGcStressBoundaryMinorGcReferenceWritebackApplications,
        commit_applications: &EvalGcStressBoundaryMinorGcCommitApplications,
    ) -> Self {
        let mut summary = Self::default();
        summary.add_preflights(preflights);
        summary.add_reference_writeback_applications(reference_writebacks);
        summary.add_commit_applications(commit_applications);
        summary
    }

    fn add_preflights(&mut self, preflights: &EvalGcStressBoundaryMinorGcCommitPreflights) {
        if let Some(preflight) = preflights.worker() {
            self.add_preflight(preflight);
        }
        if let Some(preflight) = preflights.permanent_shared() {
            self.add_preflight(preflight);
        }
    }

    fn add_preflight(&mut self, preflight: &EvalGcStressBoundaryMinorGcCommitPreflight) {
        self.copy_to_nursery_bytes = self
            .copy_to_nursery_bytes
            .saturating_add(preflight.copy_to_nursery_bytes());
        self.promote_to_old_bytes = self
            .promote_to_old_bytes
            .saturating_add(preflight.promote_to_old_bytes());
    }

    fn add_reference_writeback_applications(
        &mut self,
        applications: &EvalGcStressBoundaryMinorGcReferenceWritebackApplications,
    ) {
        if let Some(application) = applications.worker() {
            self.add_reference_writeback_report(application.report());
        }
        if let Some(application) = applications.permanent_shared() {
            self.add_reference_writeback_report(application.report());
        }
    }

    fn add_commit_applications(
        &mut self,
        applications: &EvalGcStressBoundaryMinorGcCommitApplications,
    ) {
        if let Some(application) = applications.worker() {
            self.add_commit_report(application.report());
        }
        if let Some(application) = applications.permanent_shared() {
            self.add_commit_report(application.report());
        }
    }

    fn add_reference_writeback_report(
        &mut self,
        report: AllocationCollectorPollReferenceWritebackReport,
    ) {
        self.root_writebacks = self
            .root_writebacks
            .saturating_add(report.root_writebacks());
        self.heap_field_writebacks = self
            .heap_field_writebacks
            .saturating_add(report.heap_field_writebacks());
    }

    fn add_commit_report(&mut self, report: MinorGcCommitReport) {
        self.tiers = self.tiers.saturating_add(1);
        self.object_copies = self.object_copies.saturating_add(report.object_copies());
        self.copied_to_nursery = self
            .copied_to_nursery
            .saturating_add(report.copied_to_nursery());
        self.promoted_to_old = self
            .promoted_to_old
            .saturating_add(report.promoted_to_old());
        self.forwarding_pointers = self
            .forwarding_pointers
            .saturating_add(report.forwarding_pointers());
        self.reference_rewrites = self
            .reference_rewrites
            .saturating_add(report.reference_rewrites());
        self.remembered_set_source_edges = self
            .remembered_set_source_edges
            .saturating_add(report.remembered_set_source_edges());
        self.remembered_set_published_edges = self
            .remembered_set_published_edges
            .saturating_add(report.remembered_set_published_edges());
        self.card_table_dirty_cards_cleared = self
            .card_table_dirty_cards_cleared
            .saturating_add(report.card_table_dirty_cards_cleared());
    }

    /// Returns how many allocator tiers produced dry-run applications.
    pub const fn tiers(self) -> usize {
        self.tiers
    }

    /// Returns the number of object byte-copy applications.
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

    /// Returns total object payload bytes requested by all dry-run preflights.
    ///
    /// This excludes destination-space alignment padding; use the relocation
    /// placement plans for reserved-byte sizing.
    pub const fn object_copy_bytes(self) -> usize {
        self.copy_to_nursery_bytes
            .saturating_add(self.promote_to_old_bytes)
    }

    /// Returns object payload bytes copied into next nursery spaces.
    ///
    /// This excludes destination-space alignment padding.
    pub const fn copy_to_nursery_bytes(self) -> usize {
        self.copy_to_nursery_bytes
    }

    /// Returns object payload bytes promoted into old-generation space.
    ///
    /// This excludes destination-space alignment padding.
    pub const fn promote_to_old_bytes(self) -> usize {
        self.promote_to_old_bytes
    }

    /// Returns the number of forwarding slots populated.
    pub const fn forwarding_pointers(self) -> usize {
        self.forwarding_pointers
    }

    /// Returns the number of lower-level reference rewrites applied.
    pub const fn reference_rewrites(self) -> usize {
        self.reference_rewrites
    }

    /// Returns the number of caller-owned root slots rewritten.
    pub const fn root_writebacks(self) -> usize {
        self.root_writebacks
    }

    /// Returns the number of caller-owned heap-field slots rewritten.
    pub const fn heap_field_writebacks(self) -> usize {
        self.heap_field_writebacks
    }

    /// Returns the total number of caller-owned reference slots rewritten.
    pub const fn reference_writebacks(self) -> usize {
        self.root_writebacks
            .saturating_add(self.heap_field_writebacks)
    }

    /// Returns remembered-set edges examined from source epochs.
    pub const fn remembered_set_source_edges(self) -> usize {
        self.remembered_set_source_edges
    }

    /// Returns remembered-set edges published into next epochs.
    pub const fn remembered_set_published_edges(self) -> usize {
        self.remembered_set_published_edges
    }

    /// Returns dirty cards cleared from owned dry-run card-table buffers.
    pub const fn card_table_dirty_cards_cleared(self) -> usize {
        self.card_table_dirty_cards_cleared
    }
}

/// Applied reference writeback buffers derived from boundary preflights.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcReferenceWritebackApplications {
    worker: Option<EvalGcStressBoundaryMinorGcReferenceWritebackApplication>,
    permanent_shared: Option<EvalGcStressBoundaryMinorGcReferenceWritebackApplication>,
}

impl EvalGcStressBoundaryMinorGcReferenceWritebackApplications {
    pub(crate) const fn new(
        worker: Option<EvalGcStressBoundaryMinorGcReferenceWritebackApplication>,
        permanent_shared: Option<EvalGcStressBoundaryMinorGcReferenceWritebackApplication>,
    ) -> Self {
        Self {
            worker,
            permanent_shared,
        }
    }

    /// Returns whether no allocator tier produced applied writeback buffers.
    pub const fn is_empty(&self) -> bool {
        self.worker.is_none() && self.permanent_shared.is_none()
    }

    /// Returns how many allocator tiers produced applied writeback buffers.
    pub const fn len(&self) -> usize {
        match (self.worker.is_some(), self.permanent_shared.is_some()) {
            (false, false) => 0,
            (true, false) | (false, true) => 1,
            (true, true) => 2,
        }
    }

    /// Returns the worker allocator's applied writeback buffers, if any.
    pub const fn worker(
        &self,
    ) -> Option<&EvalGcStressBoundaryMinorGcReferenceWritebackApplication> {
        self.worker.as_ref()
    }

    /// Returns the permanent-shared allocator's applied writeback buffers, if any.
    pub const fn permanent_shared(
        &self,
    ) -> Option<&EvalGcStressBoundaryMinorGcReferenceWritebackApplication> {
        self.permanent_shared.as_ref()
    }
}

/// Applied owned commit buffers derived from boundary preflights.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcCommitApplications {
    worker: Option<EvalGcStressBoundaryMinorGcCommitApplication>,
    permanent_shared: Option<EvalGcStressBoundaryMinorGcCommitApplication>,
}

impl EvalGcStressBoundaryMinorGcCommitApplications {
    pub(crate) const fn new(
        worker: Option<EvalGcStressBoundaryMinorGcCommitApplication>,
        permanent_shared: Option<EvalGcStressBoundaryMinorGcCommitApplication>,
    ) -> Self {
        Self {
            worker,
            permanent_shared,
        }
    }

    /// Returns whether no allocator tier produced an owned commit application.
    pub const fn is_empty(&self) -> bool {
        self.worker.is_none() && self.permanent_shared.is_none()
    }

    /// Returns how many allocator tiers produced owned commit applications.
    pub const fn len(&self) -> usize {
        match (self.worker.is_some(), self.permanent_shared.is_some()) {
            (false, false) => 0,
            (true, false) | (false, true) => 1,
            (true, true) => 2,
        }
    }

    /// Returns the worker allocator's owned commit application, if any.
    pub const fn worker(&self) -> Option<&EvalGcStressBoundaryMinorGcCommitApplication> {
        self.worker.as_ref()
    }

    /// Returns the permanent-shared allocator's owned commit application, if any.
    pub const fn permanent_shared(&self) -> Option<&EvalGcStressBoundaryMinorGcCommitApplication> {
        self.permanent_shared.as_ref()
    }
}

/// Applied owned destination-storage commits derived from boundary preflights.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcOwnedStorageCommitApplications {
    worker: Option<EvalGcStressBoundaryMinorGcOwnedStorageCommitApplication>,
    permanent_shared: Option<EvalGcStressBoundaryMinorGcOwnedStorageCommitApplication>,
}

impl EvalGcStressBoundaryMinorGcOwnedStorageCommitApplications {
    pub(crate) const fn new(
        worker: Option<EvalGcStressBoundaryMinorGcOwnedStorageCommitApplication>,
        permanent_shared: Option<EvalGcStressBoundaryMinorGcOwnedStorageCommitApplication>,
    ) -> Self {
        Self {
            worker,
            permanent_shared,
        }
    }

    /// Returns whether no allocator tier produced an owned-storage application.
    pub const fn is_empty(&self) -> bool {
        self.worker.is_none() && self.permanent_shared.is_none()
    }

    /// Returns how many allocator tiers produced owned-storage applications.
    pub const fn len(&self) -> usize {
        match (self.worker.is_some(), self.permanent_shared.is_some()) {
            (false, false) => 0,
            (true, false) | (false, true) => 1,
            (true, true) => 2,
        }
    }

    /// Returns the worker allocator's owned-storage application, if any.
    pub const fn worker(
        &self,
    ) -> Option<&EvalGcStressBoundaryMinorGcOwnedStorageCommitApplication> {
        self.worker.as_ref()
    }

    /// Returns the permanent-shared allocator's owned-storage application, if any.
    pub const fn permanent_shared(
        &self,
    ) -> Option<&EvalGcStressBoundaryMinorGcOwnedStorageCommitApplication> {
        self.permanent_shared.as_ref()
    }
}

pub(crate) fn boundary_minor_gc_root_reference_values(
    reference_slots: &[AllocationCollectorPollReferenceSlot],
) -> Result<Vec<AllocationCollectorPollRootReferenceValue>, EvalHeapError> {
    let root_count = reference_slots
        .iter()
        .filter(|slot| {
            matches!(
                slot.source(),
                AllocationCollectorPollReferenceSource::Root { .. }
            )
        })
        .count();
    let mut root_values = Vec::new();
    root_values.try_reserve_exact(root_count).map_err(|_| {
        EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_ROOT_REFERENCE_VALUES_TABLE,
            entries: root_count,
        }
    })?;

    for slot in reference_slots {
        let AllocationCollectorPollReferenceSource::Root { source } = slot.source() else {
            continue;
        };
        root_values.push(AllocationCollectorPollRootReferenceValue::new(
            source.clone(),
            slot.value(),
        ));
    }

    Ok(root_values)
}

pub(crate) fn boundary_minor_gc_root_writeback_slots(
    plan: &AllocationCollectorPollReferenceWritebackPlan,
) -> Result<Vec<AllocationCollectorPollRootWritebackSlot>, EvalHeapError> {
    let writebacks = plan.root_writebacks().writebacks();
    let mut slots = Vec::new();
    slots.try_reserve_exact(writebacks.len()).map_err(|_| {
        EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_ROOT_WRITEBACK_SLOTS_TABLE,
            entries: writebacks.len(),
        }
    })?;

    for writeback in writebacks {
        slots.push(AllocationCollectorPollRootWritebackSlot::new(
            writeback.source().clone(),
            writeback.expected(),
        ));
    }

    Ok(slots)
}

pub(crate) fn boundary_minor_gc_root_value_writeback_slots(
    plan: &AllocationCollectorPollReferenceWritebackPlan,
) -> Result<Vec<AllocationCollectorPollRootValueWritebackSlot>, EvalHeapError> {
    let writebacks = plan.root_writebacks().writebacks();
    let mut slots = Vec::new();
    slots.try_reserve_exact(writebacks.len()).map_err(|_| {
        EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_ROOT_VALUE_WRITEBACK_SLOTS_TABLE,
            entries: writebacks.len(),
        }
    })?;

    for writeback in writebacks {
        slots.push(AllocationCollectorPollRootValueWritebackSlot::new(
            writeback.source().clone(),
            writeback.expected_value()?,
        ));
    }

    Ok(slots)
}

pub(crate) fn boundary_minor_gc_heap_field_writeback_slots(
    plan: &AllocationCollectorPollReferenceWritebackPlan,
) -> Result<Vec<AllocationCollectorPollHeapFieldWritebackSlot>, EvalHeapError> {
    let writebacks = plan.heap_field_writebacks().writebacks();
    let mut slots = Vec::new();
    slots.try_reserve_exact(writebacks.len()).map_err(|_| {
        EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_SLOTS_TABLE,
            entries: writebacks.len(),
        }
    })?;

    for writeback in writebacks {
        slots.push(AllocationCollectorPollHeapFieldWritebackSlot::new(
            writeback.validation_object(),
            writeback.writeback_object(),
            writeback.field_index(),
            writeback.source().clone(),
            writeback.expected(),
        ));
    }

    Ok(slots)
}
