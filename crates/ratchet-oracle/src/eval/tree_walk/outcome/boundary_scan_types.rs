//! GC-stress boundary scan, relocation-plan, commit-preflight, and reference/writeback binding types.

use super::*;

/// GC-stress heap scans recorded at a successful tree-walk evaluation boundary.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryScans {
    worker: Option<AllocationCollectorPollScan>,
    permanent_shared: Option<AllocationCollectorPollScan>,
}

impl EvalGcStressBoundaryScans {
    /// Creates a boundary-scan report from per-allocator scan results.
    pub(crate) const fn new(
        worker: Option<AllocationCollectorPollScan>,
        permanent_shared: Option<AllocationCollectorPollScan>,
    ) -> Self {
        Self {
            worker,
            permanent_shared,
        }
    }

    /// Returns whether no allocator tier requested a GC-stress boundary scan.
    pub const fn is_empty(&self) -> bool {
        self.worker.is_none() && self.permanent_shared.is_none()
    }

    /// Returns how many allocator tiers produced a boundary scan.
    pub const fn len(&self) -> usize {
        match (self.worker.is_some(), self.permanent_shared.is_some()) {
            (false, false) => 0,
            (true, false) | (false, true) => 1,
            (true, true) => 2,
        }
    }

    /// Returns the worker allocator's GC-stress boundary scan, if any.
    pub const fn worker(&self) -> Option<&AllocationCollectorPollScan> {
        self.worker.as_ref()
    }

    /// Returns the permanent-shared allocator's GC-stress boundary scan, if any.
    pub const fn permanent_shared(&self) -> Option<&AllocationCollectorPollScan> {
        self.permanent_shared.as_ref()
    }
}

/// Minor-GC plans derived from GC-stress boundary scans.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcPlans {
    pub(crate) worker: Option<AllocationCollectorPollMinorGcPlan>,
    pub(crate) permanent_shared: Option<AllocationCollectorPollMinorGcPlan>,
}

impl EvalGcStressBoundaryMinorGcPlans {
    /// Creates a boundary-plan report from per-allocator plan results.
    pub(crate) const fn new(
        worker: Option<AllocationCollectorPollMinorGcPlan>,
        permanent_shared: Option<AllocationCollectorPollMinorGcPlan>,
    ) -> Self {
        Self {
            worker,
            permanent_shared,
        }
    }

    /// Returns whether no allocator tier produced a boundary minor-GC plan.
    pub const fn is_empty(&self) -> bool {
        self.worker.is_none() && self.permanent_shared.is_none()
    }

    /// Returns how many allocator tiers produced a boundary minor-GC plan.
    pub const fn len(&self) -> usize {
        match (self.worker.is_some(), self.permanent_shared.is_some()) {
            (false, false) => 0,
            (true, false) | (false, true) => 1,
            (true, true) => 2,
        }
    }

    /// Returns the worker allocator's boundary minor-GC plan, if any.
    pub const fn worker(&self) -> Option<&AllocationCollectorPollMinorGcPlan> {
        self.worker.as_ref()
    }

    /// Returns the permanent-shared allocator's boundary minor-GC plan, if any.
    pub const fn permanent_shared(&self) -> Option<&AllocationCollectorPollMinorGcPlan> {
        self.permanent_shared.as_ref()
    }
}

/// Relocation destinations derived from GC-stress boundary minor-GC plans.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcRelocationDestinations {
    worker: Option<AllocationCollectorPollMinorGcRelocationDestinations>,
    permanent_shared: Option<AllocationCollectorPollMinorGcRelocationDestinations>,
}

impl EvalGcStressBoundaryMinorGcRelocationDestinations {
    /// Creates a relocation-destination report from per-allocator results.
    pub(crate) const fn new(
        worker: Option<AllocationCollectorPollMinorGcRelocationDestinations>,
        permanent_shared: Option<AllocationCollectorPollMinorGcRelocationDestinations>,
    ) -> Self {
        Self {
            worker,
            permanent_shared,
        }
    }

    /// Returns whether no allocator tier produced a relocation-destination report.
    pub const fn is_empty(&self) -> bool {
        self.worker.is_none() && self.permanent_shared.is_none()
    }

    /// Returns how many allocator tiers produced relocation-destination reports.
    pub const fn len(&self) -> usize {
        match (self.worker.is_some(), self.permanent_shared.is_some()) {
            (false, false) => 0,
            (true, false) | (false, true) => 1,
            (true, true) => 2,
        }
    }

    /// Returns the worker allocator's relocation-destination report, if any.
    pub const fn worker(&self) -> Option<&AllocationCollectorPollMinorGcRelocationDestinations> {
        self.worker.as_ref()
    }

    /// Returns the permanent-shared allocator's relocation-destination report, if any.
    pub const fn permanent_shared(
        &self,
    ) -> Option<&AllocationCollectorPollMinorGcRelocationDestinations> {
        self.permanent_shared.as_ref()
    }
}

/// A boundary minor-GC plan paired with materialized relocation destinations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcRelocationPlan {
    minor_gc_plan: AllocationCollectorPollMinorGcPlan,
    relocation_destinations: AllocationCollectorPollMinorGcRelocationDestinations,
}

impl EvalGcStressBoundaryMinorGcRelocationPlan {
    /// Creates a paired boundary relocation plan.
    pub(crate) const fn new(
        minor_gc_plan: AllocationCollectorPollMinorGcPlan,
        relocation_destinations: AllocationCollectorPollMinorGcRelocationDestinations,
    ) -> Self {
        Self {
            minor_gc_plan,
            relocation_destinations,
        }
    }

    /// Returns the boundary minor-GC plan used to derive the destinations.
    pub const fn minor_gc_plan(&self) -> &AllocationCollectorPollMinorGcPlan {
        &self.minor_gc_plan
    }

    /// Returns the materialized relocation destinations for the minor-GC plan.
    pub const fn relocation_destinations(
        &self,
    ) -> &AllocationCollectorPollMinorGcRelocationDestinations {
        &self.relocation_destinations
    }

    /// Builds ordered commit metadata from this paired boundary plan.
    ///
    /// This delegates to the underlying allocation-poll minor-GC plan using the
    /// destinations derived for that exact plan. It still does not copy object
    /// bytes, install forwarding pointers, mutate roots or fields, publish
    /// remembered sets, or invoke a collector.
    ///
    /// # Errors
    ///
    /// Returns [`GenerationalGcError`] if the paired destination placements or
    /// relocation destinations do not match the minor-GC plan, if commit
    /// subplans cannot reserve storage, or if the subplans are inconsistent.
    pub fn commit_plan(
        &self,
    ) -> Result<AllocationCollectorPollMinorGcCommitPlan<'_>, GenerationalGcError> {
        self.minor_gc_plan
            .commit_plan(&self.relocation_destinations)
    }
}

/// Boundary minor-GC relocation plans derived from GC-stress boundary scans.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcRelocationPlans {
    pub(crate) worker: Option<EvalGcStressBoundaryMinorGcRelocationPlan>,
    pub(crate) permanent_shared: Option<EvalGcStressBoundaryMinorGcRelocationPlan>,
}

impl EvalGcStressBoundaryMinorGcRelocationPlans {
    /// Creates a paired relocation-plan report from per-allocator results.
    pub(crate) const fn new(
        worker: Option<EvalGcStressBoundaryMinorGcRelocationPlan>,
        permanent_shared: Option<EvalGcStressBoundaryMinorGcRelocationPlan>,
    ) -> Self {
        Self {
            worker,
            permanent_shared,
        }
    }

    /// Returns whether no allocator tier produced a paired relocation plan.
    pub const fn is_empty(&self) -> bool {
        self.worker.is_none() && self.permanent_shared.is_none()
    }

    /// Returns how many allocator tiers produced paired relocation plans.
    pub const fn len(&self) -> usize {
        match (self.worker.is_some(), self.permanent_shared.is_some()) {
            (false, false) => 0,
            (true, false) | (false, true) => 1,
            (true, true) => 2,
        }
    }

    /// Returns the worker allocator's paired relocation plan, if any.
    pub const fn worker(&self) -> Option<&EvalGcStressBoundaryMinorGcRelocationPlan> {
        self.worker.as_ref()
    }

    /// Returns the permanent-shared allocator's paired relocation plan, if any.
    pub const fn permanent_shared(&self) -> Option<&EvalGcStressBoundaryMinorGcRelocationPlan> {
        self.permanent_shared.as_ref()
    }

    pub(crate) fn into_relocation_destinations(
        self,
    ) -> EvalGcStressBoundaryMinorGcRelocationDestinations {
        EvalGcStressBoundaryMinorGcRelocationDestinations::new(
            self.worker.map(|plan| plan.relocation_destinations),
            self.permanent_shared
                .map(|plan| plan.relocation_destinations),
        )
    }
}

/// Owned commit-preflight metadata derived from a boundary relocation plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcCommitPreflight {
    relocation_plan: EvalGcStressBoundaryMinorGcRelocationPlan,
    object_byte_copy_plan: AllocationCollectorPollObjectByteCopyPlan,
    forwarding_slots: Vec<MinorGcForwardingSlot>,
    reference_buffer: Vec<ResolvedValueGeneration>,
    reference_writeback_plan: AllocationCollectorPollReferenceWritebackPlan,
    root_writeback_slots: Vec<AllocationCollectorPollRootWritebackSlot>,
    root_value_writeback_slots: Vec<AllocationCollectorPollRootValueWritebackSlot>,
    heap_field_writeback_slots: Vec<AllocationCollectorPollHeapFieldWritebackSlot>,
    card_table: GcCardTable,
}

impl EvalGcStressBoundaryMinorGcCommitPreflight {
    /// Creates owned commit-preflight metadata for one allocator tier.
    pub(crate) const fn new(
        relocation_plan: EvalGcStressBoundaryMinorGcRelocationPlan,
        object_byte_copy_plan: AllocationCollectorPollObjectByteCopyPlan,
        forwarding_slots: Vec<MinorGcForwardingSlot>,
        reference_buffer: Vec<ResolvedValueGeneration>,
        reference_writeback_plan: AllocationCollectorPollReferenceWritebackPlan,
        root_writeback_slots: Vec<AllocationCollectorPollRootWritebackSlot>,
        root_value_writeback_slots: Vec<AllocationCollectorPollRootValueWritebackSlot>,
        heap_field_writeback_slots: Vec<AllocationCollectorPollHeapFieldWritebackSlot>,
        card_table: GcCardTable,
    ) -> Self {
        Self {
            relocation_plan,
            object_byte_copy_plan,
            forwarding_slots,
            reference_buffer,
            reference_writeback_plan,
            root_writeback_slots,
            root_value_writeback_slots,
            heap_field_writeback_slots,
            card_table,
        }
    }

    /// Returns the paired boundary relocation plan used for preflight metadata.
    pub const fn relocation_plan(&self) -> &EvalGcStressBoundaryMinorGcRelocationPlan {
        &self.relocation_plan
    }

    /// Returns object byte-copy requests in commit order.
    pub const fn object_byte_copy_plan(&self) -> &AllocationCollectorPollObjectByteCopyPlan {
        &self.object_byte_copy_plan
    }

    /// Returns total object payload bytes requested by this preflight.
    ///
    /// This excludes destination-space alignment padding; use the paired
    /// relocation placement plan for reserved-byte sizing.
    pub fn object_copy_bytes(&self) -> usize {
        self.copy_to_nursery_bytes()
            .saturating_add(self.promote_to_old_bytes())
    }

    /// Returns object payload bytes copied into the next nursery.
    ///
    /// This excludes destination-space alignment padding; use the paired
    /// relocation placement plan for reserved-byte sizing.
    pub fn copy_to_nursery_bytes(&self) -> usize {
        self.object_byte_copy_plan.copy_to_nursery_bytes()
    }

    /// Returns object payload bytes promoted into old generation.
    ///
    /// This excludes destination-space alignment padding; use the paired
    /// relocation placement plan for reserved-byte sizing.
    pub fn promote_to_old_bytes(&self) -> usize {
        self.object_byte_copy_plan.promote_to_old_bytes()
    }

    /// Returns empty forwarding slots in forwarding-pointer order.
    pub fn forwarding_slots(&self) -> &[MinorGcForwardingSlot] {
        &self.forwarding_slots
    }

    /// Returns copied reference values in commit-buffer order.
    pub fn reference_buffer(&self) -> &[ResolvedValueGeneration] {
        &self.reference_buffer
    }

    /// Returns root and heap-field reference writebacks in commit order.
    pub const fn reference_writeback_plan(&self) -> &AllocationCollectorPollReferenceWritebackPlan {
        &self.reference_writeback_plan
    }

    /// Returns caller-owned root writeback slots copied from the plan.
    pub fn root_writeback_slots(&self) -> &[AllocationCollectorPollRootWritebackSlot] {
        &self.root_writeback_slots
    }

    /// Returns caller-owned typed root writeback slots copied from the plan.
    pub fn root_value_writeback_slots(&self) -> &[AllocationCollectorPollRootValueWritebackSlot] {
        &self.root_value_writeback_slots
    }

    /// Returns caller-owned heap-field writeback slots copied from the plan.
    pub fn heap_field_writeback_slots(&self) -> &[AllocationCollectorPollHeapFieldWritebackSlot] {
        &self.heap_field_writeback_slots
    }

    /// Returns the owned daemon card-table snapshot copy used by commit dry-runs.
    ///
    /// This table is not partitioned by boundary allocator tier; worker and
    /// permanent-shared preflights each receive an independent clone of the
    /// daemon-wide table recorded on the outcome.
    pub const fn card_table(&self) -> &GcCardTable {
        &self.card_table
    }

    /// Applies reference writebacks to this preflight's owned slot buffers.
    ///
    /// The method clones the root and heap-field writeback slots captured by
    /// this preflight, validates them against the copied reference-writeback
    /// plan, applies replacements into those owned buffers, and returns the
    /// mutated buffers with the writeback report. It still does not bind those
    /// buffers to live tree-walk roots, live heap fields, copied object bytes,
    /// object headers, forwarding slots, remembered-set storage, or semispace
    /// storage.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the copied slot buffers cannot be reserved
    /// or if the copied slots no longer match this preflight's writeback plan.
    pub fn apply_reference_writebacks_to_owned_slots(
        &self,
    ) -> Result<EvalGcStressBoundaryMinorGcReferenceWritebackApplication, EvalHeapError> {
        let mut root_writeback_slots =
            clone_boundary_root_writeback_slots(&self.root_writeback_slots)?;
        let mut root_value_writeback_slots =
            clone_boundary_root_value_writeback_slots(&self.root_value_writeback_slots)?;
        let mut heap_field_writeback_slots =
            clone_boundary_heap_field_writeback_slots(&self.heap_field_writeback_slots)?;
        let report = self
            .reference_writeback_plan
            .apply_to_slots(&mut root_writeback_slots, &mut heap_field_writeback_slots)?;
        self.reference_writeback_plan
            .root_writebacks()
            .apply_to_value_slots(&mut root_value_writeback_slots)?;

        Ok(
            EvalGcStressBoundaryMinorGcReferenceWritebackApplication::new(
                report,
                root_writeback_slots,
                root_value_writeback_slots,
                heap_field_writeback_slots,
            ),
        )
    }

    /// Applies the commit plan to boundary-owned synthetic commit buffers.
    ///
    /// The method clones this preflight's forwarding slots and reference buffer,
    /// clones the remembered set captured by the minor-GC plan, clones this
    /// preflight's daemon-wide card-table snapshot, builds synthetic source and
    /// destination byte buffers from the object byte-copy requests, copies those
    /// same source bytes into fresh owned destination storage sized from the
    /// placement plan, and applies the full lower-level commit plan to the
    /// remaining owned buffers. The synthetic bytes and owned destination
    /// storage prove commit ordering and storage placement without claiming to
    /// bind to live semispace storage or real heap object bytes. Live tree-walk
    /// roots, heap fields, object headers, remembered-set storage, card-table
    /// storage, and semispace pages remain untouched.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if any owned buffer or destination storage
    /// cannot be reserved, if commit metadata cannot be rebuilt from the paired
    /// relocation plan, or if any owned buffer fails validation.
    pub fn apply_commit_to_owned_buffers(
        &self,
    ) -> Result<EvalGcStressBoundaryMinorGcCommitApplication, EvalHeapError> {
        let mut object_byte_copies =
            boundary_minor_gc_object_byte_copy_applications(&self.object_byte_copy_plan)?;
        let destination_storage = boundary_minor_gc_destination_storage_application(
            &self.relocation_plan,
            &object_byte_copies,
        )?;
        let mut forwarding_slots = clone_boundary_forwarding_slots(&self.forwarding_slots)?;
        let mut references = clone_boundary_reference_buffer(&self.reference_buffer)?;
        let mut remembered_set =
            clone_boundary_remembered_set(self.relocation_plan.minor_gc_plan().remembered_set())?;
        let mut card_table = self.card_table.try_clone()?;

        let report = {
            let commit_plan = self.relocation_plan.commit_plan()?;
            let mut object_byte_copy_buffers =
                boundary_minor_gc_object_byte_copy_buffers(&mut object_byte_copies)?;
            commit_plan.apply_to_buffers_with_report(
                AllocationCollectorPollMinorGcCommitBuffers::with_card_table(
                    &mut object_byte_copy_buffers,
                    &mut forwarding_slots,
                    &mut references,
                    &mut remembered_set,
                    &mut card_table,
                ),
            )?
        };

        Ok(EvalGcStressBoundaryMinorGcCommitApplication::new(
            report,
            object_byte_copies,
            destination_storage,
            forwarding_slots,
            references,
            remembered_set,
            card_table,
        ))
    }

    /// Applies the commit plan directly to owned destination storage.
    ///
    /// This is the boundary counterpart to
    /// [`AllocationCollectorPollMinorGcCommitPlan::apply_to_owned_destination_storage`].
    /// It allocates fresh owned destination storage from this preflight's
    /// placement plan, rebuilds relocation destinations from that storage's
    /// aligned bases, and applies the allocation-poll commit bridge to the owned
    /// storage plus cloned forwarding, reference, remembered-set, and card-table
    /// buffers. The result proves the boundary metadata can drive the
    /// owned-storage commit path without first applying separate object byte-copy
    /// buffers.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if owned storage or source bytes cannot be
    /// reserved, if commit metadata cannot be rebuilt from the storage-derived
    /// relocation plan, or if any owned commit buffer fails validation.
    pub fn apply_commit_to_owned_destination_storage(
        &self,
    ) -> Result<EvalGcStressBoundaryMinorGcOwnedStorageCommitApplication, EvalHeapError> {
        let placement_plan = self
            .relocation_plan
            .relocation_destinations()
            .placement_plan();
        let mut destination_storage =
            MinorGcOwnedDestinationStorage::from_placement_plan(placement_plan)?;
        let nursery_layouts = boundary_minor_gc_nursery_layouts_from_placements(placement_plan)?;
        let storage_relocation_destinations = self
            .relocation_plan
            .minor_gc_plan()
            .relocation_destination_plan(
                &nursery_layouts,
                destination_storage.destination_bases(),
            )?;
        let commit_plan = self
            .relocation_plan
            .minor_gc_plan()
            .commit_plan(&storage_relocation_destinations)?;
        let source_byte_storage =
            boundary_minor_gc_object_source_byte_storage(&self.object_byte_copy_plan)?;
        let source_bytes = boundary_minor_gc_source_object_bytes_from_storage(
            &self.object_byte_copy_plan,
            &source_byte_storage,
        )?;
        let mut forwarding_slots = commit_plan.forwarding_slot_buffer()?;
        let mut references = clone_boundary_reference_buffer(&self.reference_buffer)?;
        let mut remembered_set =
            clone_boundary_remembered_set(self.relocation_plan.minor_gc_plan().remembered_set())?;
        let mut card_table = self.card_table.try_clone()?;
        let copy_report = MinorGcOwnedDestinationStorageCopyReport::from_object_copy_plan(
            commit_plan.commit_plan().object_copies(),
        );

        let report = commit_plan.apply_to_owned_destination_storage_with_report(
            AllocationCollectorPollMinorGcOwnedCommitBuffers::with_card_table(
                &mut destination_storage,
                &source_bytes,
                &mut forwarding_slots,
                &mut references,
                &mut remembered_set,
                &mut card_table,
            ),
        )?;
        let destination_storage = boundary_minor_gc_destination_storage_application_from_storage(
            copy_report,
            &destination_storage,
        )?;

        Ok(
            EvalGcStressBoundaryMinorGcOwnedStorageCommitApplication::new(
                report,
                destination_storage,
                forwarding_slots,
                references,
                remembered_set,
                card_table,
            ),
        )
    }
}

/// Applied caller-owned reference writeback buffers for one boundary preflight.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcReferenceWritebackApplication {
    report: AllocationCollectorPollReferenceWritebackReport,
    root_writeback_slots: Vec<AllocationCollectorPollRootWritebackSlot>,
    root_value_writeback_slots: Vec<AllocationCollectorPollRootValueWritebackSlot>,
    heap_field_writeback_slots: Vec<AllocationCollectorPollHeapFieldWritebackSlot>,
}

impl EvalGcStressBoundaryMinorGcReferenceWritebackApplication {
    pub(crate) const fn new(
        report: AllocationCollectorPollReferenceWritebackReport,
        root_writeback_slots: Vec<AllocationCollectorPollRootWritebackSlot>,
        root_value_writeback_slots: Vec<AllocationCollectorPollRootValueWritebackSlot>,
        heap_field_writeback_slots: Vec<AllocationCollectorPollHeapFieldWritebackSlot>,
    ) -> Self {
        Self {
            report,
            root_writeback_slots,
            root_value_writeback_slots,
            heap_field_writeback_slots,
        }
    }

    /// Returns the writeback counts reported by the applied plan.
    pub const fn report(&self) -> AllocationCollectorPollReferenceWritebackReport {
        self.report
    }

    /// Returns caller-owned root writeback slots after application.
    pub fn root_writeback_slots(&self) -> &[AllocationCollectorPollRootWritebackSlot] {
        &self.root_writeback_slots
    }

    /// Returns caller-owned typed root writeback slots after application.
    pub fn root_value_writeback_slots(&self) -> &[AllocationCollectorPollRootValueWritebackSlot] {
        &self.root_value_writeback_slots
    }

    /// Returns caller-owned heap-field writeback slots after application.
    pub fn heap_field_writeback_slots(&self) -> &[AllocationCollectorPollHeapFieldWritebackSlot] {
        &self.heap_field_writeback_slots
    }
}

/// Counts for outcome-owned reference-writeback metadata installation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveReferenceWritebackInstallReport {
    tiers: usize,
    root_writebacks: usize,
    heap_field_writebacks: usize,
}

impl EvalGcStressBoundaryMinorGcLiveReferenceWritebackInstallReport {
    pub(crate) fn record(
        &mut self,
        application: &EvalGcStressBoundaryMinorGcReferenceWritebackApplication,
    ) {
        self.tiers = self.tiers.saturating_add(1);
        let report = application.report();
        self.root_writebacks = self
            .root_writebacks
            .saturating_add(report.root_writebacks());
        self.heap_field_writebacks = self
            .heap_field_writebacks
            .saturating_add(report.heap_field_writebacks());
    }

    /// Returns how many allocator tiers installed writeback metadata.
    pub const fn tiers(self) -> usize {
        self.tiers
    }

    /// Returns how many copied root slots were installed.
    pub const fn root_writebacks(self) -> usize {
        self.root_writebacks
    }

    /// Returns how many copied heap-field slots were installed.
    pub const fn heap_field_writebacks(self) -> usize {
        self.heap_field_writebacks
    }

    /// Returns the total number of copied writeback slots installed.
    pub const fn writebacks(self) -> usize {
        self.root_writebacks
            .saturating_add(self.heap_field_writebacks)
    }
}

/// Outcome-owned reference-writeback metadata installed by live dry runs.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveReferenceWritebacks {
    pub(crate) install_report: EvalGcStressBoundaryMinorGcLiveReferenceWritebackInstallReport,
    pub(crate) applications: EvalGcStressBoundaryMinorGcReferenceWritebackApplications,
}

impl EvalGcStressBoundaryMinorGcLiveReferenceWritebacks {
    pub(crate) fn can_install(
        &self,
        install_report: EvalGcStressBoundaryMinorGcLiveReferenceWritebackInstallReport,
    ) -> Result<(), EvalHeapError> {
        if install_report.writebacks() != 0 && !self.is_empty() {
            return Err(
                EvalHeapError::BoundaryMinorGcLiveReferenceWritebacksAlreadyInstalled {
                    existing: self.install_report.writebacks(),
                },
            );
        }
        Ok(())
    }

    pub(crate) fn install(
        &mut self,
        applications: EvalGcStressBoundaryMinorGcReferenceWritebackApplications,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveReferenceWritebackInstallReport, EvalHeapError> {
        let install_report = live_reference_writeback_install_report(&applications);
        if install_report.writebacks() == 0 {
            return Ok(EvalGcStressBoundaryMinorGcLiveReferenceWritebackInstallReport::default());
        }
        self.can_install(install_report)?;

        self.install_report = install_report;
        self.applications = applications;
        Ok(install_report)
    }

    pub(crate) fn install_prevalidated(
        &mut self,
        applications: EvalGcStressBoundaryMinorGcReferenceWritebackApplications,
        install_report: EvalGcStressBoundaryMinorGcLiveReferenceWritebackInstallReport,
    ) {
        if install_report.writebacks() == 0 {
            return;
        }

        self.install_report = install_report;
        self.applications = applications;
    }

    /// Returns whether no writeback metadata has been installed.
    pub const fn is_empty(&self) -> bool {
        self.applications.is_empty()
    }

    /// Returns how many allocator tiers installed writeback metadata.
    pub const fn len(&self) -> usize {
        self.applications.len()
    }

    /// Returns the install report for the outcome-owned writeback metadata.
    pub const fn install_report(
        &self,
    ) -> EvalGcStressBoundaryMinorGcLiveReferenceWritebackInstallReport {
        self.install_report
    }

    /// Returns the installed worker writeback metadata, if present.
    pub const fn worker(
        &self,
    ) -> Option<&EvalGcStressBoundaryMinorGcReferenceWritebackApplication> {
        self.applications.worker()
    }

    /// Returns the installed permanent-shared writeback metadata, if present.
    pub const fn permanent_shared(
        &self,
    ) -> Option<&EvalGcStressBoundaryMinorGcReferenceWritebackApplication> {
        self.applications.permanent_shared()
    }

    /// Returns the installed per-tier writeback metadata.
    pub const fn applications(&self) -> &EvalGcStressBoundaryMinorGcReferenceWritebackApplications {
        &self.applications
    }
}

/// Outcome-owned writeback destination-binding installation counts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindingInstallReport {
    root_writeback_bindings: usize,
    heap_field_writeback_bindings: usize,
}

impl EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindingInstallReport {
    pub(crate) const fn new(
        root_writeback_bindings: usize,
        heap_field_writeback_bindings: usize,
    ) -> Self {
        Self {
            root_writeback_bindings,
            heap_field_writeback_bindings,
        }
    }

    /// Returns how many root writeback destination bindings were installed.
    pub const fn root_writeback_bindings(self) -> usize {
        self.root_writeback_bindings
    }

    /// Returns how many heap-field writeback destination bindings were installed.
    pub const fn heap_field_writeback_bindings(self) -> usize {
        self.heap_field_writeback_bindings
    }

    /// Returns how many total writeback destination bindings were installed.
    pub const fn bindings(self) -> usize {
        self.root_writeback_bindings
            .saturating_add(self.heap_field_writeback_bindings)
    }
}

/// Outcome-owned root/heap-field destination-binding metadata.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings {
    pub(crate) install_report:
        EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindingInstallReport,
    pub(crate) root_writeback_bindings:
        Vec<EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding>,
    pub(crate) heap_field_writeback_bindings:
        Vec<EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding>,
    pub(crate) expected_remembered_set: Option<RememberedSet>,
}

impl EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings {
    pub(crate) fn can_install(
        &self,
        install_report: EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindingInstallReport,
    ) -> Result<(), EvalHeapError> {
        if install_report.bindings() != 0 && !self.is_empty() {
            return Err(
                EvalHeapError::BoundaryMinorGcLiveWritebackDestinationBindingsAlreadyInstalled {
                    existing: self.len(),
                },
            );
        }
        Ok(())
    }

    pub(crate) fn install(
        &mut self,
        root_writeback_bindings: Vec<EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding>,
        heap_field_writeback_bindings: Vec<
            EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding,
        >,
        expected_remembered_set: Option<RememberedSet>,
    ) -> Result<
        EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindingInstallReport,
        EvalHeapError,
    > {
        let install_report = live_writeback_destination_binding_install_report(
            &root_writeback_bindings,
            &heap_field_writeback_bindings,
        );
        if install_report.bindings() == 0 {
            return Ok(
                EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindingInstallReport::default(),
            );
        }
        self.can_install(install_report)?;
        self.install_prevalidated(
            root_writeback_bindings,
            heap_field_writeback_bindings,
            expected_remembered_set,
            install_report,
        );
        Ok(install_report)
    }

    pub(crate) fn install_prevalidated(
        &mut self,
        root_writeback_bindings: Vec<EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding>,
        heap_field_writeback_bindings: Vec<
            EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding,
        >,
        expected_remembered_set: Option<RememberedSet>,
        install_report: EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindingInstallReport,
    ) {
        if install_report.bindings() == 0 {
            return;
        }

        self.install_report = install_report;
        self.root_writeback_bindings = root_writeback_bindings;
        self.heap_field_writeback_bindings = heap_field_writeback_bindings;
        self.expected_remembered_set = expected_remembered_set;
    }

    /// Returns whether no writeback destination-binding metadata is installed.
    pub fn is_empty(&self) -> bool {
        self.root_writeback_bindings.is_empty() && self.heap_field_writeback_bindings.is_empty()
    }

    /// Returns how many writeback destination-binding records are installed.
    pub fn len(&self) -> usize {
        self.root_writeback_bindings
            .len()
            .saturating_add(self.heap_field_writeback_bindings.len())
    }

    /// Returns the install report for the writeback destination bindings.
    pub const fn install_report(
        &self,
    ) -> EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindingInstallReport {
        self.install_report
    }

    /// Returns installed root writeback destination bindings.
    pub fn root_writeback_bindings(
        &self,
    ) -> &[EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding] {
        &self.root_writeback_bindings
    }

    /// Returns installed heap-field writeback destination bindings.
    pub fn heap_field_writeback_bindings(
        &self,
    ) -> &[EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding] {
        &self.heap_field_writeback_bindings
    }

    /// Returns the remembered set expected after the metadata's source dry run.
    pub const fn expected_remembered_set(&self) -> Option<&RememberedSet> {
        self.expected_remembered_set.as_ref()
    }
}

/// Applied boundary-owned object byte buffers for one minor-GC object copy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcObjectByteCopyApplication {
    pub(crate) request: AllocationCollectorPollObjectByteCopyRequest,
    pub(crate) source_bytes: Vec<u8>,
    pub(crate) destination_bytes: Vec<u8>,
}

impl EvalGcStressBoundaryMinorGcObjectByteCopyApplication {
    pub(crate) fn new(
        request: AllocationCollectorPollObjectByteCopyRequest,
        source_bytes: Vec<u8>,
        destination_bytes: Vec<u8>,
    ) -> Self {
        Self {
            request,
            source_bytes,
            destination_bytes,
        }
    }

    /// Returns the byte-copy request that shaped this owned buffer pair.
    pub const fn request(&self) -> AllocationCollectorPollObjectByteCopyRequest {
        self.request
    }

    /// Returns the synthetic source bytes supplied to the commit application.
    pub fn source_bytes(&self) -> &[u8] {
        &self.source_bytes
    }

    /// Returns the destination bytes after commit application.
    pub fn destination_bytes(&self) -> &[u8] {
        &self.destination_bytes
    }
}
