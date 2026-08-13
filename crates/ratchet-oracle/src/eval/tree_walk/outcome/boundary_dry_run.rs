//! Commit-preflight aggregation and the per-surface live commit dry-run types.

use super::*;

/// Commit-preflight metadata derived from GC-stress boundary scans.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcCommitPreflights {
    worker: Option<EvalGcStressBoundaryMinorGcCommitPreflight>,
    permanent_shared: Option<EvalGcStressBoundaryMinorGcCommitPreflight>,
}

impl EvalGcStressBoundaryMinorGcCommitPreflights {
    /// Creates a commit-preflight report from per-allocator results.
    pub(crate) const fn new(
        worker: Option<EvalGcStressBoundaryMinorGcCommitPreflight>,
        permanent_shared: Option<EvalGcStressBoundaryMinorGcCommitPreflight>,
    ) -> Self {
        Self {
            worker,
            permanent_shared,
        }
    }

    /// Returns whether no allocator tier produced commit-preflight metadata.
    pub const fn is_empty(&self) -> bool {
        self.worker.is_none() && self.permanent_shared.is_none()
    }

    /// Returns how many allocator tiers produced commit-preflight metadata.
    pub const fn len(&self) -> usize {
        match (self.worker.is_some(), self.permanent_shared.is_some()) {
            (false, false) => 0,
            (true, false) | (false, true) => 1,
            (true, true) => 2,
        }
    }

    /// Returns the worker allocator's commit-preflight metadata, if any.
    pub const fn worker(&self) -> Option<&EvalGcStressBoundaryMinorGcCommitPreflight> {
        self.worker.as_ref()
    }

    /// Returns the permanent-shared allocator's commit-preflight metadata, if any.
    pub const fn permanent_shared(&self) -> Option<&EvalGcStressBoundaryMinorGcCommitPreflight> {
        self.permanent_shared.as_ref()
    }

    /// Applies reference writebacks for every recorded boundary preflight.
    ///
    /// Each allocator tier is applied independently to owned slot-buffer copies
    /// from its preflight. The returned report preserves the worker and
    /// permanent-shared partition. This still does not mutate live evaluator
    /// roots, heap fields, object bytes, forwarding slots, remembered-set state,
    /// or semispace storage.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if any preflight cannot copy its owned
    /// writeback slots or if any copied slot buffer fails validation.
    pub fn apply_reference_writebacks_to_owned_slots(
        &self,
    ) -> Result<EvalGcStressBoundaryMinorGcReferenceWritebackApplications, EvalHeapError> {
        let worker = self
            .worker
            .as_ref()
            .map(EvalGcStressBoundaryMinorGcCommitPreflight::apply_reference_writebacks_to_owned_slots)
            .transpose()?;
        let permanent_shared = self
            .permanent_shared
            .as_ref()
            .map(EvalGcStressBoundaryMinorGcCommitPreflight::apply_reference_writebacks_to_owned_slots)
            .transpose()?;

        Ok(
            EvalGcStressBoundaryMinorGcReferenceWritebackApplications::new(
                worker,
                permanent_shared,
            ),
        )
    }

    /// Applies complete commit plans for every recorded boundary preflight.
    ///
    /// Each allocator tier is committed independently into owned synthetic
    /// byte buffers, owned destination-storage byte snapshots, and cloned
    /// forwarding, reference, remembered-set, and card-table buffers. This
    /// preserves the worker/permanent-shared partition while still avoiding
    /// mutation of live tree-walk roots, heap fields, object headers,
    /// remembered-set storage, or semispace pages.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if any preflight cannot allocate its owned
    /// buffers or destination storage, rebuild commit metadata, or validate
    /// those buffers against the lower-level commit plan.
    pub fn apply_commits_to_owned_buffers(
        &self,
    ) -> Result<EvalGcStressBoundaryMinorGcCommitApplications, EvalHeapError> {
        let worker = self
            .worker
            .as_ref()
            .map(EvalGcStressBoundaryMinorGcCommitPreflight::apply_commit_to_owned_buffers)
            .transpose()?;
        let permanent_shared = self
            .permanent_shared
            .as_ref()
            .map(EvalGcStressBoundaryMinorGcCommitPreflight::apply_commit_to_owned_buffers)
            .transpose()?;

        Ok(EvalGcStressBoundaryMinorGcCommitApplications::new(
            worker,
            permanent_shared,
        ))
    }

    /// Applies owned-storage commit plans for every recorded boundary preflight.
    ///
    /// Each allocator tier is committed independently into fresh owned
    /// destination storage plus cloned forwarding, reference, remembered-set,
    /// and card-table buffers. Unlike [`Self::apply_commits_to_owned_buffers`],
    /// this path drives the allocation-poll owned-storage commit bridge directly
    /// and does not first apply separate object byte-copy buffers.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if any preflight cannot allocate owned storage
    /// or source bytes, rebuild storage-derived commit metadata, or validate
    /// those buffers against the lower-level commit plan.
    pub fn apply_commits_to_owned_destination_storage(
        &self,
    ) -> Result<EvalGcStressBoundaryMinorGcOwnedStorageCommitApplications, EvalHeapError> {
        let worker = self
            .worker
            .as_ref()
            .map(
                EvalGcStressBoundaryMinorGcCommitPreflight::apply_commit_to_owned_destination_storage,
            )
            .transpose()?;
        let permanent_shared = self
            .permanent_shared
            .as_ref()
            .map(
                EvalGcStressBoundaryMinorGcCommitPreflight::apply_commit_to_owned_destination_storage,
            )
            .transpose()?;

        Ok(
            EvalGcStressBoundaryMinorGcOwnedStorageCommitApplications::new(
                worker,
                permanent_shared,
            ),
        )
    }

    /// Applies every boundary commit preflight to owned dry-run buffers.
    ///
    /// This consumes the preflight bundle so the returned dry-run report retains
    /// the exact metadata that produced the owned reference-writeback,
    /// synthetic commit-buffer, and direct owned-storage commit applications. It
    /// still does not mutate live evaluator roots, live heap fields, object
    /// headers, remembered-set storage, or semispace pages.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if any preflight cannot allocate its owned
    /// writeback buffers, destination storage, or commit buffers, rebuild commit
    /// metadata, or validate those buffers against the lower-level plans.
    pub fn apply_owned_commit_dry_run(
        self,
    ) -> Result<EvalGcStressBoundaryMinorGcCommitDryRun, EvalHeapError> {
        let reference_writebacks = self.apply_reference_writebacks_to_owned_slots()?;
        let commit_applications = self.apply_commits_to_owned_buffers()?;
        let owned_storage_commit_applications =
            self.apply_commits_to_owned_destination_storage()?;

        Ok(EvalGcStressBoundaryMinorGcCommitDryRun::new(
            self,
            reference_writebacks,
            commit_applications,
            owned_storage_commit_applications,
        ))
    }
}

/// Owned dry-run application of GC-stress boundary minor-GC commit preflights.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcCommitDryRun {
    preflights: EvalGcStressBoundaryMinorGcCommitPreflights,
    reference_writebacks: EvalGcStressBoundaryMinorGcReferenceWritebackApplications,
    commit_applications: EvalGcStressBoundaryMinorGcCommitApplications,
    owned_storage_commit_applications: EvalGcStressBoundaryMinorGcOwnedStorageCommitApplications,
}

impl EvalGcStressBoundaryMinorGcCommitDryRun {
    pub(crate) const fn new(
        preflights: EvalGcStressBoundaryMinorGcCommitPreflights,
        reference_writebacks: EvalGcStressBoundaryMinorGcReferenceWritebackApplications,
        commit_applications: EvalGcStressBoundaryMinorGcCommitApplications,
        owned_storage_commit_applications: EvalGcStressBoundaryMinorGcOwnedStorageCommitApplications,
    ) -> Self {
        Self {
            preflights,
            reference_writebacks,
            commit_applications,
            owned_storage_commit_applications,
        }
    }

    /// Returns whether no allocator tier produced a dry-run application.
    pub const fn is_empty(&self) -> bool {
        self.preflights.is_empty()
    }

    /// Returns how many allocator tiers produced dry-run applications.
    pub const fn len(&self) -> usize {
        self.preflights.len()
    }

    /// Returns the preflight metadata used by this dry run.
    pub const fn preflights(&self) -> &EvalGcStressBoundaryMinorGcCommitPreflights {
        &self.preflights
    }

    /// Returns the owned reference-writeback applications.
    pub const fn reference_writebacks(
        &self,
    ) -> &EvalGcStressBoundaryMinorGcReferenceWritebackApplications {
        &self.reference_writebacks
    }

    /// Returns the owned commit-buffer applications.
    pub const fn commit_applications(&self) -> &EvalGcStressBoundaryMinorGcCommitApplications {
        &self.commit_applications
    }

    /// Returns the direct owned destination-storage commit applications.
    pub const fn owned_storage_commit_applications(
        &self,
    ) -> &EvalGcStressBoundaryMinorGcOwnedStorageCommitApplications {
        &self.owned_storage_commit_applications
    }

    /// Returns aggregate counts from preflights, writebacks, and synthetic commit applications.
    pub fn summary(&self) -> EvalGcStressBoundaryMinorGcCommitDryRunSummary {
        EvalGcStressBoundaryMinorGcCommitDryRunSummary::from_preflights_and_applications(
            &self.preflights,
            &self.reference_writebacks,
            &self.commit_applications,
        )
    }
}

/// Boundary commit dry run plus mutation of the outcome-owned daemon card table.
///
/// This report preserves the full owned dry-run artifacts and separately records
/// the one live dirty-card clear applied to [`EvalOutcome`]'s card table after
/// all preflight validation and owned-buffer applications succeeded. It still
/// does not mutate live roots, heap fields, object bytes, forwarding slots,
/// remembered-set storage, heap-record object generations, or semispace storage.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveCardTableCommitDryRun {
    dry_run: EvalGcStressBoundaryMinorGcCommitDryRun,
    card_table_clear_report: GcCardTableClearReport,
}

impl EvalGcStressBoundaryMinorGcLiveCardTableCommitDryRun {
    pub(crate) const fn new(
        dry_run: EvalGcStressBoundaryMinorGcCommitDryRun,
        card_table_clear_report: GcCardTableClearReport,
    ) -> Self {
        Self {
            dry_run,
            card_table_clear_report,
        }
    }

    /// Returns the owned dry-run application that gated the live card-table clear.
    pub const fn dry_run(&self) -> &EvalGcStressBoundaryMinorGcCommitDryRun {
        &self.dry_run
    }

    /// Returns the report for the outcome-owned daemon card-table clear.
    pub const fn card_table_clear_report(&self) -> GcCardTableClearReport {
        self.card_table_clear_report
    }

    /// Returns how many dirty-card markers were cleared from live outcome state.
    pub const fn card_table_dirty_cards_cleared(&self) -> usize {
        self.card_table_clear_report.dirty_cards()
    }
}

/// Boundary commit dry run plus live side-table forwarding installation.
///
/// This report preserves the owned dry-run artifacts and records the forwarding
/// values installed into [`EvalOutcome`]'s evaluator heap side table after all
/// dry-run validation succeeds. It still does not write ABI object headers,
/// copy live object bytes, mutate roots or heap fields, publish remembered-set
/// storage, mutate heap-record object generations, clear card-table storage, or
/// manage semispaces.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveForwardingCommitDryRun {
    dry_run: EvalGcStressBoundaryMinorGcCommitDryRun,
    forwarding_install_report: AllocationCollectorPollForwardingInstallReport,
}

impl EvalGcStressBoundaryMinorGcLiveForwardingCommitDryRun {
    pub(crate) const fn new(
        dry_run: EvalGcStressBoundaryMinorGcCommitDryRun,
        forwarding_install_report: AllocationCollectorPollForwardingInstallReport,
    ) -> Self {
        Self {
            dry_run,
            forwarding_install_report,
        }
    }

    /// Returns the owned dry-run application that gated live forwarding install.
    pub const fn dry_run(&self) -> &EvalGcStressBoundaryMinorGcCommitDryRun {
        &self.dry_run
    }

    /// Returns the live side-table forwarding installation report.
    pub const fn forwarding_install_report(
        &self,
    ) -> AllocationCollectorPollForwardingInstallReport {
        self.forwarding_install_report
    }

    /// Returns how many live side-table forwarding values were installed.
    pub const fn forwarding_pointers_installed(&self) -> usize {
        self.forwarding_install_report.forwarding_pointers()
    }
}

/// Boundary commit dry run plus outcome-owned forwarding binding installation.
///
/// This report preserves the owned dry-run artifacts and records
/// forwarding-to-destination metadata installed into [`EvalOutcome`]. It is a
/// GC-stress bridge only: it does not write ABI object headers, bind payload
/// bytes to live object bodies, mutate heap-record object generations, or
/// manage semispaces.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingCommitDryRun {
    dry_run: EvalGcStressBoundaryMinorGcCommitDryRun,
    forwarding_destination_binding_install_report:
        EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingInstallReport,
}

impl EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingCommitDryRun {
    pub(crate) const fn new(
        dry_run: EvalGcStressBoundaryMinorGcCommitDryRun,
        forwarding_destination_binding_install_report:
            EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingInstallReport,
    ) -> Self {
        Self {
            dry_run,
            forwarding_destination_binding_install_report,
        }
    }

    /// Returns the owned dry run that gated forwarding binding installation.
    pub const fn dry_run(&self) -> &EvalGcStressBoundaryMinorGcCommitDryRun {
        &self.dry_run
    }

    /// Returns the live forwarding destination-binding installation report.
    pub const fn forwarding_destination_binding_install_report(
        &self,
    ) -> EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingInstallReport {
        self.forwarding_destination_binding_install_report
    }

    /// Returns how many forwarding destination bindings were installed.
    pub const fn forwarding_destination_bindings_installed(&self) -> usize {
        self.forwarding_destination_binding_install_report
            .bindings()
    }
}

/// Boundary commit dry run plus outcome-owned destination-byte installation.
///
/// This report preserves the owned dry-run artifacts and records the object
/// payload snapshots installed into [`EvalOutcome`]'s destination-byte side
/// table after all dry-run validation succeeds. It still does not bind those
/// bytes to live heap objects, write ABI object headers, mutate roots or heap
/// fields, publish remembered-set storage, mutate heap-record object
/// generations, clear card-table storage, or manage semispaces.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveDestinationStorageCommitDryRun {
    dry_run: EvalGcStressBoundaryMinorGcCommitDryRun,
    destination_storage_install_report:
        EvalGcStressBoundaryMinorGcLiveDestinationStorageInstallReport,
}

impl EvalGcStressBoundaryMinorGcLiveDestinationStorageCommitDryRun {
    pub(crate) const fn new(
        dry_run: EvalGcStressBoundaryMinorGcCommitDryRun,
        destination_storage_install_report: EvalGcStressBoundaryMinorGcLiveDestinationStorageInstallReport,
    ) -> Self {
        Self {
            dry_run,
            destination_storage_install_report,
        }
    }

    /// Returns the owned dry-run application that gated byte-snapshot install.
    pub const fn dry_run(&self) -> &EvalGcStressBoundaryMinorGcCommitDryRun {
        &self.dry_run
    }

    /// Returns the live destination-byte installation report.
    pub const fn destination_storage_install_report(
        &self,
    ) -> EvalGcStressBoundaryMinorGcLiveDestinationStorageInstallReport {
        self.destination_storage_install_report
    }

    /// Returns how many destination object payload snapshots were installed.
    pub const fn object_copies_installed(&self) -> usize {
        self.destination_storage_install_report.object_copies()
    }
}

/// Boundary commit dry run plus outcome-owned object-generation installation.
///
/// This report preserves the owned dry-run artifacts and records the
/// destination-to-generation metadata installed into [`EvalOutcome`]. It is a
/// GC-stress bridge only: it does not mutate evaluator heap records, allocate
/// old-generation storage, bind payload bytes to live object bodies, write
/// object headers, or manage semispaces.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveObjectGenerationCommitDryRun {
    dry_run: EvalGcStressBoundaryMinorGcCommitDryRun,
    object_generation_install_report: EvalGcStressBoundaryMinorGcLiveObjectGenerationInstallReport,
}

impl EvalGcStressBoundaryMinorGcLiveObjectGenerationCommitDryRun {
    pub(crate) const fn new(
        dry_run: EvalGcStressBoundaryMinorGcCommitDryRun,
        object_generation_install_report: EvalGcStressBoundaryMinorGcLiveObjectGenerationInstallReport,
    ) -> Self {
        Self {
            dry_run,
            object_generation_install_report,
        }
    }

    /// Returns the owned dry-run application that gated generation-metadata install.
    pub const fn dry_run(&self) -> &EvalGcStressBoundaryMinorGcCommitDryRun {
        &self.dry_run
    }

    /// Returns the live object-generation installation report.
    pub const fn object_generation_install_report(
        &self,
    ) -> EvalGcStressBoundaryMinorGcLiveObjectGenerationInstallReport {
        self.object_generation_install_report
    }

    /// Returns how many object-generation records were installed.
    pub const fn object_generations_installed(&self) -> usize {
        self.object_generation_install_report.objects()
    }
}

/// Boundary commit dry run plus outcome-owned reference-writeback installation.
///
/// This report preserves the owned dry-run artifacts and records the copied root
/// and heap-field writeback slots installed into [`EvalOutcome`]'s metadata
/// after all dry-run validation succeeds. It still does not mutate live roots,
/// heap fields, object bytes, forwarding headers, remembered-set storage,
/// heap-record object generations, card-table storage, or semispace pages.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveReferenceWritebackCommitDryRun {
    dry_run: EvalGcStressBoundaryMinorGcCommitDryRun,
    reference_writeback_install_report:
        EvalGcStressBoundaryMinorGcLiveReferenceWritebackInstallReport,
}

impl EvalGcStressBoundaryMinorGcLiveReferenceWritebackCommitDryRun {
    pub(crate) const fn new(
        dry_run: EvalGcStressBoundaryMinorGcCommitDryRun,
        reference_writeback_install_report: EvalGcStressBoundaryMinorGcLiveReferenceWritebackInstallReport,
    ) -> Self {
        Self {
            dry_run,
            reference_writeback_install_report,
        }
    }

    /// Returns the owned dry-run application that gated writeback metadata install.
    pub const fn dry_run(&self) -> &EvalGcStressBoundaryMinorGcCommitDryRun {
        &self.dry_run
    }

    /// Returns the live reference-writeback installation report.
    pub const fn reference_writeback_install_report(
        &self,
    ) -> EvalGcStressBoundaryMinorGcLiveReferenceWritebackInstallReport {
        self.reference_writeback_install_report
    }

    /// Returns how many copied reference writeback slots were installed.
    pub const fn reference_writebacks_installed(&self) -> usize {
        self.reference_writeback_install_report.writebacks()
    }
}

/// Boundary commit dry run plus outcome-owned writeback binding installation.
///
/// This report preserves the owned dry-run artifacts and records root/heap-field
/// destination-binding metadata installed into [`EvalOutcome`]. It is a
/// GC-stress bridge only: it does not mutate evaluator roots, heap object
/// fields, object bytes, ABI forwarding headers, or semispace storage.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindingCommitDryRun {
    dry_run: EvalGcStressBoundaryMinorGcCommitDryRun,
    writeback_destination_binding_install_report:
        EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindingInstallReport,
}

impl EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindingCommitDryRun {
    pub(crate) const fn new(
        dry_run: EvalGcStressBoundaryMinorGcCommitDryRun,
        writeback_destination_binding_install_report:
            EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindingInstallReport,
    ) -> Self {
        Self {
            dry_run,
            writeback_destination_binding_install_report,
        }
    }

    /// Returns the owned dry run that gated writeback binding installation.
    pub const fn dry_run(&self) -> &EvalGcStressBoundaryMinorGcCommitDryRun {
        &self.dry_run
    }

    /// Returns the live writeback destination-binding installation report.
    pub const fn writeback_destination_binding_install_report(
        &self,
    ) -> EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindingInstallReport {
        self.writeback_destination_binding_install_report
    }

    /// Returns how many root writeback destination bindings were installed.
    pub const fn root_writeback_destination_bindings_installed(&self) -> usize {
        self.writeback_destination_binding_install_report
            .root_writeback_bindings()
    }

    /// Returns how many heap-field writeback destination bindings were installed.
    pub const fn heap_field_writeback_destination_bindings_installed(&self) -> usize {
        self.writeback_destination_binding_install_report
            .heap_field_writeback_bindings()
    }

    /// Returns how many total writeback destination bindings were installed.
    pub const fn writeback_destination_bindings_installed(&self) -> usize {
        self.writeback_destination_binding_install_report.bindings()
    }
}

/// Boundary commit dry run plus live remembered-set publication.
///
/// This report preserves the owned dry-run artifacts and records the live
/// outcome-state mutations applied after validation. Sibling worker and
/// permanent-shared applications are merged into one next-epoch remembered set
/// after validating that their survivor relocations form one coherent merged
/// map, because they are parallel projections from the same source epoch rather
/// than sequential live commits.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveRememberedSetCommitDryRun {
    dry_run: EvalGcStressBoundaryMinorGcCommitDryRun,
    remembered_set_published: bool,
    card_table_clear_report: GcCardTableClearReport,
}

impl EvalGcStressBoundaryMinorGcLiveRememberedSetCommitDryRun {
    pub(crate) const fn new(
        dry_run: EvalGcStressBoundaryMinorGcCommitDryRun,
        remembered_set_published: bool,
        card_table_clear_report: GcCardTableClearReport,
    ) -> Self {
        Self {
            dry_run,
            remembered_set_published,
            card_table_clear_report,
        }
    }

    /// Returns the owned dry-run application that gated live-state mutation.
    pub const fn dry_run(&self) -> &EvalGcStressBoundaryMinorGcCommitDryRun {
        &self.dry_run
    }

    /// Returns whether the outcome-owned remembered set was replaced.
    pub const fn remembered_set_published(&self) -> bool {
        self.remembered_set_published
    }

    /// Returns the report for the outcome-owned daemon card-table clear.
    pub const fn card_table_clear_report(&self) -> GcCardTableClearReport {
        self.card_table_clear_report
    }

    /// Returns how many dirty-card markers were cleared from live outcome state.
    pub const fn card_table_dirty_cards_cleared(&self) -> usize {
        self.card_table_clear_report.dirty_cards()
    }
}

/// Boundary commit dry run plus staged outcome-owned GC metadata installation.
///
/// This report preserves the owned dry-run artifacts and records the live
/// metadata installed into [`EvalOutcome`] after all derived side-table payloads
/// validated against the same dry run. It installs evaluator forwarding
/// side-table values, forwarding-destination binding metadata, destination-byte
/// snapshots, reference-writeback metadata, object-generation metadata,
/// writeback destination-binding metadata, the merged next remembered set, and
/// the daemon card-table clear together. It also validates destination
/// generation, forwarding-destination, and root/heap-field writeback destination
/// bindings before the first live metadata mutation. It still does not mutate
/// live root variables, heap fields, object bytes, ABI forwarding headers,
/// evaluator heap-record generations, or semispace pages.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveMetadataCommitDryRun {
    dry_run: EvalGcStressBoundaryMinorGcCommitDryRun,
    forwarding_install_report: AllocationCollectorPollForwardingInstallReport,
    forwarding_destination_binding_install_report:
        EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingInstallReport,
    destination_storage_install_report:
        EvalGcStressBoundaryMinorGcLiveDestinationStorageInstallReport,
    object_generation_install_report: EvalGcStressBoundaryMinorGcLiveObjectGenerationInstallReport,
    reference_writeback_install_report:
        EvalGcStressBoundaryMinorGcLiveReferenceWritebackInstallReport,
    writeback_destination_binding_install_report:
        EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindingInstallReport,
    remembered_set_published: bool,
    card_table_clear_report: GcCardTableClearReport,
}

impl EvalGcStressBoundaryMinorGcLiveMetadataCommitDryRun {
    pub(crate) const fn new(
        dry_run: EvalGcStressBoundaryMinorGcCommitDryRun,
        forwarding_install_report: AllocationCollectorPollForwardingInstallReport,
        forwarding_destination_binding_install_report: EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingInstallReport,
        destination_storage_install_report: EvalGcStressBoundaryMinorGcLiveDestinationStorageInstallReport,
        object_generation_install_report: EvalGcStressBoundaryMinorGcLiveObjectGenerationInstallReport,
        reference_writeback_install_report: EvalGcStressBoundaryMinorGcLiveReferenceWritebackInstallReport,
        writeback_destination_binding_install_report: EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindingInstallReport,
        remembered_set_published: bool,
        card_table_clear_report: GcCardTableClearReport,
    ) -> Self {
        Self {
            dry_run,
            forwarding_install_report,
            forwarding_destination_binding_install_report,
            destination_storage_install_report,
            object_generation_install_report,
            reference_writeback_install_report,
            writeback_destination_binding_install_report,
            remembered_set_published,
            card_table_clear_report,
        }
    }

    /// Returns the owned dry-run application that gated metadata installation.
    pub const fn dry_run(&self) -> &EvalGcStressBoundaryMinorGcCommitDryRun {
        &self.dry_run
    }

    /// Returns the live side-table forwarding installation report.
    pub const fn forwarding_install_report(
        &self,
    ) -> AllocationCollectorPollForwardingInstallReport {
        self.forwarding_install_report
    }

    /// Returns how many live side-table forwarding values were installed.
    pub const fn forwarding_pointers_installed(&self) -> usize {
        self.forwarding_install_report.forwarding_pointers()
    }

    /// Returns the live forwarding destination-binding installation report.
    pub const fn forwarding_destination_binding_install_report(
        &self,
    ) -> EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingInstallReport {
        self.forwarding_destination_binding_install_report
    }

    /// Returns how many forwarding destination bindings were installed.
    pub const fn forwarding_destination_bindings_installed(&self) -> usize {
        self.forwarding_destination_binding_install_report
            .bindings()
    }

    /// Returns the live destination-byte installation report.
    pub const fn destination_storage_install_report(
        &self,
    ) -> EvalGcStressBoundaryMinorGcLiveDestinationStorageInstallReport {
        self.destination_storage_install_report
    }

    /// Returns how many destination object payload snapshots were installed.
    pub const fn object_copies_installed(&self) -> usize {
        self.destination_storage_install_report.object_copies()
    }

    /// Returns the live object-generation installation report.
    pub const fn object_generation_install_report(
        &self,
    ) -> EvalGcStressBoundaryMinorGcLiveObjectGenerationInstallReport {
        self.object_generation_install_report
    }

    /// Returns how many object-generation records were installed.
    pub const fn object_generations_installed(&self) -> usize {
        self.object_generation_install_report.objects()
    }

    /// Returns the live reference-writeback installation report.
    pub const fn reference_writeback_install_report(
        &self,
    ) -> EvalGcStressBoundaryMinorGcLiveReferenceWritebackInstallReport {
        self.reference_writeback_install_report
    }

    /// Returns how many copied reference writeback slots were installed.
    pub const fn reference_writebacks_installed(&self) -> usize {
        self.reference_writeback_install_report.writebacks()
    }

    /// Returns the live writeback destination-binding installation report.
    pub const fn writeback_destination_binding_install_report(
        &self,
    ) -> EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindingInstallReport {
        self.writeback_destination_binding_install_report
    }

    /// Returns how many root writeback destination bindings were installed.
    pub const fn root_writeback_destination_bindings_installed(&self) -> usize {
        self.writeback_destination_binding_install_report
            .root_writeback_bindings()
    }

    /// Returns how many heap-field writeback destination bindings were installed.
    pub const fn heap_field_writeback_destination_bindings_installed(&self) -> usize {
        self.writeback_destination_binding_install_report
            .heap_field_writeback_bindings()
    }

    /// Returns how many total writeback destination bindings were installed.
    pub const fn writeback_destination_bindings_installed(&self) -> usize {
        self.writeback_destination_binding_install_report.bindings()
    }

    /// Returns whether the outcome-owned remembered set was replaced.
    pub const fn remembered_set_published(&self) -> bool {
        self.remembered_set_published
    }

    /// Returns the report for the outcome-owned daemon-card-table clear.
    pub const fn card_table_clear_report(&self) -> GcCardTableClearReport {
        self.card_table_clear_report
    }

    /// Returns how many dirty-card markers were cleared from live outcome state.
    pub const fn card_table_dirty_cards_cleared(&self) -> usize {
        self.card_table_clear_report.dirty_cards()
    }
}

/// Boundary live metadata installation gated by existing destination records.
///
/// This report wraps the ordinary live metadata dry run and records the
/// no-mutation heap-record body/generation preflight that succeeded before any
/// live forwarding slots, outcome-owned metadata side tables, remembered-set
/// state, or card-table state were changed. It still does not write live object
/// bodies or heap-record generations; it only proves those paired writes can be
/// staged for destination records that already exist in the evaluator heap side
/// table.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcExistingDestinationLiveMetadataCommitDryRun {
    live_metadata: EvalGcStressBoundaryMinorGcLiveMetadataCommitDryRun,
    object_body_and_generation_write_report:
        AllocationCollectorPollObjectBodyAndGenerationWriteReport,
}

impl EvalGcStressBoundaryMinorGcExistingDestinationLiveMetadataCommitDryRun {
    pub(crate) const fn new(
        live_metadata: EvalGcStressBoundaryMinorGcLiveMetadataCommitDryRun,
        object_body_and_generation_write_report: AllocationCollectorPollObjectBodyAndGenerationWriteReport,
    ) -> Self {
        Self {
            live_metadata,
            object_body_and_generation_write_report,
        }
    }

    /// Returns the live metadata dry run installed after the preflight succeeded.
    pub const fn live_metadata(&self) -> &EvalGcStressBoundaryMinorGcLiveMetadataCommitDryRun {
        &self.live_metadata
    }

    /// Returns the no-mutation body/generation preflight report.
    pub const fn object_body_and_generation_write_report(
        &self,
    ) -> AllocationCollectorPollObjectBodyAndGenerationWriteReport {
        self.object_body_and_generation_write_report
    }

    /// Returns how many existing destinations were covered by the body preflight.
    pub const fn object_body_preflight_objects(&self) -> usize {
        self.object_body_and_generation_write_report
            .body_write_report()
            .objects()
    }

    /// Returns how many existing destinations were covered by the generation preflight.
    pub const fn object_generation_preflight_objects(&self) -> usize {
        self.object_body_and_generation_write_report
            .generation_write_report()
            .objects()
    }
}
