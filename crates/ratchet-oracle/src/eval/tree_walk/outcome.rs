//! Evaluation outcome, derivation, statistics, trace, IFD-realization, and warning types.

use super::*;
use crate::cache::ImpureInputTraceSource;
use crate::compile::EffectClass;
use crate::eval::heap::EvalRootSource;
use crate::heap::HeapGeneration;

type IfdRealizerCallback =
    dyn for<'a> Fn(IfdRealization<'a>) -> Result<(), IfdRealizationError> + Send + Sync;

const BOUNDARY_MINOR_GC_ROOT_REFERENCE_VALUES_TABLE: &str =
    "boundary minor-GC root reference values";
const BOUNDARY_MINOR_GC_OBJECT_BYTE_COPY_APPLICATIONS_TABLE: &str =
    "boundary minor-GC object byte-copy applications";
const BOUNDARY_MINOR_GC_OBJECT_SOURCE_BYTES_TABLE: &str = "boundary minor-GC object source bytes";
const BOUNDARY_MINOR_GC_OBJECT_DESTINATION_BYTES_TABLE: &str =
    "boundary minor-GC object destination bytes";
const BOUNDARY_MINOR_GC_OBJECT_BYTE_COPY_BUFFERS_TABLE: &str =
    "boundary minor-GC object byte-copy buffers";
const BOUNDARY_MINOR_GC_SOURCE_OBJECT_BYTES_TABLE: &str =
    "boundary minor-GC source object byte refs";
const BOUNDARY_MINOR_GC_NURSERY_DESTINATION_STORAGE_BYTES_TABLE: &str =
    "boundary minor-GC nursery destination storage bytes";
const BOUNDARY_MINOR_GC_OLD_DESTINATION_STORAGE_BYTES_TABLE: &str =
    "boundary minor-GC old destination storage bytes";
const BOUNDARY_MINOR_GC_DESTINATION_STORAGE_LAYOUTS_TABLE: &str =
    "boundary minor-GC destination storage layouts";
const BOUNDARY_MINOR_GC_LIVE_DESTINATION_OBJECT_BYTES_TABLE: &str =
    "boundary minor-GC live destination object bytes";
const BOUNDARY_MINOR_GC_DESTINATION_OBJECT_GENERATION_BINDINGS_TABLE: &str =
    "boundary minor-GC destination object-generation bindings";
const BOUNDARY_MINOR_GC_ROOT_WRITEBACK_DESTINATION_BINDINGS_TABLE: &str =
    "boundary minor-GC root writeback destination bindings";
const BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_DESTINATION_BINDINGS_TABLE: &str =
    "boundary minor-GC heap-field writeback destination bindings";
const BOUNDARY_MINOR_GC_FORWARDING_SLOT_BUFFER_TABLE: &str =
    "boundary minor-GC forwarding slot buffer";
const BOUNDARY_MINOR_GC_REFERENCE_BUFFER_TABLE: &str = "boundary minor-GC reference buffer";
const BOUNDARY_MINOR_GC_ROOT_WRITEBACK_SLOTS_TABLE: &str = "boundary minor-GC root writeback slots";
const BOUNDARY_MINOR_GC_ROOT_VALUE_WRITEBACK_SLOTS_TABLE: &str =
    "boundary minor-GC root value writeback slots";
const BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_SLOTS_TABLE: &str =
    "boundary minor-GC heap-field writeback slots";
const BOUNDARY_MINOR_GC_LIVE_ROOT_WRITEBACK_SLOTS_TABLE: &str =
    "boundary minor-GC live root writeback slots";
const BOUNDARY_MINOR_GC_LIVE_ROOT_VALUE_WRITEBACK_SLOTS_TABLE: &str =
    "boundary minor-GC live root value writeback slots";
const BOUNDARY_MINOR_GC_LIVE_HEAP_FIELD_WRITEBACK_SLOTS_TABLE: &str =
    "boundary minor-GC live heap-field writeback slots";

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
    worker: Option<AllocationCollectorPollMinorGcPlan>,
    permanent_shared: Option<AllocationCollectorPollMinorGcPlan>,
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
    worker: Option<EvalGcStressBoundaryMinorGcRelocationPlan>,
    permanent_shared: Option<EvalGcStressBoundaryMinorGcRelocationPlan>,
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

    fn into_relocation_destinations(self) -> EvalGcStressBoundaryMinorGcRelocationDestinations {
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
    const fn new(
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
    fn record(&mut self, application: &EvalGcStressBoundaryMinorGcReferenceWritebackApplication) {
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
    install_report: EvalGcStressBoundaryMinorGcLiveReferenceWritebackInstallReport,
    applications: EvalGcStressBoundaryMinorGcReferenceWritebackApplications,
}

impl EvalGcStressBoundaryMinorGcLiveReferenceWritebacks {
    fn can_install(
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

    fn install(
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

    fn install_prevalidated(
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

/// Applied boundary-owned object byte buffers for one minor-GC object copy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcObjectByteCopyApplication {
    request: AllocationCollectorPollObjectByteCopyRequest,
    source_bytes: Vec<u8>,
    destination_bytes: Vec<u8>,
}

impl EvalGcStressBoundaryMinorGcObjectByteCopyApplication {
    fn new(
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

/// Applied owned destination storage for one boundary minor-GC preflight.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcDestinationStorageApplication {
    copy_report: MinorGcOwnedDestinationStorageCopyReport,
    nursery_reserved_bytes: usize,
    old_reserved_bytes: usize,
    nursery_destination_bytes: Vec<u8>,
    old_destination_bytes: Vec<u8>,
}

impl EvalGcStressBoundaryMinorGcDestinationStorageApplication {
    fn new(
        copy_report: MinorGcOwnedDestinationStorageCopyReport,
        nursery_reserved_bytes: usize,
        old_reserved_bytes: usize,
        nursery_destination_bytes: Vec<u8>,
        old_destination_bytes: Vec<u8>,
    ) -> Self {
        Self {
            copy_report,
            nursery_reserved_bytes,
            old_reserved_bytes,
            nursery_destination_bytes,
            old_destination_bytes,
        }
    }

    /// Returns the owned destination-storage copy report.
    pub const fn copy_report(&self) -> MinorGcOwnedDestinationStorageCopyReport {
        self.copy_report
    }

    /// Returns bytes reserved for copied next-nursery destinations.
    pub const fn nursery_reserved_bytes(&self) -> usize {
        self.nursery_reserved_bytes
    }

    /// Returns bytes reserved for promoted old-generation destinations.
    pub const fn old_reserved_bytes(&self) -> usize {
        self.old_reserved_bytes
    }

    /// Returns the owned next-nursery destination bytes after copying.
    pub fn nursery_destination_bytes(&self) -> &[u8] {
        &self.nursery_destination_bytes
    }

    /// Returns the owned old-generation destination bytes after copying.
    pub fn old_destination_bytes(&self) -> &[u8] {
        &self.old_destination_bytes
    }
}

/// Outcome-owned destination-byte installation counts for a boundary dry run.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveDestinationStorageInstallReport {
    object_copies: usize,
    copied_to_nursery: usize,
    promoted_to_old: usize,
    nursery_payload_bytes: usize,
    old_payload_bytes: usize,
}

impl EvalGcStressBoundaryMinorGcLiveDestinationStorageInstallReport {
    fn record(&mut self, request: AllocationCollectorPollObjectByteCopyRequest) {
        self.object_copies = self.object_copies.saturating_add(1);
        match request.action() {
            MinorGcSurvivorAction::CopyToNursery => {
                self.copied_to_nursery = self.copied_to_nursery.saturating_add(1);
                self.nursery_payload_bytes = self
                    .nursery_payload_bytes
                    .saturating_add(request.size_bytes());
            }
            MinorGcSurvivorAction::PromoteToOld => {
                self.promoted_to_old = self.promoted_to_old.saturating_add(1);
                self.old_payload_bytes =
                    self.old_payload_bytes.saturating_add(request.size_bytes());
            }
        }
    }

    /// Returns how many destination object payloads were installed.
    pub const fn object_copies(self) -> usize {
        self.object_copies
    }

    /// Returns how many installed payloads target next-nursery storage.
    pub const fn copied_to_nursery(self) -> usize {
        self.copied_to_nursery
    }

    /// Returns how many installed payloads target old-generation storage.
    pub const fn promoted_to_old(self) -> usize {
        self.promoted_to_old
    }

    /// Returns installed next-nursery payload bytes.
    pub const fn nursery_payload_bytes(self) -> usize {
        self.nursery_payload_bytes
    }

    /// Returns installed old-generation payload bytes.
    pub const fn old_payload_bytes(self) -> usize {
        self.old_payload_bytes
    }

    /// Returns total installed object payload bytes.
    pub const fn payload_bytes(self) -> usize {
        self.nursery_payload_bytes
            .saturating_add(self.old_payload_bytes)
    }
}

/// Outcome-owned byte snapshot for one relocated minor-GC object payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes {
    request: AllocationCollectorPollObjectByteCopyRequest,
    destination_bytes: Vec<u8>,
}

impl EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes {
    fn new(
        request: AllocationCollectorPollObjectByteCopyRequest,
        destination_bytes: Vec<u8>,
    ) -> Self {
        Self {
            request,
            destination_bytes,
        }
    }

    /// Returns the byte-copy request that produced this installed snapshot.
    pub const fn request(&self) -> AllocationCollectorPollObjectByteCopyRequest {
        self.request
    }

    /// Returns the from-space source object address.
    pub const fn source(&self) -> GcHeapAddress {
        self.request.source()
    }

    /// Returns the destination object address represented by this snapshot.
    pub const fn destination(&self) -> GcHeapAddress {
        self.request.destination()
    }

    /// Returns the copied payload bytes for the destination object.
    pub fn destination_bytes(&self) -> &[u8] {
        &self.destination_bytes
    }
}

/// Outcome-owned destination-byte snapshots installed by a boundary dry run.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveDestinationStorage {
    install_report: EvalGcStressBoundaryMinorGcLiveDestinationStorageInstallReport,
    object_bytes: Vec<EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes>,
}

impl EvalGcStressBoundaryMinorGcLiveDestinationStorage {
    fn can_install(
        &self,
        install_report: EvalGcStressBoundaryMinorGcLiveDestinationStorageInstallReport,
    ) -> Result<(), EvalHeapError> {
        if install_report.object_copies() != 0 && !self.object_bytes.is_empty() {
            return Err(
                EvalHeapError::BoundaryMinorGcLiveDestinationStorageAlreadyInstalled {
                    existing: self.object_bytes.len(),
                },
            );
        }
        Ok(())
    }

    fn install(
        &mut self,
        object_bytes: Vec<EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes>,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveDestinationStorageInstallReport, EvalHeapError> {
        if object_bytes.is_empty() {
            return Ok(EvalGcStressBoundaryMinorGcLiveDestinationStorageInstallReport::default());
        }
        let install_report = live_destination_storage_install_report(&object_bytes);
        self.can_install(install_report)?;
        validate_boundary_minor_gc_destination_generation_objects(&object_bytes)?;
        self.object_bytes = object_bytes;
        self.install_report = install_report;
        Ok(install_report)
    }

    fn install_prevalidated(
        &mut self,
        object_bytes: Vec<EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes>,
        install_report: EvalGcStressBoundaryMinorGcLiveDestinationStorageInstallReport,
    ) {
        if install_report.object_copies() == 0 {
            return;
        }

        self.object_bytes = object_bytes;
        self.install_report = install_report;
    }

    /// Returns whether no destination byte snapshots are installed.
    pub fn is_empty(&self) -> bool {
        self.object_bytes.is_empty()
    }

    /// Returns how many destination object byte snapshots are installed.
    pub fn len(&self) -> usize {
        self.object_bytes.len()
    }

    /// Returns the report for the last non-empty destination-byte install.
    pub const fn install_report(
        &self,
    ) -> EvalGcStressBoundaryMinorGcLiveDestinationStorageInstallReport {
        self.install_report
    }

    /// Returns the installed destination object byte snapshots.
    pub fn object_bytes(&self) -> &[EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes] {
        &self.object_bytes
    }
}

/// A destination byte snapshot matched to its future object generation.
///
/// The binding is validation metadata for a future object-generation writer. It
/// proves that an installed destination payload's copy action, destination
/// generation, and byte length agree with the object-copy request that produced
/// it, but it does not bind bytes to heap-object storage or mutate generation
/// metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcDestinationObjectGenerationBinding {
    source: GcHeapAddress,
    destination: GcHeapAddress,
    action: MinorGcSurvivorAction,
    generation: HeapGeneration,
    request: AllocationCollectorPollObjectByteCopyRequest,
    destination_bytes: Vec<u8>,
}

impl EvalGcStressBoundaryMinorGcDestinationObjectGenerationBinding {
    fn new(
        source: GcHeapAddress,
        destination: GcHeapAddress,
        action: MinorGcSurvivorAction,
        generation: HeapGeneration,
        request: AllocationCollectorPollObjectByteCopyRequest,
        destination_bytes: Vec<u8>,
    ) -> Self {
        Self {
            source,
            destination,
            action,
            generation,
            request,
            destination_bytes,
        }
    }

    /// Returns the from-space survivor source object.
    pub const fn source(&self) -> GcHeapAddress {
        self.source
    }

    /// Returns the destination object address for the copied payload.
    pub const fn destination(&self) -> GcHeapAddress {
        self.destination
    }

    /// Returns whether this destination keeps the object young or promotes it.
    pub const fn action(&self) -> MinorGcSurvivorAction {
        self.action
    }

    /// Returns the generation that should own the destination object.
    pub const fn generation(&self) -> HeapGeneration {
        self.generation
    }

    /// Returns the object-copy request that installed the destination payload.
    pub const fn request(&self) -> AllocationCollectorPollObjectByteCopyRequest {
        self.request
    }

    /// Returns the installed destination payload bytes.
    pub fn destination_bytes(&self) -> &[u8] {
        &self.destination_bytes
    }
}

/// A root writeback matched to an installed destination-byte snapshot.
///
/// The binding is validation metadata for a future live root writer. It proves
/// that an outcome-owned typed root replacement and its generation-style slot
/// point at an installed destination payload, but it is not a live root slot and
/// does not bind bytes to heap-object storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding {
    allocation_domain: HeapAllocationDomain,
    root_source: EvalRootSource,
    replacement_tag: ValueTag,
    destination: GcHeapAddress,
    generation: HeapGeneration,
    request: AllocationCollectorPollObjectByteCopyRequest,
    destination_bytes: Vec<u8>,
}

impl EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding {
    fn new(
        allocation_domain: HeapAllocationDomain,
        root_source: EvalRootSource,
        replacement_tag: ValueTag,
        destination: GcHeapAddress,
        generation: HeapGeneration,
        request: AllocationCollectorPollObjectByteCopyRequest,
        destination_bytes: Vec<u8>,
    ) -> Self {
        Self {
            allocation_domain,
            root_source,
            replacement_tag,
            destination,
            generation,
            request,
            destination_bytes,
        }
    }

    /// Returns the allocator domain whose boundary application produced this binding.
    pub const fn allocation_domain(&self) -> HeapAllocationDomain {
        self.allocation_domain
    }

    /// Returns the copied root source that would be rewritten.
    pub const fn root_source(&self) -> &EvalRootSource {
        &self.root_source
    }

    /// Returns the heap tag needed to rebuild the typed replacement value.
    pub const fn replacement_tag(&self) -> ValueTag {
        self.replacement_tag
    }

    /// Returns the destination object address for the replacement value.
    pub const fn destination(&self) -> GcHeapAddress {
        self.destination
    }

    /// Returns the generation of the destination object.
    pub const fn generation(&self) -> HeapGeneration {
        self.generation
    }

    /// Returns the object-copy request that installed the destination payload.
    pub const fn request(&self) -> AllocationCollectorPollObjectByteCopyRequest {
        self.request
    }

    /// Returns the installed destination payload bytes matched to the root.
    pub fn destination_bytes(&self) -> &[u8] {
        &self.destination_bytes
    }
}

/// A heap-field writeback matched to installed destination-byte snapshots.
///
/// The binding is validation metadata for a future object-field writer. It
/// proves that the rewritten field value points at an installed destination
/// payload, and for copied nursery fields also proves that the relocated
/// writeback object has an installed destination payload. It does not mutate
/// live object fields or bind bytes to heap-object storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding {
    allocation_domain: HeapAllocationDomain,
    validation_object: GcHeapAddress,
    writeback_object: GcHeapAddress,
    field_index: usize,
    source: HeapEdgeSource,
    replacement_destination: GcHeapAddress,
    replacement_generation: HeapGeneration,
    replacement_request: AllocationCollectorPollObjectByteCopyRequest,
    replacement_destination_bytes: Vec<u8>,
    writeback_object_request: Option<AllocationCollectorPollObjectByteCopyRequest>,
    writeback_object_destination_bytes: Option<Vec<u8>>,
}

impl EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding {
    fn new(
        allocation_domain: HeapAllocationDomain,
        validation_object: GcHeapAddress,
        writeback_object: GcHeapAddress,
        field_index: usize,
        source: HeapEdgeSource,
        replacement_destination: GcHeapAddress,
        replacement_generation: HeapGeneration,
        replacement_request: AllocationCollectorPollObjectByteCopyRequest,
        replacement_destination_bytes: Vec<u8>,
        writeback_object_request: Option<AllocationCollectorPollObjectByteCopyRequest>,
        writeback_object_destination_bytes: Option<Vec<u8>>,
    ) -> Self {
        Self {
            allocation_domain,
            validation_object,
            writeback_object,
            field_index,
            source,
            replacement_destination,
            replacement_generation,
            replacement_request,
            replacement_destination_bytes,
            writeback_object_request,
            writeback_object_destination_bytes,
        }
    }

    /// Returns the allocator domain whose boundary application produced this binding.
    pub const fn allocation_domain(&self) -> HeapAllocationDomain {
        self.allocation_domain
    }

    /// Returns the object used to validate the copied field label.
    pub const fn validation_object(&self) -> GcHeapAddress {
        self.validation_object
    }

    /// Returns the object whose field would be rewritten.
    pub const fn writeback_object(&self) -> GcHeapAddress {
        self.writeback_object
    }

    /// Returns the field index in precise scanner order.
    pub const fn field_index(&self) -> usize {
        self.field_index
    }

    /// Returns the copied field source label.
    pub const fn source(&self) -> &HeapEdgeSource {
        &self.source
    }

    /// Returns the destination object address written into the field.
    pub const fn replacement_destination(&self) -> GcHeapAddress {
        self.replacement_destination
    }

    /// Returns the generation of the replacement destination object.
    pub const fn replacement_generation(&self) -> HeapGeneration {
        self.replacement_generation
    }

    /// Returns the object-copy request for the replacement destination payload.
    pub const fn replacement_request(&self) -> AllocationCollectorPollObjectByteCopyRequest {
        self.replacement_request
    }

    /// Returns the installed replacement destination payload bytes.
    pub fn replacement_destination_bytes(&self) -> &[u8] {
        &self.replacement_destination_bytes
    }

    /// Returns the copied writeback object's request, if the field targets one.
    pub const fn writeback_object_request(
        &self,
    ) -> Option<AllocationCollectorPollObjectByteCopyRequest> {
        self.writeback_object_request
    }

    /// Returns the copied writeback object's destination bytes, if installed.
    pub fn writeback_object_destination_bytes(&self) -> Option<&[u8]> {
        self.writeback_object_destination_bytes.as_deref()
    }
}

/// Applied boundary-owned buffers for one minor-GC commit preflight.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcCommitApplication {
    report: MinorGcCommitReport,
    object_byte_copies: Vec<EvalGcStressBoundaryMinorGcObjectByteCopyApplication>,
    destination_storage: EvalGcStressBoundaryMinorGcDestinationStorageApplication,
    forwarding_slots: Vec<MinorGcForwardingSlot>,
    references: Vec<ResolvedValueGeneration>,
    remembered_set: RememberedSet,
    card_table: GcCardTable,
}

impl EvalGcStressBoundaryMinorGcCommitApplication {
    fn new(
        report: MinorGcCommitReport,
        object_byte_copies: Vec<EvalGcStressBoundaryMinorGcObjectByteCopyApplication>,
        destination_storage: EvalGcStressBoundaryMinorGcDestinationStorageApplication,
        forwarding_slots: Vec<MinorGcForwardingSlot>,
        references: Vec<ResolvedValueGeneration>,
        remembered_set: RememberedSet,
        card_table: GcCardTable,
    ) -> Self {
        Self {
            report,
            object_byte_copies,
            destination_storage,
            forwarding_slots,
            references,
            remembered_set,
            card_table,
        }
    }

    /// Returns the lower-level commit counts for the applied owned buffers.
    pub const fn report(&self) -> MinorGcCommitReport {
        self.report
    }

    /// Returns owned object byte buffers after commit application.
    pub fn object_byte_copies(&self) -> &[EvalGcStressBoundaryMinorGcObjectByteCopyApplication] {
        &self.object_byte_copies
    }

    /// Returns the owned destination storage snapshot after object-byte copying.
    pub const fn destination_storage(
        &self,
    ) -> &EvalGcStressBoundaryMinorGcDestinationStorageApplication {
        &self.destination_storage
    }

    /// Returns forwarding slots after commit application.
    pub fn forwarding_slots(&self) -> &[MinorGcForwardingSlot] {
        &self.forwarding_slots
    }

    /// Returns copied reference values after commit application.
    pub fn references(&self) -> &[ResolvedValueGeneration] {
        &self.references
    }

    /// Returns the remembered set after commit publication into the owned buffer.
    pub const fn remembered_set(&self) -> &RememberedSet {
        &self.remembered_set
    }

    /// Returns the owned daemon card-table copy after commit application.
    ///
    /// The table is a dry-run clone of the outcome's daemon-wide card table,
    /// not tier-partitioned live card-table state.
    pub const fn card_table(&self) -> &GcCardTable {
        &self.card_table
    }
}

fn boundary_minor_gc_object_byte_copy_applications(
    plan: &AllocationCollectorPollObjectByteCopyPlan,
) -> Result<Vec<EvalGcStressBoundaryMinorGcObjectByteCopyApplication>, EvalHeapError> {
    let requests = plan.requests();
    let mut applications = Vec::new();
    applications
        .try_reserve_exact(requests.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_OBJECT_BYTE_COPY_APPLICATIONS_TABLE,
            entries: requests.len(),
        })?;

    for (index, request) in requests.iter().copied().enumerate() {
        applications.push(EvalGcStressBoundaryMinorGcObjectByteCopyApplication::new(
            request,
            boundary_minor_gc_object_source_bytes(index, request.size_bytes())?,
            boundary_minor_gc_object_destination_bytes(request.size_bytes())?,
        ));
    }

    Ok(applications)
}

fn boundary_minor_gc_object_source_bytes(
    index: usize,
    size_bytes: usize,
) -> Result<Vec<u8>, EvalHeapError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size_bytes)
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_OBJECT_SOURCE_BYTES_TABLE,
            entries: size_bytes,
        })?;
    let seed = index.to_le_bytes()[0].wrapping_mul(31).wrapping_add(0xa5);
    for offset in 0..size_bytes {
        bytes.push(seed.wrapping_add(offset.to_le_bytes()[0]));
    }
    Ok(bytes)
}

fn boundary_minor_gc_object_destination_bytes(size_bytes: usize) -> Result<Vec<u8>, EvalHeapError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size_bytes)
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_OBJECT_DESTINATION_BYTES_TABLE,
            entries: size_bytes,
        })?;
    bytes.resize(size_bytes, 0);
    Ok(bytes)
}

fn boundary_minor_gc_object_byte_copy_buffers<'a>(
    applications: &'a mut [EvalGcStressBoundaryMinorGcObjectByteCopyApplication],
) -> Result<Vec<MinorGcObjectByteCopyBuffer<'a>>, EvalHeapError> {
    let mut buffers = Vec::new();
    buffers.try_reserve_exact(applications.len()).map_err(|_| {
        EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_OBJECT_BYTE_COPY_BUFFERS_TABLE,
            entries: applications.len(),
        }
    })?;

    for application in applications.iter_mut() {
        let request = application.request;
        let source_bytes = application.source_bytes.as_slice();
        let destination_bytes = application.destination_bytes.as_mut_slice();
        buffers.push(MinorGcObjectByteCopyBuffer::new(
            request.source(),
            request.destination(),
            source_bytes,
            destination_bytes,
        ));
    }

    Ok(buffers)
}

fn boundary_minor_gc_destination_storage_application(
    relocation_plan: &EvalGcStressBoundaryMinorGcRelocationPlan,
    object_byte_copies: &[EvalGcStressBoundaryMinorGcObjectByteCopyApplication],
) -> Result<EvalGcStressBoundaryMinorGcDestinationStorageApplication, EvalHeapError> {
    let placement_plan = relocation_plan.relocation_destinations().placement_plan();
    let mut storage = MinorGcOwnedDestinationStorage::from_placement_plan(placement_plan)?;
    let copy_plan = boundary_minor_gc_destination_storage_copy_plan(
        &storage,
        relocation_plan.minor_gc_plan().plan(),
        placement_plan,
    )?;
    let source_bytes = boundary_minor_gc_source_object_bytes(object_byte_copies)?;
    let copy_report = storage.copy_from_sources(&copy_plan, &source_bytes)?;
    let nursery_reserved_bytes = storage.nursery_reserved_bytes();
    let old_reserved_bytes = storage.old_reserved_bytes();
    let nursery_destination_bytes = clone_boundary_destination_storage_bytes(
        BOUNDARY_MINOR_GC_NURSERY_DESTINATION_STORAGE_BYTES_TABLE,
        storage.nursery_destination_bytes(),
    )?;
    let old_destination_bytes = clone_boundary_destination_storage_bytes(
        BOUNDARY_MINOR_GC_OLD_DESTINATION_STORAGE_BYTES_TABLE,
        storage.old_destination_bytes(),
    )?;

    Ok(
        EvalGcStressBoundaryMinorGcDestinationStorageApplication::new(
            copy_report,
            nursery_reserved_bytes,
            old_reserved_bytes,
            nursery_destination_bytes,
            old_destination_bytes,
        ),
    )
}

fn boundary_minor_gc_destination_storage_copy_plan(
    storage: &MinorGcOwnedDestinationStorage,
    plan: &MinorGcPlan,
    placement_plan: &MinorGcDestinationPlacementPlan,
) -> Result<MinorGcObjectCopyPlan, EvalHeapError> {
    let destination_plan = storage.relocation_destination_plan(plan)?;
    let relocation_plan = destination_plan.relocation_plan(plan)?;
    let nursery_layouts = boundary_minor_gc_nursery_layouts_from_placements(placement_plan)?;
    Ok(MinorGcObjectCopyPlan::from_relocation_plan(
        &relocation_plan,
        &nursery_layouts,
    )?)
}

fn boundary_minor_gc_nursery_layouts_from_placements(
    placement_plan: &MinorGcDestinationPlacementPlan,
) -> Result<Vec<NurseryObjectLayout>, EvalHeapError> {
    let mut nursery_layouts = Vec::new();
    nursery_layouts
        .try_reserve_exact(placement_plan.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_DESTINATION_STORAGE_LAYOUTS_TABLE,
            entries: placement_plan.len(),
        })?;
    for placement in placement_plan.placements() {
        nursery_layouts.push(NurseryObjectLayout::new(
            placement.source(),
            placement.size_bytes(),
            placement.align(),
        ));
    }
    Ok(nursery_layouts)
}

fn boundary_minor_gc_source_object_bytes<'a>(
    applications: &'a [EvalGcStressBoundaryMinorGcObjectByteCopyApplication],
) -> Result<Vec<MinorGcSourceObjectBytes<'a>>, EvalHeapError> {
    let mut sources = Vec::new();
    sources.try_reserve_exact(applications.len()).map_err(|_| {
        EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_SOURCE_OBJECT_BYTES_TABLE,
            entries: applications.len(),
        }
    })?;
    for application in applications {
        sources.push(MinorGcSourceObjectBytes::new(
            application.request().source(),
            application.source_bytes(),
        ));
    }
    Ok(sources)
}

fn clone_boundary_destination_storage_bytes(
    table: &'static str,
    bytes: &[u8],
) -> Result<Vec<u8>, EvalHeapError> {
    let mut cloned = Vec::new();
    cloned
        .try_reserve_exact(bytes.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table,
            entries: bytes.len(),
        })?;
    cloned.extend_from_slice(bytes);
    Ok(cloned)
}

fn live_destination_storage_install_report(
    object_bytes: &[EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes],
) -> EvalGcStressBoundaryMinorGcLiveDestinationStorageInstallReport {
    let mut report = EvalGcStressBoundaryMinorGcLiveDestinationStorageInstallReport::default();
    for object in object_bytes {
        report.record(object.request());
    }
    report
}

fn live_reference_writeback_install_report(
    applications: &EvalGcStressBoundaryMinorGcReferenceWritebackApplications,
) -> EvalGcStressBoundaryMinorGcLiveReferenceWritebackInstallReport {
    let mut report = EvalGcStressBoundaryMinorGcLiveReferenceWritebackInstallReport::default();
    if let Some(application) = applications.worker() {
        report.record(application);
    }
    if let Some(application) = applications.permanent_shared() {
        report.record(application);
    }
    report
}

fn boundary_minor_gc_destination_object_generation_bindings(
    destination_storage: &EvalGcStressBoundaryMinorGcLiveDestinationStorage,
) -> Result<Vec<EvalGcStressBoundaryMinorGcDestinationObjectGenerationBinding>, EvalHeapError> {
    boundary_minor_gc_destination_object_generation_bindings_from_objects(
        destination_storage.object_bytes(),
    )
}

fn boundary_minor_gc_destination_object_generation_bindings_from_objects(
    destination_objects: &[EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes],
) -> Result<Vec<EvalGcStressBoundaryMinorGcDestinationObjectGenerationBinding>, EvalHeapError> {
    validate_boundary_minor_gc_destination_generation_objects(destination_objects)?;
    let mut bindings = Vec::new();
    bindings
        .try_reserve_exact(destination_objects.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_DESTINATION_OBJECT_GENERATION_BINDINGS_TABLE,
            entries: destination_objects.len(),
        })?;

    for object in destination_objects {
        let generation = validated_destination_object_generation(object)?;
        bindings.push(
            EvalGcStressBoundaryMinorGcDestinationObjectGenerationBinding::new(
                object.source(),
                object.destination(),
                object.request().action(),
                generation,
                object.request(),
                clone_boundary_destination_storage_bytes(
                    BOUNDARY_MINOR_GC_DESTINATION_OBJECT_GENERATION_BINDINGS_TABLE,
                    object.destination_bytes(),
                )?,
            ),
        );
    }

    Ok(bindings)
}

fn validate_boundary_minor_gc_destination_generation_objects(
    destination_objects: &[EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes],
) -> Result<(), EvalHeapError> {
    for (index, object) in destination_objects.iter().enumerate() {
        let _ = validated_destination_object_generation(object)?;
        if let Some(existing) = destination_objects[..index]
            .iter()
            .find(|existing| existing.destination() == object.destination())
        {
            return Err(
                EvalHeapError::BoundaryMinorGcLiveDestinationStorageDestinationCollision {
                    source_address: object.source(),
                    existing_source_address: existing.source(),
                    destination_address: object.destination(),
                },
            );
        }
    }

    Ok(())
}

fn boundary_minor_gc_root_writeback_destination_bindings(
    writebacks: &EvalGcStressBoundaryMinorGcLiveReferenceWritebacks,
    destination_storage: &EvalGcStressBoundaryMinorGcLiveDestinationStorage,
) -> Result<Vec<EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding>, EvalHeapError> {
    boundary_minor_gc_root_writeback_destination_bindings_from_applications(
        writebacks.applications(),
        destination_storage.object_bytes(),
    )
}

fn boundary_minor_gc_root_writeback_destination_bindings_from_applications(
    applications: &EvalGcStressBoundaryMinorGcReferenceWritebackApplications,
    destination_objects: &[EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes],
) -> Result<Vec<EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding>, EvalHeapError> {
    let mut bindings = Vec::new();
    extend_boundary_minor_gc_root_writeback_destination_bindings(
        &mut bindings,
        HeapAllocationDomain::Worker,
        applications.worker(),
        destination_objects,
    )?;
    extend_boundary_minor_gc_root_writeback_destination_bindings(
        &mut bindings,
        HeapAllocationDomain::PermanentShared,
        applications.permanent_shared(),
        destination_objects,
    )?;
    Ok(bindings)
}

fn extend_boundary_minor_gc_root_writeback_destination_bindings(
    bindings: &mut Vec<EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding>,
    allocation_domain: HeapAllocationDomain,
    application: Option<&EvalGcStressBoundaryMinorGcReferenceWritebackApplication>,
    destination_objects: &[EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes],
) -> Result<(), EvalHeapError> {
    let Some(application) = application else {
        return Ok(());
    };

    let root_slots = application.root_writeback_slots();
    let value_slots = application.root_value_writeback_slots();
    if root_slots.len() != value_slots.len() {
        return Err(
            EvalHeapError::CollectorPollRootWritebackSlotLengthMismatch {
                expected: root_slots.len(),
                actual: value_slots.len(),
            },
        );
    }

    for (index, (root_slot, value_slot)) in root_slots.iter().zip(value_slots.iter()).enumerate() {
        if root_slot.source() != value_slot.source() {
            return Err(EvalHeapError::CollectorPollRootReferenceSourceMismatch {
                index,
                expected: root_slot.source().clone(),
                actual: value_slot.source().clone(),
            });
        }
        let ResolvedValueGeneration::Heap {
            address: destination,
            generation,
        } = root_slot.value()
        else {
            return Err(EvalHeapError::CollectorPollRootWritebackNonHeapValue {
                tag: value_slot.value().tag(),
                value: root_slot.value(),
            });
        };
        let replacement = value_slot.value();
        let replacement_ptr = replacement.as_heap_ptr().map_err(EvalHeapError::Value)?;
        let replacement_destination = GcHeapAddress::new(replacement_ptr.as_ptr() as usize)
            .map_err(EvalHeapError::GenerationalGc)?;
        if replacement_destination != destination {
            return Err(
                EvalHeapError::BoundaryMinorGcRootWritebackDestinationMismatch {
                    root_source: root_slot.source().clone(),
                    expected_destination: destination,
                    actual_tag: replacement.tag(),
                    actual_payload: replacement.payload_bits(),
                },
            );
        }

        let destination_object = destination_objects
            .iter()
            .find(|object| object.destination() == destination)
            .ok_or_else(
                || EvalHeapError::BoundaryMinorGcRootWritebackDestinationMissing {
                    root_source: root_slot.source().clone(),
                    destination,
                },
            )?;
        let expected_generation = validated_destination_object_generation(destination_object)?;
        if generation != expected_generation {
            return Err(
                EvalHeapError::BoundaryMinorGcRootWritebackGenerationMismatch {
                    root_source: root_slot.source().clone(),
                    destination,
                    expected: expected_generation,
                    actual: generation,
                    action: destination_object.request().action(),
                },
            );
        }

        let entries =
            bindings
                .len()
                .checked_add(1)
                .ok_or(EvalHeapError::RootScanLengthOverflow {
                    table: BOUNDARY_MINOR_GC_ROOT_WRITEBACK_DESTINATION_BINDINGS_TABLE,
                })?;
        bindings
            .try_reserve_exact(1)
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: BOUNDARY_MINOR_GC_ROOT_WRITEBACK_DESTINATION_BINDINGS_TABLE,
                entries,
            })?;
        bindings.push(
            EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding::new(
                allocation_domain,
                root_slot.source().clone(),
                replacement.tag(),
                destination,
                generation,
                destination_object.request(),
                clone_boundary_destination_storage_bytes(
                    BOUNDARY_MINOR_GC_ROOT_WRITEBACK_DESTINATION_BINDINGS_TABLE,
                    destination_object.destination_bytes(),
                )?,
            ),
        );
    }

    Ok(())
}

fn boundary_minor_gc_heap_field_writeback_destination_bindings(
    writebacks: &EvalGcStressBoundaryMinorGcLiveReferenceWritebacks,
    destination_storage: &EvalGcStressBoundaryMinorGcLiveDestinationStorage,
) -> Result<Vec<EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding>, EvalHeapError> {
    boundary_minor_gc_heap_field_writeback_destination_bindings_from_applications(
        writebacks.applications(),
        destination_storage.object_bytes(),
    )
}

fn boundary_minor_gc_heap_field_writeback_destination_bindings_from_applications(
    applications: &EvalGcStressBoundaryMinorGcReferenceWritebackApplications,
    destination_objects: &[EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes],
) -> Result<Vec<EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding>, EvalHeapError> {
    let mut bindings = Vec::new();
    extend_boundary_minor_gc_heap_field_writeback_destination_bindings(
        &mut bindings,
        HeapAllocationDomain::Worker,
        applications.worker(),
        destination_objects,
    )?;
    extend_boundary_minor_gc_heap_field_writeback_destination_bindings(
        &mut bindings,
        HeapAllocationDomain::PermanentShared,
        applications.permanent_shared(),
        destination_objects,
    )?;
    Ok(bindings)
}

fn extend_boundary_minor_gc_heap_field_writeback_destination_bindings(
    bindings: &mut Vec<EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding>,
    allocation_domain: HeapAllocationDomain,
    application: Option<&EvalGcStressBoundaryMinorGcReferenceWritebackApplication>,
    destination_objects: &[EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes],
) -> Result<(), EvalHeapError> {
    let Some(application) = application else {
        return Ok(());
    };

    for slot in application.heap_field_writeback_slots() {
        let ResolvedValueGeneration::Heap {
            address: replacement_destination,
            generation: replacement_generation,
        } = slot.value()
        else {
            return Err(
                EvalHeapError::BoundaryMinorGcHeapFieldWritebackReplacementNonHeap {
                    writeback_object: slot.writeback_object(),
                    field_index: slot.field_index(),
                    field_source: slot.source().clone(),
                    value: slot.value(),
                },
            );
        };

        let replacement_object = destination_objects
            .iter()
            .find(|object| object.destination() == replacement_destination)
            .ok_or_else(
                || EvalHeapError::BoundaryMinorGcHeapFieldWritebackReplacementMissing {
                    writeback_object: slot.writeback_object(),
                    field_index: slot.field_index(),
                    field_source: slot.source().clone(),
                    replacement: replacement_destination,
                },
            )?;
        let expected_generation = validated_destination_object_generation(replacement_object)?;
        if replacement_generation != expected_generation {
            return Err(
                EvalHeapError::BoundaryMinorGcHeapFieldWritebackReplacementGenerationMismatch {
                    writeback_object: slot.writeback_object(),
                    field_index: slot.field_index(),
                    field_source: slot.source().clone(),
                    replacement: replacement_destination,
                    expected: expected_generation,
                    actual: replacement_generation,
                    action: replacement_object.request().action(),
                },
            );
        }

        let writeback_object_destination = if slot.validation_object() != slot.writeback_object() {
            let Some(object) = destination_objects
                .iter()
                .find(|object| object.destination() == slot.writeback_object())
            else {
                return Err(
                    EvalHeapError::BoundaryMinorGcHeapFieldWritebackObjectMissing {
                        validation_object: slot.validation_object(),
                        writeback_object: slot.writeback_object(),
                        field_index: slot.field_index(),
                        field_source: slot.source().clone(),
                    },
                );
            };
            if object.source() != slot.validation_object() {
                return Err(
                    EvalHeapError::BoundaryMinorGcHeapFieldWritebackObjectSourceMismatch {
                        validation_object: slot.validation_object(),
                        writeback_object: slot.writeback_object(),
                        field_index: slot.field_index(),
                        field_source: slot.source().clone(),
                        actual_source: object.source(),
                    },
                );
            }
            let _ = validated_destination_object_generation(object)?;
            Some(object)
        } else {
            None
        };

        let entries =
            bindings
                .len()
                .checked_add(1)
                .ok_or(EvalHeapError::RootScanLengthOverflow {
                    table: BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_DESTINATION_BINDINGS_TABLE,
                })?;
        bindings
            .try_reserve_exact(1)
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_DESTINATION_BINDINGS_TABLE,
                entries,
            })?;
        let replacement_destination_bytes = clone_boundary_destination_storage_bytes(
            BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_DESTINATION_BINDINGS_TABLE,
            replacement_object.destination_bytes(),
        )?;
        let writeback_object_request = writeback_object_destination
            .map(EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes::request);
        let writeback_object_destination_bytes = writeback_object_destination
            .map(|object| {
                clone_boundary_destination_storage_bytes(
                    BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_DESTINATION_BINDINGS_TABLE,
                    object.destination_bytes(),
                )
            })
            .transpose()?;
        bindings.push(
            EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding::new(
                allocation_domain,
                slot.validation_object(),
                slot.writeback_object(),
                slot.field_index(),
                slot.source().clone(),
                replacement_destination,
                replacement_generation,
                replacement_object.request(),
                replacement_destination_bytes,
                writeback_object_request,
                writeback_object_destination_bytes,
            ),
        );
    }

    Ok(())
}

const fn generation_for_destination_action(action: MinorGcSurvivorAction) -> HeapGeneration {
    match action {
        MinorGcSurvivorAction::CopyToNursery => HeapGeneration::Young,
        MinorGcSurvivorAction::PromoteToOld => HeapGeneration::Old,
    }
}

fn validated_destination_request_generation(
    request: AllocationCollectorPollObjectByteCopyRequest,
) -> Result<HeapGeneration, EvalHeapError> {
    let expected = generation_for_destination_action(request.action());
    let actual = request.destination_generation();
    if actual != expected {
        return Err(
            EvalHeapError::BoundaryMinorGcDestinationActionGenerationMismatch {
                destination: request.destination(),
                expected,
                actual,
                action: request.action(),
            },
        );
    }

    Ok(expected)
}

fn validated_destination_object_generation(
    object: &EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes,
) -> Result<HeapGeneration, EvalHeapError> {
    let generation = validated_destination_request_generation(object.request())?;
    let expected = object.request().size_bytes();
    let actual = object.destination_bytes().len();
    if actual != expected {
        return Err(
            EvalHeapError::BoundaryMinorGcDestinationPayloadSizeMismatch {
                destination: object.destination(),
                expected,
                actual,
            },
        );
    }

    Ok(generation)
}

fn clone_boundary_forwarding_slots(
    slots: &[MinorGcForwardingSlot],
) -> Result<Vec<MinorGcForwardingSlot>, EvalHeapError> {
    let mut cloned = Vec::new();
    cloned
        .try_reserve_exact(slots.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_FORWARDING_SLOT_BUFFER_TABLE,
            entries: slots.len(),
        })?;
    cloned.extend(slots.iter().copied());
    Ok(cloned)
}

fn clone_boundary_reference_buffer(
    references: &[ResolvedValueGeneration],
) -> Result<Vec<ResolvedValueGeneration>, EvalHeapError> {
    let mut cloned = Vec::new();
    cloned.try_reserve_exact(references.len()).map_err(|_| {
        EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_REFERENCE_BUFFER_TABLE,
            entries: references.len(),
        }
    })?;
    cloned.extend(references.iter().copied());
    Ok(cloned)
}

fn clone_boundary_reference_writeback_applications(
    applications: &EvalGcStressBoundaryMinorGcReferenceWritebackApplications,
) -> Result<EvalGcStressBoundaryMinorGcReferenceWritebackApplications, EvalHeapError> {
    let worker = applications
        .worker()
        .map(clone_boundary_reference_writeback_application)
        .transpose()?;
    let permanent_shared = applications
        .permanent_shared()
        .map(clone_boundary_reference_writeback_application)
        .transpose()?;
    Ok(EvalGcStressBoundaryMinorGcReferenceWritebackApplications::new(worker, permanent_shared))
}

fn clone_boundary_reference_writeback_application(
    application: &EvalGcStressBoundaryMinorGcReferenceWritebackApplication,
) -> Result<EvalGcStressBoundaryMinorGcReferenceWritebackApplication, EvalHeapError> {
    Ok(
        EvalGcStressBoundaryMinorGcReferenceWritebackApplication::new(
            application.report(),
            clone_boundary_live_root_writeback_slots(application.root_writeback_slots())?,
            clone_boundary_live_root_value_writeback_slots(
                application.root_value_writeback_slots(),
            )?,
            clone_boundary_live_heap_field_writeback_slots(
                application.heap_field_writeback_slots(),
            )?,
        ),
    )
}

fn clone_boundary_live_root_writeback_slots(
    slots: &[AllocationCollectorPollRootWritebackSlot],
) -> Result<Vec<AllocationCollectorPollRootWritebackSlot>, EvalHeapError> {
    let mut cloned = Vec::new();
    cloned
        .try_reserve_exact(slots.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_LIVE_ROOT_WRITEBACK_SLOTS_TABLE,
            entries: slots.len(),
        })?;
    cloned.extend(slots.iter().cloned());
    Ok(cloned)
}

fn clone_boundary_live_root_value_writeback_slots(
    slots: &[AllocationCollectorPollRootValueWritebackSlot],
) -> Result<Vec<AllocationCollectorPollRootValueWritebackSlot>, EvalHeapError> {
    let mut cloned = Vec::new();
    cloned
        .try_reserve_exact(slots.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_LIVE_ROOT_VALUE_WRITEBACK_SLOTS_TABLE,
            entries: slots.len(),
        })?;
    cloned.extend(slots.iter().cloned());
    Ok(cloned)
}

fn clone_boundary_live_heap_field_writeback_slots(
    slots: &[AllocationCollectorPollHeapFieldWritebackSlot],
) -> Result<Vec<AllocationCollectorPollHeapFieldWritebackSlot>, EvalHeapError> {
    let mut cloned = Vec::new();
    cloned
        .try_reserve_exact(slots.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_LIVE_HEAP_FIELD_WRITEBACK_SLOTS_TABLE,
            entries: slots.len(),
        })?;
    cloned.extend(slots.iter().cloned());
    Ok(cloned)
}

fn clone_boundary_remembered_set(
    remembered_set: &RememberedSet,
) -> Result<RememberedSet, EvalHeapError> {
    let mut cloned = RememberedSet::with_epoch(remembered_set.epoch());
    for edge in remembered_set.edges() {
        cloned.record(*edge)?;
    }
    Ok(cloned)
}

fn boundary_minor_gc_merged_destination_object_bytes(
    applications: &EvalGcStressBoundaryMinorGcCommitApplications,
) -> Result<Vec<EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes>, EvalHeapError> {
    let mut merged = Vec::new();
    merge_boundary_minor_gc_destination_object_bytes_application(
        &mut merged,
        applications.worker(),
    )?;
    merge_boundary_minor_gc_destination_object_bytes_application(
        &mut merged,
        applications.permanent_shared(),
    )?;
    Ok(merged)
}

fn merge_boundary_minor_gc_destination_object_bytes_application(
    merged: &mut Vec<EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes>,
    application: Option<&EvalGcStressBoundaryMinorGcCommitApplication>,
) -> Result<(), EvalHeapError> {
    let Some(application) = application else {
        return Ok(());
    };

    for object_copy in application.object_byte_copies() {
        let request = object_copy.request();
        if let Some(existing) = merged
            .iter()
            .find(|existing| existing.source() == request.source())
        {
            if existing.request() != request
                || existing.destination_bytes() != object_copy.destination_bytes()
            {
                return Err(
                    EvalHeapError::BoundaryMinorGcLiveDestinationStorageObjectMismatch {
                        source_address: request.source(),
                        expected: existing.request(),
                        actual: request,
                    },
                );
            }
            continue;
        }

        if let Some(existing) = merged
            .iter()
            .find(|existing| existing.destination() == request.destination())
        {
            return Err(
                EvalHeapError::BoundaryMinorGcLiveDestinationStorageDestinationCollision {
                    source_address: request.source(),
                    existing_source_address: existing.source(),
                    destination_address: request.destination(),
                },
            );
        }

        let entries = merged
            .len()
            .checked_add(1)
            .ok_or(EvalHeapError::RootScanLengthOverflow {
                table: BOUNDARY_MINOR_GC_LIVE_DESTINATION_OBJECT_BYTES_TABLE,
            })?;
        merged
            .try_reserve_exact(1)
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: BOUNDARY_MINOR_GC_LIVE_DESTINATION_OBJECT_BYTES_TABLE,
                entries,
            })?;
        merged.push(EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes::new(
            request,
            clone_boundary_destination_storage_bytes(
                BOUNDARY_MINOR_GC_LIVE_DESTINATION_OBJECT_BYTES_TABLE,
                object_copy.destination_bytes(),
            )?,
        ));
    }

    Ok(())
}

fn boundary_minor_gc_merged_forwarding_slots(
    applications: &EvalGcStressBoundaryMinorGcCommitApplications,
) -> Result<Vec<MinorGcForwardingSlot>, EvalHeapError> {
    let mut relocations = Vec::new();
    merge_boundary_minor_gc_forwarding_slot_application(&mut relocations, applications.worker())?;
    merge_boundary_minor_gc_forwarding_slot_application(
        &mut relocations,
        applications.permanent_shared(),
    )?;

    let mut slots = Vec::new();
    slots.try_reserve_exact(relocations.len()).map_err(|_| {
        EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_FORWARDING_SLOT_BUFFER_TABLE,
            entries: relocations.len(),
        }
    })?;
    for (source, forwarded) in relocations {
        slots.push(MinorGcForwardingSlot::with_forwarded_value(
            source, forwarded,
        ));
    }
    Ok(slots)
}

fn merge_boundary_minor_gc_forwarding_slot_application(
    relocations: &mut Vec<(GcHeapAddress, ResolvedValueGeneration)>,
    application: Option<&EvalGcStressBoundaryMinorGcCommitApplication>,
) -> Result<(), EvalHeapError> {
    let Some(application) = application else {
        return Ok(());
    };

    validate_boundary_minor_gc_relocations_match(relocations, application.forwarding_slots())
}

fn boundary_minor_gc_merged_remembered_set(
    applications: &EvalGcStressBoundaryMinorGcCommitApplications,
    source_epoch: RememberedSetEpoch,
) -> Result<Option<RememberedSet>, EvalHeapError> {
    let mut merged = None;
    let mut relocations = Vec::new();
    merge_boundary_minor_gc_remembered_set_application(
        &mut merged,
        &mut relocations,
        applications.worker(),
        source_epoch,
    )?;
    merge_boundary_minor_gc_remembered_set_application(
        &mut merged,
        &mut relocations,
        applications.permanent_shared(),
        source_epoch,
    )?;
    Ok(merged)
}

fn merge_boundary_minor_gc_remembered_set_application(
    merged: &mut Option<RememberedSet>,
    relocations: &mut Vec<(GcHeapAddress, ResolvedValueGeneration)>,
    application: Option<&EvalGcStressBoundaryMinorGcCommitApplication>,
    source_epoch: RememberedSetEpoch,
) -> Result<(), EvalHeapError> {
    let Some(application) = application else {
        return Ok(());
    };

    let expected_next_epoch = source_epoch.checked_next()?;
    let report = application.report();
    if report.remembered_set_source_epoch() != source_epoch {
        return Err(
            EvalHeapError::BoundaryMinorGcLiveRememberedSetSourceEpochMismatch {
                expected: source_epoch,
                actual: report.remembered_set_source_epoch(),
            },
        );
    }
    if report.remembered_set_next_epoch() != expected_next_epoch {
        return Err(
            EvalHeapError::BoundaryMinorGcLiveRememberedSetNextEpochMismatch {
                expected: expected_next_epoch,
                actual: report.remembered_set_next_epoch(),
            },
        );
    }

    let application_set = application.remembered_set();
    if application_set.epoch() != expected_next_epoch {
        return Err(
            EvalHeapError::BoundaryMinorGcLiveRememberedSetNextEpochMismatch {
                expected: expected_next_epoch,
                actual: application_set.epoch(),
            },
        );
    }
    validate_boundary_minor_gc_relocations_match(relocations, application.forwarding_slots())?;

    match merged {
        Some(merged_set) => {
            if merged_set.epoch() != application_set.epoch() {
                return Err(
                    EvalHeapError::BoundaryMinorGcLiveRememberedSetNextEpochMismatch {
                        expected: merged_set.epoch(),
                        actual: application_set.epoch(),
                    },
                );
            }
            for edge in application_set.edges() {
                merged_set.record(*edge)?;
            }
        }
        None => {
            let mut merged_set = RememberedSet::with_epoch(expected_next_epoch);
            for edge in application_set.edges() {
                merged_set.record(*edge)?;
            }
            *merged = Some(merged_set);
        }
    }

    Ok(())
}

fn validate_boundary_minor_gc_relocations_match(
    relocations: &mut Vec<(GcHeapAddress, ResolvedValueGeneration)>,
    forwarding_slots: &[MinorGcForwardingSlot],
) -> Result<(), EvalHeapError> {
    let mut application_sources = Vec::new();
    for slot in forwarding_slots {
        if slot.forwarded_value().is_none() {
            continue;
        }
        let entries = application_sources.len().checked_add(1).ok_or(
            EvalHeapError::RootScanLengthOverflow {
                table: BOUNDARY_MINOR_GC_FORWARDING_SLOT_BUFFER_TABLE,
            },
        )?;
        application_sources.try_reserve_exact(1).map_err(|_| {
            EvalHeapError::RootScanAllocationFailed {
                table: BOUNDARY_MINOR_GC_FORWARDING_SLOT_BUFFER_TABLE,
                entries,
            }
        })?;
        application_sources.push(slot.source());
    }

    for slot in forwarding_slots {
        let Some(forwarded) = slot.forwarded_value() else {
            continue;
        };
        validate_boundary_minor_gc_source_not_destination(slot.source(), relocations)?;
        validate_boundary_minor_gc_destination_not_source(
            forwarded,
            relocations,
            &application_sources,
        )?;
        if let Some((_, expected)) = relocations
            .iter()
            .find(|(source, _)| *source == slot.source())
        {
            if *expected != forwarded {
                return Err(
                    EvalHeapError::BoundaryMinorGcLiveRememberedSetRelocationMismatch {
                        source_address: slot.source(),
                        expected: *expected,
                        actual: forwarded,
                    },
                );
            }
            continue;
        }
        if let Some(forwarded_address) = resolved_heap_address(forwarded) {
            if let Some((existing_source, _)) = relocations.iter().find(|(_, destination)| {
                resolved_heap_address(*destination) == Some(forwarded_address)
            }) {
                return Err(
                    EvalHeapError::BoundaryMinorGcLiveRememberedSetDestinationCollision {
                        source_address: slot.source(),
                        existing_source_address: *existing_source,
                        destination: forwarded,
                    },
                );
            }
        }
        let entries =
            relocations
                .len()
                .checked_add(1)
                .ok_or(EvalHeapError::RootScanLengthOverflow {
                    table: BOUNDARY_MINOR_GC_FORWARDING_SLOT_BUFFER_TABLE,
                })?;
        relocations
            .try_reserve_exact(1)
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: BOUNDARY_MINOR_GC_FORWARDING_SLOT_BUFFER_TABLE,
                entries,
            })?;
        relocations.push((slot.source(), forwarded));
    }
    Ok(())
}

fn validate_boundary_minor_gc_source_not_destination(
    source: GcHeapAddress,
    relocations: &[(GcHeapAddress, ResolvedValueGeneration)],
) -> Result<(), EvalHeapError> {
    let Some((_, destination)) = relocations
        .iter()
        .find(|(_, destination)| resolved_heap_address(*destination) == Some(source))
    else {
        return Ok(());
    };

    Err(
        EvalHeapError::BoundaryMinorGcLiveRememberedSetDestinationSourceCollision {
            source_address: source,
            destination: *destination,
        },
    )
}

fn validate_boundary_minor_gc_destination_not_source(
    forwarded: ResolvedValueGeneration,
    relocations: &[(GcHeapAddress, ResolvedValueGeneration)],
    application_sources: &[GcHeapAddress],
) -> Result<(), EvalHeapError> {
    let Some(destination) = resolved_heap_address(forwarded) else {
        return Ok(());
    };

    if relocations.iter().any(|(source, _)| *source == destination)
        || application_sources
            .iter()
            .any(|source| *source == destination)
    {
        return Err(
            EvalHeapError::BoundaryMinorGcLiveRememberedSetDestinationSourceCollision {
                source_address: destination,
                destination: forwarded,
            },
        );
    }

    Ok(())
}

fn resolved_heap_address(value: ResolvedValueGeneration) -> Option<GcHeapAddress> {
    let ResolvedValueGeneration::Heap { address, .. } = value else {
        return None;
    };

    Some(address)
}

#[cfg(test)]
mod live_remembered_set_merge_tests {
    use super::*;
    use crate::heap::HeapGeneration;

    fn address(bits: usize) -> GcHeapAddress {
        GcHeapAddress::new(bits).expect("test address is non-zero")
    }

    fn heap(address: GcHeapAddress, generation: HeapGeneration) -> ResolvedValueGeneration {
        ResolvedValueGeneration::Heap {
            address,
            generation,
        }
    }

    #[test]
    fn rejects_distinct_sources_with_same_destination_address() {
        let source = address(0x1000);
        let sibling_source = address(0x2000);
        let destination = address(0x3000);
        let mut relocations = Vec::new();
        let worker_slots = [MinorGcForwardingSlot::with_forwarded_value(
            source,
            heap(destination, HeapGeneration::Young),
        )];
        validate_boundary_minor_gc_relocations_match(&mut relocations, &worker_slots)
            .expect("first relocation is accepted");

        let permanent_slots = [MinorGcForwardingSlot::with_forwarded_value(
            sibling_source,
            heap(destination, HeapGeneration::Old),
        )];
        let err = validate_boundary_minor_gc_relocations_match(&mut relocations, &permanent_slots)
            .expect_err("same destination address is rejected");
        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcLiveRememberedSetDestinationCollision {
                source_address,
                existing_source_address,
                destination: ResolvedValueGeneration::Heap {
                    address,
                    generation: HeapGeneration::Old,
                },
            } if source_address == sibling_source
                && existing_source_address == source
                && address == destination
        ));
    }

    #[test]
    fn rejects_previous_destination_as_later_source() {
        let source = address(0x1000);
        let middle = address(0x2000);
        let destination = address(0x3000);
        let mut relocations = Vec::new();
        let worker_slots = [MinorGcForwardingSlot::with_forwarded_value(
            source,
            heap(middle, HeapGeneration::Young),
        )];
        validate_boundary_minor_gc_relocations_match(&mut relocations, &worker_slots)
            .expect("first relocation is accepted");

        let permanent_slots = [MinorGcForwardingSlot::with_forwarded_value(
            middle,
            heap(destination, HeapGeneration::Old),
        )];
        let err = validate_boundary_minor_gc_relocations_match(&mut relocations, &permanent_slots)
            .expect_err("previous destination cannot become a later source");
        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcLiveRememberedSetDestinationSourceCollision {
                source_address,
                destination: ResolvedValueGeneration::Heap {
                    address,
                    generation: HeapGeneration::Young,
                },
            } if source_address == middle && address == middle
        ));
    }
}

#[cfg(test)]
mod destination_object_generation_binding_tests {
    use super::*;

    fn address(bits: usize) -> GcHeapAddress {
        GcHeapAddress::new(bits).expect("test address is non-zero")
    }

    fn request(
        source: GcHeapAddress,
        destination: GcHeapAddress,
        action: MinorGcSurvivorAction,
    ) -> AllocationCollectorPollObjectByteCopyRequest {
        request_with_parts(
            source,
            destination,
            action,
            generation_for_destination_action(action),
            4,
        )
    }

    fn request_with_parts(
        source: GcHeapAddress,
        destination: GcHeapAddress,
        action: MinorGcSurvivorAction,
        destination_generation: HeapGeneration,
        size_bytes: usize,
    ) -> AllocationCollectorPollObjectByteCopyRequest {
        AllocationCollectorPollObjectByteCopyRequest::for_test(
            source,
            destination,
            action,
            destination_generation,
            size_bytes,
            8,
        )
    }

    fn object_bytes(
        request: AllocationCollectorPollObjectByteCopyRequest,
        destination_bytes: Vec<u8>,
    ) -> EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes {
        EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes::new(request, destination_bytes)
    }

    fn destination_storage(
        object_bytes: Vec<EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes>,
    ) -> EvalGcStressBoundaryMinorGcLiveDestinationStorage {
        let install_report = live_destination_storage_install_report(&object_bytes);
        EvalGcStressBoundaryMinorGcLiveDestinationStorage {
            install_report,
            object_bytes,
        }
    }

    #[test]
    fn matches_destination_snapshots_to_object_generations() {
        let copied_request = request(
            address(0x1000),
            address(0x2000),
            MinorGcSurvivorAction::CopyToNursery,
        );
        let promoted_request = request(
            address(0x3000),
            address(0x4000),
            MinorGcSurvivorAction::PromoteToOld,
        );
        let copied_bytes = vec![1, 2, 3, 4];
        let promoted_bytes = vec![5, 6, 7, 8];
        let destination_storage = destination_storage(vec![
            object_bytes(copied_request, copied_bytes.clone()),
            object_bytes(promoted_request, promoted_bytes.clone()),
        ]);

        let bindings =
            boundary_minor_gc_destination_object_generation_bindings(&destination_storage)
                .expect("destination generation bindings validate");

        assert_eq!(bindings.len(), 2);
        assert_eq!(bindings[0].source(), copied_request.source());
        assert_eq!(bindings[0].destination(), copied_request.destination());
        assert_eq!(bindings[0].action(), MinorGcSurvivorAction::CopyToNursery);
        assert_eq!(bindings[0].generation(), HeapGeneration::Young);
        assert_eq!(bindings[0].request(), copied_request);
        assert_eq!(bindings[0].destination_bytes(), copied_bytes);
        assert_eq!(bindings[1].source(), promoted_request.source());
        assert_eq!(bindings[1].destination(), promoted_request.destination());
        assert_eq!(bindings[1].action(), MinorGcSurvivorAction::PromoteToOld);
        assert_eq!(bindings[1].generation(), HeapGeneration::Old);
        assert_eq!(bindings[1].request(), promoted_request);
        assert_eq!(bindings[1].destination_bytes(), promoted_bytes);
    }

    #[test]
    fn rejects_destination_action_generation_mismatch() {
        let request = request_with_parts(
            address(0x1000),
            address(0x2000),
            MinorGcSurvivorAction::CopyToNursery,
            HeapGeneration::Old,
            4,
        );
        let destination_storage =
            destination_storage(vec![object_bytes(request, vec![1, 2, 3, 4])]);

        let err = boundary_minor_gc_destination_object_generation_bindings(&destination_storage)
            .expect_err("action/generation mismatch is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcDestinationActionGenerationMismatch {
                destination,
                expected: HeapGeneration::Young,
                actual: HeapGeneration::Old,
                action: MinorGcSurvivorAction::CopyToNursery,
            } if destination == request.destination()
        ));
    }

    #[test]
    fn rejects_destination_payload_size_mismatch() {
        let request = request_with_parts(
            address(0x1000),
            address(0x2000),
            MinorGcSurvivorAction::CopyToNursery,
            HeapGeneration::Young,
            4,
        );
        let destination_storage = destination_storage(vec![object_bytes(request, vec![1, 2, 3])]);

        let err = boundary_minor_gc_destination_object_generation_bindings(&destination_storage)
            .expect_err("payload length mismatch is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcDestinationPayloadSizeMismatch {
                destination,
                expected: 4,
                actual: 3,
            } if destination == request.destination()
        ));
    }

    #[test]
    fn rejects_duplicate_destination_snapshot() {
        let destination = address(0x2000);
        let first = request(
            address(0x1000),
            destination,
            MinorGcSurvivorAction::CopyToNursery,
        );
        let second = request(
            address(0x3000),
            destination,
            MinorGcSurvivorAction::CopyToNursery,
        );
        let destination_storage = destination_storage(vec![
            object_bytes(first, vec![1, 2, 3, 4]),
            object_bytes(second, vec![5, 6, 7, 8]),
        ]);

        let err = boundary_minor_gc_destination_object_generation_bindings(&destination_storage)
            .expect_err("duplicate destination snapshot is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcLiveDestinationStorageDestinationCollision {
                source_address,
                existing_source_address,
                destination_address,
            } if source_address == second.source()
                && existing_source_address == first.source()
                && destination_address == destination
        ));
    }

    #[test]
    fn live_destination_storage_install_validates_generation_metadata() {
        let request = request_with_parts(
            address(0x1000),
            address(0x2000),
            MinorGcSurvivorAction::PromoteToOld,
            HeapGeneration::Young,
            4,
        );
        let mut destination_storage = EvalGcStressBoundaryMinorGcLiveDestinationStorage::default();

        let err = destination_storage
            .install(vec![object_bytes(request, vec![1, 2, 3, 4])])
            .expect_err("standalone install rejects mismatched generation metadata");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcDestinationActionGenerationMismatch {
                destination,
                expected: HeapGeneration::Old,
                actual: HeapGeneration::Young,
                action: MinorGcSurvivorAction::PromoteToOld,
            } if destination == request.destination()
        ));
        assert!(destination_storage.is_empty());
    }
}

#[cfg(test)]
mod root_writeback_destination_binding_tests {
    use std::ptr::NonNull;

    use super::*;
    use crate::value::{HeapObject, ValueError};

    fn address(bits: usize) -> GcHeapAddress {
        GcHeapAddress::new(bits).expect("test address is non-zero")
    }

    fn root_source(slot: usize) -> EvalRootSource {
        EvalRootSource::ValueStack { slot }
    }

    fn heap(address: GcHeapAddress, generation: HeapGeneration) -> ResolvedValueGeneration {
        ResolvedValueGeneration::Heap {
            address,
            generation,
        }
    }

    fn heap_value(tag: ValueTag, address: GcHeapAddress) -> Value {
        Value::heap(
            tag,
            NonNull::new(address.address_bits() as *mut HeapObject)
                .expect("test heap address is non-null"),
        )
        .expect("test heap value is aligned")
    }

    fn request(
        source: GcHeapAddress,
        destination: GcHeapAddress,
        action: MinorGcSurvivorAction,
    ) -> AllocationCollectorPollObjectByteCopyRequest {
        AllocationCollectorPollObjectByteCopyRequest::for_test(
            source,
            destination,
            action,
            generation_for_destination_action(action),
            4,
            8,
        )
    }

    fn writebacks(
        source: EvalRootSource,
        generation_value: ResolvedValueGeneration,
        typed_value: Value,
    ) -> EvalGcStressBoundaryMinorGcLiveReferenceWritebacks {
        let application = EvalGcStressBoundaryMinorGcReferenceWritebackApplication::new(
            AllocationCollectorPollReferenceWritebackReport::default(),
            vec![AllocationCollectorPollRootWritebackSlot::new(
                source.clone(),
                generation_value,
            )],
            vec![AllocationCollectorPollRootValueWritebackSlot::new(
                source,
                typed_value,
            )],
            Vec::new(),
        );
        let applications =
            EvalGcStressBoundaryMinorGcReferenceWritebackApplications::new(Some(application), None);
        let install_report = live_reference_writeback_install_report(&applications);
        EvalGcStressBoundaryMinorGcLiveReferenceWritebacks {
            install_report,
            applications,
        }
    }

    fn destination_storage(
        request: AllocationCollectorPollObjectByteCopyRequest,
        destination_bytes: Vec<u8>,
    ) -> EvalGcStressBoundaryMinorGcLiveDestinationStorage {
        let object_bytes = vec![EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes::new(
            request,
            destination_bytes,
        )];
        let install_report = live_destination_storage_install_report(&object_bytes);
        EvalGcStressBoundaryMinorGcLiveDestinationStorage {
            install_report,
            object_bytes,
        }
    }

    #[test]
    fn matches_typed_root_writeback_to_destination_snapshot() {
        let source = address(0x1000);
        let destination = address(0x2000);
        let root_source = root_source(0);
        let request = request(source, destination, MinorGcSurvivorAction::CopyToNursery);
        let destination_bytes = vec![1, 2, 3, 4];
        let writebacks = writebacks(
            root_source.clone(),
            heap(destination, HeapGeneration::Young),
            heap_value(ValueTag::Lambda, destination),
        );
        let destination_storage = destination_storage(request, destination_bytes.clone());

        let bindings = boundary_minor_gc_root_writeback_destination_bindings(
            &writebacks,
            &destination_storage,
        )
        .expect("binding report succeeds");

        assert_eq!(bindings.len(), 1);
        assert_eq!(
            bindings[0].allocation_domain(),
            HeapAllocationDomain::Worker
        );
        assert_eq!(bindings[0].root_source(), &root_source);
        assert_eq!(bindings[0].replacement_tag(), ValueTag::Lambda);
        assert_eq!(bindings[0].destination(), destination);
        assert_eq!(bindings[0].generation(), HeapGeneration::Young);
        assert_eq!(bindings[0].request(), request);
        assert_eq!(bindings[0].destination_bytes(), destination_bytes);
    }

    #[test]
    fn rejects_root_writeback_without_installed_destination_snapshot() {
        let destination = address(0x2000);
        let root_source = root_source(0);
        let writebacks = writebacks(
            root_source.clone(),
            heap(destination, HeapGeneration::Young),
            heap_value(ValueTag::Lambda, destination),
        );
        let destination_storage = EvalGcStressBoundaryMinorGcLiveDestinationStorage::default();

        let err = boundary_minor_gc_root_writeback_destination_bindings(
            &writebacks,
            &destination_storage,
        )
        .expect_err("missing destination snapshot is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcRootWritebackDestinationMissing {
                root_source: actual_root_source,
                destination: actual_destination,
            } if actual_root_source == root_source && actual_destination == destination
        ));
    }

    #[test]
    fn rejects_typed_root_writeback_destination_mismatch() {
        let source = address(0x1000);
        let destination = address(0x2000);
        let sibling_destination = address(0x3000);
        let root_source = root_source(0);
        let request = request(source, destination, MinorGcSurvivorAction::CopyToNursery);
        let writebacks = writebacks(
            root_source.clone(),
            heap(destination, HeapGeneration::Young),
            heap_value(ValueTag::Lambda, sibling_destination),
        );
        let destination_storage = destination_storage(request, vec![1, 2, 3, 4]);

        let err = boundary_minor_gc_root_writeback_destination_bindings(
            &writebacks,
            &destination_storage,
        )
        .expect_err("mismatched typed destination is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcRootWritebackDestinationMismatch {
                root_source: actual_root_source,
                expected_destination,
                actual_tag: ValueTag::Lambda,
                actual_payload,
            } if actual_root_source == root_source
                && expected_destination == destination
                && actual_payload == sibling_destination.address_bits() as u64
        ));
    }

    #[test]
    fn rejects_inline_typed_root_writeback_replacement() {
        let source = address(0x1000);
        let destination = address(0x2000);
        let root_source = root_source(0);
        let request = request(source, destination, MinorGcSurvivorAction::CopyToNursery);
        let writebacks = writebacks(
            root_source,
            heap(destination, HeapGeneration::Young),
            Value::int(7),
        );
        let destination_storage = destination_storage(request, vec![1, 2, 3, 4]);

        let err = boundary_minor_gc_root_writeback_destination_bindings(
            &writebacks,
            &destination_storage,
        )
        .expect_err("inline typed root replacement is rejected");

        assert!(matches!(
            err,
            EvalHeapError::Value(ValueError::NotHeapTag { tag: ValueTag::Int })
        ));
    }

    #[test]
    fn rejects_generation_that_disagrees_with_destination_action() {
        let source = address(0x1000);
        let destination = address(0x2000);
        let root_source = root_source(0);
        let request = request(source, destination, MinorGcSurvivorAction::CopyToNursery);
        let writebacks = writebacks(
            root_source.clone(),
            heap(destination, HeapGeneration::Old),
            heap_value(ValueTag::Lambda, destination),
        );
        let destination_storage = destination_storage(request, vec![1, 2, 3, 4]);

        let err = boundary_minor_gc_root_writeback_destination_bindings(
            &writebacks,
            &destination_storage,
        )
        .expect_err("generation/action mismatch is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcRootWritebackGenerationMismatch {
                root_source: actual_root_source,
                destination: actual_destination,
                expected: HeapGeneration::Young,
                actual: HeapGeneration::Old,
                action: MinorGcSurvivorAction::CopyToNursery,
            } if actual_root_source == root_source && actual_destination == destination
        ));
    }
}

#[cfg(test)]
mod heap_field_writeback_destination_binding_tests {
    use super::*;

    fn address(bits: usize) -> GcHeapAddress {
        GcHeapAddress::new(bits).expect("test address is non-zero")
    }

    fn field_source() -> HeapEdgeSource {
        HeapEdgeSource::ListElement { index: 0 }
    }

    fn heap(address: GcHeapAddress, generation: HeapGeneration) -> ResolvedValueGeneration {
        ResolvedValueGeneration::Heap {
            address,
            generation,
        }
    }

    fn request(
        source: GcHeapAddress,
        destination: GcHeapAddress,
        action: MinorGcSurvivorAction,
    ) -> AllocationCollectorPollObjectByteCopyRequest {
        request_with_generation(
            source,
            destination,
            action,
            generation_for_destination_action(action),
        )
    }

    fn request_with_generation(
        source: GcHeapAddress,
        destination: GcHeapAddress,
        action: MinorGcSurvivorAction,
        destination_generation: HeapGeneration,
    ) -> AllocationCollectorPollObjectByteCopyRequest {
        AllocationCollectorPollObjectByteCopyRequest::for_test(
            source,
            destination,
            action,
            destination_generation,
            4,
            8,
        )
    }

    fn writebacks(
        validation_object: GcHeapAddress,
        writeback_object: GcHeapAddress,
        replacement: ResolvedValueGeneration,
    ) -> EvalGcStressBoundaryMinorGcLiveReferenceWritebacks {
        let application = EvalGcStressBoundaryMinorGcReferenceWritebackApplication::new(
            AllocationCollectorPollReferenceWritebackReport::default(),
            Vec::new(),
            Vec::new(),
            vec![AllocationCollectorPollHeapFieldWritebackSlot::new(
                validation_object,
                writeback_object,
                0,
                field_source(),
                replacement,
            )],
        );
        let applications =
            EvalGcStressBoundaryMinorGcReferenceWritebackApplications::new(Some(application), None);
        let install_report = live_reference_writeback_install_report(&applications);
        EvalGcStressBoundaryMinorGcLiveReferenceWritebacks {
            install_report,
            applications,
        }
    }

    fn destination_storage(
        objects: Vec<(AllocationCollectorPollObjectByteCopyRequest, Vec<u8>)>,
    ) -> EvalGcStressBoundaryMinorGcLiveDestinationStorage {
        let object_bytes = objects
            .into_iter()
            .map(|(request, destination_bytes)| {
                EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes::new(
                    request,
                    destination_bytes,
                )
            })
            .collect::<Vec<_>>();
        let install_report = live_destination_storage_install_report(&object_bytes);
        EvalGcStressBoundaryMinorGcLiveDestinationStorage {
            install_report,
            object_bytes,
        }
    }

    #[test]
    fn matches_dirty_old_field_replacement_destination_snapshot() {
        let old_object = address(0x1000);
        let source = address(0x2000);
        let replacement_destination = address(0x3000);
        let replacement_request = request(
            source,
            replacement_destination,
            MinorGcSurvivorAction::CopyToNursery,
        );
        let colliding_writeback_object_request = request(
            address(0x4000),
            old_object,
            MinorGcSurvivorAction::CopyToNursery,
        );
        let replacement_bytes = vec![1, 2, 3, 4];
        let colliding_writeback_bytes = vec![5, 6, 7, 8];
        let writebacks = writebacks(
            old_object,
            old_object,
            heap(replacement_destination, HeapGeneration::Young),
        );
        let destination_storage = destination_storage(vec![
            (
                colliding_writeback_object_request,
                colliding_writeback_bytes,
            ),
            (replacement_request, replacement_bytes.clone()),
        ]);

        let bindings = boundary_minor_gc_heap_field_writeback_destination_bindings(
            &writebacks,
            &destination_storage,
        )
        .expect("dirty old-field binding report succeeds");

        assert_eq!(bindings.len(), 1);
        assert_eq!(
            bindings[0].allocation_domain(),
            HeapAllocationDomain::Worker
        );
        assert_eq!(bindings[0].validation_object(), old_object);
        assert_eq!(bindings[0].writeback_object(), old_object);
        assert_eq!(bindings[0].field_index(), 0);
        assert_eq!(bindings[0].source(), &field_source());
        assert_eq!(
            bindings[0].replacement_destination(),
            replacement_destination
        );
        assert_eq!(bindings[0].replacement_generation(), HeapGeneration::Young);
        assert_eq!(bindings[0].replacement_request(), replacement_request);
        assert_eq!(
            bindings[0].replacement_destination_bytes(),
            replacement_bytes
        );
        assert_eq!(bindings[0].writeback_object_request(), None);
        assert_eq!(bindings[0].writeback_object_destination_bytes(), None);
    }

    #[test]
    fn matches_copied_nursery_field_writeback_and_replacement_snapshots() {
        let validation_object = address(0x1000);
        let replacement_source = address(0x2000);
        let writeback_object = address(0x3000);
        let replacement_destination = address(0x4000);
        let writeback_request = request(
            validation_object,
            writeback_object,
            MinorGcSurvivorAction::CopyToNursery,
        );
        let replacement_request = request(
            replacement_source,
            replacement_destination,
            MinorGcSurvivorAction::PromoteToOld,
        );
        let writeback_bytes = vec![1, 2, 3, 4];
        let replacement_bytes = vec![5, 6, 7, 8];
        let writebacks = writebacks(
            validation_object,
            writeback_object,
            heap(replacement_destination, HeapGeneration::Old),
        );
        let destination_storage = destination_storage(vec![
            (writeback_request, writeback_bytes.clone()),
            (replacement_request, replacement_bytes.clone()),
        ]);

        let bindings = boundary_minor_gc_heap_field_writeback_destination_bindings(
            &writebacks,
            &destination_storage,
        )
        .expect("copied field binding report succeeds");

        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].validation_object(), validation_object);
        assert_eq!(bindings[0].writeback_object(), writeback_object);
        assert_eq!(
            bindings[0].replacement_destination(),
            replacement_destination
        );
        assert_eq!(bindings[0].replacement_generation(), HeapGeneration::Old);
        assert_eq!(bindings[0].replacement_request(), replacement_request);
        assert_eq!(
            bindings[0].replacement_destination_bytes(),
            replacement_bytes
        );
        assert_eq!(
            bindings[0].writeback_object_request(),
            Some(writeback_request)
        );
        assert_eq!(
            bindings[0].writeback_object_destination_bytes(),
            Some(writeback_bytes.as_slice())
        );
    }

    #[test]
    fn rejects_heap_field_replacement_without_installed_destination_snapshot() {
        let old_object = address(0x1000);
        let replacement_destination = address(0x3000);
        let writebacks = writebacks(
            old_object,
            old_object,
            heap(replacement_destination, HeapGeneration::Young),
        );
        let destination_storage = EvalGcStressBoundaryMinorGcLiveDestinationStorage::default();

        let err = boundary_minor_gc_heap_field_writeback_destination_bindings(
            &writebacks,
            &destination_storage,
        )
        .expect_err("missing replacement snapshot is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcHeapFieldWritebackReplacementMissing {
                writeback_object,
                field_index: 0,
                field_source: actual_field_source,
                replacement,
            } if writeback_object == old_object
                && actual_field_source == field_source()
                && replacement == replacement_destination
        ));
    }

    #[test]
    fn rejects_copied_heap_field_without_writeback_object_snapshot() {
        let validation_object = address(0x1000);
        let replacement_source = address(0x2000);
        let writeback_object = address(0x3000);
        let replacement_destination = address(0x4000);
        let replacement_request = request(
            replacement_source,
            replacement_destination,
            MinorGcSurvivorAction::CopyToNursery,
        );
        let writebacks = writebacks(
            validation_object,
            writeback_object,
            heap(replacement_destination, HeapGeneration::Young),
        );
        let destination_storage =
            destination_storage(vec![(replacement_request, vec![1, 2, 3, 4])]);

        let err = boundary_minor_gc_heap_field_writeback_destination_bindings(
            &writebacks,
            &destination_storage,
        )
        .expect_err("missing copied writeback-object snapshot is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcHeapFieldWritebackObjectMissing {
                validation_object: actual_validation_object,
                writeback_object: actual_writeback_object,
                field_index: 0,
                field_source: actual_field_source,
            } if actual_validation_object == validation_object
                && actual_writeback_object == writeback_object
                && actual_field_source == field_source()
        ));
    }

    #[test]
    fn rejects_copied_heap_field_writeback_object_from_another_source() {
        let validation_object = address(0x1000);
        let replacement_source = address(0x2000);
        let writeback_object = address(0x3000);
        let replacement_destination = address(0x4000);
        let mismatched_source = address(0x5000);
        let replacement_request = request(
            replacement_source,
            replacement_destination,
            MinorGcSurvivorAction::CopyToNursery,
        );
        let mismatched_writeback_request = request(
            mismatched_source,
            writeback_object,
            MinorGcSurvivorAction::CopyToNursery,
        );
        let writebacks = writebacks(
            validation_object,
            writeback_object,
            heap(replacement_destination, HeapGeneration::Young),
        );
        let destination_storage = destination_storage(vec![
            (replacement_request, vec![1, 2, 3, 4]),
            (mismatched_writeback_request, vec![5, 6, 7, 8]),
        ]);

        let err = boundary_minor_gc_heap_field_writeback_destination_bindings(
            &writebacks,
            &destination_storage,
        )
        .expect_err("writeback object from another source is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcHeapFieldWritebackObjectSourceMismatch {
                validation_object: actual_validation_object,
                writeback_object: actual_writeback_object,
                field_index: 0,
                field_source: actual_field_source,
                actual_source,
            } if actual_validation_object == validation_object
                && actual_writeback_object == writeback_object
                && actual_field_source == field_source()
                && actual_source == mismatched_source
        ));
    }

    #[test]
    fn rejects_non_heap_heap_field_replacement_metadata() {
        let old_object = address(0x1000);
        let writebacks = writebacks(old_object, old_object, ResolvedValueGeneration::Inline);
        let destination_storage = EvalGcStressBoundaryMinorGcLiveDestinationStorage::default();

        let err = boundary_minor_gc_heap_field_writeback_destination_bindings(
            &writebacks,
            &destination_storage,
        )
        .expect_err("non-heap replacement metadata is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcHeapFieldWritebackReplacementNonHeap {
                writeback_object,
                field_index: 0,
                field_source: actual_field_source,
                value: ResolvedValueGeneration::Inline,
            } if writeback_object == old_object && actual_field_source == field_source()
        ));
    }

    #[test]
    fn rejects_destination_request_generation_that_disagrees_with_action() {
        let old_object = address(0x1000);
        let source = address(0x2000);
        let replacement_destination = address(0x3000);
        let replacement_request = request_with_generation(
            source,
            replacement_destination,
            MinorGcSurvivorAction::CopyToNursery,
            HeapGeneration::Old,
        );
        let writebacks = writebacks(
            old_object,
            old_object,
            heap(replacement_destination, HeapGeneration::Young),
        );
        let destination_storage =
            destination_storage(vec![(replacement_request, vec![1, 2, 3, 4])]);

        let err = boundary_minor_gc_heap_field_writeback_destination_bindings(
            &writebacks,
            &destination_storage,
        )
        .expect_err("destination request action/generation mismatch is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcDestinationActionGenerationMismatch {
                destination,
                expected: HeapGeneration::Young,
                actual: HeapGeneration::Old,
                action: MinorGcSurvivorAction::CopyToNursery,
            } if destination == replacement_destination
        ));
    }

    #[test]
    fn rejects_heap_field_replacement_generation_mismatch() {
        let old_object = address(0x1000);
        let source = address(0x2000);
        let replacement_destination = address(0x3000);
        let replacement_request = request(
            source,
            replacement_destination,
            MinorGcSurvivorAction::CopyToNursery,
        );
        let writebacks = writebacks(
            old_object,
            old_object,
            heap(replacement_destination, HeapGeneration::Old),
        );
        let destination_storage =
            destination_storage(vec![(replacement_request, vec![1, 2, 3, 4])]);

        let err = boundary_minor_gc_heap_field_writeback_destination_bindings(
            &writebacks,
            &destination_storage,
        )
        .expect_err("replacement generation/action mismatch is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcHeapFieldWritebackReplacementGenerationMismatch {
                writeback_object,
                field_index: 0,
                field_source: actual_field_source,
                replacement,
                expected: HeapGeneration::Young,
                actual: HeapGeneration::Old,
                action: MinorGcSurvivorAction::CopyToNursery,
            } if writeback_object == old_object
                && actual_field_source == field_source()
                && replacement == replacement_destination
        ));
    }
}

fn clone_boundary_root_writeback_slots(
    slots: &[AllocationCollectorPollRootWritebackSlot],
) -> Result<Vec<AllocationCollectorPollRootWritebackSlot>, EvalHeapError> {
    let mut cloned = Vec::new();
    cloned
        .try_reserve_exact(slots.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_ROOT_WRITEBACK_SLOTS_TABLE,
            entries: slots.len(),
        })?;
    cloned.extend(slots.iter().cloned());
    Ok(cloned)
}

fn clone_boundary_root_value_writeback_slots(
    slots: &[AllocationCollectorPollRootValueWritebackSlot],
) -> Result<Vec<AllocationCollectorPollRootValueWritebackSlot>, EvalHeapError> {
    let mut cloned = Vec::new();
    cloned
        .try_reserve_exact(slots.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_ROOT_VALUE_WRITEBACK_SLOTS_TABLE,
            entries: slots.len(),
        })?;
    cloned.extend(slots.iter().cloned());
    Ok(cloned)
}

fn clone_boundary_heap_field_writeback_slots(
    slots: &[AllocationCollectorPollHeapFieldWritebackSlot],
) -> Result<Vec<AllocationCollectorPollHeapFieldWritebackSlot>, EvalHeapError> {
    let mut cloned = Vec::new();
    cloned
        .try_reserve_exact(slots.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_SLOTS_TABLE,
            entries: slots.len(),
        })?;
    cloned.extend(slots.iter().cloned());
    Ok(cloned)
}

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

    /// Applies every boundary commit preflight to owned dry-run buffers.
    ///
    /// This consumes the preflight bundle so the returned dry-run report retains
    /// the exact metadata that produced the owned reference-writeback,
    /// destination-storage, and commit applications. It still does not mutate
    /// live evaluator roots, live heap fields, object headers, remembered-set
    /// storage, or semispace pages.
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

        Ok(EvalGcStressBoundaryMinorGcCommitDryRun::new(
            self,
            reference_writebacks,
            commit_applications,
        ))
    }
}

/// Owned dry-run application of GC-stress boundary minor-GC commit preflights.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcCommitDryRun {
    preflights: EvalGcStressBoundaryMinorGcCommitPreflights,
    reference_writebacks: EvalGcStressBoundaryMinorGcReferenceWritebackApplications,
    commit_applications: EvalGcStressBoundaryMinorGcCommitApplications,
}

impl EvalGcStressBoundaryMinorGcCommitDryRun {
    const fn new(
        preflights: EvalGcStressBoundaryMinorGcCommitPreflights,
        reference_writebacks: EvalGcStressBoundaryMinorGcReferenceWritebackApplications,
        commit_applications: EvalGcStressBoundaryMinorGcCommitApplications,
    ) -> Self {
        Self {
            preflights,
            reference_writebacks,
            commit_applications,
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

    /// Returns aggregate counts for the owned dry-run applications.
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
/// remembered-set storage, object generations, or semispace storage.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveCardTableCommitDryRun {
    dry_run: EvalGcStressBoundaryMinorGcCommitDryRun,
    card_table_clear_report: GcCardTableClearReport,
}

impl EvalGcStressBoundaryMinorGcLiveCardTableCommitDryRun {
    const fn new(
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
/// storage, mutate object generations, clear card-table storage, or manage
/// semispaces.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveForwardingCommitDryRun {
    dry_run: EvalGcStressBoundaryMinorGcCommitDryRun,
    forwarding_install_report: AllocationCollectorPollForwardingInstallReport,
}

impl EvalGcStressBoundaryMinorGcLiveForwardingCommitDryRun {
    const fn new(
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

/// Boundary commit dry run plus outcome-owned destination-byte installation.
///
/// This report preserves the owned dry-run artifacts and records the object
/// payload snapshots installed into [`EvalOutcome`]'s destination-byte side
/// table after all dry-run validation succeeds. It still does not bind those
/// bytes to live heap objects, write ABI object headers, mutate roots or heap
/// fields, publish remembered-set storage, mutate object generations, clear
/// card-table storage, or manage semispaces.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveDestinationStorageCommitDryRun {
    dry_run: EvalGcStressBoundaryMinorGcCommitDryRun,
    destination_storage_install_report:
        EvalGcStressBoundaryMinorGcLiveDestinationStorageInstallReport,
}

impl EvalGcStressBoundaryMinorGcLiveDestinationStorageCommitDryRun {
    const fn new(
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

/// Boundary commit dry run plus outcome-owned reference-writeback installation.
///
/// This report preserves the owned dry-run artifacts and records the copied root
/// and heap-field writeback slots installed into [`EvalOutcome`]'s metadata
/// after all dry-run validation succeeds. It still does not mutate live roots,
/// heap fields, object bytes, forwarding headers, remembered-set storage,
/// object generations, card-table storage, or semispace pages.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveReferenceWritebackCommitDryRun {
    dry_run: EvalGcStressBoundaryMinorGcCommitDryRun,
    reference_writeback_install_report:
        EvalGcStressBoundaryMinorGcLiveReferenceWritebackInstallReport,
}

impl EvalGcStressBoundaryMinorGcLiveReferenceWritebackCommitDryRun {
    const fn new(
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
    const fn new(
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
/// side-table values, destination-byte snapshots, reference-writeback metadata,
/// the merged next remembered set, and the daemon card-table clear together. It
/// also validates root and heap-field writeback destination bindings before the
/// first live metadata mutation. It still does not mutate live root variables,
/// heap fields, object bytes, ABI forwarding headers, object generations, or
/// semispace pages.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveMetadataCommitDryRun {
    dry_run: EvalGcStressBoundaryMinorGcCommitDryRun,
    forwarding_install_report: AllocationCollectorPollForwardingInstallReport,
    destination_storage_install_report:
        EvalGcStressBoundaryMinorGcLiveDestinationStorageInstallReport,
    reference_writeback_install_report:
        EvalGcStressBoundaryMinorGcLiveReferenceWritebackInstallReport,
    remembered_set_published: bool,
    card_table_clear_report: GcCardTableClearReport,
}

impl EvalGcStressBoundaryMinorGcLiveMetadataCommitDryRun {
    const fn new(
        dry_run: EvalGcStressBoundaryMinorGcCommitDryRun,
        forwarding_install_report: AllocationCollectorPollForwardingInstallReport,
        destination_storage_install_report: EvalGcStressBoundaryMinorGcLiveDestinationStorageInstallReport,
        reference_writeback_install_report: EvalGcStressBoundaryMinorGcLiveReferenceWritebackInstallReport,
        remembered_set_published: bool,
        card_table_clear_report: GcCardTableClearReport,
    ) -> Self {
        Self {
            dry_run,
            forwarding_install_report,
            destination_storage_install_report,
            reference_writeback_install_report,
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
    fn from_preflights_and_applications(
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
    const fn new(
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
    const fn new(
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

fn boundary_minor_gc_root_reference_values(
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

fn boundary_minor_gc_root_writeback_slots(
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

fn boundary_minor_gc_root_value_writeback_slots(
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

fn boundary_minor_gc_heap_field_writeback_slots(
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

/// A tree-walk evaluation result with its owning evaluator heap.
pub struct EvalOutcome {
    pub(crate) value: Value,
    pub(crate) heap: EvalHeap,
    pub(crate) stats: EvalStats,
    pub(crate) attr_telemetry: AttrTelemetry,
    pub(crate) trace_output: Vec<EvalTraceOutput>,
    pub(crate) warning_output: Vec<EvalWarningOutput>,
    pub(crate) impure_input_trace: Vec<ImpureInputFingerprint>,
    pub(crate) impure_input_trace_complete: bool,
    pub(crate) persist_force_cache_hit_keys: Vec<PersistNodeMetadataKey>,
    pub(crate) derivations: Vec<EvalDerivation>,
    pub(crate) thunk_resolve_remembered_set: RememberedSet,
    pub(crate) thunk_resolve_card_table: GcCardTable,
    pub(crate) memory_budget_action: Option<EvalHeapMemoryBudgetAction>,
    pub(crate) cheap_memory_budget_plan: Option<EvalHeapCheapMemoryBudgetPlan>,
    pub(crate) cheap_memory_advice_report: Option<EvalHeapCheapMemoryAdviceReport>,
    pub(crate) cold_hash_consed_value_materialization:
        Option<ColdHashConsedValueMaterializationReport>,
    pub(crate) gc_stress_boundary_scans: EvalGcStressBoundaryScans,
    pub(crate) gc_stress_boundary_minor_gc_reference_writebacks:
        EvalGcStressBoundaryMinorGcLiveReferenceWritebacks,
    pub(crate) gc_stress_boundary_minor_gc_destination_storage:
        EvalGcStressBoundaryMinorGcLiveDestinationStorage,
}

impl std::fmt::Debug for EvalOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EvalOutcome")
            .field("value", &self.value)
            .field("heap", &self.heap)
            .field("stats", &self.stats)
            .field("attr_telemetry", &self.attr_telemetry)
            .field("trace_output", &self.trace_output)
            .field("warning_output", &self.warning_output)
            .field("impure_input_trace", &self.impure_input_trace)
            .field(
                "impure_input_trace_complete",
                &self.impure_input_trace_complete,
            )
            .field("derivations", &self.derivations)
            .field(
                "thunk_resolve_remembered_set",
                &self.thunk_resolve_remembered_set,
            )
            .field("thunk_resolve_card_table", &self.thunk_resolve_card_table)
            .field("memory_budget_action", &self.memory_budget_action)
            .field("cheap_memory_budget_plan", &self.cheap_memory_budget_plan)
            .field(
                "cheap_memory_advice_report",
                &self.cheap_memory_advice_report,
            )
            .field(
                "cold_hash_consed_value_materialization",
                &self.cold_hash_consed_value_materialization,
            )
            .field("gc_stress_boundary_scans", &self.gc_stress_boundary_scans)
            .field(
                "gc_stress_boundary_minor_gc_reference_writebacks",
                &self.gc_stress_boundary_minor_gc_reference_writebacks,
            )
            .field(
                "gc_stress_boundary_minor_gc_destination_storage",
                &self.gc_stress_boundary_minor_gc_destination_storage,
            )
            .finish()
    }
}

impl EvalOutcome {
    /// Returns the evaluated root value.
    pub const fn value(&self) -> Value {
        self.value
    }

    /// Returns the heap that owns heap-backed values in this result.
    pub const fn heap(&self) -> &EvalHeap {
        &self.heap
    }

    /// Returns mirrored evaluator counters captured at the end of evaluation.
    pub const fn stats(&self) -> &EvalStats {
        &self.stats
    }

    /// Returns byte-neutral attribute-set telemetry captured during evaluation.
    pub const fn attr_telemetry(&self) -> &AttrTelemetry {
        &self.attr_telemetry
    }

    /// Returns user-facing trace output emitted during evaluation.
    pub fn trace_output(&self) -> &[EvalTraceOutput] {
        &self.trace_output
    }

    /// Returns user-facing warning output emitted during evaluation.
    pub fn warning_output(&self) -> &[EvalWarningOutput] {
        &self.warning_output
    }

    /// Returns impure evaluator inputs observed during evaluation.
    pub fn impure_input_trace(&self) -> &[ImpureInputFingerprint] {
        &self.impure_input_trace
    }

    /// Returns whether the impure input trace is complete and cache-usable.
    pub const fn impure_input_trace_complete(&self) -> bool {
        self.impure_input_trace_complete
    }

    /// Returns persistent force-cache metadata keys loaded during evaluation.
    ///
    /// This is diagnostic evaluator metadata and is not serialized into any
    /// Nix-observable value, derivation path, or ATerm surface.
    pub fn persist_force_cache_hit_keys(&self) -> &[PersistNodeMetadataKey] {
        &self.persist_force_cache_hit_keys
    }

    /// Returns derivations observed while evaluating the root expression.
    pub fn derivations(&self) -> &[EvalDerivation] {
        &self.derivations
    }

    /// Returns the remembered set populated by thunk-resolution write barriers.
    pub const fn thunk_resolve_remembered_set(&self) -> &RememberedSet {
        &self.thunk_resolve_remembered_set
    }

    /// Returns the card table populated by thunk-resolution write barriers.
    pub const fn thunk_resolve_card_table(&self) -> &GcCardTable {
        &self.thunk_resolve_card_table
    }

    /// Returns the final high-water heap budget action, if one was configured.
    pub const fn memory_budget_action(&self) -> Option<EvalHeapMemoryBudgetAction> {
        self.memory_budget_action
    }

    /// Returns the final cold-aware heap budget plan, if one was requested.
    ///
    /// This is planning telemetry only. A plan can credit logical cold
    /// hash-consed bytes for future CA-store spill, but it is not evidence that
    /// resident bytes were actually reclaimed during evaluation.
    pub const fn cheap_memory_budget_plan(&self) -> Option<EvalHeapCheapMemoryBudgetPlan> {
        self.cheap_memory_budget_plan
    }

    /// Returns the post-evaluation cheap heap advice report, if one was requested.
    pub const fn cheap_memory_advice_report(&self) -> Option<EvalHeapCheapMemoryAdviceReport> {
        self.cheap_memory_advice_report
    }

    /// Returns post-evaluation cold value-pack materialization telemetry.
    ///
    /// This report is present only when the cold-aware heap budget plan asked
    /// for reclaim and a spill-preparation pass ran. It is not evidence that
    /// resident bytes were reclaimed, heap records were replaced, or value
    /// access can rematerialize content-hash handles. The pass captures
    /// payloads through normal heap reads, so coldness diagnostics on
    /// [`Self::heap`] may reflect those post-evaluation touches.
    pub fn cold_hash_consed_value_materialization(
        &self,
    ) -> Option<&ColdHashConsedValueMaterializationReport> {
        self.cold_hash_consed_value_materialization.as_ref()
    }

    /// Returns GC-stress scans recorded at the successful evaluation boundary.
    pub const fn gc_stress_boundary_scans(&self) -> &EvalGcStressBoundaryScans {
        &self.gc_stress_boundary_scans
    }

    /// Returns outcome-owned reference-writeback metadata installed by live dry runs.
    ///
    /// The installed slots are GC-stress bridge metadata. They are not live
    /// evaluator root storage or heap object fields and are not read by ordinary
    /// evaluation.
    pub const fn gc_stress_boundary_minor_gc_reference_writebacks(
        &self,
    ) -> &EvalGcStressBoundaryMinorGcLiveReferenceWritebacks {
        &self.gc_stress_boundary_minor_gc_reference_writebacks
    }

    /// Returns outcome-owned destination byte snapshots installed by live dry runs.
    ///
    /// These snapshots are GC-stress bridge metadata. They are not live
    /// semispace object bodies and are not read by ordinary evaluation.
    pub const fn gc_stress_boundary_minor_gc_destination_storage(
        &self,
    ) -> &EvalGcStressBoundaryMinorGcLiveDestinationStorage {
        &self.gc_stress_boundary_minor_gc_destination_storage
    }

    /// Matches installed destination-byte snapshots to object generations.
    ///
    /// This validates outcome-owned GC-stress bridge metadata only. Each
    /// returned binding proves that an installed destination payload's
    /// copy/promote action, destination generation, and byte length agree with
    /// its object-copy request. It does not bind bytes to heap-object storage,
    /// mutate object-generation metadata, or validate object liveness.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if an installed destination request disagrees
    /// with its copy action, if the installed byte snapshot length differs from
    /// the request size, if duplicate destination snapshots are present, or if
    /// the binding report cannot reserve storage.
    pub fn gc_stress_boundary_minor_gc_destination_object_generation_bindings(
        &self,
    ) -> Result<Vec<EvalGcStressBoundaryMinorGcDestinationObjectGenerationBinding>, EvalHeapError>
    {
        boundary_minor_gc_destination_object_generation_bindings(
            &self.gc_stress_boundary_minor_gc_destination_storage,
        )
    }

    /// Matches installed root writebacks to installed destination-byte snapshots.
    ///
    /// This validates outcome-owned GC-stress bridge metadata only. Each
    /// returned binding proves that an installed typed root replacement, its
    /// generation-style root slot, and an installed destination-byte snapshot
    /// agree on the same destination object. It does not mutate live evaluator
    /// roots, bind destination bytes to heap-object storage, or validate object
    /// liveness.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if installed root writeback metadata is
    /// internally inconsistent, if a typed root value is not heap-backed, if a
    /// root replacement points at no installed destination-byte snapshot, if the
    /// destination generation disagrees with the matched copy action, if an
    /// installed destination request disagrees with its copy action, or if the
    /// binding report cannot reserve storage.
    pub fn gc_stress_boundary_minor_gc_root_writeback_destination_bindings(
        &self,
    ) -> Result<Vec<EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding>, EvalHeapError>
    {
        boundary_minor_gc_root_writeback_destination_bindings(
            &self.gc_stress_boundary_minor_gc_reference_writebacks,
            &self.gc_stress_boundary_minor_gc_destination_storage,
        )
    }

    /// Matches installed heap-field writebacks to destination-byte snapshots.
    ///
    /// This validates outcome-owned GC-stress bridge metadata only. Each
    /// returned binding proves that an installed heap-field replacement points
    /// at an installed destination-byte snapshot. For copied nursery-field
    /// writebacks, it also proves that the relocated writeback object has an
    /// installed destination-byte snapshot. It does not mutate live evaluator
    /// object fields, bind destination bytes to heap-object storage, or validate
    /// object liveness.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if installed heap-field writeback metadata is
    /// internally inconsistent, if a replacement value is not heap-backed, if a
    /// replacement or copied writeback object points at no installed
    /// destination-byte snapshot, if a copied writeback object snapshot belongs
    /// to another source, if the replacement generation disagrees with the
    /// matched copy action, if an installed destination request disagrees with
    /// its copy action, or if the binding report cannot reserve storage.
    pub fn gc_stress_boundary_minor_gc_heap_field_writeback_destination_bindings(
        &self,
    ) -> Result<Vec<EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding>, EvalHeapError>
    {
        boundary_minor_gc_heap_field_writeback_destination_bindings(
            &self.gc_stress_boundary_minor_gc_reference_writebacks,
            &self.gc_stress_boundary_minor_gc_destination_storage,
        )
    }

    /// Builds minor-GC plans from the recorded GC-stress boundary scans.
    ///
    /// This uses the outcome's remembered-set snapshot, dirty-card snapshot, and
    /// the caller-supplied promotion policy. It is planning metadata only: it
    /// does not choose semispace destinations, install forwarding pointers,
    /// rewrite roots or fields, publish remembered sets, clear card-table
    /// storage, or invoke a collector.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if a recorded boundary scan is stale relative
    /// to the outcome heap, if the remembered set or dirty-card snapshot is
    /// incomplete or invalid for the current heap graph, or if minor-GC planning
    /// fails.
    pub fn gc_stress_boundary_minor_gc_plans(
        &self,
        promotion_policy: MinorGcPromotionPolicy,
    ) -> Result<EvalGcStressBoundaryMinorGcPlans, EvalHeapError> {
        let remembered_set = self.thunk_resolve_remembered_set.snapshot();
        let card_table = self.thunk_resolve_card_table.snapshot();
        let collection_epoch = self.thunk_resolve_remembered_set.epoch();
        let worker = match self.gc_stress_boundary_scans.worker() {
            Some(scan) => Some(self.heap.plan_collector_poll_minor_gc_with_card_table(
                scan,
                remembered_set,
                card_table,
                collection_epoch,
                promotion_policy,
            )?),
            None => None,
        };
        let permanent_shared = match self.gc_stress_boundary_scans.permanent_shared() {
            Some(scan) => Some(self.heap.plan_collector_poll_minor_gc_with_card_table(
                scan,
                remembered_set,
                card_table,
                collection_epoch,
                promotion_policy,
            )?),
            None => None,
        };
        Ok(EvalGcStressBoundaryMinorGcPlans::new(
            worker,
            permanent_shared,
        ))
    }

    /// Builds relocation destinations from recorded GC-stress boundary scans.
    ///
    /// This derives minor-GC plans with the supplied promotion policy, reads the
    /// outcome heap's current layout metadata for planned survivors, and
    /// materializes relocation destinations from `bases`. It is planning
    /// metadata only: it does not reserve semispace storage, copy object bytes,
    /// install forwarding pointers, rewrite roots or fields, publish remembered
    /// sets, or invoke a collector.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if boundary minor-GC planning fails, if the
    /// outcome heap changed since planning, if survivor layout metadata cannot be
    /// derived, or if relocation-destination planning rejects the supplied bases.
    pub fn gc_stress_boundary_minor_gc_relocation_destinations(
        &self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<EvalGcStressBoundaryMinorGcRelocationDestinations, EvalHeapError> {
        Ok(self
            .gc_stress_boundary_minor_gc_relocation_plans(promotion_policy, bases)?
            .into_relocation_destinations())
    }

    /// Builds paired minor-GC plans and relocation destinations from boundary scans.
    ///
    /// This derives minor-GC plans with the supplied promotion policy, reads the
    /// outcome heap's current layout metadata for planned survivors, and stores
    /// each plan next to the relocation destinations materialized from `bases`.
    /// The paired report can build commit metadata without recomputing or
    /// mismatching those pieces, but it still does not reserve semispace storage,
    /// copy object bytes, install forwarding pointers, rewrite roots or fields,
    /// publish remembered sets, or invoke a collector.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if boundary minor-GC planning fails, if the
    /// outcome heap changed since planning, if survivor layout metadata cannot be
    /// derived, or if relocation-destination planning rejects the supplied bases.
    pub fn gc_stress_boundary_minor_gc_relocation_plans(
        &self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<EvalGcStressBoundaryMinorGcRelocationPlans, EvalHeapError> {
        let plans = self.gc_stress_boundary_minor_gc_plans(promotion_policy)?;
        let EvalGcStressBoundaryMinorGcPlans {
            worker,
            permanent_shared,
        } = plans;
        let worker = match worker {
            Some(plan) => {
                let destinations = self
                    .heap
                    .plan_collector_poll_minor_gc_relocation_destinations(&plan, bases)?;
                Some(EvalGcStressBoundaryMinorGcRelocationPlan::new(
                    plan,
                    destinations,
                ))
            }
            None => None,
        };
        let permanent_shared = match permanent_shared {
            Some(plan) => {
                let destinations = self
                    .heap
                    .plan_collector_poll_minor_gc_relocation_destinations(&plan, bases)?;
                Some(EvalGcStressBoundaryMinorGcRelocationPlan::new(
                    plan,
                    destinations,
                ))
            }
            None => None,
        };
        Ok(EvalGcStressBoundaryMinorGcRelocationPlans::new(
            worker,
            permanent_shared,
        ))
    }

    /// Builds owned commit-preflight metadata from GC-stress boundary scans.
    ///
    /// This derives paired boundary relocation plans, builds the borrowed commit
    /// metadata long enough to validate and extract owned object byte-copy
    /// requests, empty forwarding slots, copied reference buffers, daemon-wide
    /// card-table snapshot clones, and reference writeback metadata plus
    /// caller-owned writeback slot buffers, then returns those artifacts beside
    /// the paired relocation plan. It still does not bind object byte buffers,
    /// mutate forwarding slots, rewrite live roots or heap fields, publish
    /// remembered sets, clear the live daemon card table, reserve semispace
    /// storage, or invoke a collector.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if boundary relocation planning fails, if commit
    /// metadata cannot be built, if heap-backed byte-copy or writeback
    /// validation fails, or if forwarding-slot or card-table snapshot storage
    /// cannot be reserved.
    pub fn gc_stress_boundary_minor_gc_commit_preflights(
        &self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<EvalGcStressBoundaryMinorGcCommitPreflights, EvalHeapError> {
        let plans = self.gc_stress_boundary_minor_gc_relocation_plans(promotion_policy, bases)?;
        let EvalGcStressBoundaryMinorGcRelocationPlans {
            worker,
            permanent_shared,
        } = plans;
        let worker = worker
            .map(|plan| self.gc_stress_boundary_minor_gc_commit_preflight(plan))
            .transpose()?;
        let permanent_shared = permanent_shared
            .map(|plan| self.gc_stress_boundary_minor_gc_commit_preflight(plan))
            .transpose()?;

        Ok(EvalGcStressBoundaryMinorGcCommitPreflights::new(
            worker,
            permanent_shared,
        ))
    }

    /// Runs boundary minor-GC commit preflights against owned dry-run buffers.
    ///
    /// This derives boundary commit preflight metadata from the recorded
    /// GC-stress scans, applies reference writebacks into owned slot copies, and
    /// applies commit plans into owned synthetic byte, forwarding, reference,
    /// and remembered-set buffers. The returned report carries all three
    /// artifacts for the exact same worker/permanent-shared partition. It still
    /// does not mutate live evaluator roots, live heap fields, object headers,
    /// remembered-set storage, card-table storage, or semispace pages.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if boundary commit preflight derivation fails,
    /// if any owned dry-run buffer cannot be allocated, or if any owned buffer
    /// fails validation against the lower-level commit or writeback plans.
    pub fn gc_stress_boundary_minor_gc_commit_dry_run(
        &self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<EvalGcStressBoundaryMinorGcCommitDryRun, EvalHeapError> {
        self.gc_stress_boundary_minor_gc_commit_preflights(promotion_policy, bases)?
            .apply_owned_commit_dry_run()
    }

    /// Runs a boundary dry run and installs live side-table forwarding values.
    ///
    /// The method first derives the same owned commit dry run as
    /// [`Self::gc_stress_boundary_minor_gc_commit_dry_run`]. It then validates
    /// that sibling worker/permanent applications form one coherent survivor
    /// relocation map, deduplicates overlapping forwarding sources that agree,
    /// and installs the resulting forwarding values into this outcome's
    /// evaluator heap side table. Empty boundaries, or non-empty boundaries
    /// with no copied/promoted survivors, leave the heap forwarding cells
    /// unchanged.
    ///
    /// This is a live forwarding-metadata bridge for GC-stress experiments, not
    /// a full collector commit. It does not write ABI object headers, bind live
    /// object-byte buffers, mutate roots or heap fields, publish remembered
    /// sets, clear card-table storage, mutate object generations, reserve
    /// semispace storage, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if boundary commit dry-run derivation or owned
    /// buffer application fails, if sibling forwarding applications do not form
    /// one coherent survivor relocation map, or if any target heap record is no
    /// longer a young unforwarded survivor. When an error is returned, live heap
    /// forwarding cells are left unchanged.
    pub fn gc_stress_boundary_minor_gc_commit_dry_run_with_live_forwarding_slots(
        &mut self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveForwardingCommitDryRun, EvalHeapError> {
        let dry_run = self.gc_stress_boundary_minor_gc_commit_dry_run(promotion_policy, bases)?;
        let forwarding_slots =
            boundary_minor_gc_merged_forwarding_slots(dry_run.commit_applications())?;
        let forwarding_install_report = self
            .heap
            .install_collector_poll_minor_gc_forwarding_slots(&forwarding_slots)?;

        Ok(EvalGcStressBoundaryMinorGcLiveForwardingCommitDryRun::new(
            dry_run,
            forwarding_install_report,
        ))
    }

    /// Runs a boundary dry run and installs outcome-owned destination bytes.
    ///
    /// The method derives the same owned commit dry run as
    /// [`Self::gc_stress_boundary_minor_gc_commit_dry_run`]. It validates sibling
    /// worker/permanent applications with the same raw relocation-map coherence
    /// checks used by live remembered-set publication, then merges overlapping
    /// object-copy snapshots that agree before publishing them into this
    /// outcome's destination-byte side table. Empty boundaries, or non-empty
    /// boundaries with no copied/promoted survivors, leave the side table
    /// unchanged.
    ///
    /// This is a live metadata bridge for GC-stress experiments, not a full
    /// collector commit. It does not bind bytes to live heap objects, write ABI
    /// object headers, mutate roots or heap fields, install forwarding headers,
    /// publish remembered sets, clear card-table storage, mutate object
    /// generations, reserve semispace storage, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if boundary commit dry-run derivation or owned
    /// buffer application fails, if sibling applications do not form one
    /// coherent survivor relocation map, if overlapping object-copy snapshots
    /// disagree, or if destination-byte snapshots have already been installed
    /// for this outcome. When an error is returned, the destination-byte side
    /// table is left unchanged.
    pub fn gc_stress_boundary_minor_gc_commit_dry_run_with_live_destination_storage(
        &mut self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveDestinationStorageCommitDryRun, EvalHeapError> {
        let dry_run = self.gc_stress_boundary_minor_gc_commit_dry_run(promotion_policy, bases)?;
        boundary_minor_gc_merged_forwarding_slots(dry_run.commit_applications())?;
        let object_bytes =
            boundary_minor_gc_merged_destination_object_bytes(dry_run.commit_applications())?;
        let destination_storage_install_report = self
            .gc_stress_boundary_minor_gc_destination_storage
            .install(object_bytes)?;

        Ok(
            EvalGcStressBoundaryMinorGcLiveDestinationStorageCommitDryRun::new(
                dry_run,
                destination_storage_install_report,
            ),
        )
    }

    /// Runs a boundary dry run and installs outcome-owned writeback metadata.
    ///
    /// The method derives the same owned commit dry run as
    /// [`Self::gc_stress_boundary_minor_gc_commit_dry_run`], validates sibling
    /// survivor relocations with the same raw relocation-map coherence checks
    /// used by the other live side-table bridges, clones the applied root and
    /// heap-field writeback slot buffers, and installs those copies into this
    /// outcome's metadata. Empty boundaries, or non-empty boundaries with no
    /// reference writebacks, leave the side table unchanged.
    ///
    /// This is a live metadata bridge for GC-stress experiments, not a full
    /// collector commit. It does not mutate live root variables, heap fields,
    /// object bytes, forwarding headers, remembered sets, card-table storage,
    /// object generations, reserve semispace storage, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if boundary commit dry-run derivation or owned
    /// buffer application fails, if sibling survivor relocations do not form one
    /// coherent map, if writeback metadata cannot be cloned, or if writeback
    /// metadata has already been installed for this outcome. When an error is
    /// returned, the reference-writeback side table is left unchanged.
    pub fn gc_stress_boundary_minor_gc_commit_dry_run_with_live_reference_writebacks(
        &mut self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveReferenceWritebackCommitDryRun, EvalHeapError> {
        let dry_run = self.gc_stress_boundary_minor_gc_commit_dry_run(promotion_policy, bases)?;
        boundary_minor_gc_merged_forwarding_slots(dry_run.commit_applications())?;
        let writebacks =
            clone_boundary_reference_writeback_applications(dry_run.reference_writebacks())?;
        let reference_writeback_install_report = self
            .gc_stress_boundary_minor_gc_reference_writebacks
            .install(writebacks)?;

        Ok(
            EvalGcStressBoundaryMinorGcLiveReferenceWritebackCommitDryRun::new(
                dry_run,
                reference_writeback_install_report,
            ),
        )
    }

    /// Runs a boundary dry run and installs all outcome-owned GC metadata.
    ///
    /// The method derives one owned commit dry run, then validates every live
    /// metadata payload derived from it before mutating the outcome: sibling
    /// survivor relocations, destination-byte snapshots, reference-writeback
    /// metadata, root/heap-field destination bindings, remembered-set
    /// publication, and live forwarding slots. After those checks pass, it
    /// installs evaluator side-table forwarding values, destination-byte
    /// snapshots, reference-writeback metadata, the merged next remembered set,
    /// and clears the daemon card table. Empty boundaries leave the outcome
    /// unchanged.
    ///
    /// This is a staged live-metadata bridge for GC-stress experiments, not a
    /// full collector commit. It does not mutate live root variables, heap
    /// fields, object bytes, ABI forwarding headers, object generations,
    /// reserve semispace storage, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if boundary commit dry-run derivation or owned
    /// buffer application fails, if sibling applications do not form one
    /// coherent survivor relocation map, if destination-byte snapshots or
    /// reference-writeback metadata have already been installed, if remembered
    /// set publication cannot be merged, if writeback destination bindings do
    /// not match the dry-run destination snapshots, or if forwarding
    /// installation fails. All installable side-table payloads are validated
    /// before the first live mutation; if forwarding installation fails,
    /// destination storage,
    /// reference-writeback metadata, remembered-set state, and card-table state
    /// are left unchanged.
    pub fn gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
        &mut self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveMetadataCommitDryRun, EvalHeapError> {
        let dry_run = self.gc_stress_boundary_minor_gc_commit_dry_run(promotion_policy, bases)?;
        let forwarding_slots =
            boundary_minor_gc_merged_forwarding_slots(dry_run.commit_applications())?;
        let object_bytes =
            boundary_minor_gc_merged_destination_object_bytes(dry_run.commit_applications())?;
        let destination_storage_install_report =
            live_destination_storage_install_report(&object_bytes);
        self.gc_stress_boundary_minor_gc_destination_storage
            .can_install(destination_storage_install_report)?;
        let _destination_object_generation_bindings =
            boundary_minor_gc_destination_object_generation_bindings_from_objects(&object_bytes)?;
        let writebacks =
            clone_boundary_reference_writeback_applications(dry_run.reference_writebacks())?;
        let reference_writeback_install_report =
            live_reference_writeback_install_report(&writebacks);
        self.gc_stress_boundary_minor_gc_reference_writebacks
            .can_install(reference_writeback_install_report)?;
        let _root_writeback_destination_bindings =
            boundary_minor_gc_root_writeback_destination_bindings_from_applications(
                &writebacks,
                &object_bytes,
            )?;
        let _heap_field_writeback_destination_bindings =
            boundary_minor_gc_heap_field_writeback_destination_bindings_from_applications(
                &writebacks,
                &object_bytes,
            )?;
        let remembered_set = boundary_minor_gc_merged_remembered_set(
            dry_run.commit_applications(),
            self.thunk_resolve_remembered_set.epoch(),
        )?;

        let forwarding_install_report = self
            .heap
            .install_collector_poll_minor_gc_forwarding_slots(&forwarding_slots)?;

        self.gc_stress_boundary_minor_gc_destination_storage
            .install_prevalidated(object_bytes, destination_storage_install_report);
        self.gc_stress_boundary_minor_gc_reference_writebacks
            .install_prevalidated(writebacks, reference_writeback_install_report);
        let remembered_set_published = remembered_set.is_some();
        let card_table_clear_report = if let Some(remembered_set) = remembered_set {
            self.thunk_resolve_remembered_set = remembered_set;
            self.thunk_resolve_card_table.clear_dirty_cards()
        } else {
            GcCardTableClearReport::default()
        };

        Ok(EvalGcStressBoundaryMinorGcLiveMetadataCommitDryRun::new(
            dry_run,
            forwarding_install_report,
            destination_storage_install_report,
            reference_writeback_install_report,
            remembered_set_published,
            card_table_clear_report,
        ))
    }

    /// Runs a boundary minor-GC dry run and clears the outcome-owned card table.
    ///
    /// The method first derives the same owned commit dry run as
    /// [`Self::gc_stress_boundary_minor_gc_commit_dry_run`]. Only after every
    /// recorded allocator tier has validated and applied its owned synthetic
    /// commit buffers does it clear this outcome's daemon card table. Empty
    /// boundary scans do not clear the table.
    ///
    /// This is a live card-table clearing bridge for GC-stress boundary
    /// experiments, not a full collector commit. It still does not bind live
    /// object-byte buffers, mutate live roots or heap fields, publish the
    /// outcome-owned remembered set, install forwarding pointers, mutate object
    /// generations, reserve semispace storage, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if boundary commit dry-run derivation or owned
    /// buffer application fails. When an error is returned, this outcome's card
    /// table is left unchanged.
    pub fn gc_stress_boundary_minor_gc_commit_dry_run_with_live_card_table(
        &mut self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveCardTableCommitDryRun, EvalHeapError> {
        let dry_run = self.gc_stress_boundary_minor_gc_commit_dry_run(promotion_policy, bases)?;
        let card_table_clear_report = if dry_run.is_empty() {
            GcCardTableClearReport::default()
        } else {
            self.thunk_resolve_card_table.clear_dirty_cards()
        };

        Ok(EvalGcStressBoundaryMinorGcLiveCardTableCommitDryRun::new(
            dry_run,
            card_table_clear_report,
        ))
    }

    /// Runs a boundary dry run and publishes outcome-owned GC state.
    ///
    /// This method derives the same owned commit dry run as
    /// [`Self::gc_stress_boundary_minor_gc_commit_dry_run`]. When one or more
    /// allocator tiers produced commit applications, it validates that sibling
    /// survivor relocations form one coherent merged map, merges their
    /// validated next remembered sets, replaces this outcome's remembered set
    /// with the merged next-epoch set, and then clears this outcome's daemon
    /// card table. Empty boundary scans leave both live structures unchanged.
    ///
    /// This is still a live metadata bridge, not a full collector commit. It
    /// does not bind live object-byte buffers, mutate roots or heap fields,
    /// install forwarding pointers, mutate object generations, reserve
    /// semispace storage, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if boundary commit dry-run derivation or owned
    /// buffer application fails, if sibling commit applications do not consume
    /// the outcome-owned source epoch, publish the same next epoch, or agree on
    /// one coherent survivor relocation map, or if the merged remembered set
    /// cannot reserve storage. When an error is returned, this outcome's
    /// remembered set and card table are left unchanged.
    pub fn gc_stress_boundary_minor_gc_commit_dry_run_with_live_remembered_set(
        &mut self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveRememberedSetCommitDryRun, EvalHeapError> {
        let dry_run = self.gc_stress_boundary_minor_gc_commit_dry_run(promotion_policy, bases)?;
        let remembered_set = boundary_minor_gc_merged_remembered_set(
            dry_run.commit_applications(),
            self.thunk_resolve_remembered_set.epoch(),
        )?;

        let remembered_set_published = remembered_set.is_some();
        let card_table_clear_report = if let Some(remembered_set) = remembered_set {
            self.thunk_resolve_remembered_set = remembered_set;
            self.thunk_resolve_card_table.clear_dirty_cards()
        } else {
            GcCardTableClearReport::default()
        };

        Ok(
            EvalGcStressBoundaryMinorGcLiveRememberedSetCommitDryRun::new(
                dry_run,
                remembered_set_published,
                card_table_clear_report,
            ),
        )
    }

    fn gc_stress_boundary_minor_gc_commit_preflight(
        &self,
        relocation_plan: EvalGcStressBoundaryMinorGcRelocationPlan,
    ) -> Result<EvalGcStressBoundaryMinorGcCommitPreflight, EvalHeapError> {
        let root_values = boundary_minor_gc_root_reference_values(
            relocation_plan.minor_gc_plan().reference_slots(),
        )?;
        let (
            object_byte_copy_plan,
            forwarding_slots,
            reference_buffer,
            reference_writeback_plan,
            root_writeback_slots,
            root_value_writeback_slots,
            heap_field_writeback_slots,
        ) = {
            let commit_plan = relocation_plan.commit_plan()?;
            let object_byte_copy_plan = self
                .heap
                .collector_poll_minor_gc_object_byte_copy_plan(&commit_plan)?;
            let forwarding_slots = commit_plan.forwarding_slot_buffer()?;
            let reference_buffer = self
                .heap
                .collector_poll_minor_gc_reference_buffer(&commit_plan, &root_values)?;
            let reference_writeback_plan = self
                .heap
                .collector_poll_minor_gc_reference_writeback_plan(&commit_plan)?;
            let root_writeback_slots =
                boundary_minor_gc_root_writeback_slots(&reference_writeback_plan)?;
            let root_value_writeback_slots =
                boundary_minor_gc_root_value_writeback_slots(&reference_writeback_plan)?;
            let heap_field_writeback_slots =
                boundary_minor_gc_heap_field_writeback_slots(&reference_writeback_plan)?;
            (
                object_byte_copy_plan,
                forwarding_slots,
                reference_buffer,
                reference_writeback_plan,
                root_writeback_slots,
                root_value_writeback_slots,
                heap_field_writeback_slots,
            )
        };

        Ok(EvalGcStressBoundaryMinorGcCommitPreflight::new(
            relocation_plan,
            object_byte_copy_plan,
            forwarding_slots,
            reference_buffer,
            reference_writeback_plan,
            root_writeback_slots,
            root_value_writeback_slots,
            heap_field_writeback_slots,
            self.thunk_resolve_card_table.try_clone()?,
        ))
    }

    /// Consumes the outcome into its value and heap.
    pub fn into_parts(self) -> (Value, EvalHeap) {
        (self.value, self.heap)
    }

    /// Consumes the outcome into its value, heap, and evaluation statistics.
    pub fn into_parts_with_stats(self) -> (Value, EvalHeap, EvalStats) {
        (self.value, self.heap, self.stats)
    }

    /// Consumes the outcome into its value, heap, and user-facing trace output.
    pub fn into_full_parts(self) -> (Value, EvalHeap, Vec<EvalTraceOutput>) {
        (self.value, self.heap, self.trace_output)
    }

    /// Consumes the outcome into its value, heap, trace output, and warning output.
    pub fn into_output_parts(
        self,
    ) -> (
        Value,
        EvalHeap,
        Vec<EvalTraceOutput>,
        Vec<EvalWarningOutput>,
    ) {
        (
            self.value,
            self.heap,
            self.trace_output,
            self.warning_output,
        )
    }
}

impl ImpureInputTraceSource for EvalOutcome {
    fn impure_input_trace(&self) -> &[ImpureInputFingerprint] {
        &self.impure_input_trace
    }

    fn impure_input_trace_complete(&self) -> bool {
        self.impure_input_trace_complete
    }
}

/// Mirrored native-evaluator counters aligned with the RFC-0007 stats schema.
///
/// Phase-1 fields that have no implementation yet stay present and zero so
/// downstream tracing consumers can rely on stable field names while later
/// tiers add inline caches, shape transitions, GC, promotions, deopts, and
/// early-cutoff cache behavior.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalStats {
    pub(crate) thunks_forced: u64,
    pub(crate) thunks_allocated: u64,
    pub(crate) thunks_elided: u64,
    pub(crate) thunk_cache_hits: u64,
    pub(crate) inline_cache_hits: u64,
    pub(crate) inline_cache_misses: u64,
    pub(crate) shape_transitions: u64,
    pub(crate) gc_bytes: u64,
    pub(crate) gc_pause_us: u64,
    pub(crate) tier_promotions: u64,
    pub(crate) deopts: u64,
    pub(crate) force_cache_hits: u64,
    pub(crate) force_cache_misses: u64,
    pub(crate) force_cache_memoization_admits: u64,
    pub(crate) force_cache_memoization_bypasses: u64,
    pub(crate) force_cache_materialization_materializes: u64,
    pub(crate) force_cache_materialization_keeps_in_memory: u64,
    pub(crate) source_thunk_region_plan_decisions: u64,
    pub(crate) source_thunk_region_plan_lexical_subregion_decisions: u64,
    pub(crate) source_thunk_region_plan_conservative_fallbacks: u64,
    pub(crate) cache_hits: u64,
    pub(crate) cache_misses: u64,
    pub(crate) early_cutoffs: u64,
    pub(crate) derivation_aterm_path_reuses: u64,
    pub(crate) static_derivation_output_path_reuses: u64,
    pub(crate) derivation_hash_calculations: u64,
    pub(crate) derivation_text_path_calculations: u64,
    pub(crate) heap_chunks: u64,
    pub(crate) heap_reserved_bytes: u64,
    pub(crate) heap_mapped_bytes: u64,
    pub(crate) heap_used_bytes: u64,
    pub(crate) permanent_heap_chunks: u64,
    pub(crate) permanent_heap_reserved_bytes: u64,
    pub(crate) permanent_heap_mapped_bytes: u64,
    pub(crate) permanent_heap_used_bytes: u64,
}

impl EvalStats {
    /// Returns the number of thunks that performed suspended work.
    pub const fn thunks_forced(&self) -> u64 {
        self.thunks_forced
    }

    /// Returns the number of suspended thunk heap records allocated.
    pub const fn thunks_allocated(&self) -> u64 {
        self.thunks_allocated
    }

    /// Returns the number of planned thunk allocations elided by later tiers.
    pub const fn thunks_elided(&self) -> u64 {
        self.thunks_elided
    }

    /// Returns the number of already-forced thunk cell reuses.
    pub const fn thunk_cache_hits(&self) -> u64 {
        self.thunk_cache_hits
    }

    /// Returns the number of inline-cache hits reported by optimized tiers.
    pub const fn inline_cache_hits(&self) -> u64 {
        self.inline_cache_hits
    }

    /// Returns the number of inline-cache misses reported by optimized tiers.
    pub const fn inline_cache_misses(&self) -> u64 {
        self.inline_cache_misses
    }

    /// Returns the number of object-shape transitions reported by optimized tiers.
    pub const fn shape_transitions(&self) -> u64 {
        self.shape_transitions
    }

    /// Returns bytes reclaimed or scanned by a future GC subsystem.
    pub const fn gc_bytes(&self) -> u64 {
        self.gc_bytes
    }

    /// Returns microseconds spent in a future GC subsystem.
    pub const fn gc_pause_us(&self) -> u64 {
        self.gc_pause_us
    }

    /// Returns the number of promotions into optimized evaluator tiers.
    pub const fn tier_promotions(&self) -> u64 {
        self.tier_promotions
    }

    /// Returns the number of optimized-tier deoptimizations.
    pub const fn deopts(&self) -> u64 {
        self.deopts
    }

    /// Returns the number of advisory force-cache hits.
    pub const fn force_cache_hits(&self) -> u64 {
        self.force_cache_hits
    }

    /// Returns the number of advisory force-cache misses.
    pub const fn force_cache_misses(&self) -> u64 {
        self.force_cache_misses
    }

    /// Returns the number of advisory force-cache probes.
    pub const fn force_cache_probes(&self) -> u64 {
        self.force_cache_hits
            .saturating_add(self.force_cache_misses)
    }

    /// Returns force-cache memoization-policy decisions that admitted memoization.
    pub const fn force_cache_memoization_admits(&self) -> u64 {
        self.force_cache_memoization_admits
    }

    /// Returns force-cache memoization-policy decisions that bypassed memoization.
    pub const fn force_cache_memoization_bypasses(&self) -> u64 {
        self.force_cache_memoization_bypasses
    }

    /// Returns force-cache memoization-policy demands with a recorded decision.
    pub const fn force_cache_memoization_demands(&self) -> u64 {
        self.force_cache_memoization_admits
            .saturating_add(self.force_cache_memoization_bypasses)
    }

    /// Returns force-cache materialization decisions that selected durable storage.
    pub const fn force_cache_materialization_materializes(&self) -> u64 {
        self.force_cache_materialization_materializes
    }

    /// Returns force-cache materialization decisions that kept payloads in memory.
    pub const fn force_cache_materialization_keeps_in_memory(&self) -> u64 {
        self.force_cache_materialization_keeps_in_memory
    }

    /// Returns force-cache materialization threshold decisions.
    pub const fn force_cache_materialization_decisions(&self) -> u64 {
        self.force_cache_materialization_materializes
            .saturating_add(self.force_cache_materialization_keeps_in_memory)
    }

    /// Returns region-placement policy decisions sampled at source thunk allocations.
    pub const fn source_thunk_region_plan_decisions(&self) -> u64 {
        self.source_thunk_region_plan_decisions
    }

    /// Returns sampled source thunk decisions that selected a lexical subregion candidate.
    pub const fn source_thunk_region_plan_lexical_subregion_decisions(&self) -> u64 {
        self.source_thunk_region_plan_lexical_subregion_decisions
    }

    /// Returns sampled source thunk decisions that failed closed to the active runtime tier.
    pub const fn source_thunk_region_plan_conservative_fallbacks(&self) -> u64 {
        self.source_thunk_region_plan_conservative_fallbacks
    }

    /// Returns the aggregate number of evaluator cache hits.
    pub const fn cache_hits(&self) -> u64 {
        self.cache_hits
    }

    /// Returns the aggregate number of evaluator cache misses.
    pub const fn cache_misses(&self) -> u64 {
        self.cache_misses
    }

    /// Returns the number of incremental-cache early cutoffs.
    pub const fn early_cutoffs(&self) -> u64 {
        self.early_cutoffs
    }

    /// Returns the number of `.drv` paths reused from clean derivation ATerm records.
    pub const fn derivation_aterm_path_reuses(&self) -> u64 {
        self.derivation_aterm_path_reuses
    }

    /// Returns the number of static derivation output path sets reused from clean records.
    pub const fn static_derivation_output_path_reuses(&self) -> u64 {
        self.static_derivation_output_path_reuses
    }

    /// Returns the number of derivation hash-boundary calculations performed.
    pub const fn derivation_hash_calculations(&self) -> u64 {
        self.derivation_hash_calculations
    }

    /// Returns the number of derivation `.drv` text-path calculations performed.
    pub const fn derivation_text_path_calculations(&self) -> u64 {
        self.derivation_text_path_calculations
    }

    /// Returns the number of worker bump-arena chunks allocated by the evaluator heap.
    pub const fn heap_chunks(&self) -> u64 {
        self.heap_chunks
    }

    /// Returns bytes reserved by worker evaluator heap chunks.
    pub const fn heap_reserved_bytes(&self) -> u64 {
        self.heap_reserved_bytes
    }

    /// Returns page-rounded bytes mapped by the worker evaluator heap arena.
    pub const fn heap_mapped_bytes(&self) -> u64 {
        self.heap_mapped_bytes
    }

    /// Returns bytes consumed by worker evaluator heap allocations.
    pub const fn heap_used_bytes(&self) -> u64 {
        self.heap_used_bytes
    }

    /// Returns the number of permanent shared bump-arena chunks allocated.
    pub const fn permanent_heap_chunks(&self) -> u64 {
        self.permanent_heap_chunks
    }

    /// Returns bytes reserved by permanent shared evaluator heap chunks.
    pub const fn permanent_heap_reserved_bytes(&self) -> u64 {
        self.permanent_heap_reserved_bytes
    }

    /// Returns page-rounded bytes mapped by the permanent shared evaluator heap arena.
    pub const fn permanent_heap_mapped_bytes(&self) -> u64 {
        self.permanent_heap_mapped_bytes
    }

    /// Returns bytes consumed by permanent shared evaluator heap allocations.
    pub const fn permanent_heap_used_bytes(&self) -> u64 {
        self.permanent_heap_used_bytes
    }
}

/// A derivation recorded during tree-walk evaluation.
///
/// Recorded derivations include their ATerm bytes when byte materialization is
/// possible during evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalDerivation {
    pub(crate) absolute_path: String,
    pub(crate) aterm_bytes: Option<Vec<u8>>,
}

impl EvalDerivation {
    pub(crate) fn new(absolute_path: String, aterm_bytes: Option<Vec<u8>>) -> Self {
        Self {
            absolute_path,
            aterm_bytes,
        }
    }

    /// Returns the absolute `/nix/store` path of the `.drv`.
    pub fn absolute_path(&self) -> &str {
        &self.absolute_path
    }

    /// Returns the serialized `.drv` ATerm bytes when they are statically known.
    pub fn aterm_bytes(&self) -> Option<&[u8]> {
        self.aterm_bytes.as_deref()
    }
}

/// User-facing trace output emitted by `builtins.trace`-style builtins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalTraceOutput {
    pub(crate) kind: EvalTraceKind,
    pub(crate) message: Vec<u8>,
}

impl EvalTraceOutput {
    /// Creates a trace output record.
    pub(crate) fn new(kind: EvalTraceKind, message: Vec<u8>) -> Self {
        Self { kind, message }
    }

    /// Returns the builtin family that emitted this output.
    pub const fn kind(&self) -> EvalTraceKind {
        self.kind
    }

    /// Returns the rendered trace message bytes without the `trace: ` prefix.
    pub fn message(&self) -> &[u8] {
        &self.message
    }
}

/// The trace-like builtin that produced user-facing output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvalTraceKind {
    /// Output from `builtins.trace`.
    Trace,
    /// Output from `builtins.traceVerbose`.
    TraceVerbose,
}

/// A request to realize a derivation output needed during evaluation.
///
/// Import-from-derivation (IFD) is the one point where evaluation must pause for
/// the build layer. The tree-walk evaluator does not build by itself; callers
/// may install an [`IfdRealizer`] that realizes the requested derivation output
/// and returns once the filesystem path can be read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IfdRealization<'a> {
    pub(crate) path: &'a [u8],
    pub(crate) drv_path: &'a [u8],
    pub(crate) output_name: Option<&'a [u8]>,
    pub(crate) context_kind: ContextKind,
    pub(crate) op: &'static str,
}

impl<'a> IfdRealization<'a> {
    /// Returns the filesystem path that triggered the IFD demand.
    pub const fn path(&self) -> &'a [u8] {
        self.path
    }

    /// Returns the derivation path whose output must be realized.
    pub const fn drv_path(&self) -> &'a [u8] {
        self.drv_path
    }

    /// Returns the requested output name for single-output contexts.
    pub const fn output_name(&self) -> Option<&'a [u8]> {
        self.output_name
    }

    /// Returns the string-context kind that caused the IFD demand.
    pub const fn context_kind(&self) -> ContextKind {
        self.context_kind
    }

    /// Returns the filesystem-reading builtin that triggered the demand.
    pub const fn op(&self) -> &'static str {
        self.op
    }

    /// Returns the dialect effect member for this realization boundary.
    pub const fn effect(&self) -> EffectClass {
        aos_nix_dialect::NIX_EFFECT_IFD
    }
}

/// A failure reported by an import-from-derivation realizer.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{message}")]
pub struct IfdRealizationError {
    pub(crate) message: String,
}

impl IfdRealizationError {
    /// Creates a realization error from a user-facing message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the realizer failure message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Detailed context for an import-from-derivation evaluator error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IfdErrorDetail {
    pub(crate) path: Box<[u8]>,
    pub(crate) drv_path: Box<[u8]>,
    pub(crate) output_name: Option<Box<[u8]>>,
    pub(crate) context_kind: ContextKind,
    pub(crate) message: Option<String>,
}

impl IfdErrorDetail {
    pub(crate) fn new(
        path: Vec<u8>,
        drv_path: Vec<u8>,
        output_name: Option<Vec<u8>>,
        context_kind: ContextKind,
        message: Option<String>,
    ) -> Self {
        Self {
            path: path.into_boxed_slice(),
            drv_path: drv_path.into_boxed_slice(),
            output_name: output_name.map(Vec::into_boxed_slice),
            context_kind,
            message,
        }
    }

    /// Returns the filesystem path that triggered the IFD demand.
    pub fn path(&self) -> &[u8] {
        &self.path
    }

    /// Returns the derivation path recorded in the string context.
    pub fn drv_path(&self) -> &[u8] {
        &self.drv_path
    }

    /// Returns the requested output name for single-output contexts.
    pub fn output_name(&self) -> Option<&[u8]> {
        self.output_name.as_deref()
    }

    /// Returns the context kind that caused the IFD demand.
    pub const fn context_kind(&self) -> ContextKind {
        self.context_kind
    }

    /// Returns the realizer diagnostic, if the realizer failed.
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

impl fmt::Display for IfdErrorDetail {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "path {:?}, derivation {:?}, output {:?}, context {:?}",
            self.path,
            self.drv_path,
            self.output_name.as_deref(),
            self.context_kind
        )?;
        if let Some(message) = &self.message {
            write!(formatter, ": {message}")?;
        }
        Ok(())
    }
}

/// Callback used to realize derivation outputs at IFD boundaries.
#[derive(Clone)]
pub struct IfdRealizer {
    realize: Arc<IfdRealizerCallback>,
}

impl IfdRealizer {
    /// Creates an IFD realizer from a callback.
    pub fn new<F>(realize: F) -> Self
    where
        F: for<'a> Fn(IfdRealization<'a>) -> Result<(), IfdRealizationError>
            + Send
            + Sync
            + 'static,
    {
        Self {
            realize: Arc::new(realize),
        }
    }

    pub(crate) fn realize(&self, request: IfdRealization<'_>) -> Result<(), IfdRealizationError> {
        (self.realize)(request)
    }
}

impl fmt::Debug for IfdRealizer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IfdRealizer")
            .finish_non_exhaustive()
    }
}

/// User-facing warning output emitted by `builtins.warn`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalWarningOutput {
    pub(crate) message: Vec<u8>,
}

impl EvalWarningOutput {
    /// Creates a warning output record.
    pub(crate) fn new(message: Vec<u8>) -> Self {
        Self { message }
    }

    /// Returns the warning message bytes without the `evaluation warning: ` prefix.
    pub fn message(&self) -> &[u8] {
        &self.message
    }
}
