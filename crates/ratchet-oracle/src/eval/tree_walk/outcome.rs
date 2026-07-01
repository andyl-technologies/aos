//! Evaluation outcome, derivation, statistics, trace, IFD-realization, and warning types.

use super::*;
use crate::cache::ImpureInputTraceSource;
use crate::compile::EffectClass;

type IfdRealizerCallback =
    dyn for<'a> Fn(IfdRealization<'a>) -> Result<(), IfdRealizationError> + Send + Sync;

const BOUNDARY_MINOR_GC_ROOT_REFERENCE_VALUES_TABLE: &str =
    "boundary minor-GC root reference values";
const BOUNDARY_MINOR_GC_ROOT_WRITEBACK_SLOTS_TABLE: &str = "boundary minor-GC root writeback slots";
const BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_SLOTS_TABLE: &str =
    "boundary minor-GC heap-field writeback slots";

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
    heap_field_writeback_slots: Vec<AllocationCollectorPollHeapFieldWritebackSlot>,
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
        heap_field_writeback_slots: Vec<AllocationCollectorPollHeapFieldWritebackSlot>,
    ) -> Self {
        Self {
            relocation_plan,
            object_byte_copy_plan,
            forwarding_slots,
            reference_buffer,
            reference_writeback_plan,
            root_writeback_slots,
            heap_field_writeback_slots,
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

    /// Returns caller-owned heap-field writeback slots copied from the plan.
    pub fn heap_field_writeback_slots(&self) -> &[AllocationCollectorPollHeapFieldWritebackSlot] {
        &self.heap_field_writeback_slots
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
        let mut heap_field_writeback_slots =
            clone_boundary_heap_field_writeback_slots(&self.heap_field_writeback_slots)?;
        let report = self
            .reference_writeback_plan
            .apply_to_slots(&mut root_writeback_slots, &mut heap_field_writeback_slots)?;

        Ok(
            EvalGcStressBoundaryMinorGcReferenceWritebackApplication::new(
                report,
                root_writeback_slots,
                heap_field_writeback_slots,
            ),
        )
    }
}

/// Applied caller-owned reference writeback buffers for one boundary preflight.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcReferenceWritebackApplication {
    report: AllocationCollectorPollReferenceWritebackReport,
    root_writeback_slots: Vec<AllocationCollectorPollRootWritebackSlot>,
    heap_field_writeback_slots: Vec<AllocationCollectorPollHeapFieldWritebackSlot>,
}

impl EvalGcStressBoundaryMinorGcReferenceWritebackApplication {
    const fn new(
        report: AllocationCollectorPollReferenceWritebackReport,
        root_writeback_slots: Vec<AllocationCollectorPollRootWritebackSlot>,
        heap_field_writeback_slots: Vec<AllocationCollectorPollHeapFieldWritebackSlot>,
    ) -> Self {
        Self {
            report,
            root_writeback_slots,
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

    /// Returns caller-owned heap-field writeback slots after application.
    pub fn heap_field_writeback_slots(&self) -> &[AllocationCollectorPollHeapFieldWritebackSlot] {
        &self.heap_field_writeback_slots
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
    pub(crate) memory_budget_action: Option<EvalHeapMemoryBudgetAction>,
    pub(crate) cheap_memory_advice_report: Option<EvalHeapCheapMemoryAdviceReport>,
    pub(crate) gc_stress_boundary_scans: EvalGcStressBoundaryScans,
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
            .field("memory_budget_action", &self.memory_budget_action)
            .field(
                "cheap_memory_advice_report",
                &self.cheap_memory_advice_report,
            )
            .field("gc_stress_boundary_scans", &self.gc_stress_boundary_scans)
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

    /// Returns the final high-water heap budget action, if one was configured.
    pub const fn memory_budget_action(&self) -> Option<EvalHeapMemoryBudgetAction> {
        self.memory_budget_action
    }

    /// Returns the post-evaluation cheap heap advice report, if one was requested.
    pub const fn cheap_memory_advice_report(&self) -> Option<EvalHeapCheapMemoryAdviceReport> {
        self.cheap_memory_advice_report
    }

    /// Returns GC-stress scans recorded at the successful evaluation boundary.
    pub const fn gc_stress_boundary_scans(&self) -> &EvalGcStressBoundaryScans {
        &self.gc_stress_boundary_scans
    }

    /// Builds minor-GC plans from the recorded GC-stress boundary scans.
    ///
    /// This uses the outcome's remembered-set snapshot and the caller-supplied
    /// promotion policy. It is planning metadata only: it does not choose
    /// semispace destinations, install forwarding pointers, rewrite roots or
    /// fields, publish remembered sets, or invoke a collector.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if a recorded boundary scan is stale relative
    /// to the outcome heap, if the remembered set is incomplete or invalid for
    /// the current heap graph, or if minor-GC planning fails.
    pub fn gc_stress_boundary_minor_gc_plans(
        &self,
        promotion_policy: MinorGcPromotionPolicy,
    ) -> Result<EvalGcStressBoundaryMinorGcPlans, EvalHeapError> {
        let remembered_set = self.thunk_resolve_remembered_set.snapshot();
        let collection_epoch = self.thunk_resolve_remembered_set.epoch();
        let worker = match self.gc_stress_boundary_scans.worker() {
            Some(scan) => Some(self.heap.plan_collector_poll_minor_gc(
                scan,
                remembered_set,
                collection_epoch,
                promotion_policy,
            )?),
            None => None,
        };
        let permanent_shared = match self.gc_stress_boundary_scans.permanent_shared() {
            Some(scan) => Some(self.heap.plan_collector_poll_minor_gc(
                scan,
                remembered_set,
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
    /// requests, empty forwarding slots, copied reference buffers, and reference
    /// writeback metadata plus caller-owned writeback slot buffers, then returns
    /// those artifacts beside the paired relocation plan. It still does not bind
    /// object byte buffers, mutate forwarding slots, rewrite live roots or heap
    /// fields, publish remembered sets, reserve semispace storage, or invoke a
    /// collector.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if boundary relocation planning fails, if commit
    /// metadata cannot be built, if heap-backed byte-copy or writeback validation
    /// fails, or if forwarding-slot storage cannot be reserved.
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
            let heap_field_writeback_slots =
                boundary_minor_gc_heap_field_writeback_slots(&reference_writeback_plan)?;
            (
                object_byte_copy_plan,
                forwarding_slots,
                reference_buffer,
                reference_writeback_plan,
                root_writeback_slots,
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
            heap_field_writeback_slots,
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
    pub(crate) cache_hits: u64,
    pub(crate) cache_misses: u64,
    pub(crate) early_cutoffs: u64,
    pub(crate) derivation_aterm_path_reuses: u64,
    pub(crate) static_derivation_output_path_reuses: u64,
    pub(crate) derivation_hash_calculations: u64,
    pub(crate) derivation_text_path_calculations: u64,
    pub(crate) heap_chunks: u64,
    pub(crate) heap_reserved_bytes: u64,
    pub(crate) heap_used_bytes: u64,
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

    /// Returns the number of bump-arena chunks allocated by the evaluator heap.
    pub const fn heap_chunks(&self) -> u64 {
        self.heap_chunks
    }

    /// Returns bytes reserved by evaluator heap chunks.
    pub const fn heap_reserved_bytes(&self) -> u64 {
        self.heap_reserved_bytes
    }

    /// Returns bytes consumed by evaluator heap allocations.
    pub const fn heap_used_bytes(&self) -> u64 {
        self.heap_used_bytes
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
