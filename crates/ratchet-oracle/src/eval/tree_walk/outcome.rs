//! Evaluation outcome, derivation, statistics, trace, IFD-realization, and warning types.

use std::ptr::NonNull;

use thiserror::Error;

use super::*;
use crate::cache::ImpureInputTraceSource;
use crate::compile::EffectClass;
use crate::eval::heap::{
    AllocationCollectorPollObjectBodyAndGenerationWriteReport,
    AllocationCollectorPollObjectBodyWriteReport, AllocationCollectorPollObjectByteCopyPlan,
    AllocationCollectorPollObjectGenerationWritePlan,
    AllocationCollectorPollObjectGenerationWriteReport, EvalHeapError, EvalHeapMemoryAdviceReport,
    EvalHeapMemoryBudgetDecision, EvalHeapTierBAdmissionPlan, EvalHeapTierBAdmissionReport,
    EvalRootSource,
};
use crate::heap::{ArenaStats, HeapGeneration};
use crate::value::HeapObject;

mod memo_stats;
pub use memo_stats::{MemoEconomicsStats, MemoTierEvents};

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
const BOUNDARY_MINOR_GC_LIVE_OBJECT_GENERATIONS_TABLE: &str =
    "boundary minor-GC live object generations";
const BOUNDARY_MINOR_GC_DESTINATION_OBJECT_GENERATION_BINDINGS_TABLE: &str =
    "boundary minor-GC destination object-generation bindings";
const BOUNDARY_MINOR_GC_OBJECT_GENERATION_WRITES_TABLE: &str =
    "boundary minor-GC object-generation writes";
const BOUNDARY_MINOR_GC_OBJECT_GENERATION_WRITE_BYTES_TABLE: &str =
    "boundary minor-GC object-generation write bytes";
const BOUNDARY_MINOR_GC_OBJECT_BODY_GENERATION_PREFLIGHT_REQUESTS_TABLE: &str =
    "boundary minor-GC object body/generation preflight requests";
const BOUNDARY_MINOR_GC_FORWARDING_DESTINATION_BINDINGS_TABLE: &str =
    "boundary minor-GC forwarding destination bindings";
const BOUNDARY_MINOR_GC_FORWARDING_HEADER_WRITES_TABLE: &str =
    "boundary minor-GC forwarding-header writes";
const BOUNDARY_MINOR_GC_FORWARDING_HEADER_WRITE_BYTES_TABLE: &str =
    "boundary minor-GC forwarding-header write bytes";
const BOUNDARY_MINOR_GC_ROOT_WRITEBACK_DESTINATION_BINDINGS_TABLE: &str =
    "boundary minor-GC root writeback destination bindings";
const BOUNDARY_MINOR_GC_ROOT_WRITEBACK_WRITES_TABLE: &str =
    "boundary minor-GC root writeback writes";
const BOUNDARY_MINOR_GC_ROOT_WRITEBACK_WRITE_BYTES_TABLE: &str =
    "boundary minor-GC root writeback write bytes";
const BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_DESTINATION_BINDINGS_TABLE: &str =
    "boundary minor-GC heap-field writeback destination bindings";
const BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_WRITES_TABLE: &str =
    "boundary minor-GC heap-field writeback writes";
const BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_WRITE_BYTES_TABLE: &str =
    "boundary minor-GC heap-field writeback write bytes";
const BOUNDARY_MINOR_GC_REFERENCE_WRITEBACK_WRITES_TABLE: &str =
    "boundary minor-GC reference writeback writes";
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

/// Metadata for a requested Tier-B heap transition.
///
/// This report is derived from the final high-water memory-budget action. It
/// records the exact would-be pre-flip arena accounting and cheap advice
/// telemetry that caused the safety valve to ask for Tier B, but it does not
/// install a collector or mutate the owning heap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvalTierBTransitionRequest {
    decision: EvalHeapMemoryBudgetDecision,
    report: EvalHeapMemoryAdviceReport,
}

impl EvalTierBTransitionRequest {
    pub(in crate::eval::tree_walk) const fn from_memory_budget_action(
        action: EvalHeapMemoryBudgetAction,
    ) -> Option<Self> {
        match action {
            EvalHeapMemoryBudgetAction::RequestTierB { decision, report } => {
                Some(Self { decision, report })
            }
            EvalHeapMemoryBudgetAction::ContinueTierA { .. }
            | EvalHeapMemoryBudgetAction::AdviseUnusedTails { .. } => None,
        }
    }

    /// Returns the memory-budget action that requested Tier B.
    pub const fn action(self) -> EvalHeapMemoryBudgetAction {
        EvalHeapMemoryBudgetAction::RequestTierB {
            decision: self.decision,
            report: self.report,
        }
    }

    /// Returns the whole-heap budget decision captured before transition.
    pub const fn decision(self) -> EvalHeapMemoryBudgetDecision {
        self.decision
    }

    /// Returns the unused-tail advice report run before requesting Tier B.
    pub const fn advice_report(self) -> EvalHeapMemoryAdviceReport {
        self.report
    }

    /// Returns worker-domain arena accounting captured before transition.
    pub const fn worker_stats(self) -> crate::heap::ArenaStats {
        self.decision().worker_stats()
    }

    /// Returns permanent-shared arena accounting captured before transition.
    pub const fn permanent_stats(self) -> crate::heap::ArenaStats {
        self.decision().permanent_stats()
    }

    /// Returns total mapped bytes in the would-be pre-flip heap domains.
    pub const fn pre_flip_mapped_bytes(self) -> usize {
        self.worker_stats()
            .mapped_bytes
            .saturating_add(self.permanent_stats().mapped_bytes)
    }

    /// Validates this request against current heap accounting.
    ///
    /// The returned preflight records the worker Tier-A arena as an immortal
    /// old-generation input and preserves permanent-shared storage as
    /// permanent. It is still read-only metadata; it does not install a
    /// collector, mutate heap-record generations, rewrite values, or switch the
    /// allocator tier.
    ///
    /// # Errors
    ///
    /// Returns [`EvalTierBTransitionPreflightError`] if the heap's worker or
    /// permanent-shared arena accounting no longer matches the request's
    /// pre-flip snapshot.
    pub fn preflight(
        self,
        heap: &EvalHeap,
    ) -> Result<EvalTierBTransitionPreflight, EvalTierBTransitionPreflightError> {
        let worker_stats = heap.arena_stats();
        if worker_stats != self.worker_stats() {
            return Err(EvalTierBTransitionPreflightError::WorkerStatsChanged {
                expected: self.worker_stats(),
                actual: worker_stats,
            });
        }

        let permanent_stats = heap.permanent_arena_stats();
        if permanent_stats != self.permanent_stats() {
            return Err(
                EvalTierBTransitionPreflightError::PermanentSharedStatsChanged {
                    expected: self.permanent_stats(),
                    actual: permanent_stats,
                },
            );
        }

        Ok(EvalTierBTransitionPreflight::new(
            self,
            EvalTierBTransitionDomainPreflight::new(
                EvalTierBTransitionDomain::Worker,
                worker_stats,
                HeapGeneration::Old,
            ),
            EvalTierBTransitionDomainPreflight::new(
                EvalTierBTransitionDomain::PermanentShared,
                permanent_stats,
                HeapGeneration::Permanent,
            ),
        ))
    }

    /// Builds a read-only Tier-B admission plan for this request.
    ///
    /// This first validates that the request still matches current heap
    /// accounting, then snapshots the current heap-record admission plan. The
    /// returned plan still does not install a collector, switch allocators,
    /// rewrite heap records, or relocate values.
    ///
    /// # Errors
    ///
    /// Returns [`EvalTierBTransitionAdmissionPlanError`] if the request is
    /// stale for `heap` or if the heap-record admission plan cannot be built.
    pub fn admission_plan(
        self,
        heap: &EvalHeap,
    ) -> Result<EvalTierBTransitionAdmissionPlan, EvalTierBTransitionAdmissionPlanError> {
        let preflight = self.preflight(heap)?;
        let heap_plan = heap.plan_tier_b_admission()?;
        Ok(EvalTierBTransitionAdmissionPlan::new(preflight, heap_plan))
    }
}

/// One pre-flip allocation domain considered for Tier-B admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvalTierBTransitionDomain {
    /// The per-worker Tier-A arena that becomes an immortal old-generation region.
    Worker,
    /// The permanent-shared arena that keeps permanent-generation semantics.
    PermanentShared,
}

/// Validated pre-flip accounting for one Tier-B transition domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvalTierBTransitionDomainPreflight {
    domain: EvalTierBTransitionDomain,
    stats: ArenaStats,
    generation: HeapGeneration,
}

impl EvalTierBTransitionDomainPreflight {
    const fn new(
        domain: EvalTierBTransitionDomain,
        stats: ArenaStats,
        generation: HeapGeneration,
    ) -> Self {
        Self {
            domain,
            stats,
            generation,
        }
    }

    /// Returns the allocation domain described by this preflight row.
    pub const fn domain(self) -> EvalTierBTransitionDomain {
        self.domain
    }

    /// Returns the validated pre-flip arena accounting for this domain.
    pub const fn stats(self) -> ArenaStats {
        self.stats
    }

    /// Returns the generation assigned to this domain after Tier-B admission.
    pub const fn generation(self) -> HeapGeneration {
        self.generation
    }
}

/// Read-only admission metadata for a requested Tier-B transition.
///
/// This validates that the request still matches the current heap's pre-flip
/// arena accounting and names the generation each allocation domain would
/// occupy after admission. It deliberately stops before collector
/// installation, allocator switching, heap-record generation mutation, and
/// value relocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvalTierBTransitionPreflight {
    request: EvalTierBTransitionRequest,
    worker: EvalTierBTransitionDomainPreflight,
    permanent_shared: EvalTierBTransitionDomainPreflight,
}

impl EvalTierBTransitionPreflight {
    const fn new(
        request: EvalTierBTransitionRequest,
        worker: EvalTierBTransitionDomainPreflight,
        permanent_shared: EvalTierBTransitionDomainPreflight,
    ) -> Self {
        Self {
            request,
            worker,
            permanent_shared,
        }
    }

    /// Returns the Tier-B request validated by this preflight.
    pub const fn request(self) -> EvalTierBTransitionRequest {
        self.request
    }

    /// Returns validated worker-domain admission metadata.
    pub const fn worker(self) -> EvalTierBTransitionDomainPreflight {
        self.worker
    }

    /// Returns validated permanent-shared admission metadata.
    pub const fn permanent_shared(self) -> EvalTierBTransitionDomainPreflight {
        self.permanent_shared
    }

    /// Returns all domain preflights in worker, permanent-shared order.
    pub const fn domains(self) -> [EvalTierBTransitionDomainPreflight; 2] {
        [self.worker, self.permanent_shared]
    }

    /// Returns total mapped bytes in the admitted pre-flip heap domains.
    pub const fn pre_flip_mapped_bytes(self) -> usize {
        self.request.pre_flip_mapped_bytes()
    }
}

/// Read-only cross-tier admission plan for a requested Tier-B transition.
///
/// This combines request-level arena-accounting validation with the current
/// heap-record admission plan. It is still planning metadata only: no collector
/// is installed, no allocator tier changes, no heap-record generations are
/// rewritten, and no values are relocated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvalTierBTransitionAdmissionPlan {
    preflight: EvalTierBTransitionPreflight,
    heap_plan: EvalHeapTierBAdmissionPlan,
}

impl EvalTierBTransitionAdmissionPlan {
    const fn new(
        preflight: EvalTierBTransitionPreflight,
        heap_plan: EvalHeapTierBAdmissionPlan,
    ) -> Self {
        Self {
            preflight,
            heap_plan,
        }
    }

    /// Returns the validated request-level admission preflight.
    pub const fn preflight(&self) -> EvalTierBTransitionPreflight {
        self.preflight
    }

    /// Returns the Tier-B request validated by this admission plan.
    pub const fn request(&self) -> EvalTierBTransitionRequest {
        self.preflight.request()
    }

    /// Returns the heap-record admission plan.
    pub fn heap_plan(&self) -> &EvalHeapTierBAdmissionPlan {
        &self.heap_plan
    }

    /// Returns total mapped bytes in the admitted pre-flip heap domains.
    pub const fn pre_flip_mapped_bytes(&self) -> usize {
        self.preflight.pre_flip_mapped_bytes()
    }
}

/// A Tier-B transition request no longer matches the heap snapshot it captured.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum EvalTierBTransitionPreflightError {
    /// Worker-domain arena accounting changed after the request was captured.
    #[error(
        "Tier-B transition worker arena accounting changed: expected {expected:?}, actual {actual:?}"
    )]
    WorkerStatsChanged {
        /// The worker-domain accounting recorded by the request.
        expected: ArenaStats,
        /// The worker-domain accounting currently reported by the heap.
        actual: ArenaStats,
    },
    /// Permanent-shared arena accounting changed after the request was captured.
    #[error(
        "Tier-B transition permanent-shared arena accounting changed: expected {expected:?}, actual {actual:?}"
    )]
    PermanentSharedStatsChanged {
        /// The permanent-shared accounting recorded by the request.
        expected: ArenaStats,
        /// The permanent-shared accounting currently reported by the heap.
        actual: ArenaStats,
    },
}

/// A Tier-B transition admission plan could not be built.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum EvalTierBTransitionAdmissionPlanError {
    /// The transition request no longer matches the heap accounting snapshot.
    #[error("Tier-B transition preflight failed: {0}")]
    Preflight(#[from] EvalTierBTransitionPreflightError),
    /// The heap-record admission plan could not be built.
    #[error("Tier-B heap admission planning failed: {0}")]
    Heap(#[from] EvalHeapError),
}

/// A Tier-B transition admission plan could not be applied.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum EvalTierBTransitionAdmissionApplyError {
    /// The transition admission plan could not be built.
    #[error("Tier-B transition admission planning failed: {0}")]
    Plan(#[from] EvalTierBTransitionAdmissionPlanError),
    /// The heap rejected the admission plan during application.
    #[error("Tier-B heap admission application failed: {0}")]
    Heap(#[from] EvalHeapError),
}

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

/// Outcome-owned writeback destination-binding installation counts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindingInstallReport {
    root_writeback_bindings: usize,
    heap_field_writeback_bindings: usize,
}

impl EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindingInstallReport {
    const fn new(root_writeback_bindings: usize, heap_field_writeback_bindings: usize) -> Self {
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
    install_report: EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindingInstallReport,
    root_writeback_bindings: Vec<EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding>,
    heap_field_writeback_bindings:
        Vec<EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding>,
    expected_remembered_set: Option<RememberedSet>,
}

impl EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings {
    fn can_install(
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

    fn install(
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

    fn install_prevalidated(
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

/// Outcome-owned object-generation installation counts for a boundary dry run.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveObjectGenerationInstallReport {
    objects: usize,
    copied_to_nursery: usize,
    promoted_to_old: usize,
}

impl EvalGcStressBoundaryMinorGcLiveObjectGenerationInstallReport {
    fn record(&mut self, generation: &EvalGcStressBoundaryMinorGcLiveObjectGeneration) {
        self.objects = self.objects.saturating_add(1);
        match generation.action() {
            MinorGcSurvivorAction::CopyToNursery => {
                self.copied_to_nursery = self.copied_to_nursery.saturating_add(1);
            }
            MinorGcSurvivorAction::PromoteToOld => {
                self.promoted_to_old = self.promoted_to_old.saturating_add(1);
            }
        }
    }

    /// Returns how many object-generation records were installed.
    pub const fn objects(self) -> usize {
        self.objects
    }

    /// Returns how many installed records target next-nursery generation.
    pub const fn copied_to_nursery(self) -> usize {
        self.copied_to_nursery
    }

    /// Returns how many installed records target old generation.
    pub const fn promoted_to_old(self) -> usize {
        self.promoted_to_old
    }
}

/// Outcome-owned generation metadata for one relocated minor-GC object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveObjectGeneration {
    source: GcHeapAddress,
    destination: GcHeapAddress,
    action: MinorGcSurvivorAction,
    generation: HeapGeneration,
    request: AllocationCollectorPollObjectByteCopyRequest,
}

impl EvalGcStressBoundaryMinorGcLiveObjectGeneration {
    const fn new(
        source: GcHeapAddress,
        destination: GcHeapAddress,
        action: MinorGcSurvivorAction,
        generation: HeapGeneration,
        request: AllocationCollectorPollObjectByteCopyRequest,
    ) -> Self {
        Self {
            source,
            destination,
            action,
            generation,
            request,
        }
    }

    /// Returns the from-space survivor source object.
    pub const fn source(&self) -> GcHeapAddress {
        self.source
    }

    /// Returns the destination object address.
    pub const fn destination(&self) -> GcHeapAddress {
        self.destination
    }

    /// Returns whether this destination keeps the object young or promotes it.
    pub const fn action(&self) -> MinorGcSurvivorAction {
        self.action
    }

    /// Returns the generation that owns the destination object in this metadata.
    pub const fn generation(&self) -> HeapGeneration {
        self.generation
    }

    /// Returns the object-copy request that produced this generation metadata.
    pub const fn request(&self) -> AllocationCollectorPollObjectByteCopyRequest {
        self.request
    }
}

/// Outcome-owned object-generation metadata installed by a boundary dry run.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveObjectGenerations {
    install_report: EvalGcStressBoundaryMinorGcLiveObjectGenerationInstallReport,
    object_generations: Vec<EvalGcStressBoundaryMinorGcLiveObjectGeneration>,
}

impl EvalGcStressBoundaryMinorGcLiveObjectGenerations {
    fn can_install(
        &self,
        install_report: EvalGcStressBoundaryMinorGcLiveObjectGenerationInstallReport,
    ) -> Result<(), EvalHeapError> {
        if install_report.objects() != 0 && !self.object_generations.is_empty() {
            return Err(
                EvalHeapError::BoundaryMinorGcLiveObjectGenerationsAlreadyInstalled {
                    existing: self.object_generations.len(),
                },
            );
        }
        Ok(())
    }

    fn install(
        &mut self,
        object_generations: Vec<EvalGcStressBoundaryMinorGcLiveObjectGeneration>,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveObjectGenerationInstallReport, EvalHeapError> {
        if object_generations.is_empty() {
            return Ok(EvalGcStressBoundaryMinorGcLiveObjectGenerationInstallReport::default());
        }
        let install_report = live_object_generation_install_report(&object_generations);
        self.can_install(install_report)?;
        self.install_prevalidated(object_generations, install_report);
        Ok(install_report)
    }

    fn install_prevalidated(
        &mut self,
        object_generations: Vec<EvalGcStressBoundaryMinorGcLiveObjectGeneration>,
        install_report: EvalGcStressBoundaryMinorGcLiveObjectGenerationInstallReport,
    ) {
        if install_report.objects() == 0 {
            return;
        }

        self.object_generations = object_generations;
        self.install_report = install_report;
    }

    /// Returns whether no object-generation metadata is installed.
    pub fn is_empty(&self) -> bool {
        self.object_generations.is_empty()
    }

    /// Returns how many object-generation records are installed.
    pub fn len(&self) -> usize {
        self.object_generations.len()
    }

    /// Returns the report for the last non-empty object-generation install.
    pub const fn install_report(
        &self,
    ) -> EvalGcStressBoundaryMinorGcLiveObjectGenerationInstallReport {
        self.install_report
    }

    /// Returns the installed object-generation metadata records.
    pub fn object_generations(&self) -> &[EvalGcStressBoundaryMinorGcLiveObjectGeneration] {
        &self.object_generations
    }
}

/// Outcome-owned forwarding destination-binding installation counts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingInstallReport {
    bindings: usize,
}

impl EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingInstallReport {
    const fn new(bindings: usize) -> Self {
        Self { bindings }
    }

    /// Returns how many forwarding destination bindings were installed.
    pub const fn bindings(self) -> usize {
        self.bindings
    }
}

/// Outcome-owned forwarding-to-destination binding metadata.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindings {
    install_report: EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingInstallReport,
    forwarding_destination_bindings: Vec<EvalGcStressBoundaryMinorGcForwardingDestinationBinding>,
}

impl EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindings {
    fn can_install(
        &self,
        install_report: EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingInstallReport,
    ) -> Result<(), EvalHeapError> {
        if install_report.bindings() != 0 && !self.forwarding_destination_bindings.is_empty() {
            return Err(
                EvalHeapError::BoundaryMinorGcLiveForwardingDestinationBindingsAlreadyInstalled {
                    existing: self.forwarding_destination_bindings.len(),
                },
            );
        }
        Ok(())
    }

    fn install(
        &mut self,
        forwarding_destination_bindings: Vec<
            EvalGcStressBoundaryMinorGcForwardingDestinationBinding,
        >,
    ) -> Result<
        EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingInstallReport,
        EvalHeapError,
    > {
        if forwarding_destination_bindings.is_empty() {
            return Ok(
                EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingInstallReport::default(),
            );
        }
        let install_report =
            live_forwarding_destination_binding_install_report(&forwarding_destination_bindings);
        self.can_install(install_report)?;
        self.install_prevalidated(forwarding_destination_bindings, install_report);
        Ok(install_report)
    }

    fn install_prevalidated(
        &mut self,
        forwarding_destination_bindings: Vec<
            EvalGcStressBoundaryMinorGcForwardingDestinationBinding,
        >,
        install_report: EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingInstallReport,
    ) {
        if install_report.bindings() == 0 {
            return;
        }

        self.forwarding_destination_bindings = forwarding_destination_bindings;
        self.install_report = install_report;
    }

    /// Returns whether no forwarding destination-binding metadata is installed.
    pub fn is_empty(&self) -> bool {
        self.forwarding_destination_bindings.is_empty()
    }

    /// Returns how many forwarding destination-binding records are installed.
    pub fn len(&self) -> usize {
        self.forwarding_destination_bindings.len()
    }

    /// Returns the install report for the forwarding destination bindings.
    pub const fn install_report(
        &self,
    ) -> EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingInstallReport {
        self.install_report
    }

    /// Returns installed forwarding destination-binding records.
    pub fn forwarding_destination_bindings(
        &self,
    ) -> &[EvalGcStressBoundaryMinorGcForwardingDestinationBinding] {
        &self.forwarding_destination_bindings
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

/// Counts for a live object-generation write plan.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcObjectGenerationWritePlanReport {
    objects: usize,
    copied_to_nursery: usize,
    promoted_to_old: usize,
    payload_bytes: usize,
}

impl EvalGcStressBoundaryMinorGcObjectGenerationWritePlanReport {
    fn record(&mut self, write: &EvalGcStressBoundaryMinorGcObjectGenerationWrite) {
        self.objects = self.objects.saturating_add(1);
        self.payload_bytes = self
            .payload_bytes
            .saturating_add(write.destination_bytes().len());
        match write.action() {
            MinorGcSurvivorAction::CopyToNursery => {
                self.copied_to_nursery = self.copied_to_nursery.saturating_add(1);
            }
            MinorGcSurvivorAction::PromoteToOld => {
                self.promoted_to_old = self.promoted_to_old.saturating_add(1);
            }
        }
    }

    /// Returns how many object-generation fields would be written.
    pub const fn objects(self) -> usize {
        self.objects
    }

    /// Returns how many planned generation writes target next-nursery objects.
    pub const fn copied_to_nursery(self) -> usize {
        self.copied_to_nursery
    }

    /// Returns how many planned generation writes target old objects.
    pub const fn promoted_to_old(self) -> usize {
        self.promoted_to_old
    }

    /// Returns the total destination payload bytes covered by the plan.
    pub const fn payload_bytes(self) -> usize {
        self.payload_bytes
    }
}

/// One validated live object-generation write input.
///
/// This is an immutable write plan for a future heap-record generation writer.
/// It proves that installed live object-generation metadata still matches an
/// installed destination-byte snapshot and carries the payload metadata needed
/// by the eventual writer, but it does not mutate heap records or semispace
/// ownership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcObjectGenerationWrite {
    source: GcHeapAddress,
    destination: GcHeapAddress,
    action: MinorGcSurvivorAction,
    generation: HeapGeneration,
    request: AllocationCollectorPollObjectByteCopyRequest,
    destination_bytes: Vec<u8>,
}

impl EvalGcStressBoundaryMinorGcObjectGenerationWrite {
    fn from_generation_and_binding(
        generation: &EvalGcStressBoundaryMinorGcLiveObjectGeneration,
        binding: &EvalGcStressBoundaryMinorGcDestinationObjectGenerationBinding,
    ) -> Result<Self, EvalHeapError> {
        Ok(Self {
            source: generation.source(),
            destination: generation.destination(),
            action: generation.action(),
            generation: generation.generation(),
            request: generation.request(),
            destination_bytes: clone_boundary_destination_storage_bytes(
                BOUNDARY_MINOR_GC_OBJECT_GENERATION_WRITE_BYTES_TABLE,
                binding.destination_bytes(),
            )?,
        })
    }

    /// Returns the from-space survivor source object.
    pub const fn source(&self) -> GcHeapAddress {
        self.source
    }

    /// Returns the destination object address whose generation would be written.
    pub const fn destination(&self) -> GcHeapAddress {
        self.destination
    }

    /// Returns whether this destination keeps the object young or promotes it.
    pub const fn action(&self) -> MinorGcSurvivorAction {
        self.action
    }

    /// Returns the generation that would be written to the destination object.
    pub const fn generation(&self) -> HeapGeneration {
        self.generation
    }

    /// Returns the object-copy request associated with this generation write.
    pub const fn request(&self) -> AllocationCollectorPollObjectByteCopyRequest {
        self.request
    }

    /// Returns the installed destination payload bytes covered by this write.
    pub fn destination_bytes(&self) -> &[u8] {
        &self.destination_bytes
    }
}

/// A validated live object-generation write plan.
///
/// The plan is derived from installed live object-generation metadata and
/// installed destination-byte snapshots. It is a checked input set for a future
/// heap-record generation writer; creating it does not write heap records, copy
/// object bodies, or change semispace ownership.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcObjectGenerationWritePlan {
    report: EvalGcStressBoundaryMinorGcObjectGenerationWritePlanReport,
    writes: Vec<EvalGcStressBoundaryMinorGcObjectGenerationWrite>,
}

impl EvalGcStressBoundaryMinorGcObjectGenerationWritePlan {
    fn new(writes: Vec<EvalGcStressBoundaryMinorGcObjectGenerationWrite>) -> Self {
        let mut report = EvalGcStressBoundaryMinorGcObjectGenerationWritePlanReport::default();
        for write in &writes {
            report.record(write);
        }
        Self { report, writes }
    }

    /// Returns whether this plan has no object-generation writes.
    pub fn is_empty(&self) -> bool {
        self.writes.is_empty()
    }

    /// Returns how many object-generation writes are planned.
    pub fn len(&self) -> usize {
        self.writes.len()
    }

    /// Returns aggregate counts for the plan.
    pub const fn report(&self) -> EvalGcStressBoundaryMinorGcObjectGenerationWritePlanReport {
        self.report
    }

    /// Returns the planned live object-generation writes.
    pub fn writes(&self) -> &[EvalGcStressBoundaryMinorGcObjectGenerationWrite] {
        &self.writes
    }
}

/// A forwarding value matched to an installed destination-byte snapshot.
///
/// The binding is validation metadata for a future ABI object-header writer. It
/// proves that a forwarding value names the same destination object, generation,
/// and payload bytes as the destination-copy metadata for its source. It does
/// not write object headers, bind bytes to heap-object storage, or mutate
/// generation state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcForwardingDestinationBinding {
    source: GcHeapAddress,
    destination: GcHeapAddress,
    generation: HeapGeneration,
    forwarded_value: ResolvedValueGeneration,
    request: AllocationCollectorPollObjectByteCopyRequest,
    destination_bytes: Vec<u8>,
}

impl EvalGcStressBoundaryMinorGcForwardingDestinationBinding {
    fn new(
        source: GcHeapAddress,
        destination: GcHeapAddress,
        generation: HeapGeneration,
        forwarded_value: ResolvedValueGeneration,
        request: AllocationCollectorPollObjectByteCopyRequest,
        destination_bytes: Vec<u8>,
    ) -> Self {
        Self {
            source,
            destination,
            generation,
            forwarded_value,
            request,
            destination_bytes,
        }
    }

    /// Returns the from-space object that owns the forwarding value.
    pub const fn source(&self) -> GcHeapAddress {
        self.source
    }

    /// Returns the destination object address carried by the forwarding value.
    pub const fn destination(&self) -> GcHeapAddress {
        self.destination
    }

    /// Returns the generation carried by the forwarding value.
    pub const fn generation(&self) -> HeapGeneration {
        self.generation
    }

    /// Returns the complete forwarding metadata value.
    pub const fn forwarded_value(&self) -> ResolvedValueGeneration {
        self.forwarded_value
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

/// Counts for an ABI forwarding-header write plan.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcForwardingHeaderWritePlanReport {
    headers: usize,
    copied_to_nursery: usize,
    promoted_to_old: usize,
    payload_bytes: usize,
}

impl EvalGcStressBoundaryMinorGcForwardingHeaderWritePlanReport {
    fn record(&mut self, write: &EvalGcStressBoundaryMinorGcForwardingHeaderWrite) {
        self.headers = self.headers.saturating_add(1);
        self.payload_bytes = self
            .payload_bytes
            .saturating_add(write.destination_bytes().len());
        match write.request().action() {
            MinorGcSurvivorAction::CopyToNursery => {
                self.copied_to_nursery = self.copied_to_nursery.saturating_add(1);
            }
            MinorGcSurvivorAction::PromoteToOld => {
                self.promoted_to_old = self.promoted_to_old.saturating_add(1);
            }
        }
    }

    /// Returns how many object headers would receive forwarding metadata.
    pub const fn headers(self) -> usize {
        self.headers
    }

    /// Returns how many planned header writes point to next-nursery objects.
    pub const fn copied_to_nursery(self) -> usize {
        self.copied_to_nursery
    }

    /// Returns how many planned header writes point to promoted old objects.
    pub const fn promoted_to_old(self) -> usize {
        self.promoted_to_old
    }

    /// Returns the total destination payload bytes covered by the plan.
    pub const fn payload_bytes(self) -> usize {
        self.payload_bytes
    }
}

/// One validated forwarding-header write input.
///
/// This is an immutable write plan for a future ABI object-header writer. It
/// proves that an installed live forwarding cell still matches an installed
/// forwarding-destination binding and carries the destination payload metadata
/// needed by the eventual writer, but it does not mutate object headers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcForwardingHeaderWrite {
    source: GcHeapAddress,
    destination: GcHeapAddress,
    generation: HeapGeneration,
    forwarded_value: ResolvedValueGeneration,
    request: AllocationCollectorPollObjectByteCopyRequest,
    destination_bytes: Vec<u8>,
}

impl EvalGcStressBoundaryMinorGcForwardingHeaderWrite {
    fn from_binding(
        binding: &EvalGcStressBoundaryMinorGcForwardingDestinationBinding,
    ) -> Result<Self, EvalHeapError> {
        Ok(Self {
            source: binding.source(),
            destination: binding.destination(),
            generation: binding.generation(),
            forwarded_value: binding.forwarded_value(),
            request: binding.request(),
            destination_bytes: clone_boundary_destination_storage_bytes(
                BOUNDARY_MINOR_GC_FORWARDING_HEADER_WRITE_BYTES_TABLE,
                binding.destination_bytes(),
            )?,
        })
    }

    /// Returns the from-space object whose ABI header would be written.
    pub const fn source(&self) -> GcHeapAddress {
        self.source
    }

    /// Returns the destination object address carried by the forwarding value.
    pub const fn destination(&self) -> GcHeapAddress {
        self.destination
    }

    /// Returns the destination generation carried by the forwarding value.
    pub const fn generation(&self) -> HeapGeneration {
        self.generation
    }

    /// Returns the forwarding value that would be written into the header.
    pub const fn forwarded_value(&self) -> ResolvedValueGeneration {
        self.forwarded_value
    }

    /// Returns the object-copy request associated with this header write.
    pub const fn request(&self) -> AllocationCollectorPollObjectByteCopyRequest {
        self.request
    }

    /// Returns the installed destination payload bytes covered by this write.
    pub fn destination_bytes(&self) -> &[u8] {
        &self.destination_bytes
    }
}

/// A validated forwarding-header write plan.
///
/// The plan is derived from installed live forwarding cells and installed
/// forwarding-destination bindings. It is a checked input set for a future
/// unsafe ABI header writer; creating it does not write headers, copy object
/// bodies, or change evaluator heap records.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcForwardingHeaderWritePlan {
    report: EvalGcStressBoundaryMinorGcForwardingHeaderWritePlanReport,
    writes: Vec<EvalGcStressBoundaryMinorGcForwardingHeaderWrite>,
}

impl EvalGcStressBoundaryMinorGcForwardingHeaderWritePlan {
    fn new(writes: Vec<EvalGcStressBoundaryMinorGcForwardingHeaderWrite>) -> Self {
        let mut report = EvalGcStressBoundaryMinorGcForwardingHeaderWritePlanReport::default();
        for write in &writes {
            report.record(write);
        }
        Self { report, writes }
    }

    /// Returns whether this plan has no header writes.
    pub fn is_empty(&self) -> bool {
        self.writes.is_empty()
    }

    /// Returns how many header writes are planned.
    pub fn len(&self) -> usize {
        self.writes.len()
    }

    /// Returns aggregate counts for the plan.
    pub const fn report(&self) -> EvalGcStressBoundaryMinorGcForwardingHeaderWritePlanReport {
        self.report
    }

    /// Returns the planned forwarding-header writes.
    pub fn writes(&self) -> &[EvalGcStressBoundaryMinorGcForwardingHeaderWrite] {
        &self.writes
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

    /// Returns the allocator domain assigned to this root writeback.
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

/// Counts for a live root-writeback write plan.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcRootWritebackWritePlanReport {
    roots: usize,
    copied_to_nursery: usize,
    promoted_to_old: usize,
    payload_bytes: usize,
}

impl EvalGcStressBoundaryMinorGcRootWritebackWritePlanReport {
    fn record(&mut self, write: &EvalGcStressBoundaryMinorGcRootWritebackWrite) {
        self.roots = self.roots.saturating_add(1);
        self.payload_bytes = self
            .payload_bytes
            .saturating_add(write.destination_bytes().len());
        match write.request().action() {
            MinorGcSurvivorAction::CopyToNursery => {
                self.copied_to_nursery = self.copied_to_nursery.saturating_add(1);
            }
            MinorGcSurvivorAction::PromoteToOld => {
                self.promoted_to_old = self.promoted_to_old.saturating_add(1);
            }
        }
    }

    /// Returns how many evaluator roots would receive relocated values.
    pub const fn roots(self) -> usize {
        self.roots
    }

    /// Returns how many planned root writes point to next-nursery objects.
    pub const fn copied_to_nursery(self) -> usize {
        self.copied_to_nursery
    }

    /// Returns how many planned root writes point to promoted old objects.
    pub const fn promoted_to_old(self) -> usize {
        self.promoted_to_old
    }

    /// Returns the total destination payload bytes covered by the plan.
    pub const fn payload_bytes(self) -> usize {
        self.payload_bytes
    }
}

/// One validated live root-writeback input.
///
/// This is an immutable write plan for a future root writer. It proves that an
/// installed root writeback slot still matches an installed root destination
/// binding and carries both the typed replacement [`Value`] and
/// generation-style metadata needed by the eventual writer. It does not mutate
/// evaluator roots.
#[derive(Clone, Debug)]
pub struct EvalGcStressBoundaryMinorGcRootWritebackWrite {
    allocation_domain: HeapAllocationDomain,
    root_source: EvalRootSource,
    replacement_tag: ValueTag,
    replacement_value: Value,
    destination: GcHeapAddress,
    generation: HeapGeneration,
    replacement_metadata: ResolvedValueGeneration,
    request: AllocationCollectorPollObjectByteCopyRequest,
    destination_bytes: Vec<u8>,
}

impl EvalGcStressBoundaryMinorGcRootWritebackWrite {
    fn from_source_and_binding(
        source: BoundaryMinorGcRootWritebackWriteSource,
        binding: &EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding,
    ) -> Result<Self, EvalHeapError> {
        Ok(Self {
            allocation_domain: source.allocation_domain,
            root_source: source.root_source,
            replacement_tag: source.replacement_tag,
            replacement_value: source.replacement_value,
            destination: source.destination,
            generation: source.generation,
            replacement_metadata: source.replacement_metadata,
            request: binding.request(),
            destination_bytes: clone_boundary_destination_storage_bytes(
                BOUNDARY_MINOR_GC_ROOT_WRITEBACK_WRITE_BYTES_TABLE,
                binding.destination_bytes(),
            )?,
        })
    }

    /// Returns the allocator domain assigned to this root writeback.
    pub const fn allocation_domain(&self) -> HeapAllocationDomain {
        self.allocation_domain
    }

    /// Returns the copied root source that would be rewritten.
    pub const fn root_source(&self) -> &EvalRootSource {
        &self.root_source
    }

    /// Returns the heap tag carried by the typed replacement value.
    pub const fn replacement_tag(&self) -> ValueTag {
        self.replacement_tag
    }

    /// Returns the typed evaluator value that would be written to the root.
    pub const fn replacement_value(&self) -> Value {
        self.replacement_value
    }

    /// Returns the destination object address for the replacement value.
    pub const fn destination(&self) -> GcHeapAddress {
        self.destination
    }

    /// Returns the generation of the destination object.
    pub const fn generation(&self) -> HeapGeneration {
        self.generation
    }

    /// Returns the generation-style replacement metadata paired with the root.
    pub const fn replacement_metadata(&self) -> ResolvedValueGeneration {
        self.replacement_metadata
    }

    /// Returns the object-copy request that installed the destination payload.
    pub const fn request(&self) -> AllocationCollectorPollObjectByteCopyRequest {
        self.request
    }

    /// Returns the installed destination payload bytes covered by this write.
    pub fn destination_bytes(&self) -> &[u8] {
        &self.destination_bytes
    }
}

impl PartialEq for EvalGcStressBoundaryMinorGcRootWritebackWrite {
    fn eq(&self, other: &Self) -> bool {
        self.allocation_domain == other.allocation_domain
            && self.root_source == other.root_source
            && self.replacement_tag == other.replacement_tag
            && self.replacement_value.raw_eq(other.replacement_value)
            && self.destination == other.destination
            && self.generation == other.generation
            && self.replacement_metadata == other.replacement_metadata
            && self.request == other.request
            && self.destination_bytes == other.destination_bytes
    }
}

impl Eq for EvalGcStressBoundaryMinorGcRootWritebackWrite {}

/// A validated live root-writeback write plan.
///
/// The plan is derived from installed live reference-writeback metadata and
/// installed writeback-destination bindings. It is a checked input set for a
/// future live root writer; creating it does not write roots, copy object
/// bodies, or bind destination bytes to heap storage.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcRootWritebackWritePlan {
    report: EvalGcStressBoundaryMinorGcRootWritebackWritePlanReport,
    writes: Vec<EvalGcStressBoundaryMinorGcRootWritebackWrite>,
}

impl EvalGcStressBoundaryMinorGcRootWritebackWritePlan {
    fn new(writes: Vec<EvalGcStressBoundaryMinorGcRootWritebackWrite>) -> Self {
        let mut report = EvalGcStressBoundaryMinorGcRootWritebackWritePlanReport::default();
        for write in &writes {
            report.record(write);
        }
        Self { report, writes }
    }

    /// Returns whether this plan has no root writes.
    pub fn is_empty(&self) -> bool {
        self.writes.is_empty()
    }

    /// Returns how many root writes are planned.
    pub fn len(&self) -> usize {
        self.writes.len()
    }

    /// Returns aggregate counts for the plan.
    pub const fn report(&self) -> EvalGcStressBoundaryMinorGcRootWritebackWritePlanReport {
        self.report
    }

    /// Returns the planned live root writes.
    pub fn writes(&self) -> &[EvalGcStressBoundaryMinorGcRootWritebackWrite] {
        &self.writes
    }
}

/// Counts for outcome-owned root slots rewritten by a boundary minor-GC plan.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcOutcomeRootWritebackReport {
    value_stack_roots: usize,
}

impl EvalGcStressBoundaryMinorGcOutcomeRootWritebackReport {
    const fn new(value_stack_roots: usize) -> Self {
        Self { value_stack_roots }
    }

    /// Returns how many outcome-owned value-stack roots were rewritten.
    pub const fn value_stack_roots(self) -> usize {
        self.value_stack_roots
    }

    /// Returns the total number of outcome-owned roots rewritten.
    pub const fn roots(self) -> usize {
        self.value_stack_roots
    }
}

/// Counts for live object-body writes and outcome-owned root rewrites.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveOutcomeRootWritebackReport {
    object_body_and_generation_write_report:
        AllocationCollectorPollObjectBodyAndGenerationWriteReport,
    outcome_root_writeback_report: EvalGcStressBoundaryMinorGcOutcomeRootWritebackReport,
}

impl EvalGcStressBoundaryMinorGcLiveOutcomeRootWritebackReport {
    const fn new(
        object_body_and_generation_write_report:
            AllocationCollectorPollObjectBodyAndGenerationWriteReport,
        outcome_root_writeback_report: EvalGcStressBoundaryMinorGcOutcomeRootWritebackReport,
    ) -> Self {
        Self {
            object_body_and_generation_write_report,
            outcome_root_writeback_report,
        }
    }

    /// Returns the paired object-body and object-generation write report.
    pub const fn object_body_and_generation_write_report(
        self,
    ) -> AllocationCollectorPollObjectBodyAndGenerationWriteReport {
        self.object_body_and_generation_write_report
    }

    /// Returns the destination object-body write report.
    pub const fn object_body_write_report(self) -> AllocationCollectorPollObjectBodyWriteReport {
        self.object_body_and_generation_write_report
            .body_write_report()
    }

    /// Returns how many destination object bodies were written.
    pub const fn object_bodies_written(self) -> usize {
        self.object_body_write_report().objects()
    }

    /// Returns the destination object-generation write report.
    pub const fn object_generation_write_report(
        self,
    ) -> AllocationCollectorPollObjectGenerationWriteReport {
        self.object_body_and_generation_write_report
            .generation_write_report()
    }

    /// Returns how many destination object generations were written.
    pub const fn object_generations_written(self) -> usize {
        self.object_generation_write_report().objects()
    }

    /// Returns the outcome-root writeback report.
    pub const fn outcome_root_writeback_report(
        self,
    ) -> EvalGcStressBoundaryMinorGcOutcomeRootWritebackReport {
        self.outcome_root_writeback_report
    }

    /// Returns how many outcome-owned value-stack roots were rewritten.
    pub const fn value_stack_roots(self) -> usize {
        self.outcome_root_writeback_report.value_stack_roots()
    }

    /// Returns how many outcome-owned roots were rewritten.
    pub const fn roots(self) -> usize {
        self.outcome_root_writeback_report.roots()
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

    /// Returns the allocator domain assigned to the heap-field source.
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

/// Counts for a live heap-field writeback write plan.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport {
    fields: usize,
    copied_replacements_to_nursery: usize,
    promoted_replacements_to_old: usize,
    replacement_payload_bytes: usize,
    writeback_object_payload_bytes: usize,
}

impl EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport {
    fn record(&mut self, write: &EvalGcStressBoundaryMinorGcHeapFieldWritebackWrite) {
        self.fields = self.fields.saturating_add(1);
        self.replacement_payload_bytes = self
            .replacement_payload_bytes
            .saturating_add(write.replacement_destination_bytes().len());
        self.writeback_object_payload_bytes = self.writeback_object_payload_bytes.saturating_add(
            write
                .writeback_object_destination_bytes()
                .map_or(0, <[u8]>::len),
        );
        match write.replacement_request().action() {
            MinorGcSurvivorAction::CopyToNursery => {
                self.copied_replacements_to_nursery =
                    self.copied_replacements_to_nursery.saturating_add(1);
            }
            MinorGcSurvivorAction::PromoteToOld => {
                self.promoted_replacements_to_old =
                    self.promoted_replacements_to_old.saturating_add(1);
            }
        }
    }

    /// Returns how many heap fields would receive relocated values.
    pub const fn fields(self) -> usize {
        self.fields
    }

    /// Returns how many planned field replacements point to next-nursery objects.
    pub const fn copied_replacements_to_nursery(self) -> usize {
        self.copied_replacements_to_nursery
    }

    /// Returns how many planned field replacements point to promoted old objects.
    pub const fn promoted_replacements_to_old(self) -> usize {
        self.promoted_replacements_to_old
    }

    /// Returns the total replacement payload bytes covered by the plan.
    pub const fn replacement_payload_bytes(self) -> usize {
        self.replacement_payload_bytes
    }

    /// Returns payload bytes for relocated writeback objects covered by the plan.
    pub const fn writeback_object_payload_bytes(self) -> usize {
        self.writeback_object_payload_bytes
    }
}

/// Counts for live object-body/generation writes and heap-field rewrites.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveHeapFieldWritebackReport {
    object_body_and_generation_write_report:
        AllocationCollectorPollObjectBodyAndGenerationWriteReport,
    heap_field_writeback_report: EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport,
}

impl EvalGcStressBoundaryMinorGcLiveHeapFieldWritebackReport {
    const fn new(
        object_body_and_generation_write_report:
            AllocationCollectorPollObjectBodyAndGenerationWriteReport,
        heap_field_writeback_report: EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport,
    ) -> Self {
        Self {
            object_body_and_generation_write_report,
            heap_field_writeback_report,
        }
    }

    /// Returns the paired object-body and object-generation write report.
    pub const fn object_body_and_generation_write_report(
        self,
    ) -> AllocationCollectorPollObjectBodyAndGenerationWriteReport {
        self.object_body_and_generation_write_report
    }

    /// Returns the destination object-body write report.
    pub const fn object_body_write_report(self) -> AllocationCollectorPollObjectBodyWriteReport {
        self.object_body_and_generation_write_report
            .body_write_report()
    }

    /// Returns how many destination object bodies were written.
    pub const fn object_bodies_written(self) -> usize {
        self.object_body_write_report().objects()
    }

    /// Returns the destination object-generation write report.
    pub const fn object_generation_write_report(
        self,
    ) -> AllocationCollectorPollObjectGenerationWriteReport {
        self.object_body_and_generation_write_report
            .generation_write_report()
    }

    /// Returns how many destination object generations were written.
    pub const fn object_generations_written(self) -> usize {
        self.object_generation_write_report().objects()
    }

    /// Returns the heap-field writeback report.
    pub const fn heap_field_writeback_report(
        self,
    ) -> EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport {
        self.heap_field_writeback_report
    }

    /// Returns how many heap fields were rewritten.
    pub const fn fields(self) -> usize {
        self.heap_field_writeback_report.fields()
    }
}

/// Counts for prevalidated live object and heap-field writebacks.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveHeapFieldWritebackPreflightReport {
    object_body_and_generation_write_report:
        AllocationCollectorPollObjectBodyAndGenerationWriteReport,
    heap_field_writeback_report: EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport,
}

impl EvalGcStressBoundaryMinorGcLiveHeapFieldWritebackPreflightReport {
    const fn new(
        object_body_and_generation_write_report:
            AllocationCollectorPollObjectBodyAndGenerationWriteReport,
        heap_field_writeback_report: EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport,
    ) -> Self {
        Self {
            object_body_and_generation_write_report,
            heap_field_writeback_report,
        }
    }

    /// Returns the paired object-body and object-generation preflight report.
    pub const fn object_body_and_generation_write_report(
        self,
    ) -> AllocationCollectorPollObjectBodyAndGenerationWriteReport {
        self.object_body_and_generation_write_report
    }

    /// Returns the destination object-body preflight report.
    pub const fn object_body_write_report(self) -> AllocationCollectorPollObjectBodyWriteReport {
        self.object_body_and_generation_write_report
            .body_write_report()
    }

    /// Returns how many destination object bodies were covered by the preflight.
    pub const fn object_body_preflight_objects(self) -> usize {
        self.object_body_write_report().objects()
    }

    /// Returns the destination object-generation preflight report.
    pub const fn object_generation_write_report(
        self,
    ) -> AllocationCollectorPollObjectGenerationWriteReport {
        self.object_body_and_generation_write_report
            .generation_write_report()
    }

    /// Returns how many destination object generations were covered by the preflight.
    pub const fn object_generation_preflight_objects(self) -> usize {
        self.object_generation_write_report().objects()
    }

    /// Returns the heap-field writeback plan report.
    pub const fn heap_field_writeback_report(
        self,
    ) -> EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport {
        self.heap_field_writeback_report
    }

    /// Returns how many supported heap fields are covered by the preflight.
    pub const fn fields(self) -> usize {
        self.heap_field_writeback_report.fields()
    }
}

/// Counts for live object-body/generation writes plus supported reference rewrites.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveReferenceWritebackApplyReport {
    object_body_and_generation_write_report:
        AllocationCollectorPollObjectBodyAndGenerationWriteReport,
    outcome_root_writeback_report: EvalGcStressBoundaryMinorGcOutcomeRootWritebackReport,
    heap_field_writeback_report: EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport,
}

impl EvalGcStressBoundaryMinorGcLiveReferenceWritebackApplyReport {
    const fn new(
        object_body_and_generation_write_report:
            AllocationCollectorPollObjectBodyAndGenerationWriteReport,
        outcome_root_writeback_report: EvalGcStressBoundaryMinorGcOutcomeRootWritebackReport,
        heap_field_writeback_report: EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport,
    ) -> Self {
        Self {
            object_body_and_generation_write_report,
            outcome_root_writeback_report,
            heap_field_writeback_report,
        }
    }

    /// Returns the paired object-body and object-generation write report.
    pub const fn object_body_and_generation_write_report(
        self,
    ) -> AllocationCollectorPollObjectBodyAndGenerationWriteReport {
        self.object_body_and_generation_write_report
    }

    /// Returns the destination object-body write report.
    pub const fn object_body_write_report(self) -> AllocationCollectorPollObjectBodyWriteReport {
        self.object_body_and_generation_write_report
            .body_write_report()
    }

    /// Returns how many destination object bodies were written.
    pub const fn object_bodies_written(self) -> usize {
        self.object_body_write_report().objects()
    }

    /// Returns the destination object-generation write report.
    pub const fn object_generation_write_report(
        self,
    ) -> AllocationCollectorPollObjectGenerationWriteReport {
        self.object_body_and_generation_write_report
            .generation_write_report()
    }

    /// Returns how many destination object generations were written.
    pub const fn object_generations_written(self) -> usize {
        self.object_generation_write_report().objects()
    }

    /// Returns the outcome-root writeback report.
    pub const fn outcome_root_writeback_report(
        self,
    ) -> EvalGcStressBoundaryMinorGcOutcomeRootWritebackReport {
        self.outcome_root_writeback_report
    }

    /// Returns how many outcome-owned value-stack roots were rewritten.
    pub const fn value_stack_roots(self) -> usize {
        self.outcome_root_writeback_report.value_stack_roots()
    }

    /// Returns how many outcome-owned roots were rewritten.
    pub const fn roots(self) -> usize {
        self.outcome_root_writeback_report.roots()
    }

    /// Returns the heap-field writeback report.
    pub const fn heap_field_writeback_report(
        self,
    ) -> EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport {
        self.heap_field_writeback_report
    }

    /// Returns how many heap fields were rewritten.
    pub const fn fields(self) -> usize {
        self.heap_field_writeback_report.fields()
    }

    /// Returns how many supported references were rewritten.
    pub const fn references(self) -> usize {
        self.roots().saturating_add(self.fields())
    }
}

/// Counts for prevalidated live object and reference writebacks.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveReferenceWritebackPreflightReport {
    object_body_and_generation_write_report:
        AllocationCollectorPollObjectBodyAndGenerationWriteReport,
    root_writeback_report: EvalGcStressBoundaryMinorGcRootWritebackWritePlanReport,
    heap_field_writeback_report: EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport,
}

impl EvalGcStressBoundaryMinorGcLiveReferenceWritebackPreflightReport {
    const fn new(
        object_body_and_generation_write_report:
            AllocationCollectorPollObjectBodyAndGenerationWriteReport,
        root_writeback_report: EvalGcStressBoundaryMinorGcRootWritebackWritePlanReport,
        heap_field_writeback_report: EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport,
    ) -> Self {
        Self {
            object_body_and_generation_write_report,
            root_writeback_report,
            heap_field_writeback_report,
        }
    }

    /// Returns the paired object-body and object-generation preflight report.
    pub const fn object_body_and_generation_write_report(
        self,
    ) -> AllocationCollectorPollObjectBodyAndGenerationWriteReport {
        self.object_body_and_generation_write_report
    }

    /// Returns the destination object-body preflight report.
    pub const fn object_body_write_report(self) -> AllocationCollectorPollObjectBodyWriteReport {
        self.object_body_and_generation_write_report
            .body_write_report()
    }

    /// Returns how many destination object bodies were covered by the preflight.
    pub const fn object_body_preflight_objects(self) -> usize {
        self.object_body_write_report().objects()
    }

    /// Returns the destination object-generation preflight report.
    pub const fn object_generation_write_report(
        self,
    ) -> AllocationCollectorPollObjectGenerationWriteReport {
        self.object_body_and_generation_write_report
            .generation_write_report()
    }

    /// Returns how many destination object generations were covered by the preflight.
    pub const fn object_generation_preflight_objects(self) -> usize {
        self.object_generation_write_report().objects()
    }

    /// Returns the root writeback plan report.
    pub const fn root_writeback_report(
        self,
    ) -> EvalGcStressBoundaryMinorGcRootWritebackWritePlanReport {
        self.root_writeback_report
    }

    /// Returns how many supported roots are covered by the preflight.
    pub const fn roots(self) -> usize {
        self.root_writeback_report.roots()
    }

    /// Returns the heap-field writeback plan report.
    pub const fn heap_field_writeback_report(
        self,
    ) -> EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport {
        self.heap_field_writeback_report
    }

    /// Returns how many supported heap fields are covered by the preflight.
    pub const fn fields(self) -> usize {
        self.heap_field_writeback_report.fields()
    }

    /// Returns how many supported references are covered by the preflight.
    pub const fn references(self) -> usize {
        self.roots().saturating_add(self.fields())
    }
}

/// Counts for a read-only existing-destination live commit preflight.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveExistingDestinationCommitPreflightReport {
    forwarding_header_write_plan_report: EvalGcStressBoundaryMinorGcForwardingHeaderWritePlanReport,
    reference_writeback_preflight_report:
        EvalGcStressBoundaryMinorGcLiveReferenceWritebackPreflightReport,
}

impl EvalGcStressBoundaryMinorGcLiveExistingDestinationCommitPreflightReport {
    const fn new(
        forwarding_header_write_plan_report:
            EvalGcStressBoundaryMinorGcForwardingHeaderWritePlanReport,
        reference_writeback_preflight_report:
            EvalGcStressBoundaryMinorGcLiveReferenceWritebackPreflightReport,
    ) -> Self {
        Self {
            forwarding_header_write_plan_report,
            reference_writeback_preflight_report,
        }
    }

    /// Returns the forwarding-header write-plan report.
    pub const fn forwarding_header_write_plan_report(
        self,
    ) -> EvalGcStressBoundaryMinorGcForwardingHeaderWritePlanReport {
        self.forwarding_header_write_plan_report
    }

    /// Returns how many forwarding headers are covered by the preflight.
    pub const fn forwarding_headers(self) -> usize {
        self.forwarding_header_write_plan_report.headers()
    }

    /// Returns how many forwarding headers point to next-nursery objects.
    pub const fn forwarding_headers_copied_to_nursery(self) -> usize {
        self.forwarding_header_write_plan_report.copied_to_nursery()
    }

    /// Returns how many forwarding headers point to promoted old objects.
    pub const fn forwarding_headers_promoted_to_old(self) -> usize {
        self.forwarding_header_write_plan_report.promoted_to_old()
    }

    /// Returns the payload bytes covered by forwarding-header metadata.
    pub const fn forwarding_header_payload_bytes(self) -> usize {
        self.forwarding_header_write_plan_report.payload_bytes()
    }

    /// Returns the live reference writeback preflight report.
    pub const fn reference_writeback_preflight_report(
        self,
    ) -> EvalGcStressBoundaryMinorGcLiveReferenceWritebackPreflightReport {
        self.reference_writeback_preflight_report
    }

    /// Returns the paired object-body and object-generation preflight report.
    pub const fn object_body_and_generation_write_report(
        self,
    ) -> AllocationCollectorPollObjectBodyAndGenerationWriteReport {
        self.reference_writeback_preflight_report
            .object_body_and_generation_write_report()
    }

    /// Returns how many destination object bodies were covered by the preflight.
    pub const fn object_body_preflight_objects(self) -> usize {
        self.reference_writeback_preflight_report
            .object_body_preflight_objects()
    }

    /// Returns how many destination object generations were covered by the preflight.
    pub const fn object_generation_preflight_objects(self) -> usize {
        self.reference_writeback_preflight_report
            .object_generation_preflight_objects()
    }

    /// Returns how many supported roots are covered by the preflight.
    pub const fn roots(self) -> usize {
        self.reference_writeback_preflight_report.roots()
    }

    /// Returns how many supported heap fields are covered by the preflight.
    pub const fn fields(self) -> usize {
        self.reference_writeback_preflight_report.fields()
    }

    /// Returns how many supported references are covered by the preflight.
    pub const fn references(self) -> usize {
        self.reference_writeback_preflight_report.references()
    }
}

/// Counts for validated forwarding metadata plus committed live reference writes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcLiveExistingDestinationCommitApplyReport {
    forwarding_header_write_plan_report: EvalGcStressBoundaryMinorGcForwardingHeaderWritePlanReport,
    reference_writeback_apply_report: EvalGcStressBoundaryMinorGcLiveReferenceWritebackApplyReport,
    remembered_set_published_edges: usize,
    card_table_clear_report: GcCardTableClearReport,
}

impl EvalGcStressBoundaryMinorGcLiveExistingDestinationCommitApplyReport {
    const fn new(
        forwarding_header_write_plan_report:
            EvalGcStressBoundaryMinorGcForwardingHeaderWritePlanReport,
        reference_writeback_apply_report:
            EvalGcStressBoundaryMinorGcLiveReferenceWritebackApplyReport,
        remembered_set_published_edges: usize,
        card_table_clear_report: GcCardTableClearReport,
    ) -> Self {
        Self {
            forwarding_header_write_plan_report,
            reference_writeback_apply_report,
            remembered_set_published_edges,
            card_table_clear_report,
        }
    }

    /// Returns the forwarding-header write-plan report that was validated.
    pub const fn forwarding_header_write_plan_report(
        self,
    ) -> EvalGcStressBoundaryMinorGcForwardingHeaderWritePlanReport {
        self.forwarding_header_write_plan_report
    }

    /// Returns how many forwarding headers were validated.
    pub const fn forwarding_headers_validated(self) -> usize {
        self.forwarding_header_write_plan_report.headers()
    }

    /// Returns how many validated forwarding headers point to next-nursery objects.
    pub const fn forwarding_headers_copied_to_nursery(self) -> usize {
        self.forwarding_header_write_plan_report.copied_to_nursery()
    }

    /// Returns how many validated forwarding headers point to promoted old objects.
    pub const fn forwarding_headers_promoted_to_old(self) -> usize {
        self.forwarding_header_write_plan_report.promoted_to_old()
    }

    /// Returns the payload bytes covered by validated forwarding-header metadata.
    pub const fn forwarding_header_payload_bytes(self) -> usize {
        self.forwarding_header_write_plan_report.payload_bytes()
    }

    /// Returns the live reference writeback apply report.
    pub const fn reference_writeback_apply_report(
        self,
    ) -> EvalGcStressBoundaryMinorGcLiveReferenceWritebackApplyReport {
        self.reference_writeback_apply_report
    }

    /// Returns the paired object-body and object-generation write report.
    pub const fn object_body_and_generation_write_report(
        self,
    ) -> AllocationCollectorPollObjectBodyAndGenerationWriteReport {
        self.reference_writeback_apply_report
            .object_body_and_generation_write_report()
    }

    /// Returns the destination object-body write report.
    pub const fn object_body_write_report(self) -> AllocationCollectorPollObjectBodyWriteReport {
        self.reference_writeback_apply_report
            .object_body_write_report()
    }

    /// Returns how many destination object bodies were written.
    pub const fn object_bodies_written(self) -> usize {
        self.reference_writeback_apply_report
            .object_bodies_written()
    }

    /// Returns the destination object-generation write report.
    pub const fn object_generation_write_report(
        self,
    ) -> AllocationCollectorPollObjectGenerationWriteReport {
        self.reference_writeback_apply_report
            .object_generation_write_report()
    }

    /// Returns how many destination object generations were written.
    pub const fn object_generations_written(self) -> usize {
        self.reference_writeback_apply_report
            .object_generations_written()
    }

    /// Returns the outcome-root writeback report.
    pub const fn outcome_root_writeback_report(
        self,
    ) -> EvalGcStressBoundaryMinorGcOutcomeRootWritebackReport {
        self.reference_writeback_apply_report
            .outcome_root_writeback_report()
    }

    /// Returns how many outcome-owned value-stack roots were rewritten.
    pub const fn value_stack_roots(self) -> usize {
        self.reference_writeback_apply_report.value_stack_roots()
    }

    /// Returns how many outcome-owned roots were rewritten.
    pub const fn roots(self) -> usize {
        self.reference_writeback_apply_report.roots()
    }

    /// Returns the heap-field writeback report.
    pub const fn heap_field_writeback_report(
        self,
    ) -> EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport {
        self.reference_writeback_apply_report
            .heap_field_writeback_report()
    }

    /// Returns how many heap fields were rewritten.
    pub const fn fields(self) -> usize {
        self.reference_writeback_apply_report.fields()
    }

    /// Returns how many supported references were rewritten.
    pub const fn references(self) -> usize {
        self.reference_writeback_apply_report.references()
    }

    /// Returns the number of remembered edges kept published for the next epoch.
    pub const fn remembered_set_published_edges(self) -> usize {
        self.remembered_set_published_edges
    }

    /// Returns the report for the post-reference live card-table clear.
    pub const fn card_table_clear_report(self) -> GcCardTableClearReport {
        self.card_table_clear_report
    }

    /// Returns how many dirty-card markers were cleared from live outcome state.
    pub const fn card_table_dirty_cards_cleared(self) -> usize {
        self.card_table_clear_report.dirty_cards()
    }
}

/// Result of running the existing-destination live commit bridge end to end.
///
/// This report keeps the strict existing-destination metadata installation next
/// to the subsequent live reference commit. The operation is still a
/// tree-walk/GC-stress bridge: it requires destination records that already
/// exist in the evaluator heap, and it does not allocate synthetic destinations,
/// reserve semispace storage, write ABI forwarding headers, mutate active
/// evaluator frames or import caches, update JIT stack maps, or invoke Tier B.
/// The report is returned only when both phases complete; it does not represent
/// a rollback token for metadata installed before a later commit error.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcExistingDestinationLiveCommit {
    live_metadata: EvalGcStressBoundaryMinorGcExistingDestinationLiveMetadataCommitDryRun,
    live_commit: EvalGcStressBoundaryMinorGcLiveExistingDestinationCommitApplyReport,
}

impl EvalGcStressBoundaryMinorGcExistingDestinationLiveCommit {
    const fn new(
        live_metadata: EvalGcStressBoundaryMinorGcExistingDestinationLiveMetadataCommitDryRun,
        live_commit: EvalGcStressBoundaryMinorGcLiveExistingDestinationCommitApplyReport,
    ) -> Self {
        Self {
            live_metadata,
            live_commit,
        }
    }

    /// Returns the strict existing-destination metadata installation report.
    pub const fn live_metadata(
        &self,
    ) -> &EvalGcStressBoundaryMinorGcExistingDestinationLiveMetadataCommitDryRun {
        &self.live_metadata
    }

    /// Returns the applied live reference commit report.
    pub const fn live_commit(
        &self,
    ) -> EvalGcStressBoundaryMinorGcLiveExistingDestinationCommitApplyReport {
        self.live_commit
    }

    /// Returns how many forwarding values were installed by the metadata phase.
    pub const fn forwarding_pointers_installed(&self) -> usize {
        self.live_metadata
            .live_metadata()
            .forwarding_pointers_installed()
    }

    /// Returns how many destination object bodies were written by the commit phase.
    pub const fn object_bodies_written(&self) -> usize {
        self.live_commit.object_bodies_written()
    }

    /// Returns how many destination object generations were written by the commit phase.
    pub const fn object_generations_written(&self) -> usize {
        self.live_commit.object_generations_written()
    }

    /// Returns how many outcome-owned value-stack roots were rewritten.
    pub const fn value_stack_roots(&self) -> usize {
        self.live_commit.value_stack_roots()
    }

    /// Returns how many live heap fields were rewritten.
    pub const fn fields(&self) -> usize {
        self.live_commit.fields()
    }

    /// Returns how many supported references were rewritten.
    pub const fn references(&self) -> usize {
        self.live_commit.references()
    }

    /// Returns how many dirty-card markers were cleared after live field writes.
    pub const fn card_table_dirty_cards_cleared(&self) -> usize {
        self.live_commit.card_table_dirty_cards_cleared()
    }
}

/// One validated live heap-field writeback input.
///
/// This is an immutable write plan for a future object-field writer. It proves
/// that an installed heap-field writeback slot still matches an installed field
/// destination binding, including replacement destination bytes and, when the
/// field belongs to a copied nursery survivor, the relocated writeback object's
/// destination bytes. It does not mutate evaluator object fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcHeapFieldWritebackWrite {
    allocation_domain: HeapAllocationDomain,
    validation_object: GcHeapAddress,
    writeback_object: GcHeapAddress,
    field_index: usize,
    source: HeapEdgeSource,
    replacement_destination: GcHeapAddress,
    replacement_generation: HeapGeneration,
    replacement_metadata: ResolvedValueGeneration,
    replacement_request: AllocationCollectorPollObjectByteCopyRequest,
    replacement_destination_bytes: Vec<u8>,
    writeback_object_request: Option<AllocationCollectorPollObjectByteCopyRequest>,
    writeback_object_destination_bytes: Option<Vec<u8>>,
}

impl EvalGcStressBoundaryMinorGcHeapFieldWritebackWrite {
    fn from_source_and_binding(
        source: BoundaryMinorGcHeapFieldWritebackWriteSource,
        binding: &EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding,
    ) -> Result<Self, EvalHeapError> {
        Ok(Self {
            allocation_domain: source.allocation_domain,
            validation_object: source.validation_object,
            writeback_object: source.writeback_object,
            field_index: source.field_index,
            source: source.source,
            replacement_destination: source.replacement_destination,
            replacement_generation: source.replacement_generation,
            replacement_metadata: source.replacement_metadata,
            replacement_request: binding.replacement_request(),
            replacement_destination_bytes: clone_boundary_destination_storage_bytes(
                BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_WRITE_BYTES_TABLE,
                binding.replacement_destination_bytes(),
            )?,
            writeback_object_request: binding.writeback_object_request(),
            writeback_object_destination_bytes: binding
                .writeback_object_destination_bytes()
                .map(|bytes| {
                    clone_boundary_destination_storage_bytes(
                        BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_WRITE_BYTES_TABLE,
                        bytes,
                    )
                })
                .transpose()?,
        })
    }

    /// Returns the allocator domain assigned to the heap-field source.
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

    /// Returns the generation-style replacement metadata paired with the field.
    pub const fn replacement_metadata(&self) -> ResolvedValueGeneration {
        self.replacement_metadata
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

/// A validated live heap-field writeback write plan.
///
/// The plan is derived from installed live reference-writeback metadata and
/// installed writeback-destination bindings. It is a checked input set for a
/// live heap-field bridge or future broader live object-field writer; creating
/// it does not write fields, copy object bodies, or bind destination bytes to
/// heap storage.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan {
    report: EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport,
    writes: Vec<EvalGcStressBoundaryMinorGcHeapFieldWritebackWrite>,
}

impl EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan {
    fn new(writes: Vec<EvalGcStressBoundaryMinorGcHeapFieldWritebackWrite>) -> Self {
        let mut report = EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport::default();
        for write in &writes {
            report.record(write);
        }
        Self { report, writes }
    }

    /// Returns whether this plan has no heap-field writes.
    pub fn is_empty(&self) -> bool {
        self.writes.is_empty()
    }

    /// Returns how many heap-field writes are planned.
    pub fn len(&self) -> usize {
        self.writes.len()
    }

    /// Returns aggregate counts for the plan.
    pub const fn report(&self) -> EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport {
        self.report
    }

    /// Returns the planned live heap-field writes.
    pub fn writes(&self) -> &[EvalGcStressBoundaryMinorGcHeapFieldWritebackWrite] {
        &self.writes
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

/// Boundary-owned storage application for one minor-GC commit preflight.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcOwnedStorageCommitApplication {
    report: MinorGcCommitReport,
    destination_storage: EvalGcStressBoundaryMinorGcDestinationStorageApplication,
    forwarding_slots: Vec<MinorGcForwardingSlot>,
    references: Vec<ResolvedValueGeneration>,
    remembered_set: RememberedSet,
    card_table: GcCardTable,
}

impl EvalGcStressBoundaryMinorGcOwnedStorageCommitApplication {
    fn new(
        report: MinorGcCommitReport,
        destination_storage: EvalGcStressBoundaryMinorGcDestinationStorageApplication,
        forwarding_slots: Vec<MinorGcForwardingSlot>,
        references: Vec<ResolvedValueGeneration>,
        remembered_set: RememberedSet,
        card_table: GcCardTable,
    ) -> Self {
        Self {
            report,
            destination_storage,
            forwarding_slots,
            references,
            remembered_set,
            card_table,
        }
    }

    /// Returns the lower-level commit counts for the owned-storage application.
    pub const fn report(&self) -> MinorGcCommitReport {
        self.report
    }

    /// Returns the owned destination storage snapshot after commit application.
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

    /// Returns the remembered set after publication into the owned buffer.
    pub const fn remembered_set(&self) -> &RememberedSet {
        &self.remembered_set
    }

    /// Returns the owned daemon card-table copy after commit application.
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

fn boundary_minor_gc_object_source_byte_storage(
    plan: &AllocationCollectorPollObjectByteCopyPlan,
) -> Result<Vec<Vec<u8>>, EvalHeapError> {
    let requests = plan.requests();
    let mut sources = Vec::new();
    sources.try_reserve_exact(requests.len()).map_err(|_| {
        EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_OBJECT_SOURCE_BYTES_TABLE,
            entries: requests.len(),
        }
    })?;
    for (index, request) in requests.iter().copied().enumerate() {
        sources.push(boundary_minor_gc_object_source_bytes(
            index,
            request.size_bytes(),
        )?);
    }
    Ok(sources)
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

fn boundary_minor_gc_destination_storage_application_from_storage(
    copy_report: MinorGcOwnedDestinationStorageCopyReport,
    storage: &MinorGcOwnedDestinationStorage,
) -> Result<EvalGcStressBoundaryMinorGcDestinationStorageApplication, EvalHeapError> {
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
    boundary_minor_gc_destination_storage_application_from_storage(copy_report, &storage)
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

fn boundary_minor_gc_source_object_bytes_from_storage<'a>(
    plan: &AllocationCollectorPollObjectByteCopyPlan,
    source_byte_storage: &'a [Vec<u8>],
) -> Result<Vec<MinorGcSourceObjectBytes<'a>>, EvalHeapError> {
    let requests = plan.requests();
    if source_byte_storage.len() != requests.len() {
        return Err(GenerationalGcError::MinorGcSourceObjectBytesCountMismatch {
            copies: requests.len(),
            sources: source_byte_storage.len(),
        }
        .into());
    }
    let mut sources = Vec::new();
    sources.try_reserve_exact(requests.len()).map_err(|_| {
        EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_SOURCE_OBJECT_BYTES_TABLE,
            entries: requests.len(),
        }
    })?;
    for (request, source_bytes) in requests.iter().copied().zip(source_byte_storage) {
        sources.push(MinorGcSourceObjectBytes::new(
            request.source(),
            source_bytes.as_slice(),
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

fn live_object_generation_install_report(
    object_generations: &[EvalGcStressBoundaryMinorGcLiveObjectGeneration],
) -> EvalGcStressBoundaryMinorGcLiveObjectGenerationInstallReport {
    let mut report = EvalGcStressBoundaryMinorGcLiveObjectGenerationInstallReport::default();
    for generation in object_generations {
        report.record(generation);
    }
    report
}

fn live_forwarding_destination_binding_install_report(
    forwarding_destination_bindings: &[EvalGcStressBoundaryMinorGcForwardingDestinationBinding],
) -> EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingInstallReport {
    EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingInstallReport::new(
        forwarding_destination_bindings.len(),
    )
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

fn live_writeback_destination_binding_install_report(
    root_writeback_bindings: &[EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding],
    heap_field_writeback_bindings: &[EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding],
) -> EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindingInstallReport {
    EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindingInstallReport::new(
        root_writeback_bindings.len(),
        heap_field_writeback_bindings.len(),
    )
}

fn boundary_minor_gc_destination_object_generation_bindings(
    destination_storage: &EvalGcStressBoundaryMinorGcLiveDestinationStorage,
) -> Result<Vec<EvalGcStressBoundaryMinorGcDestinationObjectGenerationBinding>, EvalHeapError> {
    boundary_minor_gc_destination_object_generation_bindings_from_objects(
        destination_storage.object_bytes(),
    )
}

fn boundary_minor_gc_live_object_generations_from_objects(
    destination_objects: &[EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes],
) -> Result<Vec<EvalGcStressBoundaryMinorGcLiveObjectGeneration>, EvalHeapError> {
    validate_boundary_minor_gc_destination_generation_objects(destination_objects)?;
    let mut object_generations = Vec::new();
    object_generations
        .try_reserve_exact(destination_objects.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_LIVE_OBJECT_GENERATIONS_TABLE,
            entries: destination_objects.len(),
        })?;

    for object in destination_objects {
        let generation = validated_destination_object_generation(object)?;
        object_generations.push(EvalGcStressBoundaryMinorGcLiveObjectGeneration::new(
            object.source(),
            object.destination(),
            object.request().action(),
            generation,
            object.request(),
        ));
    }

    Ok(object_generations)
}

fn boundary_minor_gc_object_body_generation_preflight_plan_from_generations(
    object_generations: &[EvalGcStressBoundaryMinorGcLiveObjectGeneration],
) -> Result<AllocationCollectorPollObjectByteCopyPlan, EvalHeapError> {
    let mut requests = Vec::new();
    requests
        .try_reserve_exact(object_generations.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_OBJECT_BODY_GENERATION_PREFLIGHT_REQUESTS_TABLE,
            entries: object_generations.len(),
        })?;

    for generation in object_generations {
        requests.push(generation.request());
    }

    Ok(AllocationCollectorPollObjectByteCopyPlan::from_requests(
        requests,
    ))
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

fn boundary_minor_gc_object_generation_write_plan(
    destination_storage: &EvalGcStressBoundaryMinorGcLiveDestinationStorage,
    live_object_generations: &EvalGcStressBoundaryMinorGcLiveObjectGenerations,
) -> Result<EvalGcStressBoundaryMinorGcObjectGenerationWritePlan, EvalHeapError> {
    let bindings = boundary_minor_gc_destination_object_generation_bindings(destination_storage)?;
    let generations = live_object_generations.object_generations();
    validate_boundary_minor_gc_object_generation_write_generations(generations)?;
    validate_boundary_minor_gc_object_generation_write_bindings(&bindings)?;

    let mut writes = Vec::new();
    writes.try_reserve_exact(generations.len()).map_err(|_| {
        EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_OBJECT_GENERATION_WRITES_TABLE,
            entries: generations.len(),
        }
    })?;

    for generation in generations {
        let Some(binding) = bindings
            .iter()
            .find(|binding| binding.source() == generation.source())
        else {
            return Err(
                EvalHeapError::BoundaryMinorGcObjectGenerationWriteMissingDestination {
                    source_address: generation.source(),
                    destination: generation.destination(),
                    action: generation.action(),
                    generation: generation.generation(),
                },
            );
        };

        if !object_generation_write_generation_matches_binding(generation, binding) {
            return Err(
                EvalHeapError::BoundaryMinorGcObjectGenerationWriteBindingMismatch {
                    source_address: generation.source(),
                    expected: generation.request(),
                    expected_generation: generation.generation(),
                    actual: binding.request(),
                    actual_generation: binding.generation(),
                },
            );
        }

        writes.push(
            EvalGcStressBoundaryMinorGcObjectGenerationWrite::from_generation_and_binding(
                generation, binding,
            )?,
        );
    }

    for binding in &bindings {
        if !writes
            .iter()
            .any(|write| object_generation_write_matches_binding(write, binding))
        {
            return Err(
                EvalHeapError::BoundaryMinorGcObjectGenerationWriteUnboundDestination {
                    source_address: binding.source(),
                    destination: binding.destination(),
                    action: binding.action(),
                    generation: binding.generation(),
                },
            );
        }
    }

    Ok(EvalGcStressBoundaryMinorGcObjectGenerationWritePlan::new(
        writes,
    ))
}

fn validate_boundary_minor_gc_object_generation_write_generations(
    generations: &[EvalGcStressBoundaryMinorGcLiveObjectGeneration],
) -> Result<(), EvalHeapError> {
    for (index, generation) in generations.iter().enumerate() {
        if generations[..index]
            .iter()
            .any(|existing| existing.source() == generation.source())
        {
            return Err(
                EvalHeapError::BoundaryMinorGcObjectGenerationWriteDuplicateSource {
                    index,
                    source_address: generation.source(),
                },
            );
        }
        if let Some(existing) = generations[..index]
            .iter()
            .find(|existing| existing.destination() == generation.destination())
        {
            return Err(
                EvalHeapError::BoundaryMinorGcObjectGenerationWriteDuplicateDestination {
                    index,
                    source_address: generation.source(),
                    existing_source_address: existing.source(),
                    destination: generation.destination(),
                },
            );
        }

        let request = generation.request();
        if request.source() != generation.source() {
            return Err(
                EvalHeapError::BoundaryMinorGcObjectGenerationWriteRequestSourceMismatch {
                    source_address: generation.source(),
                    request_source: request.source(),
                },
            );
        }
        if request.destination() != generation.destination() {
            return Err(
                EvalHeapError::BoundaryMinorGcObjectGenerationWriteRequestDestinationMismatch {
                    source_address: generation.source(),
                    generation_destination: generation.destination(),
                    request_destination: request.destination(),
                },
            );
        }
        if request.action() != generation.action() {
            return Err(
                EvalHeapError::BoundaryMinorGcObjectGenerationWriteRequestActionMismatch {
                    source_address: generation.source(),
                    destination: generation.destination(),
                    generation_action: generation.action(),
                    request_action: request.action(),
                },
            );
        }

        let expected_generation = validated_destination_request_generation(request)?;
        if generation.generation() != expected_generation {
            return Err(
                EvalHeapError::BoundaryMinorGcObjectGenerationWriteGenerationMismatch {
                    source_address: generation.source(),
                    destination: generation.destination(),
                    expected: expected_generation,
                    actual: generation.generation(),
                    action: request.action(),
                },
            );
        }
    }

    Ok(())
}

fn validate_boundary_minor_gc_object_generation_write_bindings(
    bindings: &[EvalGcStressBoundaryMinorGcDestinationObjectGenerationBinding],
) -> Result<(), EvalHeapError> {
    for (index, binding) in bindings.iter().enumerate() {
        if bindings[..index]
            .iter()
            .any(|existing| existing.source() == binding.source())
        {
            return Err(
                EvalHeapError::BoundaryMinorGcObjectGenerationWriteDuplicateDestinationSource {
                    index,
                    source_address: binding.source(),
                },
            );
        }
    }

    Ok(())
}

fn object_generation_write_generation_matches_binding(
    generation: &EvalGcStressBoundaryMinorGcLiveObjectGeneration,
    binding: &EvalGcStressBoundaryMinorGcDestinationObjectGenerationBinding,
) -> bool {
    generation.source() == binding.source()
        && generation.destination() == binding.destination()
        && generation.action() == binding.action()
        && generation.generation() == binding.generation()
        && generation.request() == binding.request()
}

fn object_generation_write_matches_binding(
    write: &EvalGcStressBoundaryMinorGcObjectGenerationWrite,
    binding: &EvalGcStressBoundaryMinorGcDestinationObjectGenerationBinding,
) -> bool {
    write.source() == binding.source()
        && write.destination() == binding.destination()
        && write.action() == binding.action()
        && write.generation() == binding.generation()
        && write.request() == binding.request()
}

fn apply_boundary_minor_gc_live_object_bodies(
    heap: &mut EvalHeap,
    plan: &EvalGcStressBoundaryMinorGcObjectGenerationWritePlan,
) -> Result<AllocationCollectorPollObjectBodyWriteReport, EvalHeapError> {
    let heap_plan = boundary_minor_gc_object_body_heap_write_plan(plan)?;
    let report = heap.apply_collector_poll_minor_gc_object_body_writes(&heap_plan)?;
    debug_assert_eq!(report.objects(), plan.report().objects());
    debug_assert_eq!(
        report.copied_to_nursery(),
        plan.report().copied_to_nursery()
    );
    debug_assert_eq!(report.promoted_to_old(), plan.report().promoted_to_old());
    debug_assert_eq!(report.payload_bytes(), plan.report().payload_bytes());
    Ok(report)
}

fn apply_boundary_minor_gc_live_object_generations(
    heap: &mut EvalHeap,
    plan: &EvalGcStressBoundaryMinorGcObjectGenerationWritePlan,
) -> Result<AllocationCollectorPollObjectGenerationWriteReport, EvalHeapError> {
    let heap_plan = boundary_minor_gc_object_generation_heap_write_plan(plan)?;
    let report = heap.apply_collector_poll_minor_gc_object_generation_writes(&heap_plan)?;
    debug_assert_eq!(report.objects(), plan.report().objects());
    debug_assert_eq!(
        report.copied_to_nursery(),
        plan.report().copied_to_nursery()
    );
    debug_assert_eq!(report.promoted_to_old(), plan.report().promoted_to_old());
    debug_assert_eq!(report.payload_bytes(), plan.report().payload_bytes());
    Ok(report)
}

fn apply_boundary_minor_gc_live_object_bodies_and_generations(
    heap: &mut EvalHeap,
    plan: &EvalGcStressBoundaryMinorGcObjectGenerationWritePlan,
) -> Result<AllocationCollectorPollObjectBodyAndGenerationWriteReport, EvalHeapError> {
    let heap_plan = boundary_minor_gc_object_body_heap_write_plan(plan)?;
    let report =
        heap.apply_collector_poll_minor_gc_object_body_and_generation_writes(&heap_plan)?;
    debug_assert_eq!(
        report.body_write_report().objects(),
        plan.report().objects()
    );
    debug_assert_eq!(
        report.generation_write_report().objects(),
        plan.report().objects()
    );
    debug_assert_eq!(
        report.body_write_report().payload_bytes(),
        plan.report().payload_bytes()
    );
    debug_assert_eq!(
        report.generation_write_report().payload_bytes(),
        plan.report().payload_bytes()
    );
    Ok(report)
}

fn validate_boundary_minor_gc_live_object_bodies_and_generations(
    heap: &EvalHeap,
    plan: &EvalGcStressBoundaryMinorGcObjectGenerationWritePlan,
) -> Result<AllocationCollectorPollObjectBodyAndGenerationWriteReport, EvalHeapError> {
    let heap_plan = boundary_minor_gc_object_body_heap_write_plan(plan)?;
    let report =
        heap.validate_collector_poll_minor_gc_object_body_and_generation_writes(&heap_plan)?;
    debug_assert_eq!(
        report.body_write_report().objects(),
        plan.report().objects()
    );
    debug_assert_eq!(
        report.generation_write_report().objects(),
        plan.report().objects()
    );
    debug_assert_eq!(
        report.body_write_report().payload_bytes(),
        plan.report().payload_bytes()
    );
    debug_assert_eq!(
        report.generation_write_report().payload_bytes(),
        plan.report().payload_bytes()
    );
    Ok(report)
}

fn boundary_minor_gc_object_body_heap_write_plan(
    plan: &EvalGcStressBoundaryMinorGcObjectGenerationWritePlan,
) -> Result<AllocationCollectorPollObjectByteCopyPlan, EvalHeapError> {
    let mut requests = Vec::new();
    requests
        .try_reserve_exact(plan.writes().len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_OBJECT_GENERATION_WRITES_TABLE,
            entries: plan.writes().len(),
        })?;
    requests.extend(plan.writes().iter().map(|write| write.request()));
    Ok(AllocationCollectorPollObjectByteCopyPlan::from_requests(
        requests,
    ))
}

fn boundary_minor_gc_object_generation_heap_write_plan(
    plan: &EvalGcStressBoundaryMinorGcObjectGenerationWritePlan,
) -> Result<AllocationCollectorPollObjectGenerationWritePlan, EvalHeapError> {
    boundary_minor_gc_object_body_heap_write_plan(plan)?.object_generation_write_plan()
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

fn boundary_minor_gc_forwarding_destination_bindings(
    heap: &EvalHeap,
    destination_storage: &EvalGcStressBoundaryMinorGcLiveDestinationStorage,
) -> Result<Vec<EvalGcStressBoundaryMinorGcForwardingDestinationBinding>, EvalHeapError> {
    boundary_minor_gc_forwarding_destination_bindings_from_heap_and_slots(
        heap,
        &[],
        destination_storage.object_bytes(),
    )
}

fn boundary_minor_gc_forwarding_destination_bindings_from_heap_and_slots(
    heap: &EvalHeap,
    forwarding_slots: &[MinorGcForwardingSlot],
    destination_objects: &[EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes],
) -> Result<Vec<EvalGcStressBoundaryMinorGcForwardingDestinationBinding>, EvalHeapError> {
    let forwarding_values = heap.minor_gc_forwarding_values()?;
    let combined_len = forwarding_values
        .len()
        .checked_add(forwarding_slots.len())
        .ok_or(EvalHeapError::RootScanLengthOverflow {
            table: BOUNDARY_MINOR_GC_FORWARDING_DESTINATION_BINDINGS_TABLE,
        })?;
    let mut combined_slots = Vec::new();
    combined_slots
        .try_reserve_exact(combined_len)
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_FORWARDING_DESTINATION_BINDINGS_TABLE,
            entries: combined_len,
        })?;

    for forwarding_value in forwarding_values {
        combined_slots.push(MinorGcForwardingSlot::with_forwarded_value(
            forwarding_value.source(),
            forwarding_value.forwarded_value(),
        ));
    }
    combined_slots.extend_from_slice(forwarding_slots);

    boundary_minor_gc_forwarding_destination_bindings_from_slots(
        &combined_slots,
        destination_objects,
    )
}

fn boundary_minor_gc_forwarding_destination_bindings_from_slots(
    forwarding_slots: &[MinorGcForwardingSlot],
    destination_objects: &[EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes],
) -> Result<Vec<EvalGcStressBoundaryMinorGcForwardingDestinationBinding>, EvalHeapError> {
    validate_boundary_minor_gc_destination_generation_objects(destination_objects)?;
    for object in destination_objects {
        if !forwarding_slots
            .iter()
            .any(|slot| slot.source() == object.source())
        {
            return Err(EvalHeapError::BoundaryMinorGcDestinationForwardingMissing {
                source_address: object.source(),
                destination: object.destination(),
            });
        }
    }

    validate_boundary_minor_gc_forwarding_slot_sources(forwarding_slots, destination_objects)?;

    let mut bindings = Vec::new();
    bindings
        .try_reserve_exact(forwarding_slots.len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_FORWARDING_DESTINATION_BINDINGS_TABLE,
            entries: forwarding_slots.len(),
        })?;

    for (index, slot) in forwarding_slots.iter().enumerate() {
        if forwarding_slots[..index]
            .iter()
            .any(|existing| existing.source() == slot.source())
        {
            return Err(EvalHeapError::CollectorPollForwardingSlotDuplicateSource {
                index,
                address: slot.source(),
            });
        }
        let Some(forwarded_value) = slot.forwarded_value() else {
            return Err(EvalHeapError::CollectorPollForwardingSlotEmpty {
                index,
                address: slot.source(),
            });
        };
        let ResolvedValueGeneration::Heap {
            address: destination,
            generation,
        } = forwarded_value
        else {
            return Err(EvalHeapError::BoundaryMinorGcForwardingDestinationNonHeap {
                source_address: slot.source(),
                actual: forwarded_value,
            });
        };
        let destination_object = destination_objects
            .iter()
            .find(|object| object.source() == slot.source())
            .ok_or(EvalHeapError::BoundaryMinorGcForwardingDestinationMissing {
                source_address: slot.source(),
            })?;
        if destination != destination_object.destination() {
            return Err(
                EvalHeapError::BoundaryMinorGcForwardingDestinationMismatch {
                    source_address: slot.source(),
                    expected: destination_object.destination(),
                    actual: destination,
                },
            );
        }
        let expected_generation = validated_destination_object_generation(destination_object)?;
        if generation != expected_generation {
            return Err(EvalHeapError::BoundaryMinorGcForwardingGenerationMismatch {
                source_address: slot.source(),
                destination,
                expected: expected_generation,
                actual: generation,
                action: destination_object.request().action(),
            });
        }

        bindings.push(
            EvalGcStressBoundaryMinorGcForwardingDestinationBinding::new(
                slot.source(),
                destination,
                generation,
                forwarded_value,
                destination_object.request(),
                clone_boundary_destination_storage_bytes(
                    BOUNDARY_MINOR_GC_FORWARDING_DESTINATION_BINDINGS_TABLE,
                    destination_object.destination_bytes(),
                )?,
            ),
        );
    }

    Ok(bindings)
}

fn boundary_minor_gc_forwarding_header_write_plan(
    heap: &EvalHeap,
    live_bindings: &EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindings,
) -> Result<EvalGcStressBoundaryMinorGcForwardingHeaderWritePlan, EvalHeapError> {
    let bindings = live_bindings.forwarding_destination_bindings();
    let forwarding_values = heap.minor_gc_forwarding_values()?;

    for forwarding_value in forwarding_values.iter().copied() {
        if !bindings
            .iter()
            .any(|binding| binding.source() == forwarding_value.source())
        {
            return Err(
                EvalHeapError::BoundaryMinorGcForwardingHeaderWriteUnboundForwarding {
                    source_address: forwarding_value.source(),
                    actual: forwarding_value.forwarded_value(),
                },
            );
        }
    }

    let mut writes = Vec::new();
    writes.try_reserve_exact(bindings.len()).map_err(|_| {
        EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_FORWARDING_HEADER_WRITES_TABLE,
            entries: bindings.len(),
        }
    })?;

    for binding in bindings {
        let expected = binding.forwarded_value();
        let Some(actual) = heap.minor_gc_forwarding_value_at(binding.source())? else {
            return Err(
                EvalHeapError::BoundaryMinorGcForwardingHeaderWriteMissingForwarding {
                    source_address: binding.source(),
                    expected,
                },
            );
        };
        if actual != expected {
            return Err(
                EvalHeapError::BoundaryMinorGcForwardingHeaderWriteForwardingMismatch {
                    source_address: binding.source(),
                    expected,
                    actual,
                },
            );
        }

        writes.push(EvalGcStressBoundaryMinorGcForwardingHeaderWrite::from_binding(binding)?);
    }

    Ok(EvalGcStressBoundaryMinorGcForwardingHeaderWritePlan::new(
        writes,
    ))
}

fn validate_boundary_minor_gc_existing_destination_commit_forwarding_header_coverage(
    report: EvalGcStressBoundaryMinorGcForwardingHeaderWritePlanReport,
    installed_references: usize,
) -> Result<(), EvalHeapError> {
    if installed_references != 0 && report.headers() == 0 {
        return Err(
            EvalHeapError::BoundaryMinorGcExistingDestinationCommitMissingForwardingHeaders {
                references: installed_references,
                forwarding_headers: report.headers(),
            },
        );
    }

    Ok(())
}

#[derive(Clone, Debug)]
struct BoundaryMinorGcRootWritebackWriteSource {
    allocation_domain: HeapAllocationDomain,
    root_source: EvalRootSource,
    replacement_tag: ValueTag,
    replacement_value: Value,
    destination: GcHeapAddress,
    generation: HeapGeneration,
    replacement_metadata: ResolvedValueGeneration,
}

fn boundary_minor_gc_root_writeback_write_plan(
    writebacks: &EvalGcStressBoundaryMinorGcLiveReferenceWritebacks,
    live_bindings: &EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings,
) -> Result<EvalGcStressBoundaryMinorGcRootWritebackWritePlan, EvalHeapError> {
    let bindings = live_bindings.root_writeback_bindings();
    let sources = boundary_minor_gc_root_writeback_write_sources(writebacks.applications())?;
    validate_boundary_minor_gc_root_writeback_write_sources(&sources)?;
    validate_boundary_minor_gc_root_writeback_write_bindings(bindings)?;
    let mut writes = Vec::new();
    writes.try_reserve_exact(sources.len()).map_err(|_| {
        EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_ROOT_WRITEBACK_WRITES_TABLE,
            entries: sources.len(),
        }
    })?;

    for source in sources {
        let Some(binding) = bindings
            .iter()
            .find(|binding| root_writeback_write_source_matches_binding(&source, binding))
        else {
            if let Some(binding) = bindings.iter().find(|binding| {
                root_writeback_write_source_matches_binding_identity(&source, binding)
            }) {
                return Err(
                    EvalHeapError::BoundaryMinorGcRootWritebackWriteBindingMismatch {
                        allocation_domain: source.allocation_domain,
                        root_source: source.root_source,
                        expected_tag: source.replacement_tag,
                        expected_destination: source.destination,
                        expected_generation: source.generation,
                        actual_tag: binding.replacement_tag(),
                        actual_destination: binding.destination(),
                        actual_generation: binding.generation(),
                    },
                );
            }

            return Err(
                EvalHeapError::BoundaryMinorGcRootWritebackWriteMissingBinding {
                    allocation_domain: source.allocation_domain,
                    root_source: source.root_source,
                    replacement_tag: source.replacement_tag,
                    destination: source.destination,
                    generation: source.generation,
                },
            );
        };

        writes.push(
            EvalGcStressBoundaryMinorGcRootWritebackWrite::from_source_and_binding(
                source, binding,
            )?,
        );
    }

    for binding in bindings {
        if !writes
            .iter()
            .any(|write| root_writeback_write_matches_binding(write, binding))
        {
            return Err(
                EvalHeapError::BoundaryMinorGcRootWritebackWriteUnboundBinding {
                    allocation_domain: binding.allocation_domain(),
                    root_source: binding.root_source().clone(),
                    replacement_tag: binding.replacement_tag(),
                    destination: binding.destination(),
                    generation: binding.generation(),
                },
            );
        }
    }

    Ok(EvalGcStressBoundaryMinorGcRootWritebackWritePlan::new(
        writes,
    ))
}

fn validate_boundary_minor_gc_root_writeback_write_sources(
    sources: &[BoundaryMinorGcRootWritebackWriteSource],
) -> Result<(), EvalHeapError> {
    for (index, source) in sources.iter().enumerate() {
        if sources[..index].iter().any(|existing| {
            existing.allocation_domain == source.allocation_domain
                && existing.root_source == source.root_source
        }) {
            return Err(
                EvalHeapError::BoundaryMinorGcRootWritebackWriteDuplicateSource {
                    index,
                    allocation_domain: source.allocation_domain,
                    root_source: source.root_source.clone(),
                },
            );
        }
    }

    Ok(())
}

fn validate_boundary_minor_gc_root_writeback_write_bindings(
    bindings: &[EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding],
) -> Result<(), EvalHeapError> {
    for (index, binding) in bindings.iter().enumerate() {
        if bindings[..index].iter().any(|existing| {
            existing.allocation_domain() == binding.allocation_domain()
                && existing.root_source() == binding.root_source()
        }) {
            return Err(
                EvalHeapError::BoundaryMinorGcRootWritebackWriteDuplicateBinding {
                    index,
                    allocation_domain: binding.allocation_domain(),
                    root_source: binding.root_source().clone(),
                },
            );
        }

        let request = binding.request();
        if request.destination() != binding.destination() {
            return Err(
                EvalHeapError::BoundaryMinorGcRootWritebackWriteRequestDestinationMismatch {
                    allocation_domain: binding.allocation_domain(),
                    root_source: binding.root_source().clone(),
                    binding_destination: binding.destination(),
                    request_destination: request.destination(),
                },
            );
        }

        let expected_generation = validated_destination_request_generation(request)?;
        if binding.generation() != expected_generation {
            return Err(
                EvalHeapError::BoundaryMinorGcRootWritebackGenerationMismatch {
                    root_source: binding.root_source().clone(),
                    destination: binding.destination(),
                    expected: expected_generation,
                    actual: binding.generation(),
                    action: request.action(),
                },
            );
        }

        if binding.destination_bytes().len() != request.size_bytes() {
            return Err(
                EvalHeapError::BoundaryMinorGcDestinationPayloadSizeMismatch {
                    destination: binding.destination(),
                    expected: request.size_bytes(),
                    actual: binding.destination_bytes().len(),
                },
            );
        }
    }

    Ok(())
}

fn boundary_minor_gc_root_writeback_write_sources(
    applications: &EvalGcStressBoundaryMinorGcReferenceWritebackApplications,
) -> Result<Vec<BoundaryMinorGcRootWritebackWriteSource>, EvalHeapError> {
    let mut sources = Vec::new();
    extend_boundary_minor_gc_root_writeback_write_sources(
        &mut sources,
        HeapAllocationDomain::Worker,
        applications.worker(),
    )?;
    extend_boundary_minor_gc_root_writeback_write_sources(
        &mut sources,
        HeapAllocationDomain::PermanentShared,
        applications.permanent_shared(),
    )?;
    Ok(sources)
}

fn extend_boundary_minor_gc_root_writeback_write_sources(
    sources: &mut Vec<BoundaryMinorGcRootWritebackWriteSource>,
    allocation_domain: HeapAllocationDomain,
    application: Option<&EvalGcStressBoundaryMinorGcReferenceWritebackApplication>,
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

        let entries =
            sources
                .len()
                .checked_add(1)
                .ok_or(EvalHeapError::RootScanLengthOverflow {
                    table: BOUNDARY_MINOR_GC_ROOT_WRITEBACK_WRITES_TABLE,
                })?;
        sources
            .try_reserve_exact(1)
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: BOUNDARY_MINOR_GC_ROOT_WRITEBACK_WRITES_TABLE,
                entries,
            })?;
        sources.push(BoundaryMinorGcRootWritebackWriteSource {
            allocation_domain,
            root_source: root_slot.source().clone(),
            replacement_tag: replacement.tag(),
            replacement_value: replacement,
            destination,
            generation,
            replacement_metadata: root_slot.value(),
        });
    }

    Ok(())
}

fn root_writeback_write_source_matches_binding(
    source: &BoundaryMinorGcRootWritebackWriteSource,
    binding: &EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding,
) -> bool {
    root_writeback_write_source_matches_binding_identity(source, binding)
        && source.replacement_tag == binding.replacement_tag()
        && source.destination == binding.destination()
        && source.generation == binding.generation()
}

fn root_writeback_write_source_matches_binding_identity(
    source: &BoundaryMinorGcRootWritebackWriteSource,
    binding: &EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding,
) -> bool {
    source.allocation_domain == binding.allocation_domain()
        && source.root_source == *binding.root_source()
}

fn root_writeback_write_matches_binding(
    write: &EvalGcStressBoundaryMinorGcRootWritebackWrite,
    binding: &EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding,
) -> bool {
    write.allocation_domain() == binding.allocation_domain()
        && write.root_source() == binding.root_source()
        && write.replacement_tag() == binding.replacement_tag()
        && write.destination() == binding.destination()
        && write.generation() == binding.generation()
}

fn apply_boundary_minor_gc_outcome_root_writebacks(
    outcome_value: &mut Value,
    heap: &EvalHeap,
    plan: &EvalGcStressBoundaryMinorGcRootWritebackWritePlan,
) -> Result<EvalGcStressBoundaryMinorGcOutcomeRootWritebackReport, EvalHeapError> {
    let value_stack_roots = validate_boundary_minor_gc_outcome_root_writeback_source_destinations(
        outcome_value,
        heap,
        plan,
    )?;
    let mut replacement = None;

    for write in plan.writes() {
        let next = write.replacement_value();
        heap.validate_collector_poll_minor_gc_object_body_binding(
            write.request(),
            write.replacement_tag(),
        )?;
        replacement = Some(next);
    }

    if let Some(next) = replacement {
        *outcome_value = next;
    }

    Ok(EvalGcStressBoundaryMinorGcOutcomeRootWritebackReport::new(
        value_stack_roots,
    ))
}

fn apply_boundary_minor_gc_live_outcome_root_writebacks(
    outcome_value: &mut Value,
    heap: &mut EvalHeap,
    plan: &EvalGcStressBoundaryMinorGcRootWritebackWritePlan,
) -> Result<EvalGcStressBoundaryMinorGcLiveOutcomeRootWritebackReport, EvalHeapError> {
    validate_boundary_minor_gc_outcome_root_writeback_source_values(outcome_value, heap, plan)?;
    let object_body_plan = boundary_minor_gc_outcome_root_object_body_write_plan(plan)?;
    let object_body_and_generation_write_report =
        heap.apply_collector_poll_minor_gc_object_body_and_generation_writes(&object_body_plan)?;
    let outcome_root_writeback_report =
        apply_boundary_minor_gc_outcome_root_writebacks(outcome_value, heap, plan)?;

    Ok(
        EvalGcStressBoundaryMinorGcLiveOutcomeRootWritebackReport::new(
            object_body_and_generation_write_report,
            outcome_root_writeback_report,
        ),
    )
}

fn apply_boundary_minor_gc_live_reference_writebacks(
    outcome_value: &mut Value,
    heap: &mut EvalHeap,
    remembered_set: &mut RememberedSet,
    card_table: &mut GcCardTable,
    root_plan: &EvalGcStressBoundaryMinorGcRootWritebackWritePlan,
    heap_field_plan: &EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan,
) -> Result<EvalGcStressBoundaryMinorGcLiveReferenceWritebackApplyReport, EvalHeapError> {
    let value_stack_roots = validate_boundary_minor_gc_outcome_root_writeback_source_values(
        outcome_value,
        heap,
        root_plan,
    )?;
    let (copied_writes, direct_writes) =
        boundary_minor_gc_heap_field_writeback_writes(heap_field_plan)?;
    let object_body_plan =
        boundary_minor_gc_reference_writeback_object_body_write_plan(root_plan, heap_field_plan)?;
    validate_boundary_minor_gc_reference_writeback_direct_destination_aliases(
        &object_body_plan,
        heap_field_plan,
    )?;
    let (object_body_and_generation_write_report, copied_report, direct_report) = heap
        .apply_collector_poll_minor_gc_live_heap_field_writes_with_card_table(
            &object_body_plan,
            &copied_writes,
            &direct_writes,
            remembered_set,
            card_table,
        )?;
    debug_assert_eq!(
        copied_report
            .fields()
            .saturating_add(direct_report.fields()),
        heap_field_plan.report().fields()
    );
    let outcome_root_writeback_report =
        commit_boundary_minor_gc_outcome_root_writebacks_prevalidated(
            outcome_value,
            root_plan,
            value_stack_roots,
        );

    Ok(
        EvalGcStressBoundaryMinorGcLiveReferenceWritebackApplyReport::new(
            object_body_and_generation_write_report,
            outcome_root_writeback_report,
            heap_field_plan.report(),
        ),
    )
}

fn validate_boundary_minor_gc_live_reference_writebacks(
    outcome_value: &Value,
    heap: &EvalHeap,
    remembered_set: &RememberedSet,
    card_table: &GcCardTable,
    root_plan: &EvalGcStressBoundaryMinorGcRootWritebackWritePlan,
    heap_field_plan: &EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan,
) -> Result<EvalGcStressBoundaryMinorGcLiveReferenceWritebackPreflightReport, EvalHeapError> {
    let _ = validate_boundary_minor_gc_outcome_root_writeback_source_values(
        outcome_value,
        heap,
        root_plan,
    )?;
    let (copied_writes, direct_writes) =
        boundary_minor_gc_heap_field_writeback_writes(heap_field_plan)?;
    let object_body_plan =
        boundary_minor_gc_reference_writeback_object_body_write_plan(root_plan, heap_field_plan)?;
    validate_boundary_minor_gc_reference_writeback_direct_destination_aliases(
        &object_body_plan,
        heap_field_plan,
    )?;
    let (object_body_and_generation_write_report, copied_report, direct_report) = heap
        .validate_collector_poll_minor_gc_live_heap_field_writes_with_card_table(
            &object_body_plan,
            &copied_writes,
            &direct_writes,
            remembered_set,
            card_table,
        )?;
    debug_assert_eq!(
        copied_report
            .fields()
            .saturating_add(direct_report.fields()),
        heap_field_plan.report().fields()
    );

    Ok(
        EvalGcStressBoundaryMinorGcLiveReferenceWritebackPreflightReport::new(
            object_body_and_generation_write_report,
            root_plan.report(),
            heap_field_plan.report(),
        ),
    )
}

fn validate_boundary_minor_gc_existing_destination_commit_published_remembered_edges(
    remembered_set: &RememberedSet,
    live_bindings: &EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings,
) -> Result<(), EvalHeapError> {
    for binding in live_bindings.heap_field_writeback_bindings() {
        if binding.writeback_object_request().is_some()
            || binding.replacement_generation() != HeapGeneration::Young
        {
            continue;
        }

        let expected_edge = RememberedEdge::new(
            binding.writeback_object(),
            binding.replacement_destination(),
        );
        if !remembered_set.edges().contains(&expected_edge) {
            return Err(
                EvalHeapError::BoundaryMinorGcExistingDestinationCommitMissingRememberedEdge {
                    source_address: expected_edge.source(),
                    target_address: expected_edge.target(),
                },
            );
        }
    }

    Ok(())
}

fn validate_boundary_minor_gc_existing_destination_commit_published_remembered_set(
    remembered_set: &RememberedSet,
    live_bindings: &EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings,
) -> Result<(), EvalHeapError> {
    let Some(expected_remembered_set) = live_bindings.expected_remembered_set() else {
        if live_bindings.install_report().bindings() == 0 {
            return Ok(());
        }
        return Err(
            EvalHeapError::BoundaryMinorGcExistingDestinationCommitMissingRememberedSetPublication {
                bindings: live_bindings.install_report().bindings(),
            },
        );
    };

    if remembered_set != expected_remembered_set {
        return Err(
            EvalHeapError::BoundaryMinorGcExistingDestinationCommitRememberedSetPublicationMismatch {
                expected_epoch: expected_remembered_set.epoch(),
                actual_epoch: remembered_set.epoch(),
                expected_edges: expected_remembered_set.len(),
                actual_edges: remembered_set.len(),
            },
        );
    }

    validate_boundary_minor_gc_existing_destination_commit_published_remembered_edges(
        remembered_set,
        live_bindings,
    )
}

fn validate_boundary_minor_gc_reference_writeback_direct_destination_aliases(
    object_body_plan: &AllocationCollectorPollObjectByteCopyPlan,
    heap_field_plan: &EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan,
) -> Result<(), EvalHeapError> {
    for write in heap_field_plan.writes() {
        if write.writeback_object_request().is_some() {
            continue;
        }
        if object_body_plan
            .requests()
            .iter()
            .any(|request| request.destination() == write.writeback_object())
        {
            return Err(
                EvalHeapError::BoundaryMinorGcLiveReferenceWritebackDestinationAliasesDirectWriteback {
                    allocation_domain: write.allocation_domain(),
                    writeback_object: write.writeback_object(),
                    field_index: write.field_index(),
                    field_source: write.source().clone(),
                    destination: write.writeback_object(),
                },
            );
        }
    }

    Ok(())
}

fn apply_boundary_minor_gc_heap_field_writebacks(
    heap: &mut EvalHeap,
    remembered_set: &mut RememberedSet,
    card_table: &mut GcCardTable,
    plan: &EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan,
) -> Result<EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport, EvalHeapError> {
    let (copied_writes, direct_writes) = boundary_minor_gc_heap_field_writeback_writes(plan)?;
    apply_boundary_minor_gc_heap_field_writebacks_from_writes(
        heap,
        remembered_set,
        card_table,
        plan.report(),
        &copied_writes,
        &direct_writes,
    )
}

fn apply_boundary_minor_gc_live_heap_field_writebacks(
    heap: &mut EvalHeap,
    remembered_set: &mut RememberedSet,
    card_table: &mut GcCardTable,
    plan: &EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan,
) -> Result<EvalGcStressBoundaryMinorGcLiveHeapFieldWritebackReport, EvalHeapError> {
    let (copied_writes, direct_writes) = boundary_minor_gc_heap_field_writeback_writes(plan)?;
    let object_body_plan = boundary_minor_gc_heap_field_writeback_object_body_write_plan(plan)?;
    validate_boundary_minor_gc_reference_writeback_direct_destination_aliases(
        &object_body_plan,
        plan,
    )?;
    let (object_body_and_generation_write_report, copied_report, direct_report) = heap
        .apply_collector_poll_minor_gc_live_heap_field_writes_with_card_table(
            &object_body_plan,
            &copied_writes,
            &direct_writes,
            remembered_set,
            card_table,
        )?;
    debug_assert_eq!(
        copied_report
            .fields()
            .saturating_add(direct_report.fields()),
        plan.report().fields()
    );

    Ok(
        EvalGcStressBoundaryMinorGcLiveHeapFieldWritebackReport::new(
            object_body_and_generation_write_report,
            plan.report(),
        ),
    )
}

fn validate_boundary_minor_gc_live_heap_field_writebacks(
    heap: &EvalHeap,
    remembered_set: &RememberedSet,
    card_table: &GcCardTable,
    plan: &EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan,
) -> Result<EvalGcStressBoundaryMinorGcLiveHeapFieldWritebackPreflightReport, EvalHeapError> {
    let (copied_writes, direct_writes) = boundary_minor_gc_heap_field_writeback_writes(plan)?;
    let object_body_plan = boundary_minor_gc_heap_field_writeback_object_body_write_plan(plan)?;
    validate_boundary_minor_gc_reference_writeback_direct_destination_aliases(
        &object_body_plan,
        plan,
    )?;
    let (object_body_and_generation_write_report, copied_report, direct_report) = heap
        .validate_collector_poll_minor_gc_live_heap_field_writes_with_card_table(
            &object_body_plan,
            &copied_writes,
            &direct_writes,
            remembered_set,
            card_table,
        )?;
    debug_assert_eq!(
        copied_report
            .fields()
            .saturating_add(direct_report.fields()),
        plan.report().fields()
    );

    Ok(
        EvalGcStressBoundaryMinorGcLiveHeapFieldWritebackPreflightReport::new(
            object_body_and_generation_write_report,
            plan.report(),
        ),
    )
}

fn boundary_minor_gc_heap_field_writeback_writes(
    plan: &EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan,
) -> Result<
    (
        Vec<AllocationCollectorPollCopiedHeapFieldWrite>,
        Vec<AllocationCollectorPollDirectHeapFieldWrite>,
    ),
    EvalHeapError,
> {
    let mut copied_writes = Vec::new();
    copied_writes
        .try_reserve_exact(plan.writes().len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_WRITES_TABLE,
            entries: plan.writes().len(),
        })?;
    let mut direct_writes = Vec::new();
    direct_writes
        .try_reserve_exact(plan.writes().len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_WRITES_TABLE,
            entries: plan.writes().len(),
        })?;

    for write in plan.writes() {
        if let Some(writeback_object_request) = write.writeback_object_request() {
            copied_writes.push(AllocationCollectorPollCopiedHeapFieldWrite::new(
                write.allocation_domain(),
                write.validation_object(),
                write.writeback_object(),
                write.field_index(),
                write.source().clone(),
                write.replacement_metadata(),
                write.replacement_request(),
                writeback_object_request,
            ));
        } else {
            direct_writes.push(AllocationCollectorPollDirectHeapFieldWrite::new(
                write.allocation_domain(),
                write.writeback_object(),
                write.field_index(),
                write.source().clone(),
                write.replacement_metadata(),
                write.replacement_request(),
            ));
        };
    }

    Ok((copied_writes, direct_writes))
}

fn apply_boundary_minor_gc_heap_field_writebacks_from_writes(
    heap: &mut EvalHeap,
    remembered_set: &mut RememberedSet,
    card_table: &mut GcCardTable,
    report: EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport,
    copied_writes: &[AllocationCollectorPollCopiedHeapFieldWrite],
    direct_writes: &[AllocationCollectorPollDirectHeapFieldWrite],
) -> Result<EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport, EvalHeapError> {
    let (copied_report, direct_report) = heap
        .apply_collector_poll_minor_gc_heap_field_writes_with_card_table(
            copied_writes,
            direct_writes,
            remembered_set,
            card_table,
        )?;
    debug_assert_eq!(
        copied_report
            .fields()
            .saturating_add(direct_report.fields()),
        report.fields()
    );
    Ok(report)
}

fn commit_boundary_minor_gc_outcome_root_writebacks_prevalidated(
    outcome_value: &mut Value,
    plan: &EvalGcStressBoundaryMinorGcRootWritebackWritePlan,
    value_stack_roots: usize,
) -> EvalGcStressBoundaryMinorGcOutcomeRootWritebackReport {
    let mut replacement = None;
    for write in plan.writes() {
        replacement = Some(write.replacement_value());
    }
    if let Some(next) = replacement {
        *outcome_value = next;
    }

    EvalGcStressBoundaryMinorGcOutcomeRootWritebackReport::new(value_stack_roots)
}

fn validate_boundary_minor_gc_outcome_root_writeback_source_destinations(
    outcome_value: &Value,
    heap: &EvalHeap,
    plan: &EvalGcStressBoundaryMinorGcRootWritebackWritePlan,
) -> Result<usize, EvalHeapError> {
    let value_stack_roots =
        validate_boundary_minor_gc_outcome_root_writeback_source_values(outcome_value, heap, plan)?;
    for write in plan.writes() {
        let destination_generation = heap.generation(write.replacement_value())?;
        if destination_generation != write.generation() {
            return Err(
                EvalHeapError::BoundaryMinorGcOutcomeRootWritebackDestinationGenerationMismatch {
                    root_source: write.root_source().clone(),
                    destination: write.destination(),
                    expected: write.generation(),
                    actual: destination_generation,
                },
            );
        }
    }

    Ok(value_stack_roots)
}

fn validate_boundary_minor_gc_outcome_root_writeback_source_values(
    outcome_value: &Value,
    heap: &EvalHeap,
    plan: &EvalGcStressBoundaryMinorGcRootWritebackWritePlan,
) -> Result<usize, EvalHeapError> {
    let value_stack_roots = validate_boundary_minor_gc_outcome_root_writeback_sources(plan)?;
    for write in plan.writes() {
        let expected =
            boundary_minor_gc_heap_value(write.replacement_tag(), write.request().source())?;
        if !outcome_value.raw_eq(expected) {
            return Err(EvalHeapError::CollectorPollRootValueWritebackSlotMismatch {
                index: 0,
                expected_tag: expected.tag(),
                expected_payload: expected.payload_bits(),
                actual_tag: outcome_value.tag(),
                actual_payload: outcome_value.payload_bits(),
            });
        }

        let source_generation = heap.generation(expected)?;
        if source_generation != HeapGeneration::Young {
            return Err(
                EvalHeapError::BoundaryMinorGcOutcomeRootWritebackSourceGenerationMismatch {
                    root_source: write.root_source().clone(),
                    source_address: write.request().source(),
                    expected: HeapGeneration::Young,
                    actual: source_generation,
                },
            );
        }
    }

    Ok(value_stack_roots)
}

fn validate_boundary_minor_gc_outcome_root_writeback_sources(
    plan: &EvalGcStressBoundaryMinorGcRootWritebackWritePlan,
) -> Result<usize, EvalHeapError> {
    let mut value_stack_zero_seen = false;
    let mut value_stack_roots = 0usize;

    for (index, write) in plan.writes().iter().enumerate() {
        let EvalRootSource::ValueStack { slot: 0 } = write.root_source() else {
            return Err(
                EvalHeapError::BoundaryMinorGcOutcomeRootWritebackUnsupportedSource {
                    root_source: write.root_source().clone(),
                },
            );
        };
        if value_stack_zero_seen {
            return Err(
                EvalHeapError::BoundaryMinorGcOutcomeRootWritebackDuplicateValueStackRoot {
                    index,
                    root_source: write.root_source().clone(),
                },
            );
        }

        value_stack_zero_seen = true;
        value_stack_roots = value_stack_roots.saturating_add(1);
    }

    Ok(value_stack_roots)
}

fn boundary_minor_gc_outcome_root_object_body_write_plan(
    plan: &EvalGcStressBoundaryMinorGcRootWritebackWritePlan,
) -> Result<AllocationCollectorPollObjectByteCopyPlan, EvalHeapError> {
    let mut requests = Vec::new();
    requests
        .try_reserve_exact(plan.writes().len())
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_ROOT_WRITEBACK_WRITES_TABLE,
            entries: plan.writes().len(),
        })?;
    requests.extend(plan.writes().iter().map(|write| write.request()));
    Ok(AllocationCollectorPollObjectByteCopyPlan::from_requests(
        requests,
    ))
}

fn boundary_minor_gc_heap_field_writeback_object_body_write_plan(
    plan: &EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan,
) -> Result<AllocationCollectorPollObjectByteCopyPlan, EvalHeapError> {
    let entries =
        plan.writes()
            .len()
            .checked_mul(2)
            .ok_or(EvalHeapError::RootScanLengthOverflow {
                table: BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_WRITES_TABLE,
            })?;
    let mut requests = Vec::new();
    requests
        .try_reserve_exact(entries)
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_WRITES_TABLE,
            entries,
        })?;

    for write in plan.writes() {
        if let Some(writeback_object_request) = write.writeback_object_request() {
            push_unique_boundary_minor_gc_object_copy_request(
                &mut requests,
                writeback_object_request,
            );
        }
        push_unique_boundary_minor_gc_object_copy_request(
            &mut requests,
            write.replacement_request(),
        );
    }

    Ok(AllocationCollectorPollObjectByteCopyPlan::from_requests(
        requests,
    ))
}

fn boundary_minor_gc_reference_writeback_object_body_write_plan(
    root_plan: &EvalGcStressBoundaryMinorGcRootWritebackWritePlan,
    heap_field_plan: &EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan,
) -> Result<AllocationCollectorPollObjectByteCopyPlan, EvalHeapError> {
    let heap_field_entries = heap_field_plan.writes().len().checked_mul(2).ok_or(
        EvalHeapError::RootScanLengthOverflow {
            table: BOUNDARY_MINOR_GC_REFERENCE_WRITEBACK_WRITES_TABLE,
        },
    )?;
    let entries = root_plan
        .writes()
        .len()
        .checked_add(heap_field_entries)
        .ok_or(EvalHeapError::RootScanLengthOverflow {
            table: BOUNDARY_MINOR_GC_REFERENCE_WRITEBACK_WRITES_TABLE,
        })?;
    let mut requests = Vec::new();
    requests
        .try_reserve_exact(entries)
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_REFERENCE_WRITEBACK_WRITES_TABLE,
            entries,
        })?;

    for write in root_plan.writes() {
        push_unique_boundary_minor_gc_object_copy_request(&mut requests, write.request());
    }
    for write in heap_field_plan.writes() {
        if let Some(writeback_object_request) = write.writeback_object_request() {
            push_unique_boundary_minor_gc_object_copy_request(
                &mut requests,
                writeback_object_request,
            );
        }
        push_unique_boundary_minor_gc_object_copy_request(
            &mut requests,
            write.replacement_request(),
        );
    }

    Ok(AllocationCollectorPollObjectByteCopyPlan::from_requests(
        requests,
    ))
}

fn push_unique_boundary_minor_gc_object_copy_request(
    requests: &mut Vec<AllocationCollectorPollObjectByteCopyRequest>,
    request: AllocationCollectorPollObjectByteCopyRequest,
) {
    if !requests.iter().any(|existing| *existing == request) {
        requests.push(request);
    }
}

fn boundary_minor_gc_heap_value(
    tag: ValueTag,
    address: GcHeapAddress,
) -> Result<Value, EvalHeapError> {
    let ptr = NonNull::new(address.address_bits() as *mut HeapObject).ok_or(
        EvalHeapError::Value(crate::value::ValueError::NullHeapPointer { tag }),
    )?;
    Value::heap(tag, ptr).map_err(EvalHeapError::Value)
}

#[derive(Clone, Debug)]
struct BoundaryMinorGcHeapFieldWritebackWriteSource {
    allocation_domain: HeapAllocationDomain,
    validation_object: GcHeapAddress,
    writeback_object: GcHeapAddress,
    field_index: usize,
    source: HeapEdgeSource,
    replacement_destination: GcHeapAddress,
    replacement_generation: HeapGeneration,
    replacement_metadata: ResolvedValueGeneration,
}

#[cfg(test)]
fn boundary_minor_gc_heap_field_writeback_write_plan(
    writebacks: &EvalGcStressBoundaryMinorGcLiveReferenceWritebacks,
    live_bindings: &EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings,
) -> Result<EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan, EvalHeapError> {
    let sources = boundary_minor_gc_heap_field_writeback_write_sources(writebacks.applications())?;
    boundary_minor_gc_heap_field_writeback_write_plan_from_sources(sources, live_bindings)
}

fn boundary_minor_gc_heap_field_writeback_write_plan_for_heap(
    heap: &EvalHeap,
    writebacks: &EvalGcStressBoundaryMinorGcLiveReferenceWritebacks,
    live_bindings: &EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings,
) -> Result<EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan, EvalHeapError> {
    let sources = boundary_minor_gc_heap_field_writeback_write_sources_for_heap(
        heap,
        writebacks.applications(),
    )?;
    boundary_minor_gc_heap_field_writeback_write_plan_from_sources(sources, live_bindings)
}

fn boundary_minor_gc_heap_field_writeback_write_plan_from_sources(
    sources: Vec<BoundaryMinorGcHeapFieldWritebackWriteSource>,
    live_bindings: &EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings,
) -> Result<EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan, EvalHeapError> {
    let bindings = live_bindings.heap_field_writeback_bindings();
    validate_boundary_minor_gc_heap_field_writeback_write_sources(&sources)?;
    validate_boundary_minor_gc_heap_field_writeback_write_bindings(bindings)?;
    let mut writes = Vec::new();
    writes.try_reserve_exact(sources.len()).map_err(|_| {
        EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_WRITES_TABLE,
            entries: sources.len(),
        }
    })?;

    for source in sources {
        let Some(binding) = bindings
            .iter()
            .find(|binding| heap_field_writeback_write_source_matches_binding(&source, binding))
        else {
            if let Some(binding) = bindings.iter().find(|binding| {
                heap_field_writeback_write_source_matches_binding_identity(&source, binding)
            }) {
                return Err(
                    EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteBindingMismatch {
                        allocation_domain: source.allocation_domain,
                        writeback_object: source.writeback_object,
                        field_index: source.field_index,
                        field_source: source.source,
                        expected_replacement: source.replacement_destination,
                        expected_generation: source.replacement_generation,
                        actual_replacement: binding.replacement_destination(),
                        actual_generation: binding.replacement_generation(),
                    },
                );
            }

            return Err(
                EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteMissingBinding {
                    allocation_domain: source.allocation_domain,
                    writeback_object: source.writeback_object,
                    field_index: source.field_index,
                    field_source: source.source,
                    replacement: source.replacement_destination,
                    generation: source.replacement_generation,
                },
            );
        };

        writes.push(
            EvalGcStressBoundaryMinorGcHeapFieldWritebackWrite::from_source_and_binding(
                source, binding,
            )?,
        );
    }

    for binding in bindings {
        if !writes
            .iter()
            .any(|write| heap_field_writeback_write_matches_binding(write, binding))
        {
            return Err(
                EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteUnboundBinding {
                    allocation_domain: binding.allocation_domain(),
                    writeback_object: binding.writeback_object(),
                    field_index: binding.field_index(),
                    field_source: binding.source().clone(),
                    replacement: binding.replacement_destination(),
                    generation: binding.replacement_generation(),
                },
            );
        }
    }

    Ok(EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan::new(
        writes,
    ))
}

#[cfg(test)]
fn boundary_minor_gc_heap_field_writeback_write_sources(
    applications: &EvalGcStressBoundaryMinorGcReferenceWritebackApplications,
) -> Result<Vec<BoundaryMinorGcHeapFieldWritebackWriteSource>, EvalHeapError> {
    let mut sources = Vec::new();
    extend_boundary_minor_gc_heap_field_writeback_write_sources(
        &mut sources,
        HeapAllocationDomain::Worker,
        applications.worker(),
    )?;
    extend_boundary_minor_gc_heap_field_writeback_write_sources(
        &mut sources,
        HeapAllocationDomain::PermanentShared,
        applications.permanent_shared(),
    )?;
    Ok(sources)
}

fn boundary_minor_gc_heap_field_writeback_write_sources_for_heap(
    heap: &EvalHeap,
    applications: &EvalGcStressBoundaryMinorGcReferenceWritebackApplications,
) -> Result<Vec<BoundaryMinorGcHeapFieldWritebackWriteSource>, EvalHeapError> {
    let mut sources = Vec::new();
    extend_boundary_minor_gc_heap_field_writeback_write_sources_for_heap(
        &mut sources,
        heap,
        applications.worker(),
    )?;
    extend_boundary_minor_gc_heap_field_writeback_write_sources_for_heap(
        &mut sources,
        heap,
        applications.permanent_shared(),
    )?;
    Ok(sources)
}

#[cfg(test)]
fn extend_boundary_minor_gc_heap_field_writeback_write_sources(
    sources: &mut Vec<BoundaryMinorGcHeapFieldWritebackWriteSource>,
    allocation_domain: HeapAllocationDomain,
    application: Option<&EvalGcStressBoundaryMinorGcReferenceWritebackApplication>,
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

        let entries =
            sources
                .len()
                .checked_add(1)
                .ok_or(EvalHeapError::RootScanLengthOverflow {
                    table: BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_WRITES_TABLE,
                })?;
        sources
            .try_reserve_exact(1)
            .map_err(|_| EvalHeapError::RootScanAllocationFailed {
                table: BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_WRITES_TABLE,
                entries,
            })?;
        sources.push(BoundaryMinorGcHeapFieldWritebackWriteSource {
            allocation_domain,
            validation_object: slot.validation_object(),
            writeback_object: slot.writeback_object(),
            field_index: slot.field_index(),
            source: slot.source().clone(),
            replacement_destination,
            replacement_generation,
            replacement_metadata: slot.value(),
        });
    }

    Ok(())
}

fn extend_boundary_minor_gc_heap_field_writeback_write_sources_for_heap(
    sources: &mut Vec<BoundaryMinorGcHeapFieldWritebackWriteSource>,
    heap: &EvalHeap,
    application: Option<&EvalGcStressBoundaryMinorGcReferenceWritebackApplication>,
) -> Result<(), EvalHeapError> {
    let Some(application) = application else {
        return Ok(());
    };

    for slot in application.heap_field_writeback_slots() {
        let allocation_domain = heap_field_writeback_slot_allocation_domain(heap, slot)?;
        extend_boundary_minor_gc_heap_field_writeback_write_source(
            sources,
            allocation_domain,
            slot,
        )?;
    }

    Ok(())
}

fn extend_boundary_minor_gc_heap_field_writeback_write_source(
    sources: &mut Vec<BoundaryMinorGcHeapFieldWritebackWriteSource>,
    allocation_domain: HeapAllocationDomain,
    slot: &AllocationCollectorPollHeapFieldWritebackSlot,
) -> Result<(), EvalHeapError> {
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

    let source = BoundaryMinorGcHeapFieldWritebackWriteSource {
        allocation_domain,
        validation_object: slot.validation_object(),
        writeback_object: slot.writeback_object(),
        field_index: slot.field_index(),
        source: slot.source().clone(),
        replacement_destination,
        replacement_generation,
        replacement_metadata: slot.value(),
    };
    if sources
        .iter()
        .any(|existing| heap_field_writeback_write_source_matches(existing, &source))
    {
        return Ok(());
    }

    let entries = sources
        .len()
        .checked_add(1)
        .ok_or(EvalHeapError::RootScanLengthOverflow {
            table: BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_WRITES_TABLE,
        })?;
    sources
        .try_reserve_exact(1)
        .map_err(|_| EvalHeapError::RootScanAllocationFailed {
            table: BOUNDARY_MINOR_GC_HEAP_FIELD_WRITEBACK_WRITES_TABLE,
            entries,
        })?;
    sources.push(source);

    Ok(())
}

fn validate_boundary_minor_gc_heap_field_writeback_write_sources(
    sources: &[BoundaryMinorGcHeapFieldWritebackWriteSource],
) -> Result<(), EvalHeapError> {
    for (index, source) in sources.iter().enumerate() {
        if sources[..index]
            .iter()
            .any(|existing| heap_field_writeback_write_source_identity_matches(existing, source))
        {
            return Err(
                EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteDuplicateSource {
                    index,
                    allocation_domain: source.allocation_domain,
                    writeback_object: source.writeback_object,
                    field_index: source.field_index,
                    field_source: source.source.clone(),
                },
            );
        }
    }

    Ok(())
}

fn validate_boundary_minor_gc_heap_field_writeback_write_bindings(
    bindings: &[EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding],
) -> Result<(), EvalHeapError> {
    for (index, binding) in bindings.iter().enumerate() {
        if bindings[..index]
            .iter()
            .any(|existing| heap_field_writeback_write_binding_identity_matches(existing, binding))
        {
            return Err(
                EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteDuplicateBinding {
                    index,
                    allocation_domain: binding.allocation_domain(),
                    writeback_object: binding.writeback_object(),
                    field_index: binding.field_index(),
                    field_source: binding.source().clone(),
                },
            );
        }

        let replacement_request = binding.replacement_request();
        if replacement_request.destination() != binding.replacement_destination() {
            return Err(
                EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteReplacementRequestDestinationMismatch {
                    allocation_domain: binding.allocation_domain(),
                    writeback_object: binding.writeback_object(),
                    field_index: binding.field_index(),
                    field_source: binding.source().clone(),
                    binding_replacement: binding.replacement_destination(),
                    request_destination: replacement_request.destination(),
                },
            );
        }
        let expected_generation = validated_destination_request_generation(replacement_request)?;
        if binding.replacement_generation() != expected_generation {
            return Err(
                EvalHeapError::BoundaryMinorGcHeapFieldWritebackReplacementGenerationMismatch {
                    writeback_object: binding.writeback_object(),
                    field_index: binding.field_index(),
                    field_source: binding.source().clone(),
                    replacement: binding.replacement_destination(),
                    expected: expected_generation,
                    actual: binding.replacement_generation(),
                    action: replacement_request.action(),
                },
            );
        }
        if binding.replacement_destination_bytes().len() != replacement_request.size_bytes() {
            return Err(
                EvalHeapError::BoundaryMinorGcDestinationPayloadSizeMismatch {
                    destination: binding.replacement_destination(),
                    expected: replacement_request.size_bytes(),
                    actual: binding.replacement_destination_bytes().len(),
                },
            );
        }

        match (
            binding.validation_object() != binding.writeback_object(),
            binding.writeback_object_request(),
            binding.writeback_object_destination_bytes(),
        ) {
            (false, None, None) => {}
            (false, _, _) | (true, None, _) | (true, _, None) => {
                return Err(
                    EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteObjectBindingMalformed {
                        allocation_domain: binding.allocation_domain(),
                        validation_object: binding.validation_object(),
                        writeback_object: binding.writeback_object(),
                        field_index: binding.field_index(),
                        field_source: binding.source().clone(),
                    },
                );
            }
            (true, Some(writeback_object_request), Some(bytes)) => {
                if writeback_object_request.source() != binding.validation_object() {
                    return Err(
                        EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteObjectRequestSourceMismatch {
                            allocation_domain: binding.allocation_domain(),
                            validation_object: binding.validation_object(),
                            writeback_object: binding.writeback_object(),
                            field_index: binding.field_index(),
                            field_source: binding.source().clone(),
                            actual_source: writeback_object_request.source(),
                        },
                    );
                }
                if writeback_object_request.destination() != binding.writeback_object() {
                    return Err(
                        EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteObjectRequestDestinationMismatch {
                            allocation_domain: binding.allocation_domain(),
                            validation_object: binding.validation_object(),
                            writeback_object: binding.writeback_object(),
                            field_index: binding.field_index(),
                            field_source: binding.source().clone(),
                            request_destination: writeback_object_request.destination(),
                        },
                    );
                }
                let _ = validated_destination_request_generation(writeback_object_request)?;
                if bytes.len() != writeback_object_request.size_bytes() {
                    return Err(
                        EvalHeapError::BoundaryMinorGcDestinationPayloadSizeMismatch {
                            destination: binding.writeback_object(),
                            expected: writeback_object_request.size_bytes(),
                            actual: bytes.len(),
                        },
                    );
                }
            }
        }
    }

    Ok(())
}

fn heap_field_writeback_write_source_matches_binding(
    source: &BoundaryMinorGcHeapFieldWritebackWriteSource,
    binding: &EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding,
) -> bool {
    heap_field_writeback_write_source_matches_binding_identity(source, binding)
        && source.replacement_destination == binding.replacement_destination()
        && source.replacement_generation == binding.replacement_generation()
}

fn heap_field_writeback_write_source_matches_binding_identity(
    source: &BoundaryMinorGcHeapFieldWritebackWriteSource,
    binding: &EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding,
) -> bool {
    source.allocation_domain == binding.allocation_domain()
        && source.validation_object == binding.validation_object()
        && source.writeback_object == binding.writeback_object()
        && source.field_index == binding.field_index()
        && source.source == *binding.source()
}

fn heap_field_writeback_write_matches_binding(
    write: &EvalGcStressBoundaryMinorGcHeapFieldWritebackWrite,
    binding: &EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding,
) -> bool {
    write.allocation_domain() == binding.allocation_domain()
        && write.validation_object() == binding.validation_object()
        && write.writeback_object() == binding.writeback_object()
        && write.field_index() == binding.field_index()
        && write.source() == binding.source()
        && write.replacement_destination() == binding.replacement_destination()
        && write.replacement_generation() == binding.replacement_generation()
}

fn heap_field_writeback_write_source_identity_matches(
    left: &BoundaryMinorGcHeapFieldWritebackWriteSource,
    right: &BoundaryMinorGcHeapFieldWritebackWriteSource,
) -> bool {
    left.allocation_domain == right.allocation_domain
        && left.validation_object == right.validation_object
        && left.writeback_object == right.writeback_object
        && left.field_index == right.field_index
        && left.source == right.source
}

fn heap_field_writeback_write_source_matches(
    left: &BoundaryMinorGcHeapFieldWritebackWriteSource,
    right: &BoundaryMinorGcHeapFieldWritebackWriteSource,
) -> bool {
    heap_field_writeback_write_source_identity_matches(left, right)
        && left.replacement_destination == right.replacement_destination
        && left.replacement_generation == right.replacement_generation
        && left.replacement_metadata == right.replacement_metadata
}

fn heap_field_writeback_write_binding_identity_matches(
    left: &EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding,
    right: &EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding,
) -> bool {
    left.allocation_domain() == right.allocation_domain()
        && left.validation_object() == right.validation_object()
        && left.writeback_object() == right.writeback_object()
        && left.field_index() == right.field_index()
        && left.source() == right.source()
}

fn validate_boundary_minor_gc_forwarding_slot_sources(
    forwarding_slots: &[MinorGcForwardingSlot],
    destination_objects: &[EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes],
) -> Result<(), EvalHeapError> {
    for (index, slot) in forwarding_slots.iter().enumerate() {
        if forwarding_slots[..index]
            .iter()
            .any(|existing| existing.source() == slot.source())
        {
            return Err(EvalHeapError::CollectorPollForwardingSlotDuplicateSource {
                index,
                address: slot.source(),
            });
        }
        if slot.forwarded_value().is_none() {
            return Err(EvalHeapError::CollectorPollForwardingSlotEmpty {
                index,
                address: slot.source(),
            });
        }
        if !destination_objects
            .iter()
            .any(|object| object.source() == slot.source())
        {
            return Err(EvalHeapError::BoundaryMinorGcForwardingDestinationMissing {
                source_address: slot.source(),
            });
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

#[cfg(test)]
fn boundary_minor_gc_heap_field_writeback_destination_bindings(
    writebacks: &EvalGcStressBoundaryMinorGcLiveReferenceWritebacks,
    destination_storage: &EvalGcStressBoundaryMinorGcLiveDestinationStorage,
) -> Result<Vec<EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding>, EvalHeapError> {
    boundary_minor_gc_heap_field_writeback_destination_bindings_from_applications(
        writebacks.applications(),
        destination_storage.object_bytes(),
    )
}

fn boundary_minor_gc_heap_field_writeback_destination_bindings_for_heap(
    heap: &EvalHeap,
    writebacks: &EvalGcStressBoundaryMinorGcLiveReferenceWritebacks,
    destination_storage: &EvalGcStressBoundaryMinorGcLiveDestinationStorage,
) -> Result<Vec<EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding>, EvalHeapError> {
    boundary_minor_gc_heap_field_writeback_destination_bindings_from_applications_for_heap(
        heap,
        writebacks.applications(),
        destination_storage.object_bytes(),
    )
}

#[cfg(test)]
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

fn boundary_minor_gc_heap_field_writeback_destination_bindings_from_applications_for_heap(
    heap: &EvalHeap,
    applications: &EvalGcStressBoundaryMinorGcReferenceWritebackApplications,
    destination_objects: &[EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes],
) -> Result<Vec<EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding>, EvalHeapError> {
    let mut bindings = Vec::new();
    extend_boundary_minor_gc_heap_field_writeback_destination_bindings_for_heap(
        &mut bindings,
        heap,
        applications.worker(),
        destination_objects,
    )?;
    extend_boundary_minor_gc_heap_field_writeback_destination_bindings_for_heap(
        &mut bindings,
        heap,
        applications.permanent_shared(),
        destination_objects,
    )?;
    Ok(bindings)
}

#[cfg(test)]
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

fn extend_boundary_minor_gc_heap_field_writeback_destination_bindings_for_heap(
    bindings: &mut Vec<EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding>,
    heap: &EvalHeap,
    application: Option<&EvalGcStressBoundaryMinorGcReferenceWritebackApplication>,
    destination_objects: &[EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes],
) -> Result<(), EvalHeapError> {
    let Some(application) = application else {
        return Ok(());
    };

    for slot in application.heap_field_writeback_slots() {
        let allocation_domain = heap_field_writeback_slot_allocation_domain(heap, slot)?;
        extend_boundary_minor_gc_heap_field_writeback_destination_binding(
            bindings,
            allocation_domain,
            slot,
            destination_objects,
        )?;
    }

    Ok(())
}

fn extend_boundary_minor_gc_heap_field_writeback_destination_binding(
    bindings: &mut Vec<EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding>,
    allocation_domain: HeapAllocationDomain,
    slot: &AllocationCollectorPollHeapFieldWritebackSlot,
    destination_objects: &[EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes],
) -> Result<(), EvalHeapError> {
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
    let binding = EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding::new(
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
    );
    if bindings.iter().any(|existing| existing == &binding) {
        return Ok(());
    }

    let entries = bindings
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
    bindings.push(binding);

    Ok(())
}

fn heap_field_writeback_slot_allocation_domain(
    heap: &EvalHeap,
    slot: &AllocationCollectorPollHeapFieldWritebackSlot,
) -> Result<HeapAllocationDomain, EvalHeapError> {
    let (address, role) = if slot.validation_object() == slot.writeback_object() {
        (slot.writeback_object(), "heap-field writeback object")
    } else {
        (slot.validation_object(), "heap-field validation object")
    };
    heap.allocation_domain_for_address(address, role)
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
mod object_generation_write_plan_tests {
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

    fn object_generation(
        request: AllocationCollectorPollObjectByteCopyRequest,
    ) -> EvalGcStressBoundaryMinorGcLiveObjectGeneration {
        EvalGcStressBoundaryMinorGcLiveObjectGeneration::new(
            request.source(),
            request.destination(),
            request.action(),
            generation_for_destination_action(request.action()),
            request,
        )
    }

    fn object_generation_with_parts(
        source: GcHeapAddress,
        destination: GcHeapAddress,
        action: MinorGcSurvivorAction,
        generation: HeapGeneration,
        request: AllocationCollectorPollObjectByteCopyRequest,
    ) -> EvalGcStressBoundaryMinorGcLiveObjectGeneration {
        EvalGcStressBoundaryMinorGcLiveObjectGeneration::new(
            source,
            destination,
            action,
            generation,
            request,
        )
    }

    fn live_object_generations(
        object_generations: Vec<EvalGcStressBoundaryMinorGcLiveObjectGeneration>,
    ) -> EvalGcStressBoundaryMinorGcLiveObjectGenerations {
        let install_report = live_object_generation_install_report(&object_generations);
        EvalGcStressBoundaryMinorGcLiveObjectGenerations {
            install_report,
            object_generations,
        }
    }

    #[test]
    fn plans_object_generation_writes_from_installed_live_metadata() {
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
        let object_generations = live_object_generations(vec![
            object_generation(copied_request),
            object_generation(promoted_request),
        ]);

        let write_plan = boundary_minor_gc_object_generation_write_plan(
            &destination_storage,
            &object_generations,
        )
        .expect("object-generation write plan validates");

        assert_eq!(write_plan.len(), 2);
        assert_eq!(write_plan.report().objects(), 2);
        assert_eq!(write_plan.report().copied_to_nursery(), 1);
        assert_eq!(write_plan.report().promoted_to_old(), 1);
        assert_eq!(write_plan.report().payload_bytes(), 8);
        assert_eq!(write_plan.writes()[0].source(), copied_request.source());
        assert_eq!(
            write_plan.writes()[0].destination(),
            copied_request.destination()
        );
        assert_eq!(
            write_plan.writes()[0].action(),
            MinorGcSurvivorAction::CopyToNursery
        );
        assert_eq!(write_plan.writes()[0].generation(), HeapGeneration::Young);
        assert_eq!(write_plan.writes()[0].request(), copied_request);
        assert_eq!(write_plan.writes()[0].destination_bytes(), copied_bytes);
        assert_eq!(write_plan.writes()[1].source(), promoted_request.source());
        assert_eq!(
            write_plan.writes()[1].destination(),
            promoted_request.destination()
        );
        assert_eq!(
            write_plan.writes()[1].action(),
            MinorGcSurvivorAction::PromoteToOld
        );
        assert_eq!(write_plan.writes()[1].generation(), HeapGeneration::Old);
        assert_eq!(write_plan.writes()[1].request(), promoted_request);
        assert_eq!(write_plan.writes()[1].destination_bytes(), promoted_bytes);
    }

    #[test]
    fn plans_empty_object_generation_writes_when_no_metadata_is_installed() {
        let destination_storage = destination_storage(Vec::new());
        let object_generations = live_object_generations(Vec::new());

        let write_plan = boundary_minor_gc_object_generation_write_plan(
            &destination_storage,
            &object_generations,
        )
        .expect("empty object-generation write plan validates");

        assert!(write_plan.is_empty());
        assert_eq!(write_plan.report().objects(), 0);
        assert_eq!(write_plan.report().payload_bytes(), 0);
    }

    #[test]
    fn rejects_object_generation_without_destination_snapshot() {
        let copied_request = request(
            address(0x1000),
            address(0x2000),
            MinorGcSurvivorAction::CopyToNursery,
        );
        let destination_storage = destination_storage(Vec::new());
        let object_generations = live_object_generations(vec![object_generation(copied_request)]);

        let err = boundary_minor_gc_object_generation_write_plan(
            &destination_storage,
            &object_generations,
        )
        .expect_err("object generation without destination bytes is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcObjectGenerationWriteMissingDestination {
                source_address,
                destination,
                action: MinorGcSurvivorAction::CopyToNursery,
                generation: HeapGeneration::Young,
            } if source_address == copied_request.source()
                && destination == copied_request.destination()
        ));
    }

    #[test]
    fn rejects_destination_snapshot_without_object_generation() {
        let copied_request = request(
            address(0x1000),
            address(0x2000),
            MinorGcSurvivorAction::CopyToNursery,
        );
        let destination_storage =
            destination_storage(vec![object_bytes(copied_request, vec![1, 2, 3, 4])]);
        let object_generations = live_object_generations(Vec::new());

        let err = boundary_minor_gc_object_generation_write_plan(
            &destination_storage,
            &object_generations,
        )
        .expect_err("destination bytes without object generation are rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcObjectGenerationWriteUnboundDestination {
                source_address,
                destination,
                action: MinorGcSurvivorAction::CopyToNursery,
                generation: HeapGeneration::Young,
            } if source_address == copied_request.source()
                && destination == copied_request.destination()
        ));
    }

    #[test]
    fn rejects_stale_destination_snapshot_for_object_generation() {
        let source = address(0x1000);
        let installed_request = request(
            source,
            address(0x2000),
            MinorGcSurvivorAction::CopyToNursery,
        );
        let current_request = request(
            source,
            address(0x3000),
            MinorGcSurvivorAction::CopyToNursery,
        );
        let destination_storage =
            destination_storage(vec![object_bytes(installed_request, vec![1, 2, 3, 4])]);
        let object_generations = live_object_generations(vec![object_generation(current_request)]);

        let err = boundary_minor_gc_object_generation_write_plan(
            &destination_storage,
            &object_generations,
        )
        .expect_err("stale destination snapshot is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcObjectGenerationWriteBindingMismatch {
                source_address,
                expected,
                expected_generation: HeapGeneration::Young,
                actual,
                actual_generation: HeapGeneration::Young,
            } if source_address == source
                && expected == current_request
                && actual == installed_request
        ));
    }

    #[test]
    fn rejects_duplicate_object_generation_source() {
        let source = address(0x1000);
        let first = request(
            source,
            address(0x2000),
            MinorGcSurvivorAction::CopyToNursery,
        );
        let second = request(
            source,
            address(0x3000),
            MinorGcSurvivorAction::CopyToNursery,
        );
        let destination_storage = destination_storage(Vec::new());
        let object_generations =
            live_object_generations(vec![object_generation(first), object_generation(second)]);

        let err = boundary_minor_gc_object_generation_write_plan(
            &destination_storage,
            &object_generations,
        )
        .expect_err("duplicate object-generation source is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcObjectGenerationWriteDuplicateSource {
                index: 1,
                source_address,
            } if source_address == source
        ));
    }

    #[test]
    fn rejects_duplicate_object_generation_destination() {
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
        let destination_storage = destination_storage(Vec::new());
        let object_generations =
            live_object_generations(vec![object_generation(first), object_generation(second)]);

        let err = boundary_minor_gc_object_generation_write_plan(
            &destination_storage,
            &object_generations,
        )
        .expect_err("duplicate object-generation destination is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcObjectGenerationWriteDuplicateDestination {
                index: 1,
                source_address,
                existing_source_address,
                destination: duplicate_destination,
            } if source_address == second.source()
                && existing_source_address == first.source()
                && duplicate_destination == destination
        ));
    }

    #[test]
    fn rejects_duplicate_destination_snapshot_source() {
        let source = address(0x1000);
        let first = request(
            source,
            address(0x2000),
            MinorGcSurvivorAction::CopyToNursery,
        );
        let second = request(
            source,
            address(0x3000),
            MinorGcSurvivorAction::CopyToNursery,
        );
        let destination_storage = destination_storage(vec![
            object_bytes(first, vec![1, 2, 3, 4]),
            object_bytes(second, vec![5, 6, 7, 8]),
        ]);
        let object_generations = live_object_generations(Vec::new());

        let err = boundary_minor_gc_object_generation_write_plan(
            &destination_storage,
            &object_generations,
        )
        .expect_err("duplicate destination snapshot source is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcObjectGenerationWriteDuplicateDestinationSource {
                index: 1,
                source_address,
            } if source_address == source
        ));
    }

    #[test]
    fn rejects_duplicate_destination_snapshot_destination() {
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
        let object_generations = live_object_generations(Vec::new());

        let err = boundary_minor_gc_object_generation_write_plan(
            &destination_storage,
            &object_generations,
        )
        .expect_err("duplicate destination snapshot address is rejected");

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
    fn rejects_object_generation_request_source_mismatch() {
        let source = address(0x1000);
        let request = request(
            address(0x3000),
            address(0x2000),
            MinorGcSurvivorAction::CopyToNursery,
        );
        let generation = object_generation_with_parts(
            source,
            request.destination(),
            request.action(),
            HeapGeneration::Young,
            request,
        );
        let destination_storage = destination_storage(Vec::new());
        let object_generations = live_object_generations(vec![generation]);

        let err = boundary_minor_gc_object_generation_write_plan(
            &destination_storage,
            &object_generations,
        )
        .expect_err("request source mismatch is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcObjectGenerationWriteRequestSourceMismatch {
                source_address,
                request_source,
            } if source_address == source && request_source == request.source()
        ));
    }

    #[test]
    fn rejects_object_generation_request_destination_mismatch() {
        let source = address(0x1000);
        let generation_destination = address(0x2000);
        let request = request(
            source,
            address(0x3000),
            MinorGcSurvivorAction::CopyToNursery,
        );
        let generation = object_generation_with_parts(
            source,
            generation_destination,
            request.action(),
            HeapGeneration::Young,
            request,
        );
        let destination_storage = destination_storage(Vec::new());
        let object_generations = live_object_generations(vec![generation]);

        let err = boundary_minor_gc_object_generation_write_plan(
            &destination_storage,
            &object_generations,
        )
        .expect_err("request destination mismatch is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcObjectGenerationWriteRequestDestinationMismatch {
                source_address,
                generation_destination: actual_generation_destination,
                request_destination,
            } if source_address == source
                && actual_generation_destination == generation_destination
                && request_destination == request.destination()
        ));
    }

    #[test]
    fn rejects_object_generation_request_action_mismatch() {
        let source = address(0x1000);
        let destination = address(0x2000);
        let request = request(source, destination, MinorGcSurvivorAction::PromoteToOld);
        let generation = object_generation_with_parts(
            source,
            destination,
            MinorGcSurvivorAction::CopyToNursery,
            HeapGeneration::Old,
            request,
        );
        let destination_storage = destination_storage(Vec::new());
        let object_generations = live_object_generations(vec![generation]);

        let err = boundary_minor_gc_object_generation_write_plan(
            &destination_storage,
            &object_generations,
        )
        .expect_err("request action mismatch is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcObjectGenerationWriteRequestActionMismatch {
                source_address,
                destination: actual_destination,
                generation_action: MinorGcSurvivorAction::CopyToNursery,
                request_action: MinorGcSurvivorAction::PromoteToOld,
            } if source_address == source && actual_destination == destination
        ));
    }

    #[test]
    fn rejects_object_generation_generation_mismatch() {
        let request = request(
            address(0x1000),
            address(0x2000),
            MinorGcSurvivorAction::CopyToNursery,
        );
        let generation = object_generation_with_parts(
            request.source(),
            request.destination(),
            request.action(),
            HeapGeneration::Old,
            request,
        );
        let destination_storage = destination_storage(Vec::new());
        let object_generations = live_object_generations(vec![generation]);

        let err = boundary_minor_gc_object_generation_write_plan(
            &destination_storage,
            &object_generations,
        )
        .expect_err("generation mismatch is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcObjectGenerationWriteGenerationMismatch {
                source_address,
                destination,
                expected: HeapGeneration::Young,
                actual: HeapGeneration::Old,
                action: MinorGcSurvivorAction::CopyToNursery,
            } if source_address == request.source()
                && destination == request.destination()
        ));
    }

    #[test]
    fn rejects_destination_payload_size_mismatch_for_write_plan() {
        let request = request_with_parts(
            address(0x1000),
            address(0x2000),
            MinorGcSurvivorAction::CopyToNursery,
            HeapGeneration::Young,
            4,
        );
        let destination_storage = destination_storage(vec![object_bytes(request, vec![1, 2, 3])]);
        let object_generations = live_object_generations(vec![object_generation(request)]);

        let err = boundary_minor_gc_object_generation_write_plan(
            &destination_storage,
            &object_generations,
        )
        .expect_err("destination payload length mismatch is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcDestinationPayloadSizeMismatch {
                destination,
                expected: 4,
                actual: 3,
            } if destination == request.destination()
        ));
    }
}

#[cfg(test)]
mod forwarding_destination_binding_tests {
    use super::*;

    fn address(bits: usize) -> GcHeapAddress {
        GcHeapAddress::new(bits).expect("test address is non-zero")
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
        AllocationCollectorPollObjectByteCopyRequest::for_test(
            source,
            destination,
            action,
            generation_for_destination_action(action),
            4,
            8,
        )
    }

    fn object_bytes(
        request: AllocationCollectorPollObjectByteCopyRequest,
        destination_bytes: Vec<u8>,
    ) -> EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes {
        EvalGcStressBoundaryMinorGcLiveDestinationObjectBytes::new(request, destination_bytes)
    }

    fn forwarding_slot(
        source: GcHeapAddress,
        destination: GcHeapAddress,
        generation: HeapGeneration,
    ) -> MinorGcForwardingSlot {
        MinorGcForwardingSlot::with_forwarded_value(source, heap(destination, generation))
    }

    #[test]
    fn matches_forwarding_slots_to_destination_snapshots() {
        let copied_source = address(0x1000);
        let copied_destination = address(0x2000);
        let promoted_source = address(0x3000);
        let promoted_destination = address(0x4000);
        let copied_request = request(
            copied_source,
            copied_destination,
            MinorGcSurvivorAction::CopyToNursery,
        );
        let promoted_request = request(
            promoted_source,
            promoted_destination,
            MinorGcSurvivorAction::PromoteToOld,
        );
        let copied_bytes = vec![1, 2, 3, 4];
        let promoted_bytes = vec![5, 6, 7, 8];
        let forwarding_slots = [
            forwarding_slot(copied_source, copied_destination, HeapGeneration::Young),
            forwarding_slot(promoted_source, promoted_destination, HeapGeneration::Old),
        ];
        let destination_objects = [
            object_bytes(copied_request, copied_bytes.clone()),
            object_bytes(promoted_request, promoted_bytes.clone()),
        ];

        let bindings = boundary_minor_gc_forwarding_destination_bindings_from_slots(
            &forwarding_slots,
            &destination_objects,
        )
        .expect("forwarding destination bindings validate");

        assert_eq!(bindings.len(), 2);
        assert_eq!(bindings[0].source(), copied_source);
        assert_eq!(bindings[0].destination(), copied_destination);
        assert_eq!(bindings[0].generation(), HeapGeneration::Young);
        assert_eq!(
            bindings[0].forwarded_value(),
            heap(copied_destination, HeapGeneration::Young)
        );
        assert_eq!(bindings[0].request(), copied_request);
        assert_eq!(bindings[0].destination_bytes(), copied_bytes);
        assert_eq!(bindings[1].source(), promoted_source);
        assert_eq!(bindings[1].destination(), promoted_destination);
        assert_eq!(bindings[1].generation(), HeapGeneration::Old);
        assert_eq!(
            bindings[1].forwarded_value(),
            heap(promoted_destination, HeapGeneration::Old)
        );
        assert_eq!(bindings[1].request(), promoted_request);
        assert_eq!(bindings[1].destination_bytes(), promoted_bytes);
    }

    #[test]
    fn rejects_destination_snapshot_without_forwarding_value() {
        let source = address(0x1000);
        let destination = address(0x2000);
        let request = request(source, destination, MinorGcSurvivorAction::CopyToNursery);
        let destination_objects = [object_bytes(request, vec![1, 2, 3, 4])];

        let err =
            boundary_minor_gc_forwarding_destination_bindings_from_slots(&[], &destination_objects)
                .expect_err("missing forwarding value is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcDestinationForwardingMissing {
                source_address: actual_source,
                destination: actual_destination,
            } if actual_source == source && actual_destination == destination
        ));
    }

    #[test]
    fn rejects_forwarding_value_without_destination_snapshot() {
        let source = address(0x1000);
        let destination = address(0x2000);
        let forwarding_slots = [forwarding_slot(source, destination, HeapGeneration::Young)];

        let err =
            boundary_minor_gc_forwarding_destination_bindings_from_slots(&forwarding_slots, &[])
                .expect_err("forwarding without destination is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcForwardingDestinationMissing {
                source_address: actual_source,
            } if actual_source == source
        ));
    }

    #[test]
    fn rejects_duplicate_forwarding_source() {
        let source = address(0x1000);
        let destination = address(0x2000);
        let request = request(source, destination, MinorGcSurvivorAction::CopyToNursery);
        let forwarding_slots = [
            forwarding_slot(source, destination, HeapGeneration::Young),
            forwarding_slot(source, destination, HeapGeneration::Young),
        ];
        let destination_objects = [object_bytes(request, vec![1, 2, 3, 4])];

        let err = boundary_minor_gc_forwarding_destination_bindings_from_slots(
            &forwarding_slots,
            &destination_objects,
        )
        .expect_err("duplicate forwarding source is rejected");

        assert_eq!(
            err,
            EvalHeapError::CollectorPollForwardingSlotDuplicateSource {
                index: 1,
                address: source,
            }
        );
    }

    #[test]
    fn rejects_non_heap_forwarding_metadata() {
        let source = address(0x1000);
        let destination = address(0x2000);
        let request = request(source, destination, MinorGcSurvivorAction::CopyToNursery);
        let forwarding_slots = [MinorGcForwardingSlot::with_forwarded_value(
            source,
            ResolvedValueGeneration::Inline,
        )];
        let destination_objects = [object_bytes(request, vec![1, 2, 3, 4])];

        let err = boundary_minor_gc_forwarding_destination_bindings_from_slots(
            &forwarding_slots,
            &destination_objects,
        )
        .expect_err("non-heap forwarding metadata is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcForwardingDestinationNonHeap {
                source_address: actual_source,
                actual: ResolvedValueGeneration::Inline,
            } if actual_source == source
        ));
    }

    #[test]
    fn rejects_forwarding_destination_mismatch() {
        let source = address(0x1000);
        let destination = address(0x2000);
        let other_destination = address(0x3000);
        let request = request(source, destination, MinorGcSurvivorAction::CopyToNursery);
        let forwarding_slots = [forwarding_slot(
            source,
            other_destination,
            HeapGeneration::Young,
        )];
        let destination_objects = [object_bytes(request, vec![1, 2, 3, 4])];

        let err = boundary_minor_gc_forwarding_destination_bindings_from_slots(
            &forwarding_slots,
            &destination_objects,
        )
        .expect_err("destination mismatch is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcForwardingDestinationMismatch {
                source_address: actual_source,
                expected,
                actual,
            } if actual_source == source
                && expected == destination
                && actual == other_destination
        ));
    }

    #[test]
    fn rejects_forwarding_generation_mismatch() {
        let source = address(0x1000);
        let destination = address(0x2000);
        let request = request(source, destination, MinorGcSurvivorAction::CopyToNursery);
        let forwarding_slots = [forwarding_slot(source, destination, HeapGeneration::Old)];
        let destination_objects = [object_bytes(request, vec![1, 2, 3, 4])];

        let err = boundary_minor_gc_forwarding_destination_bindings_from_slots(
            &forwarding_slots,
            &destination_objects,
        )
        .expect_err("generation mismatch is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcForwardingGenerationMismatch {
                source_address: actual_source,
                destination: actual_destination,
                expected: HeapGeneration::Young,
                actual: HeapGeneration::Old,
                action: MinorGcSurvivorAction::CopyToNursery,
            } if actual_source == source && actual_destination == destination
        ));
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

    fn duplicated_writebacks(
        source: EvalRootSource,
        generation_value: ResolvedValueGeneration,
        typed_value: Value,
    ) -> EvalGcStressBoundaryMinorGcLiveReferenceWritebacks {
        let application = EvalGcStressBoundaryMinorGcReferenceWritebackApplication::new(
            AllocationCollectorPollReferenceWritebackReport::default(),
            vec![
                AllocationCollectorPollRootWritebackSlot::new(source.clone(), generation_value),
                AllocationCollectorPollRootWritebackSlot::new(source.clone(), generation_value),
            ],
            vec![
                AllocationCollectorPollRootValueWritebackSlot::new(source.clone(), typed_value),
                AllocationCollectorPollRootValueWritebackSlot::new(source, typed_value),
            ],
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

    fn live_writeback_destination_bindings(
        root_writeback_bindings: Vec<EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding>,
    ) -> EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings {
        let install_report =
            live_writeback_destination_binding_install_report(&root_writeback_bindings, &[]);
        EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings {
            install_report,
            root_writeback_bindings,
            heap_field_writeback_bindings: Vec::new(),
            expected_remembered_set: None,
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
    fn plans_root_writeback_writes_from_live_bindings() {
        let source = address(0x1000);
        let destination = address(0x2000);
        let root_source = root_source(0);
        let request = request(source, destination, MinorGcSurvivorAction::CopyToNursery);
        let destination_bytes = vec![1, 2, 3, 4];
        let replacement_value = heap_value(ValueTag::Lambda, destination);
        let writebacks = writebacks(
            root_source.clone(),
            heap(destination, HeapGeneration::Young),
            replacement_value,
        );
        let destination_storage = destination_storage(request, destination_bytes.clone());
        let bindings = boundary_minor_gc_root_writeback_destination_bindings(
            &writebacks,
            &destination_storage,
        )
        .expect("binding report succeeds");
        let live_bindings = live_writeback_destination_bindings(bindings);

        let write_plan = boundary_minor_gc_root_writeback_write_plan(&writebacks, &live_bindings)
            .expect("root writeback write plan validates");

        assert_eq!(write_plan.len(), 1);
        assert_eq!(write_plan.report().roots(), 1);
        assert_eq!(write_plan.report().copied_to_nursery(), 1);
        assert_eq!(write_plan.report().promoted_to_old(), 0);
        assert_eq!(write_plan.report().payload_bytes(), destination_bytes.len());
        assert_eq!(
            write_plan.writes()[0].allocation_domain(),
            HeapAllocationDomain::Worker
        );
        assert_eq!(write_plan.writes()[0].root_source(), &root_source);
        assert_eq!(write_plan.writes()[0].replacement_tag(), ValueTag::Lambda);
        assert!(
            write_plan.writes()[0]
                .replacement_value()
                .raw_eq(replacement_value)
        );
        assert_eq!(write_plan.writes()[0].destination(), destination);
        assert_eq!(write_plan.writes()[0].generation(), HeapGeneration::Young);
        assert_eq!(
            write_plan.writes()[0].replacement_metadata(),
            heap(destination, HeapGeneration::Young)
        );
        assert_eq!(write_plan.writes()[0].request(), request);
        assert_eq!(
            write_plan.writes()[0].destination_bytes(),
            destination_bytes
        );
    }

    #[test]
    fn outcome_root_writebacks_reject_duplicate_physical_value_stack_slot() {
        let source = address(0x1000);
        let first_destination = address(0x2000);
        let second_destination = address(0x3000);
        let root_source = root_source(0);
        let first_replacement = heap_value(ValueTag::Lambda, first_destination);
        let second_replacement = heap_value(ValueTag::Lambda, second_destination);
        let plan = EvalGcStressBoundaryMinorGcRootWritebackWritePlan::new(vec![
            EvalGcStressBoundaryMinorGcRootWritebackWrite {
                allocation_domain: HeapAllocationDomain::Worker,
                root_source: root_source.clone(),
                replacement_tag: ValueTag::Lambda,
                replacement_value: first_replacement,
                destination: first_destination,
                generation: HeapGeneration::Young,
                replacement_metadata: heap(first_destination, HeapGeneration::Young),
                request: request(
                    source,
                    first_destination,
                    MinorGcSurvivorAction::CopyToNursery,
                ),
                destination_bytes: vec![1, 2, 3, 4],
            },
            EvalGcStressBoundaryMinorGcRootWritebackWrite {
                allocation_domain: HeapAllocationDomain::PermanentShared,
                root_source: root_source.clone(),
                replacement_tag: ValueTag::Lambda,
                replacement_value: second_replacement,
                destination: second_destination,
                generation: HeapGeneration::Young,
                replacement_metadata: heap(second_destination, HeapGeneration::Young),
                request: request(
                    source,
                    second_destination,
                    MinorGcSurvivorAction::CopyToNursery,
                ),
                destination_bytes: vec![1, 2, 3, 4],
            },
        ]);
        let mut outcome_value = heap_value(ValueTag::Lambda, source);
        let original_value = outcome_value;
        let heap = EvalHeap::new();

        let err = apply_boundary_minor_gc_outcome_root_writebacks(&mut outcome_value, &heap, &plan)
            .expect_err("duplicate physical outcome root is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcOutcomeRootWritebackDuplicateValueStackRoot {
                index: 1,
                root_source: actual_root_source,
            } if actual_root_source == root_source
        ));
        assert!(outcome_value.raw_eq(original_value));
    }

    #[test]
    fn live_outcome_root_writebacks_reject_source_tag_mismatch_before_body_write() {
        let mut eval_heap = EvalHeap::with_initial_chunk_bytes(512).expect("heap creates");
        // FV-3: object-copy requests describe record-table worker objects
        // (the Tier-B B2 relocation scaffolding placement).
        eval_heap.use_record_worker_closures_for_gc_scaffolding();
        let source = eval_heap
            .alloc_lambda(EvalLambda::new(
                IrId::new(7),
                IrId::new(8),
                FrameId::new(9),
                EvalEnv::default(),
            ))
            .expect("source lambda allocates");
        let destination = eval_heap
            .alloc_lambda(EvalLambda::new(
                IrId::new(0),
                IrId::new(0),
                FrameId::new(0),
                EvalEnv::default(),
            ))
            .expect("destination lambda allocates");
        let request = eval_heap
            .collector_poll_minor_gc_object_byte_copy_request_for_test(
                source,
                destination,
                MinorGcSurvivorAction::CopyToNursery,
            )
            .expect("test object-copy request builds");
        let root_source = root_source(0);
        let mut outcome_value = heap_value(ValueTag::String, request.source());
        let original_value = outcome_value;
        let plan = EvalGcStressBoundaryMinorGcRootWritebackWritePlan::new(vec![
            EvalGcStressBoundaryMinorGcRootWritebackWrite {
                allocation_domain: HeapAllocationDomain::Worker,
                root_source,
                replacement_tag: ValueTag::String,
                replacement_value: heap_value(ValueTag::String, request.destination()),
                destination: request.destination(),
                generation: HeapGeneration::Young,
                replacement_metadata: heap(request.destination(), HeapGeneration::Young),
                request,
                destination_bytes: vec![0; request.size_bytes()],
            },
        ]);
        assert!(matches!(
            eval_heap
                .validate_collector_poll_minor_gc_object_body_binding(request, ValueTag::Lambda),
            Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
                reason: "destination record body does not match source record body",
                ..
            })
        ));

        let err = apply_boundary_minor_gc_live_outcome_root_writebacks(
            &mut outcome_value,
            &mut eval_heap,
            &plan,
        )
        .expect_err("source tag mismatch is rejected before body writes");

        assert!(matches!(
            err,
            EvalHeapError::RecordTypeMismatch {
                expected: ValueTag::String,
                actual: ValueTag::Lambda,
                ..
            }
        ));
        assert!(outcome_value.raw_eq(original_value));
        assert!(matches!(
            eval_heap
                .validate_collector_poll_minor_gc_object_body_binding(request, ValueTag::Lambda),
            Err(EvalHeapError::CollectorPollObjectBodyWriteBindingMismatch {
                reason: "destination record body does not match source record body",
                ..
            })
        ));
    }

    #[test]
    fn rejects_root_writeback_write_without_installed_binding() {
        let destination = address(0x2000);
        let root_source = root_source(0);
        let current_writebacks = writebacks(
            root_source.clone(),
            heap(destination, HeapGeneration::Young),
            heap_value(ValueTag::Lambda, destination),
        );
        let live_bindings = EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings::default();

        let err = boundary_minor_gc_root_writeback_write_plan(&current_writebacks, &live_bindings)
            .expect_err("missing root writeback binding is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcRootWritebackWriteMissingBinding {
                allocation_domain: HeapAllocationDomain::Worker,
                root_source: actual_root_source,
                replacement_tag: ValueTag::Lambda,
                destination: actual_destination,
                generation: HeapGeneration::Young,
            } if actual_root_source == root_source && actual_destination == destination
        ));
    }

    #[test]
    fn rejects_root_writeback_write_stale_binding() {
        let source = address(0x1000);
        let destination = address(0x2000);
        let stale_destination = address(0x3000);
        let root_source = root_source(0);
        let current_writebacks = writebacks(
            root_source.clone(),
            heap(destination, HeapGeneration::Young),
            heap_value(ValueTag::Lambda, destination),
        );
        let stale_writebacks = writebacks(
            root_source.clone(),
            heap(stale_destination, HeapGeneration::Young),
            heap_value(ValueTag::Lambda, stale_destination),
        );
        let stale_storage = destination_storage(
            request(
                source,
                stale_destination,
                MinorGcSurvivorAction::CopyToNursery,
            ),
            vec![1, 2, 3, 4],
        );
        let stale_bindings = boundary_minor_gc_root_writeback_destination_bindings(
            &stale_writebacks,
            &stale_storage,
        )
        .expect("stale binding report succeeds");
        let live_bindings = live_writeback_destination_bindings(stale_bindings);

        let err = boundary_minor_gc_root_writeback_write_plan(&current_writebacks, &live_bindings)
            .expect_err("stale root writeback binding is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcRootWritebackWriteBindingMismatch {
                allocation_domain: HeapAllocationDomain::Worker,
                root_source: actual_root_source,
                expected_tag: ValueTag::Lambda,
                expected_destination,
                expected_generation: HeapGeneration::Young,
                actual_tag: ValueTag::Lambda,
                actual_destination,
                actual_generation: HeapGeneration::Young,
            } if actual_root_source == root_source
                && expected_destination == destination
                && actual_destination == stale_destination
        ));
    }

    #[test]
    fn rejects_unbound_root_writeback_binding() {
        let source = address(0x1000);
        let destination = address(0x2000);
        let root_source = root_source(0);
        let writebacks = writebacks(
            root_source.clone(),
            heap(destination, HeapGeneration::Young),
            heap_value(ValueTag::Lambda, destination),
        );
        let destination_storage = destination_storage(
            request(source, destination, MinorGcSurvivorAction::CopyToNursery),
            vec![1, 2, 3, 4],
        );
        let bindings = boundary_minor_gc_root_writeback_destination_bindings(
            &writebacks,
            &destination_storage,
        )
        .expect("binding report succeeds");
        let live_bindings = live_writeback_destination_bindings(bindings);
        let empty_writebacks = EvalGcStressBoundaryMinorGcLiveReferenceWritebacks::default();

        let err = boundary_minor_gc_root_writeback_write_plan(&empty_writebacks, &live_bindings)
            .expect_err("unbound root writeback binding is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcRootWritebackWriteUnboundBinding {
                allocation_domain: HeapAllocationDomain::Worker,
                root_source: actual_root_source,
                replacement_tag: ValueTag::Lambda,
                destination: actual_destination,
                generation: HeapGeneration::Young,
            } if actual_root_source == root_source && actual_destination == destination
        ));
    }

    #[test]
    fn rejects_duplicate_root_writeback_write_sources() {
        let source = address(0x1000);
        let destination = address(0x2000);
        let root_source = root_source(0);
        let writebacks = duplicated_writebacks(
            root_source.clone(),
            heap(destination, HeapGeneration::Young),
            heap_value(ValueTag::Lambda, destination),
        );
        let destination_storage = destination_storage(
            request(source, destination, MinorGcSurvivorAction::CopyToNursery),
            vec![1, 2, 3, 4],
        );
        let bindings = boundary_minor_gc_root_writeback_destination_bindings(
            &writebacks,
            &destination_storage,
        )
        .expect("duplicate source binding report currently mirrors the slots");
        let live_bindings = live_writeback_destination_bindings(bindings);

        let err = boundary_minor_gc_root_writeback_write_plan(&writebacks, &live_bindings)
            .expect_err("duplicate live root writeback sources are rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcRootWritebackWriteDuplicateSource {
                index: 1,
                allocation_domain: HeapAllocationDomain::Worker,
                root_source: actual_root_source,
            } if actual_root_source == root_source
        ));
    }

    #[test]
    fn rejects_duplicate_root_writeback_write_bindings() {
        let source = address(0x1000);
        let destination = address(0x2000);
        let root_source = root_source(0);
        let writebacks = writebacks(
            root_source.clone(),
            heap(destination, HeapGeneration::Young),
            heap_value(ValueTag::Lambda, destination),
        );
        let destination_storage = destination_storage(
            request(source, destination, MinorGcSurvivorAction::CopyToNursery),
            vec![1, 2, 3, 4],
        );
        let binding = boundary_minor_gc_root_writeback_destination_bindings(
            &writebacks,
            &destination_storage,
        )
        .expect("binding report succeeds")[0]
            .clone();
        let live_bindings = live_writeback_destination_bindings(vec![binding.clone(), binding]);

        let err = boundary_minor_gc_root_writeback_write_plan(&writebacks, &live_bindings)
            .expect_err("duplicate root writeback destination bindings are rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcRootWritebackWriteDuplicateBinding {
                index: 1,
                allocation_domain: HeapAllocationDomain::Worker,
                root_source: actual_root_source,
            } if actual_root_source == root_source
        ));
    }

    #[test]
    fn rejects_root_writeback_binding_request_destination_mismatch() {
        let source = address(0x1000);
        let destination = address(0x2000);
        let request_destination = address(0x3000);
        let root_source = root_source(0);
        let writebacks = writebacks(
            root_source.clone(),
            heap(destination, HeapGeneration::Young),
            heap_value(ValueTag::Lambda, destination),
        );
        let binding = EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding::new(
            HeapAllocationDomain::Worker,
            root_source.clone(),
            ValueTag::Lambda,
            destination,
            HeapGeneration::Young,
            request(
                source,
                request_destination,
                MinorGcSurvivorAction::CopyToNursery,
            ),
            vec![1, 2, 3, 4],
        );
        let live_bindings = live_writeback_destination_bindings(vec![binding]);

        let err = boundary_minor_gc_root_writeback_write_plan(&writebacks, &live_bindings)
            .expect_err("binding request destination mismatch is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcRootWritebackWriteRequestDestinationMismatch {
                allocation_domain: HeapAllocationDomain::Worker,
                root_source: actual_root_source,
                binding_destination,
                request_destination: actual_request_destination,
            } if actual_root_source == root_source
                && binding_destination == destination
                && actual_request_destination == request_destination
        ));
    }

    #[test]
    fn rejects_root_writeback_binding_generation_mismatch() {
        let source = address(0x1000);
        let destination = address(0x2000);
        let root_source = root_source(0);
        let writebacks = writebacks(
            root_source.clone(),
            heap(destination, HeapGeneration::Young),
            heap_value(ValueTag::Lambda, destination),
        );
        let binding = EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding::new(
            HeapAllocationDomain::Worker,
            root_source.clone(),
            ValueTag::Lambda,
            destination,
            HeapGeneration::Old,
            request(source, destination, MinorGcSurvivorAction::CopyToNursery),
            vec![1, 2, 3, 4],
        );
        let live_bindings = live_writeback_destination_bindings(vec![binding]);

        let err = boundary_minor_gc_root_writeback_write_plan(&writebacks, &live_bindings)
            .expect_err("binding generation/action mismatch is rejected");

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

    #[test]
    fn rejects_root_writeback_binding_payload_size_mismatch() {
        let source = address(0x1000);
        let destination = address(0x2000);
        let root_source = root_source(0);
        let writebacks = writebacks(
            root_source.clone(),
            heap(destination, HeapGeneration::Young),
            heap_value(ValueTag::Lambda, destination),
        );
        let binding = EvalGcStressBoundaryMinorGcRootWritebackDestinationBinding::new(
            HeapAllocationDomain::Worker,
            root_source,
            ValueTag::Lambda,
            destination,
            HeapGeneration::Young,
            request(source, destination, MinorGcSurvivorAction::CopyToNursery),
            vec![1, 2, 3],
        );
        let live_bindings = live_writeback_destination_bindings(vec![binding]);

        let err = boundary_minor_gc_root_writeback_write_plan(&writebacks, &live_bindings)
            .expect_err("binding payload length mismatch is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcDestinationPayloadSizeMismatch {
                destination: actual_destination,
                expected: 4,
                actual: 3,
            } if actual_destination == destination
        ));
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

    fn duplicated_writebacks(
        validation_object: GcHeapAddress,
        writeback_object: GcHeapAddress,
        replacement: ResolvedValueGeneration,
    ) -> EvalGcStressBoundaryMinorGcLiveReferenceWritebacks {
        let application = EvalGcStressBoundaryMinorGcReferenceWritebackApplication::new(
            AllocationCollectorPollReferenceWritebackReport::default(),
            Vec::new(),
            Vec::new(),
            vec![
                AllocationCollectorPollHeapFieldWritebackSlot::new(
                    validation_object,
                    writeback_object,
                    0,
                    field_source(),
                    replacement,
                ),
                AllocationCollectorPollHeapFieldWritebackSlot::new(
                    validation_object,
                    writeback_object,
                    0,
                    field_source(),
                    replacement,
                ),
            ],
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

    fn live_writeback_destination_bindings(
        heap_field_writeback_bindings: Vec<
            EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding,
        >,
    ) -> EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings {
        let install_report =
            live_writeback_destination_binding_install_report(&[], &heap_field_writeback_bindings);
        EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings {
            install_report,
            root_writeback_bindings: Vec::new(),
            heap_field_writeback_bindings,
            expected_remembered_set: None,
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
    fn plans_heap_field_writeback_writes_from_live_bindings() {
        let old_object = address(0x1000);
        let source = address(0x2000);
        let replacement_destination = address(0x3000);
        let replacement_request = request(
            source,
            replacement_destination,
            MinorGcSurvivorAction::CopyToNursery,
        );
        let replacement_bytes = vec![1, 2, 3, 4];
        let writebacks = writebacks(
            old_object,
            old_object,
            heap(replacement_destination, HeapGeneration::Young),
        );
        let destination_storage =
            destination_storage(vec![(replacement_request, replacement_bytes.clone())]);
        let bindings = boundary_minor_gc_heap_field_writeback_destination_bindings(
            &writebacks,
            &destination_storage,
        )
        .expect("heap-field binding report succeeds");
        let live_bindings = live_writeback_destination_bindings(bindings);

        let write_plan =
            boundary_minor_gc_heap_field_writeback_write_plan(&writebacks, &live_bindings)
                .expect("heap-field writeback write plan validates");

        assert_eq!(write_plan.len(), 1);
        assert_eq!(write_plan.report().fields(), 1);
        assert_eq!(write_plan.report().copied_replacements_to_nursery(), 1);
        assert_eq!(write_plan.report().promoted_replacements_to_old(), 0);
        assert_eq!(
            write_plan.report().replacement_payload_bytes(),
            replacement_bytes.len()
        );
        assert_eq!(write_plan.report().writeback_object_payload_bytes(), 0);
        assert_eq!(
            write_plan.writes()[0].allocation_domain(),
            HeapAllocationDomain::Worker
        );
        assert_eq!(write_plan.writes()[0].validation_object(), old_object);
        assert_eq!(write_plan.writes()[0].writeback_object(), old_object);
        assert_eq!(write_plan.writes()[0].field_index(), 0);
        assert_eq!(write_plan.writes()[0].source(), &field_source());
        assert_eq!(
            write_plan.writes()[0].replacement_destination(),
            replacement_destination
        );
        assert_eq!(
            write_plan.writes()[0].replacement_generation(),
            HeapGeneration::Young
        );
        assert_eq!(
            write_plan.writes()[0].replacement_metadata(),
            heap(replacement_destination, HeapGeneration::Young)
        );
        assert_eq!(
            write_plan.writes()[0].replacement_request(),
            replacement_request
        );
        assert_eq!(
            write_plan.writes()[0].replacement_destination_bytes(),
            replacement_bytes
        );
        assert_eq!(write_plan.writes()[0].writeback_object_request(), None);
        assert_eq!(
            write_plan.writes()[0].writeback_object_destination_bytes(),
            None
        );
    }

    #[test]
    fn rejects_heap_field_writeback_write_without_installed_binding() {
        let old_object = address(0x1000);
        let replacement_destination = address(0x3000);
        let writebacks = writebacks(
            old_object,
            old_object,
            heap(replacement_destination, HeapGeneration::Young),
        );
        let live_bindings = EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings::default();

        let err = boundary_minor_gc_heap_field_writeback_write_plan(&writebacks, &live_bindings)
            .expect_err("missing heap-field binding is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteMissingBinding {
                allocation_domain: HeapAllocationDomain::Worker,
                writeback_object,
                field_index: 0,
                field_source,
                replacement,
                generation: HeapGeneration::Young,
            } if writeback_object == old_object
                && field_source == (HeapEdgeSource::ListElement { index: 0 })
                && replacement == replacement_destination
        ));
    }

    #[test]
    fn rejects_heap_field_writeback_write_stale_binding() {
        let old_object = address(0x1000);
        let source = address(0x2000);
        let replacement_destination = address(0x3000);
        let stale_replacement_destination = address(0x4000);
        let current_writebacks = writebacks(
            old_object,
            old_object,
            heap(replacement_destination, HeapGeneration::Young),
        );
        let stale_writebacks = writebacks(
            old_object,
            old_object,
            heap(stale_replacement_destination, HeapGeneration::Young),
        );
        let stale_storage = destination_storage(vec![(
            request(
                source,
                stale_replacement_destination,
                MinorGcSurvivorAction::CopyToNursery,
            ),
            vec![1, 2, 3, 4],
        )]);
        let stale_bindings = boundary_minor_gc_heap_field_writeback_destination_bindings(
            &stale_writebacks,
            &stale_storage,
        )
        .expect("stale heap-field binding report succeeds");
        let live_bindings = live_writeback_destination_bindings(stale_bindings);

        let err =
            boundary_minor_gc_heap_field_writeback_write_plan(&current_writebacks, &live_bindings)
                .expect_err("stale heap-field binding is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteBindingMismatch {
                allocation_domain: HeapAllocationDomain::Worker,
                writeback_object,
                field_index: 0,
                field_source,
                expected_replacement,
                expected_generation: HeapGeneration::Young,
                actual_replacement,
                actual_generation: HeapGeneration::Young,
            } if writeback_object == old_object
                && field_source == (HeapEdgeSource::ListElement { index: 0 })
                && expected_replacement == replacement_destination
                && actual_replacement == stale_replacement_destination
        ));
    }

    #[test]
    fn rejects_duplicate_heap_field_writeback_write_sources() {
        let old_object = address(0x1000);
        let source = address(0x2000);
        let replacement_destination = address(0x3000);
        let writebacks = duplicated_writebacks(
            old_object,
            old_object,
            heap(replacement_destination, HeapGeneration::Young),
        );
        let destination_storage = destination_storage(vec![(
            request(
                source,
                replacement_destination,
                MinorGcSurvivorAction::CopyToNursery,
            ),
            vec![1, 2, 3, 4],
        )]);
        let bindings = boundary_minor_gc_heap_field_writeback_destination_bindings(
            &writebacks,
            &destination_storage,
        )
        .expect("duplicate heap-field binding report currently mirrors the slots");
        let live_bindings = live_writeback_destination_bindings(bindings);

        let err = boundary_minor_gc_heap_field_writeback_write_plan(&writebacks, &live_bindings)
            .expect_err("duplicate heap-field writeback sources are rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteDuplicateSource {
                index: 1,
                allocation_domain: HeapAllocationDomain::Worker,
                writeback_object,
                field_index: 0,
                field_source,
            } if writeback_object == old_object
                && field_source == (HeapEdgeSource::ListElement { index: 0 })
        ));
    }

    #[test]
    fn rejects_duplicate_heap_field_writeback_write_bindings() {
        let old_object = address(0x1000);
        let source = address(0x2000);
        let replacement_destination = address(0x3000);
        let writebacks = writebacks(
            old_object,
            old_object,
            heap(replacement_destination, HeapGeneration::Young),
        );
        let destination_storage = destination_storage(vec![(
            request(
                source,
                replacement_destination,
                MinorGcSurvivorAction::CopyToNursery,
            ),
            vec![1, 2, 3, 4],
        )]);
        let binding = boundary_minor_gc_heap_field_writeback_destination_bindings(
            &writebacks,
            &destination_storage,
        )
        .expect("heap-field binding report succeeds")[0]
            .clone();
        let live_bindings = live_writeback_destination_bindings(vec![binding.clone(), binding]);

        let err = boundary_minor_gc_heap_field_writeback_write_plan(&writebacks, &live_bindings)
            .expect_err("duplicate heap-field destination bindings are rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteDuplicateBinding {
                index: 1,
                allocation_domain: HeapAllocationDomain::Worker,
                writeback_object,
                field_index: 0,
                field_source,
            } if writeback_object == old_object
                && field_source == (HeapEdgeSource::ListElement { index: 0 })
        ));
    }

    #[test]
    fn rejects_unbound_heap_field_writeback_binding() {
        let old_object = address(0x1000);
        let source = address(0x2000);
        let replacement_destination = address(0x3000);
        let writebacks = writebacks(
            old_object,
            old_object,
            heap(replacement_destination, HeapGeneration::Young),
        );
        let destination_storage = destination_storage(vec![(
            request(
                source,
                replacement_destination,
                MinorGcSurvivorAction::CopyToNursery,
            ),
            vec![1, 2, 3, 4],
        )]);
        let bindings = boundary_minor_gc_heap_field_writeback_destination_bindings(
            &writebacks,
            &destination_storage,
        )
        .expect("heap-field binding report succeeds");
        let live_bindings = live_writeback_destination_bindings(bindings);
        let empty_writebacks = EvalGcStressBoundaryMinorGcLiveReferenceWritebacks::default();

        let err =
            boundary_minor_gc_heap_field_writeback_write_plan(&empty_writebacks, &live_bindings)
                .expect_err("unbound heap-field binding is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteUnboundBinding {
                allocation_domain: HeapAllocationDomain::Worker,
                writeback_object,
                field_index: 0,
                field_source,
                replacement,
                generation: HeapGeneration::Young,
            } if writeback_object == old_object
                && field_source == (HeapEdgeSource::ListElement { index: 0 })
                && replacement == replacement_destination
        ));
    }

    #[test]
    fn rejects_heap_field_binding_replacement_payload_size_mismatch() {
        let old_object = address(0x1000);
        let source = address(0x2000);
        let replacement_destination = address(0x3000);
        let writebacks = writebacks(
            old_object,
            old_object,
            heap(replacement_destination, HeapGeneration::Young),
        );
        let binding = EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding::new(
            HeapAllocationDomain::Worker,
            old_object,
            old_object,
            0,
            field_source(),
            replacement_destination,
            HeapGeneration::Young,
            request(
                source,
                replacement_destination,
                MinorGcSurvivorAction::CopyToNursery,
            ),
            vec![1, 2, 3],
            None,
            None,
        );
        let live_bindings = live_writeback_destination_bindings(vec![binding]);

        let err = boundary_minor_gc_heap_field_writeback_write_plan(&writebacks, &live_bindings)
            .expect_err("binding replacement payload length mismatch is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcDestinationPayloadSizeMismatch {
                destination,
                expected: 4,
                actual: 3,
            } if destination == replacement_destination
        ));
    }

    #[test]
    fn plans_copied_nursery_heap_field_writeback_writes_from_live_bindings() {
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
        .expect("copied heap-field binding report succeeds");
        let live_bindings = live_writeback_destination_bindings(bindings);

        let write_plan =
            boundary_minor_gc_heap_field_writeback_write_plan(&writebacks, &live_bindings)
                .expect("copied heap-field writeback write plan validates");

        assert_eq!(write_plan.len(), 1);
        assert_eq!(write_plan.report().fields(), 1);
        assert_eq!(write_plan.report().copied_replacements_to_nursery(), 0);
        assert_eq!(write_plan.report().promoted_replacements_to_old(), 1);
        assert_eq!(
            write_plan.report().replacement_payload_bytes(),
            replacement_bytes.len()
        );
        assert_eq!(
            write_plan.report().writeback_object_payload_bytes(),
            writeback_bytes.len()
        );
        assert_eq!(
            write_plan.writes()[0].validation_object(),
            validation_object
        );
        assert_eq!(write_plan.writes()[0].writeback_object(), writeback_object);
        assert_eq!(
            write_plan.writes()[0].replacement_destination(),
            replacement_destination
        );
        assert_eq!(
            write_plan.writes()[0].replacement_generation(),
            HeapGeneration::Old
        );
        assert_eq!(
            write_plan.writes()[0].replacement_request(),
            replacement_request
        );
        assert_eq!(
            write_plan.writes()[0].replacement_destination_bytes(),
            replacement_bytes
        );
        assert_eq!(
            write_plan.writes()[0].writeback_object_request(),
            Some(writeback_request)
        );
        assert_eq!(
            write_plan.writes()[0].writeback_object_destination_bytes(),
            Some(writeback_bytes.as_slice())
        );
    }

    #[test]
    fn empty_heap_field_writeback_write_plan_is_empty() {
        let writebacks = EvalGcStressBoundaryMinorGcLiveReferenceWritebacks::default();
        let live_bindings = EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings::default();

        let write_plan =
            boundary_minor_gc_heap_field_writeback_write_plan(&writebacks, &live_bindings)
                .expect("empty heap-field writeback write plan validates");

        assert!(write_plan.is_empty());
        assert_eq!(write_plan.report().fields(), 0);
        assert_eq!(write_plan.report().replacement_payload_bytes(), 0);
        assert_eq!(write_plan.report().writeback_object_payload_bytes(), 0);
    }

    #[test]
    fn heap_field_writeback_applicator_routes_in_place_dirty_fields_to_direct_writer() {
        let old_object = address(0x1000);
        let source = address(0x2000);
        let replacement_destination = address(0x3000);
        let replacement_request = request(
            source,
            replacement_destination,
            MinorGcSurvivorAction::PromoteToOld,
        );
        let write_plan = EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan::new(vec![
            EvalGcStressBoundaryMinorGcHeapFieldWritebackWrite {
                allocation_domain: HeapAllocationDomain::Worker,
                validation_object: old_object,
                writeback_object: old_object,
                field_index: 0,
                source: field_source(),
                replacement_destination,
                replacement_generation: HeapGeneration::Old,
                replacement_metadata: heap(replacement_destination, HeapGeneration::Old),
                replacement_request,
                replacement_destination_bytes: vec![1, 2, 3, 4],
                writeback_object_request: None,
                writeback_object_destination_bytes: None,
            },
        ]);
        let mut heap = EvalHeap::new();
        let mut remembered_set = RememberedSet::new();
        let mut card_table = GcCardTable::default();

        let err = apply_boundary_minor_gc_heap_field_writebacks(
            &mut heap,
            &mut remembered_set,
            &mut card_table,
            &write_plan,
        )
        .expect_err("direct in-place writeback is routed to the heap writer");

        assert!(matches!(
            err,
            EvalHeapError::UnknownCollectorPollReferenceSlotAddress {
                address: actual_address,
            } if actual_address == old_object
        ));
    }

    #[test]
    fn rejects_missing_copied_heap_field_writeback_object_metadata() {
        let validation_object = address(0x1000);
        let replacement_source = address(0x2000);
        let writeback_object = address(0x3000);
        let replacement_destination = address(0x4000);
        let writebacks = writebacks(
            validation_object,
            writeback_object,
            heap(replacement_destination, HeapGeneration::Old),
        );
        let binding = EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding::new(
            HeapAllocationDomain::Worker,
            validation_object,
            writeback_object,
            0,
            field_source(),
            replacement_destination,
            HeapGeneration::Old,
            request(
                replacement_source,
                replacement_destination,
                MinorGcSurvivorAction::PromoteToOld,
            ),
            vec![1, 2, 3, 4],
            None,
            None,
        );
        let live_bindings = live_writeback_destination_bindings(vec![binding]);

        let err = boundary_minor_gc_heap_field_writeback_write_plan(&writebacks, &live_bindings)
            .expect_err("missing copied writeback-object metadata is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteObjectBindingMalformed {
                allocation_domain: HeapAllocationDomain::Worker,
                validation_object: actual_validation_object,
                writeback_object: actual_writeback_object,
                field_index: 0,
                field_source,
            } if actual_validation_object == validation_object
                && actual_writeback_object == writeback_object
                && field_source == (HeapEdgeSource::ListElement { index: 0 })
        ));
    }

    #[test]
    fn rejects_extra_old_field_writeback_object_metadata() {
        let old_object = address(0x1000);
        let replacement_source = address(0x2000);
        let replacement_destination = address(0x3000);
        let writebacks = writebacks(
            old_object,
            old_object,
            heap(replacement_destination, HeapGeneration::Young),
        );
        let binding = EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding::new(
            HeapAllocationDomain::Worker,
            old_object,
            old_object,
            0,
            field_source(),
            replacement_destination,
            HeapGeneration::Young,
            request(
                replacement_source,
                replacement_destination,
                MinorGcSurvivorAction::CopyToNursery,
            ),
            vec![1, 2, 3, 4],
            Some(request(
                old_object,
                old_object,
                MinorGcSurvivorAction::CopyToNursery,
            )),
            Some(vec![5, 6, 7, 8]),
        );
        let live_bindings = live_writeback_destination_bindings(vec![binding]);

        let err = boundary_minor_gc_heap_field_writeback_write_plan(&writebacks, &live_bindings)
            .expect_err("extra old-field writeback-object metadata is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteObjectBindingMalformed {
                allocation_domain: HeapAllocationDomain::Worker,
                validation_object,
                writeback_object,
                field_index: 0,
                field_source,
            } if validation_object == old_object
                && writeback_object == old_object
                && field_source == (HeapEdgeSource::ListElement { index: 0 })
        ));
    }

    #[test]
    fn rejects_copied_heap_field_writeback_object_request_from_another_source() {
        let validation_object = address(0x1000);
        let replacement_source = address(0x2000);
        let writeback_object = address(0x3000);
        let replacement_destination = address(0x4000);
        let wrong_source = address(0x5000);
        let writebacks = writebacks(
            validation_object,
            writeback_object,
            heap(replacement_destination, HeapGeneration::Old),
        );
        let binding = EvalGcStressBoundaryMinorGcHeapFieldWritebackDestinationBinding::new(
            HeapAllocationDomain::Worker,
            validation_object,
            writeback_object,
            0,
            field_source(),
            replacement_destination,
            HeapGeneration::Old,
            request(
                replacement_source,
                replacement_destination,
                MinorGcSurvivorAction::PromoteToOld,
            ),
            vec![1, 2, 3, 4],
            Some(request(
                wrong_source,
                writeback_object,
                MinorGcSurvivorAction::CopyToNursery,
            )),
            Some(vec![5, 6, 7, 8]),
        );
        let live_bindings = live_writeback_destination_bindings(vec![binding]);

        let err = boundary_minor_gc_heap_field_writeback_write_plan(&writebacks, &live_bindings)
            .expect_err("copied writeback-object request source mismatch is rejected");

        assert!(matches!(
            err,
            EvalHeapError::BoundaryMinorGcHeapFieldWritebackWriteObjectRequestSourceMismatch {
                allocation_domain: HeapAllocationDomain::Worker,
                validation_object: actual_validation_object,
                writeback_object: actual_writeback_object,
                field_index: 0,
                field_source,
                actual_source,
            } if actual_validation_object == validation_object
                && actual_writeback_object == writeback_object
                && field_source == (HeapEdgeSource::ListElement { index: 0 })
                && actual_source == wrong_source
        ));
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
    const fn new(
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
/// storage, mutate heap-record object generations, clear card-table storage, or
/// manage semispaces.
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
    const fn new(
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
    const fn new(
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
    const fn new(
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
    const fn new(
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
    const fn new(
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

/// Applied owned destination-storage commits derived from boundary preflights.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvalGcStressBoundaryMinorGcOwnedStorageCommitApplications {
    worker: Option<EvalGcStressBoundaryMinorGcOwnedStorageCommitApplication>,
    permanent_shared: Option<EvalGcStressBoundaryMinorGcOwnedStorageCommitApplication>,
}

impl EvalGcStressBoundaryMinorGcOwnedStorageCommitApplications {
    const fn new(
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
    pub(crate) tier_b_transition_admission_report: Option<EvalHeapTierBAdmissionReport>,
    pub(crate) cheap_memory_budget_plan: Option<EvalHeapCheapMemoryBudgetPlan>,
    pub(crate) cheap_memory_advice_report: Option<EvalHeapCheapMemoryAdviceReport>,
    pub(crate) cold_hash_consed_value_materialization:
        Option<ColdHashConsedValueMaterializationReport>,
    pub(crate) gc_stress_boundary_scans: EvalGcStressBoundaryScans,
    pub(crate) gc_stress_boundary_minor_gc_reference_writebacks:
        EvalGcStressBoundaryMinorGcLiveReferenceWritebacks,
    pub(crate) gc_stress_boundary_minor_gc_forwarding_destination_bindings:
        EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindings,
    pub(crate) gc_stress_boundary_minor_gc_destination_storage:
        EvalGcStressBoundaryMinorGcLiveDestinationStorage,
    pub(crate) gc_stress_boundary_minor_gc_object_generations:
        EvalGcStressBoundaryMinorGcLiveObjectGenerations,
    pub(crate) gc_stress_boundary_minor_gc_writeback_destination_bindings:
        EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings,
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
            .field(
                "tier_b_transition_admission_report",
                &self.tier_b_transition_admission_report,
            )
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
                "gc_stress_boundary_minor_gc_forwarding_destination_bindings",
                &self.gc_stress_boundary_minor_gc_forwarding_destination_bindings,
            )
            .field(
                "gc_stress_boundary_minor_gc_destination_storage",
                &self.gc_stress_boundary_minor_gc_destination_storage,
            )
            .field(
                "gc_stress_boundary_minor_gc_object_generations",
                &self.gc_stress_boundary_minor_gc_object_generations,
            )
            .field(
                "gc_stress_boundary_minor_gc_writeback_destination_bindings",
                &self.gc_stress_boundary_minor_gc_writeback_destination_bindings,
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

    /// Returns the requested Tier-B transition metadata, if the budget asked for it.
    ///
    /// This is safety-valve telemetry only. It captures the would-be pre-flip
    /// heap accounting and advice report but does not install Tier B or change
    /// evaluation results.
    pub const fn tier_b_transition_request(&self) -> Option<EvalTierBTransitionRequest> {
        match self.memory_budget_action {
            Some(action) => EvalTierBTransitionRequest::from_memory_budget_action(action),
            None => None,
        }
    }

    /// Returns the latest successful Tier-B transition admission report.
    ///
    /// Automatic admission records this before returning an owned outcome, and
    /// explicit calls to [`Self::apply_tier_b_transition_admission_plan`]
    /// update it after successful application. A missing report means no
    /// transition admission has been applied to this outcome heap.
    pub const fn tier_b_transition_admission_report(&self) -> Option<EvalHeapTierBAdmissionReport> {
        self.tier_b_transition_admission_report
    }

    /// Returns validated Tier-B transition admission metadata, if requested.
    ///
    /// This checks that the outcome heap still matches the request's pre-flip
    /// worker and permanent-shared arena snapshots, then reports the generation
    /// assignment each domain would use for a future Tier-B install. It does
    /// not mutate the heap or install a collector.
    ///
    /// # Errors
    ///
    /// Returns [`EvalTierBTransitionPreflightError`] if the heap's arena
    /// accounting no longer matches the captured Tier-B request.
    pub fn tier_b_transition_preflight(
        &self,
    ) -> Result<Option<EvalTierBTransitionPreflight>, EvalTierBTransitionPreflightError> {
        self.tier_b_transition_request()
            .map(|request| request.preflight(&self.heap))
            .transpose()
    }

    /// Returns a validated Tier-B transition admission plan, if requested.
    ///
    /// This combines the request-level arena-accounting preflight with the
    /// heap-record admission plan for the outcome heap. It remains read-only
    /// metadata and does not mutate the heap or install a collector.
    ///
    /// # Errors
    ///
    /// Returns [`EvalTierBTransitionAdmissionPlanError`] if the request no
    /// longer matches the outcome heap or if heap-record admission planning
    /// fails.
    pub fn tier_b_transition_admission_plan(
        &self,
    ) -> Result<Option<EvalTierBTransitionAdmissionPlan>, EvalTierBTransitionAdmissionPlanError>
    {
        self.tier_b_transition_request()
            .map(|request| request.admission_plan(&self.heap))
            .transpose()
    }

    /// Applies the requested Tier-B transition admission to heap metadata.
    ///
    /// This builds the current read-only transition admission plan and then
    /// applies its heap-record generation metadata update to the outcome heap.
    /// It only rewrites existing heap-record generation fields; it does not
    /// install a collector, switch allocators, reserve semispace storage,
    /// rewrite handles, mutate object bodies, publish remembered/card state, or
    /// relocate values.
    ///
    /// # Errors
    ///
    /// Returns [`EvalTierBTransitionAdmissionApplyError`] if transition
    /// admission planning fails or if the heap rejects the plan during
    /// application.
    pub fn apply_tier_b_transition_admission_plan(
        &mut self,
    ) -> Result<Option<EvalHeapTierBAdmissionReport>, EvalTierBTransitionAdmissionApplyError> {
        let Some(request) = self.tier_b_transition_request() else {
            return Ok(None);
        };
        let admission = request.admission_plan(&self.heap)?;
        let report = self
            .heap
            .apply_tier_b_admission_plan(admission.heap_plan())?;
        self.tier_b_transition_admission_report = Some(report);
        self.stats.record_heap_tier_b_admission(report);
        Ok(Some(report))
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

    /// Returns outcome-owned forwarding destination bindings installed by live dry runs.
    ///
    /// These records are GC-stress bridge metadata. They bind planned
    /// forwarding values to destination-byte snapshots, but they are not ABI
    /// object headers and ordinary evaluation does not read them.
    pub const fn gc_stress_boundary_minor_gc_forwarding_destination_binding_metadata(
        &self,
    ) -> &EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindings {
        &self.gc_stress_boundary_minor_gc_forwarding_destination_bindings
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

    /// Returns outcome-owned object-generation metadata installed by live dry runs.
    ///
    /// These records are GC-stress bridge metadata. They are not evaluator heap
    /// record generation fields, old-generation semispace ownership, or object
    /// headers, and ordinary evaluation does not read them.
    pub const fn gc_stress_boundary_minor_gc_object_generations(
        &self,
    ) -> &EvalGcStressBoundaryMinorGcLiveObjectGenerations {
        &self.gc_stress_boundary_minor_gc_object_generations
    }

    /// Returns outcome-owned writeback destination bindings installed by live dry runs.
    ///
    /// These records are GC-stress bridge metadata. They bind installed
    /// root/heap-field writeback snapshots to destination-byte snapshots, but
    /// they are not live evaluator root slots or heap object fields and
    /// ordinary evaluation does not read them.
    pub const fn gc_stress_boundary_minor_gc_writeback_destination_bindings(
        &self,
    ) -> &EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindings {
        &self.gc_stress_boundary_minor_gc_writeback_destination_bindings
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

    /// Plans live object-generation writes from installed live metadata.
    ///
    /// This validates installed live object-generation metadata against
    /// installed destination-byte snapshots. The returned plan is an immutable
    /// input set for a future heap-record generation writer; it does not mutate
    /// heap records, bind destination bytes to heap-object storage, validate
    /// semispace ownership, or publish old-generation metadata.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if an installed object-generation record has
    /// no installed destination snapshot, if an installed destination snapshot
    /// has no installed object-generation record, if object-generation metadata
    /// disagrees with its byte-copy request or destination snapshot, if either
    /// installed table contains duplicate identities, if destination generation
    /// or payload-size validation fails, or if the plan cannot reserve storage.
    pub fn gc_stress_boundary_minor_gc_object_generation_write_plan(
        &self,
    ) -> Result<EvalGcStressBoundaryMinorGcObjectGenerationWritePlan, EvalHeapError> {
        boundary_minor_gc_object_generation_write_plan(
            &self.gc_stress_boundary_minor_gc_destination_storage,
            &self.gc_stress_boundary_minor_gc_object_generations,
        )
    }

    /// Binds relocated destination bodies to live heap records.
    ///
    /// This consumes the installed boundary object-generation write plan,
    /// revalidates the installed destination-byte and generation metadata,
    /// lowers its object-copy requests to the heap-level body writer, and
    /// mutates only existing destination heap records by cloning current source
    /// record bodies. It still does not write installed byte buffers directly,
    /// write destination generation metadata, allocate synthetic destination
    /// records, reserve semispace storage, mutate roots or heap fields, write
    /// ABI object headers, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if installed destination/object-generation
    /// metadata is inconsistent, if a source is no longer a young survivor, if a
    /// source or destination layout no longer matches the request, if a
    /// destination address does not belong to the evaluator heap, if a request's
    /// action and generation disagree, or if the heap-level body write plan
    /// cannot reserve storage. When an error is returned, destination heap-record
    /// bodies are left unchanged.
    pub fn apply_gc_stress_boundary_minor_gc_live_object_bodies(
        &mut self,
    ) -> Result<AllocationCollectorPollObjectBodyWriteReport, EvalHeapError> {
        let plan = self.gc_stress_boundary_minor_gc_object_generation_write_plan()?;
        apply_boundary_minor_gc_live_object_bodies(&mut self.heap, &plan)
    }

    /// Applies installed object-generation metadata to live heap records.
    ///
    /// This consumes the installed boundary object-generation write plan,
    /// lowers it to the heap-level generation writer, and mutates only existing
    /// destination heap records. It still does not bind destination object
    /// bodies, allocate synthetic destination records, reserve semispace
    /// storage, mutate roots or heap fields, write ABI object headers, or
    /// invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if installed object-generation metadata is
    /// inconsistent, if a source is no longer a young survivor, if a destination
    /// address does not belong to the evaluator heap, if a request's action and
    /// generation disagree, or if the heap-level generation write plan cannot
    /// reserve storage. When an error is returned, heap-record generation
    /// metadata is left unchanged.
    pub fn apply_gc_stress_boundary_minor_gc_live_object_generations(
        &mut self,
    ) -> Result<AllocationCollectorPollObjectGenerationWriteReport, EvalHeapError> {
        let plan = self.gc_stress_boundary_minor_gc_object_generation_write_plan()?;
        apply_boundary_minor_gc_live_object_generations(&mut self.heap, &plan)
    }

    /// Validates relocated destination bodies and generations against live heap records.
    ///
    /// This consumes the installed boundary object-generation write plan,
    /// revalidates the installed destination-byte and generation metadata, and
    /// stages the heap-level paired body/generation writes without committing
    /// them. It is a read-only preflight for existing destination records only:
    /// it does not write object bodies, mutate generation metadata, allocate
    /// synthetic destination records, reserve semispace storage, mutate roots or
    /// heap fields, write ABI object headers, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if installed destination/object-generation
    /// metadata is inconsistent, if a source is no longer a young survivor, if a
    /// source or destination layout no longer matches the request, if a
    /// destination address does not belong to the evaluator heap, if a request's
    /// action and generation disagree, or if paired heap-level write planning
    /// cannot reserve storage. Whether this returns `Ok` or `Err`, destination
    /// heap-record bodies and generations are left unchanged.
    pub fn validate_gc_stress_boundary_minor_gc_live_object_bodies_and_generations(
        &self,
    ) -> Result<AllocationCollectorPollObjectBodyAndGenerationWriteReport, EvalHeapError> {
        let plan = self.gc_stress_boundary_minor_gc_object_generation_write_plan()?;
        validate_boundary_minor_gc_live_object_bodies_and_generations(&self.heap, &plan)
    }

    /// Binds relocated destination bodies and generations to live heap records.
    ///
    /// This consumes the installed boundary object-generation write plan,
    /// revalidates the installed destination-byte and generation metadata, and
    /// lowers its object-copy requests to the heap-level paired body/generation
    /// writer. Only existing destination heap records are mutated, and body and
    /// generation writes are staged together before either side is committed. It
    /// still does not write installed byte buffers directly, allocate synthetic
    /// destination records, reserve semispace storage, mutate roots or heap
    /// fields, write ABI object headers, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if installed destination/object-generation
    /// metadata is inconsistent, if a source is no longer a young survivor, if a
    /// source or destination layout no longer matches the request, if a
    /// destination address does not belong to the evaluator heap, if a request's
    /// action and generation disagree, or if paired heap-level write planning
    /// cannot reserve storage. When an error is returned, destination heap-record
    /// bodies and generations are left unchanged.
    pub fn apply_gc_stress_boundary_minor_gc_live_object_bodies_and_generations(
        &mut self,
    ) -> Result<AllocationCollectorPollObjectBodyAndGenerationWriteReport, EvalHeapError> {
        let plan = self.gc_stress_boundary_minor_gc_object_generation_write_plan()?;
        apply_boundary_minor_gc_live_object_bodies_and_generations(&mut self.heap, &plan)
    }

    /// Matches installed forwarding values to destination-byte snapshots.
    ///
    /// This validates outcome-owned GC-stress bridge metadata only. Each
    /// returned binding proves that an installed source forwarding value points
    /// at the destination payload and action-implied generation produced for the
    /// same source. It does not write ABI object headers, bind bytes to
    /// heap-object storage, mutate object-generation state, or validate object
    /// liveness.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if an installed destination snapshot has no
    /// matching forwarding value, if an installed forwarding value has no
    /// destination snapshot, if forwarding metadata is not heap-backed, if the
    /// forwarding destination or generation disagrees with its destination
    /// snapshot, if destination generation or payload-size validation fails, or
    /// if the binding report cannot reserve storage.
    pub fn gc_stress_boundary_minor_gc_forwarding_destination_bindings(
        &self,
    ) -> Result<Vec<EvalGcStressBoundaryMinorGcForwardingDestinationBinding>, EvalHeapError> {
        boundary_minor_gc_forwarding_destination_bindings(
            &self.heap,
            &self.gc_stress_boundary_minor_gc_destination_storage,
        )
    }

    /// Plans ABI forwarding-header writes from installed live metadata.
    ///
    /// This validates the installed live forwarding cells against the
    /// outcome-owned forwarding-destination binding side table. The returned
    /// plan is an immutable input set for a future ABI object-header writer; it
    /// does not write headers, bind destination bytes to heap-object storage,
    /// mutate object-generation state, or validate semispace ownership.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if an installed forwarding value has no
    /// installed forwarding-destination binding, if an installed binding has no
    /// matching live forwarding value, if the live forwarding value disagrees
    /// with the installed binding, if a binding source no longer belongs to the
    /// evaluator heap, or if the plan cannot reserve storage.
    pub fn gc_stress_boundary_minor_gc_forwarding_header_write_plan(
        &self,
    ) -> Result<EvalGcStressBoundaryMinorGcForwardingHeaderWritePlan, EvalHeapError> {
        boundary_minor_gc_forwarding_header_write_plan(
            &self.heap,
            &self.gc_stress_boundary_minor_gc_forwarding_destination_bindings,
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

    /// Plans live root writes from installed live metadata.
    ///
    /// This validates installed live root writeback metadata against installed
    /// root destination-binding metadata. The returned plan is an immutable
    /// input set for a future live root writer; it does not mutate evaluator
    /// roots, bind destination bytes to heap-object storage, or validate
    /// semispace ownership.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if installed root writeback metadata is
    /// internally inconsistent, if a root writeback has no installed
    /// destination binding, if an installed destination binding disagrees with
    /// the root writeback, if an installed root destination binding has no
    /// installed live writeback, if installed writebacks or bindings contain
    /// duplicate root identities, if a binding's byte-copy request disagrees
    /// with its destination, generation, or payload bytes, or if the plan
    /// cannot reserve storage.
    pub fn gc_stress_boundary_minor_gc_root_writeback_write_plan(
        &self,
    ) -> Result<EvalGcStressBoundaryMinorGcRootWritebackWritePlan, EvalHeapError> {
        boundary_minor_gc_root_writeback_write_plan(
            &self.gc_stress_boundary_minor_gc_reference_writebacks,
            &self.gc_stress_boundary_minor_gc_writeback_destination_bindings,
        )
    }

    /// Applies supported boundary root writes to this outcome's returned value.
    ///
    /// This is a narrow live-root precursor for the synthetic boundary
    /// value-stack root published by
    /// `TreeWalk::gc_stress_boundary_scans`. It accepts only
    /// `ValueStack { slot: 0 }`, validates that [`Self::value`] still contains
    /// the expected young from-space object, and validates that the replacement
    /// destination already belongs to this outcome's heap with the generation
    /// carried by the write plan. It also requires the destination object body to
    /// be bound to the planned source by
    /// [`EvalHeap::validate_collector_poll_minor_gc_object_body_binding`] before
    /// mutating the returned value. It does not bind destination bodies itself,
    /// allocate destination records, mutate active evaluator frames, rewrite
    /// import caches, update JIT stack maps, or commit semispace state.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if installed root-writeback metadata is
    /// inconsistent, if the write plan contains a root source other than the
    /// outcome-owned value-stack slot 0, if more than one write targets that
    /// physical outcome slot, if the returned value no longer holds the expected
    /// from-space source, if the source/destination heap records are missing or
    /// have the wrong generation, or if the destination object body is not bound
    /// to the planned source.
    pub fn apply_gc_stress_boundary_minor_gc_outcome_root_writebacks(
        &mut self,
    ) -> Result<EvalGcStressBoundaryMinorGcOutcomeRootWritebackReport, EvalHeapError> {
        let plan = self.gc_stress_boundary_minor_gc_root_writeback_write_plan()?;
        apply_boundary_minor_gc_outcome_root_writebacks(&mut self.value, &self.heap, &plan)
    }

    /// Binds root replacement bodies and applies supported outcome root writes.
    ///
    /// This consumes the installed live root-writeback metadata and installed
    /// root writeback-destination bindings for the outcome-owned
    /// `ValueStack { slot: 0 }` root. It first validates that the current returned
    /// value still holds the expected young from-space object. It then applies
    /// paired object-body/generation writes only for the replacement requests
    /// named by that outcome-root write plan, and finally rewrites
    /// [`Self::value`] through
    /// [`Self::apply_gc_stress_boundary_minor_gc_outcome_root_writebacks`]'s
    /// binding checks.
    ///
    /// This is a narrow live-root bridge for GC-stress experiments. It does not
    /// install live metadata, allocate destination records, reserve semispace
    /// storage, mutate active evaluator frames or import caches, update JIT stack
    /// maps, mutate heap fields, write ABI forwarding headers, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if installed root-writeback metadata is
    /// inconsistent, if the write plan contains an unsupported root source, if the
    /// returned value no longer holds the expected from-space source, if a source
    /// heap record is missing or has the wrong generation, if a destination heap
    /// record is missing or rejects the paired body/generation write, or if the
    /// final outcome-root binding check fails. Root prevalidation happens before
    /// destination object bodies or generations are written; when a paired-write
    /// error is returned, the paired writer leaves destination bodies and
    /// generations unchanged.
    pub fn apply_gc_stress_boundary_minor_gc_live_outcome_root_writebacks(
        &mut self,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveOutcomeRootWritebackReport, EvalHeapError> {
        let plan = self.gc_stress_boundary_minor_gc_root_writeback_write_plan()?;
        apply_boundary_minor_gc_live_outcome_root_writebacks(&mut self.value, &mut self.heap, &plan)
    }

    /// Preflights supported live reference writebacks without mutation.
    ///
    /// This consumes the installed live root and heap-field writeback metadata
    /// plus installed writeback-destination bindings. It validates the
    /// outcome-owned `ValueStack { slot: 0 }` root source, current record-owned
    /// heap fields, paired object-body/generation staging for every replacement
    /// or copied writeback object, staged field mutations, and staged
    /// remembered-set/card-table barriers. It returns the same object/root/
    /// field counts the live-reference applicator would cover, but does not
    /// commit any of those staged writes.
    ///
    /// This is a read-only live-reference bridge for GC-stress experiments. It
    /// still requires destination heap records to pre-exist, and it does not
    /// allocate destination records, reserve semispace storage, mutate active
    /// evaluator frames or import caches, update JIT stack maps, rewrite shared
    /// lexical frame slots, blackholed thunk deferred-work/capture fields, or
    /// write ABI forwarding headers, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if installed root or heap-field writeback
    /// metadata is inconsistent, if the outcome value no longer holds the
    /// expected root source, if a current source field no longer holds its
    /// expected young from-space value, if field or barrier staging fails, if a
    /// destination heap record aliases a direct in-place heap-field write owner,
    /// if a destination heap record is missing or rejects paired
    /// body/generation staging, or if a supported field write cannot be staged.
    /// Whether this returns `Ok` or `Err`, destination object bodies,
    /// generations, heap fields, remembered-set/card-table state, and the
    /// outcome value are left unchanged.
    pub fn validate_gc_stress_boundary_minor_gc_live_reference_writebacks(
        &self,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveReferenceWritebackPreflightReport, EvalHeapError>
    {
        let root_plan = self.gc_stress_boundary_minor_gc_root_writeback_write_plan()?;
        let heap_field_plan = self.gc_stress_boundary_minor_gc_heap_field_writeback_write_plan()?;
        validate_boundary_minor_gc_live_reference_writebacks(
            &self.value,
            &self.heap,
            &self.thunk_resolve_remembered_set,
            &self.thunk_resolve_card_table,
            &root_plan,
            &heap_field_plan,
        )
    }

    /// Preflights the existing-destination live commit bridge without mutation.
    ///
    /// This validates installed live forwarding cells against installed
    /// forwarding-destination bindings, verifies that prior live metadata
    /// publication left the card table clean, then validates the installed live
    /// root/heap-field writeback metadata through the read-only reference
    /// writeback preflight. It covers the currently modeled live commit
    /// projections for existing destination records: forwarding-header metadata,
    /// paired object-body/generation staging, outcome-owned value-stack root
    /// writeback, supported record-owned heap-field writes, direct
    /// owner/destination alias rejection, exact published remembered-set
    /// coherence for the writeback-destination metadata, direct
    /// old/permanent-to-young edge coverage, and remembered-set/card-table
    /// barrier staging against side-table clones.
    ///
    /// This is a read-only GC-stress orchestration bridge. It does not write ABI
    /// object headers, commit destination bodies or generations, mutate roots or
    /// heap fields, publish remembered/card state, allocate synthetic
    /// destinations, reserve semispace storage, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if forwarding-header metadata is missing,
    /// absent for installed reference writebacks, or stale, if installed
    /// root/heap-field writeback metadata is inconsistent, if live roots or
    /// fields no longer hold the expected from-space values, if the card table
    /// is dirty after live metadata publication, if the already-published
    /// remembered set does not match the publication recorded with installed
    /// writeback metadata, if it is missing a direct old/permanent-to-young edge
    /// required by that metadata, if a destination heap record aliases a direct
    /// in-place heap-field write owner, or if existing destination records
    /// reject paired body/generation staging.
    /// Whether this returns `Ok` or `Err`, live forwarding cells, destination
    /// object bodies/generations, roots, heap fields, remembered-set/card-table
    /// state, and the outcome value are left unchanged.
    /// The forwarding-header coverage gate is intentionally a zero-coverage
    /// guard for independently installed reference metadata; future per-source
    /// header coverage belongs with the eventual header writer.
    pub fn validate_gc_stress_boundary_minor_gc_live_existing_destination_commit(
        &self,
    ) -> Result<
        EvalGcStressBoundaryMinorGcLiveExistingDestinationCommitPreflightReport,
        EvalHeapError,
    > {
        let forwarding_header_write_plan =
            self.gc_stress_boundary_minor_gc_forwarding_header_write_plan()?;
        let installed_references = self
            .gc_stress_boundary_minor_gc_reference_writebacks
            .install_report()
            .writebacks();
        validate_boundary_minor_gc_existing_destination_commit_forwarding_header_coverage(
            forwarding_header_write_plan.report(),
            installed_references,
        )?;
        if !self.thunk_resolve_card_table.is_empty() {
            return Err(
                EvalHeapError::BoundaryMinorGcExistingDestinationCommitDirtyCardTable {
                    dirty_cards: self.thunk_resolve_card_table.len(),
                },
            );
        }
        validate_boundary_minor_gc_existing_destination_commit_published_remembered_set(
            &self.thunk_resolve_remembered_set,
            &self.gc_stress_boundary_minor_gc_writeback_destination_bindings,
        )?;
        let reference_writeback_preflight =
            self.validate_gc_stress_boundary_minor_gc_live_reference_writebacks()?;
        Ok(
            EvalGcStressBoundaryMinorGcLiveExistingDestinationCommitPreflightReport::new(
                forwarding_header_write_plan.report(),
                reference_writeback_preflight,
            ),
        )
    }

    /// Validates forwarding metadata and applies supported live reference writes.
    ///
    /// This is the mutating counterpart to
    /// [`Self::validate_gc_stress_boundary_minor_gc_live_existing_destination_commit`].
    /// It first validates installed live forwarding cells against installed
    /// forwarding-destination bindings, including the zero-coverage guard for
    /// independently installed reference metadata, verifies that prior live
    /// metadata publication left the card table clean, checks that the
    /// already-published remembered set exactly matches the publication recorded
    /// with the installed writeback-destination metadata and covers its direct
    /// old/permanent-to-young edges, and clones that remembered set before
    /// mutation. It then consumes installed root and heap-field writeback
    /// metadata plus installed writeback destination bindings through the
    /// live-reference applicator, binding destination object bodies/generations,
    /// rewriting supported record-owned heap fields, updating the prevalidated
    /// outcome root, restoring the published remembered set, and clearing the
    /// card table dirt introduced by the apply-time direct barriers.
    ///
    /// This is a narrow GC-stress orchestration bridge for existing destination
    /// records. It validates forwarding-header metadata but does not write ABI
    /// object headers, allocate synthetic destinations, reserve semispace
    /// storage, mutate active evaluator frames or import caches, update JIT
    /// stack maps, rewrite blackholed thunk
    /// deferred-work/capture fields, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if forwarding-header metadata is missing,
    /// absent for installed reference writebacks, or stale, if installed
    /// root/heap-field writeback metadata is inconsistent, if live roots or
    /// fields no longer hold the expected from-space values, if a destination
    /// heap record aliases a direct in-place heap-field write owner, if existing
    /// destination records reject paired body/generation writes, or if supported
    /// field or remembered/card-table writes cannot be staged, if the card table
    /// is dirty after live metadata publication, if the already-published
    /// remembered set does not match the publication recorded with installed
    /// writeback metadata, if it is missing a direct old/permanent-to-young edge
    /// required by that metadata, or if the published remembered set cannot be
    /// cloned before mutation. Forwarding metadata, card-table, and
    /// remembered-set coherence validation happen before destination object
    /// bodies, generations, roots, heap fields, remembered-set/card-table state,
    /// or the outcome value are changed.
    pub fn apply_gc_stress_boundary_minor_gc_live_existing_destination_commit(
        &mut self,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveExistingDestinationCommitApplyReport, EvalHeapError>
    {
        let forwarding_header_write_plan =
            self.gc_stress_boundary_minor_gc_forwarding_header_write_plan()?;
        let installed_references = self
            .gc_stress_boundary_minor_gc_reference_writebacks
            .install_report()
            .writebacks();
        validate_boundary_minor_gc_existing_destination_commit_forwarding_header_coverage(
            forwarding_header_write_plan.report(),
            installed_references,
        )?;
        if !self.thunk_resolve_card_table.is_empty() {
            return Err(
                EvalHeapError::BoundaryMinorGcExistingDestinationCommitDirtyCardTable {
                    dirty_cards: self.thunk_resolve_card_table.len(),
                },
            );
        }
        validate_boundary_minor_gc_existing_destination_commit_published_remembered_set(
            &self.thunk_resolve_remembered_set,
            &self.gc_stress_boundary_minor_gc_writeback_destination_bindings,
        )?;
        let published_remembered_set = self.thunk_resolve_remembered_set.try_clone()?;
        let remembered_set_published_edges = published_remembered_set.len();
        let root_plan = self.gc_stress_boundary_minor_gc_root_writeback_write_plan()?;
        let heap_field_plan = self.gc_stress_boundary_minor_gc_heap_field_writeback_write_plan()?;
        let reference_writeback_apply_report = apply_boundary_minor_gc_live_reference_writebacks(
            &mut self.value,
            &mut self.heap,
            &mut self.thunk_resolve_remembered_set,
            &mut self.thunk_resolve_card_table,
            &root_plan,
            &heap_field_plan,
        )?;
        self.thunk_resolve_remembered_set = published_remembered_set;
        let card_table_clear_report = self.thunk_resolve_card_table.clear_dirty_cards();

        Ok(
            EvalGcStressBoundaryMinorGcLiveExistingDestinationCommitApplyReport::new(
                forwarding_header_write_plan.report(),
                reference_writeback_apply_report,
                remembered_set_published_edges,
                card_table_clear_report,
            ),
        )
    }

    /// Applies supported boundary heap-field writebacks to live records.
    ///
    /// This consumes the installed heap-field writeback write plan and delegates
    /// relocated nursery-object fields to the copied-object field writer while
    /// applying in-place writes for old-generation worker records or
    /// permanent-shared records whose replacement is promoted to old directly or
    /// copied to young with a remembered-set/card-table barrier published
    /// atomically with the field mutation. The writeback object body for copied
    /// fields and every replacement body must already be bound by
    /// [`EvalHeap::apply_collector_poll_minor_gc_object_body_writes`], and their
    /// destination generations must already be installed. It revalidates the
    /// combined copied/direct object-copy request set before staging any record
    /// mutation. The applicator rewrites record-owned list elements, attrset
    /// bindings, primop arguments, lambda dynamic/global capture arrays,
    /// suspended thunk deferred-work fields, and suspended thunk dynamic/global
    /// capture arrays, and forced thunk cached-result fields.
    /// Direct old/permanent-to-young write barriers are staged against cloned
    /// outcome-owned remembered/card side tables before live side-table
    /// publication and heap mutation. Copied destinations still assume unaliased
    /// collector-owned scratch records because the side table cannot prove
    /// semispace ownership yet. Shared lexical frame slots, blackholed thunk
    /// deferred-work/capture fields, ABI headers, semispace storage, and Tier-B
    /// dispatch remain unsupported.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if installed heap-field writeback metadata is
    /// inconsistent, if a direct writeback object is not an old worker or
    /// permanent-shared record, if remembered/card side-table staging fails for
    /// a direct old/permanent-to-young replacement, if a copied writeback or
    /// replacement body/generation is not already bound, if the field no longer
    /// contains the expected from-space value, or if the field source is not a
    /// supported record-owned list element, attrset binding, primop argument,
    /// lambda dynamic/global capture array slot, suspended thunk deferred-work
    /// field, suspended thunk dynamic/global capture array slot, or forced thunk
    /// cached-result field.
    pub fn apply_gc_stress_boundary_minor_gc_heap_field_writebacks(
        &mut self,
    ) -> Result<EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport, EvalHeapError> {
        let plan = self.gc_stress_boundary_minor_gc_heap_field_writeback_write_plan()?;
        apply_boundary_minor_gc_heap_field_writebacks(
            &mut self.heap,
            &mut self.thunk_resolve_remembered_set,
            &mut self.thunk_resolve_card_table,
            &plan,
        )
    }

    /// Preflights supported boundary heap-field writebacks without mutation.
    ///
    /// This consumes the installed heap-field writeback write plan, validates
    /// paired object-body/generation staging for replacement objects and copied
    /// writeback-object destinations, validates current record-owned source
    /// fields, rejects direct in-place field owners that alias those object-copy
    /// destinations, and stages remembered-set/card-table barriers against local
    /// side-table clones. It returns the same object and field counts the
    /// live-field applicator would cover, but does not commit any staged writes.
    ///
    /// This is a read-only live-field bridge for GC-stress experiments. It still
    /// requires destination heap records to pre-exist, and it does not allocate
    /// destination records, reserve semispace storage, mutate shared lexical
    /// frame slots, rewrite blackholed thunk deferred-work/capture fields, write
    /// ABI forwarding headers, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if installed heap-field writeback metadata is
    /// inconsistent, if a current source field no longer holds the expected
    /// young from-space value, if field or barrier staging fails, if a
    /// destination heap record aliases a direct in-place heap-field write owner,
    /// or if a destination heap record is missing or rejects paired
    /// body/generation staging. Whether this returns `Ok` or `Err`, destination
    /// object bodies, generations, heap fields, remembered-set/card-table state,
    /// and the outcome value are left unchanged.
    pub fn validate_gc_stress_boundary_minor_gc_live_heap_field_writebacks(
        &self,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveHeapFieldWritebackPreflightReport, EvalHeapError>
    {
        let plan = self.gc_stress_boundary_minor_gc_heap_field_writeback_write_plan()?;
        validate_boundary_minor_gc_live_heap_field_writebacks(
            &self.heap,
            &self.thunk_resolve_remembered_set,
            &self.thunk_resolve_card_table,
            &plan,
        )
    }

    /// Binds heap-field replacement bodies and applies supported field writes.
    ///
    /// This consumes the installed live heap-field writeback metadata and
    /// installed writeback-destination bindings. It first validates request
    /// identities, current source fields, staged field mutations, and staged
    /// remembered-set/card-table publication before mutating destination records.
    /// It then applies paired object-body/generation writes for replacement
    /// objects and copied writeback-object destinations named by the heap-field
    /// write plan, and finally rewrites record-owned heap fields through
    /// [`Self::apply_gc_stress_boundary_minor_gc_heap_field_writebacks`]'s
    /// binding checks.
    ///
    /// This is a narrow live-field bridge for GC-stress experiments. It still
    /// requires destination heap records to pre-exist, and it does not allocate
    /// destination records, reserve semispace storage, mutate shared lexical
    /// frame slots, rewrite blackholed thunk deferred-work/capture fields, write
    /// ABI forwarding headers, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if installed heap-field writeback metadata is
    /// inconsistent, if a current source field no longer holds the expected
    /// young from-space value, if field or barrier staging fails, if a
    /// destination heap record aliases a direct in-place heap-field write owner,
    /// if a destination heap record is missing or rejects the paired
    /// body/generation write, or if the final heap-field writeback applicator
    /// fails. Source-field and final field/barrier prevalidation happen before
    /// destination object bodies or generations are written; when a paired-write
    /// error is returned, the paired writer leaves destination bodies and
    /// generations unchanged.
    pub fn apply_gc_stress_boundary_minor_gc_live_heap_field_writebacks(
        &mut self,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveHeapFieldWritebackReport, EvalHeapError> {
        let plan = self.gc_stress_boundary_minor_gc_heap_field_writeback_write_plan()?;
        apply_boundary_minor_gc_live_heap_field_writebacks(
            &mut self.heap,
            &mut self.thunk_resolve_remembered_set,
            &mut self.thunk_resolve_card_table,
            &plan,
        )
    }

    /// Binds replacement bodies and applies supported live reference writes.
    ///
    /// This consumes the installed live root and heap-field writeback metadata
    /// plus installed writeback-destination bindings. It validates the
    /// outcome-owned `ValueStack { slot: 0 }` root source, current record-owned
    /// heap fields, staged field mutations, and staged remembered-set/card-table
    /// publication before mutating destination records. It then applies paired
    /// object-body/generation writes for every replacement or copied writeback
    /// object named by the root and heap-field write plans, rewrites supported
    /// record-owned heap fields, and finally writes the already prevalidated
    /// outcome value.
    ///
    /// This is a narrow live-reference bridge for GC-stress experiments. It
    /// still requires destination heap records to pre-exist, and it does not
    /// allocate destination records, reserve semispace storage, mutate active
    /// evaluator frames or import caches, update JIT stack maps, rewrite shared
    /// lexical frame slots, blackholed thunk deferred-work/capture fields, write
    /// ABI forwarding headers, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if installed root or heap-field writeback
    /// metadata is inconsistent, if the outcome value no longer holds the
    /// expected root source, if a current source field no longer holds its
    /// expected young from-space value, if field or barrier staging fails, if a
    /// destination heap record aliases a direct in-place heap-field write owner,
    /// if a destination heap record is missing or rejects a paired
    /// body/generation write, or if a supported field write cannot be staged.
    /// Root and source-field prevalidation happens before destination object
    /// bodies, generations, heap fields, remembered-set/card-table state, or the
    /// outcome value are changed.
    pub fn apply_gc_stress_boundary_minor_gc_live_reference_writebacks(
        &mut self,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveReferenceWritebackApplyReport, EvalHeapError> {
        let root_plan = self.gc_stress_boundary_minor_gc_root_writeback_write_plan()?;
        let heap_field_plan = self.gc_stress_boundary_minor_gc_heap_field_writeback_write_plan()?;
        apply_boundary_minor_gc_live_reference_writebacks(
            &mut self.value,
            &mut self.heap,
            &mut self.thunk_resolve_remembered_set,
            &mut self.thunk_resolve_card_table,
            &root_plan,
            &heap_field_plan,
        )
    }

    /// Applies supported boundary heap-field writebacks to live records.
    ///
    /// This compatibility wrapper preserves the copied-field precursor method
    /// name while delegating to
    /// [`Self::apply_gc_stress_boundary_minor_gc_heap_field_writebacks`].
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] under the same conditions as
    /// [`Self::apply_gc_stress_boundary_minor_gc_heap_field_writebacks`].
    pub fn apply_gc_stress_boundary_minor_gc_copied_heap_field_writebacks(
        &mut self,
    ) -> Result<EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlanReport, EvalHeapError> {
        self.apply_gc_stress_boundary_minor_gc_heap_field_writebacks()
    }

    /// Matches installed heap-field writebacks to destination-byte snapshots.
    ///
    /// This validates outcome-owned GC-stress bridge metadata only. Each
    /// returned binding proves that an installed heap-field replacement points
    /// at an installed destination-byte snapshot. For copied nursery-field
    /// writebacks, it also proves that the relocated writeback object has an
    /// installed destination-byte snapshot. It does not mutate live evaluator
    /// object fields, bind destination bytes to heap-object storage, or validate
    /// semispace ownership of destination objects.
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
        boundary_minor_gc_heap_field_writeback_destination_bindings_for_heap(
            &self.heap,
            &self.gc_stress_boundary_minor_gc_reference_writebacks,
            &self.gc_stress_boundary_minor_gc_destination_storage,
        )
    }

    /// Plans live heap-field writes from installed live metadata.
    ///
    /// This validates installed live heap-field writeback metadata against
    /// installed heap-field destination-binding metadata. The returned plan is
    /// an immutable input set for the live heap-field bridge or a future
    /// broader live object-field writer; it does not mutate evaluator object
    /// fields, bind destination bytes to heap-object storage, or validate
    /// semispace ownership.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if installed heap-field writeback metadata is
    /// internally inconsistent, if a heap-field writeback has no installed
    /// destination binding, if an installed destination binding disagrees with
    /// the heap-field writeback, if an installed heap-field destination binding
    /// has no installed live writeback, if installed writebacks or bindings
    /// contain conflicting duplicate field identities after exact duplicate
    /// live entries have been canonicalized, if a binding's byte-copy request
    /// disagrees with its replacement destination, generation, or payload bytes,
    /// or if the plan cannot reserve storage.
    pub fn gc_stress_boundary_minor_gc_heap_field_writeback_write_plan(
        &self,
    ) -> Result<EvalGcStressBoundaryMinorGcHeapFieldWritebackWritePlan, EvalHeapError> {
        boundary_minor_gc_heap_field_writeback_write_plan_for_heap(
            &self.heap,
            &self.gc_stress_boundary_minor_gc_reference_writebacks,
            &self.gc_stress_boundary_minor_gc_writeback_destination_bindings,
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
    /// applies commit plans into owned synthetic byte, owned destination-storage,
    /// forwarding, reference, remembered-set, and card-table buffers. The
    /// returned report carries preflights, writebacks, synthetic commit
    /// applications, and direct owned-storage commit applications for the exact
    /// same worker/permanent-shared partition. It still does not mutate live
    /// evaluator roots, live heap fields, object headers, remembered-set
    /// storage, card-table storage, or semispace pages.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if boundary commit preflight derivation fails,
    /// if any owned dry-run buffer or destination storage cannot be allocated,
    /// if storage-derived relocation metadata cannot be rebuilt, or if any
    /// owned buffer fails validation against the lower-level commit or writeback
    /// plans.
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
    /// sets, clear card-table storage, mutate heap-record object generations, reserve
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

    /// Runs a boundary dry run and installs forwarding destination bindings.
    ///
    /// The method derives the same owned commit dry run as
    /// [`Self::gc_stress_boundary_minor_gc_commit_dry_run`], validates sibling
    /// survivor relocations, merges destination-byte snapshots, matches the
    /// planned forwarding values to those snapshots, and installs the resulting
    /// binding records into outcome-owned metadata. Empty boundaries, or
    /// non-empty boundaries with no copied/promoted survivors, leave the side
    /// table unchanged.
    ///
    /// This is a live forwarding destination-binding metadata bridge for
    /// GC-stress experiments, not a full collector commit. It does not install
    /// forwarding slots, write ABI object headers, bind bytes to live object
    /// bodies, mutate heap-record object generations, reserve semispace storage,
    /// or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if boundary commit dry-run derivation or owned
    /// buffer application fails, if sibling applications do not form one
    /// coherent survivor relocation map, if forwarding values do not match the
    /// merged destination snapshots, or if forwarding destination-binding
    /// metadata has already been installed for this outcome. When an error is
    /// returned, the forwarding destination-binding side table is left
    /// unchanged.
    pub fn gc_stress_boundary_minor_gc_commit_dry_run_with_live_forwarding_destination_bindings(
        &mut self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<
        EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingCommitDryRun,
        EvalHeapError,
    > {
        let dry_run = self.gc_stress_boundary_minor_gc_commit_dry_run(promotion_policy, bases)?;
        let forwarding_slots =
            boundary_minor_gc_merged_forwarding_slots(dry_run.commit_applications())?;
        let object_bytes =
            boundary_minor_gc_merged_destination_object_bytes(dry_run.commit_applications())?;
        let forwarding_destination_bindings =
            boundary_minor_gc_forwarding_destination_bindings_from_slots(
                &forwarding_slots,
                &object_bytes,
            )?;
        let forwarding_destination_binding_install_report = self
            .gc_stress_boundary_minor_gc_forwarding_destination_bindings
            .install(forwarding_destination_bindings)?;

        Ok(
            EvalGcStressBoundaryMinorGcLiveForwardingDestinationBindingCommitDryRun::new(
                dry_run,
                forwarding_destination_binding_install_report,
            ),
        )
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

    /// Runs a boundary dry run and installs outcome-owned object generations.
    ///
    /// The method derives the same owned commit dry run as
    /// [`Self::gc_stress_boundary_minor_gc_commit_dry_run`]. It validates sibling
    /// survivor relocations, merges the destination object-copy snapshots, and
    /// installs destination-to-generation metadata derived from each copy action.
    /// Empty boundaries, or non-empty boundaries with no copied/promoted
    /// survivors, leave the side table unchanged.
    ///
    /// This is a live object-generation metadata bridge for GC-stress
    /// experiments, not a full collector commit. It does not mutate evaluator
    /// heap records, allocate old-generation storage, bind bytes to live object
    /// bodies, write object headers, mutate roots or fields, publish remembered
    /// sets, clear card-table storage, reserve semispace storage, or invoke Tier
    /// B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if boundary commit dry-run derivation or owned
    /// buffer application fails, if sibling applications do not form one
    /// coherent survivor relocation map, if destination snapshots fail
    /// generation validation, or if object-generation metadata has already been
    /// installed for this outcome. When an error is returned, the
    /// object-generation side table is left unchanged.
    pub fn gc_stress_boundary_minor_gc_commit_dry_run_with_live_object_generations(
        &mut self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveObjectGenerationCommitDryRun, EvalHeapError> {
        let dry_run = self.gc_stress_boundary_minor_gc_commit_dry_run(promotion_policy, bases)?;
        boundary_minor_gc_merged_forwarding_slots(dry_run.commit_applications())?;
        let object_bytes =
            boundary_minor_gc_merged_destination_object_bytes(dry_run.commit_applications())?;
        let object_generations =
            boundary_minor_gc_live_object_generations_from_objects(&object_bytes)?;
        let object_generation_install_report = self
            .gc_stress_boundary_minor_gc_object_generations
            .install(object_generations)?;

        Ok(
            EvalGcStressBoundaryMinorGcLiveObjectGenerationCommitDryRun::new(
                dry_run,
                object_generation_install_report,
            ),
        )
    }

    /// Runs a boundary dry run and installs writeback destination bindings.
    ///
    /// The method derives the same owned commit dry run as
    /// [`Self::gc_stress_boundary_minor_gc_commit_dry_run`], validates sibling
    /// survivor relocations, merges destination-byte snapshots, clones the root
    /// and heap-field writeback snapshots, validates each writeback against the
    /// merged destinations, records the remembered-set publication expected from
    /// the same dry run, and installs the resulting binding records into
    /// outcome-owned metadata. Empty boundaries, or non-empty boundaries with no
    /// writebacks, leave the side table unchanged.
    ///
    /// This is a live writeback destination-binding metadata bridge for
    /// GC-stress experiments, not a full collector commit. It does not mutate
    /// evaluator roots, heap object fields, object bytes, forwarding headers,
    /// remembered-set storage, semispace storage, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if boundary commit dry-run derivation or owned
    /// buffer application fails, if sibling applications do not form one
    /// coherent survivor relocation map, if writeback metadata cannot be
    /// cloned, if root/heap-field destination binding validation fails, or if
    /// writeback destination-binding metadata has already been installed for
    /// this outcome. When an error is returned, the writeback destination-binding
    /// side table is left unchanged.
    pub fn gc_stress_boundary_minor_gc_commit_dry_run_with_live_writeback_destination_bindings(
        &mut self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindingCommitDryRun, EvalHeapError>
    {
        let dry_run = self.gc_stress_boundary_minor_gc_commit_dry_run(promotion_policy, bases)?;
        boundary_minor_gc_merged_forwarding_slots(dry_run.commit_applications())?;
        let object_bytes =
            boundary_minor_gc_merged_destination_object_bytes(dry_run.commit_applications())?;
        let writebacks =
            clone_boundary_reference_writeback_applications(dry_run.reference_writebacks())?;
        let root_writeback_destination_bindings =
            boundary_minor_gc_root_writeback_destination_bindings_from_applications(
                &writebacks,
                &object_bytes,
            )?;
        let heap_field_writeback_destination_bindings =
            boundary_minor_gc_heap_field_writeback_destination_bindings_from_applications_for_heap(
                &self.heap,
                &writebacks,
                &object_bytes,
            )?;
        let expected_remembered_set = boundary_minor_gc_merged_remembered_set(
            dry_run.commit_applications(),
            self.thunk_resolve_remembered_set.epoch(),
        )?;
        let writeback_destination_binding_install_report = self
            .gc_stress_boundary_minor_gc_writeback_destination_bindings
            .install(
                root_writeback_destination_bindings,
                heap_field_writeback_destination_bindings,
                expected_remembered_set,
            )?;

        Ok(
            EvalGcStressBoundaryMinorGcLiveWritebackDestinationBindingCommitDryRun::new(
                dry_run,
                writeback_destination_binding_install_report,
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
    /// heap-record object generations, reserve semispace storage, or invoke Tier B.
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
    /// survivor relocations, destination-byte snapshots, destination
    /// object-generation bindings, forwarding-destination bindings over the
    /// combined installed and planned forwarding cells, reference-writeback
    /// metadata, root/heap-field destination bindings, remembered-set
    /// publication, and live forwarding slots. After those checks pass, it
    /// installs evaluator side-table forwarding values, forwarding-destination
    /// binding metadata, destination-byte snapshots, object-generation metadata,
    /// reference-writeback metadata, writeback destination-binding metadata, the
    /// merged next remembered set, and clears the daemon card table. Empty
    /// boundaries leave the outcome unchanged.
    ///
    /// This is a staged live-metadata bridge for GC-stress experiments, not a
    /// full collector commit. It does not mutate live root variables, heap
    /// fields, object bytes, ABI forwarding headers, evaluator heap-record
    /// generations, reserve semispace storage, or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if boundary commit dry-run derivation or owned
    /// buffer application fails, if sibling applications do not form one
    /// coherent survivor relocation map, if destination-byte snapshots or
    /// forwarding-destination, object-generation, reference-writeback, or
    /// writeback destination-binding metadata have already been installed, if
    /// remembered set publication cannot be merged, if destination generation or
    /// writeback destination bindings do not match the dry-run destination
    /// snapshots, if the combined installed and planned forwarding cells do not
    /// match the final destination snapshot view, or if forwarding installation
    /// fails.
    /// All installable side-table payloads are validated before the first live
    /// mutation; if forwarding installation fails, forwarding-destination
    /// binding metadata, destination storage, object-generation metadata,
    /// reference-writeback metadata, writeback destination-binding metadata,
    /// remembered-set state, and card-table state are left unchanged.
    pub fn gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata(
        &mut self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<EvalGcStressBoundaryMinorGcLiveMetadataCommitDryRun, EvalHeapError> {
        let (live_metadata, _) = self
            .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata_inner(
                promotion_policy,
                bases,
                false,
            )?;
        Ok(live_metadata)
    }

    /// Runs a boundary dry run, preflights existing destinations, and installs metadata.
    ///
    /// This is the strict existing-destination variant of
    /// [`Self::gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata`].
    /// It derives the same owned dry run and validates the same side-table
    /// payloads, then stages paired heap-record object-body/generation writes
    /// for the merged destination plan before any live forwarding slots,
    /// outcome-owned metadata, remembered-set state, or card-table state are
    /// mutated. Only after that no-mutation preflight succeeds does it install
    /// the same live metadata as the ordinary installer.
    ///
    /// This remains a metadata bridge: it does not commit the staged object-body
    /// or generation writes, allocate synthetic destination records, reserve
    /// semispace storage, mutate roots or heap fields, write ABI object headers,
    /// or invoke Tier B.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] under the same conditions as
    /// [`Self::gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata`],
    /// and also if any copied/promoted destination address does not already
    /// belong to this evaluator heap or if the paired body/generation preflight
    /// cannot be staged. When an error is returned before forwarding
    /// installation, live metadata and heap-record state are left unchanged.
    pub fn gc_stress_boundary_minor_gc_commit_dry_run_with_existing_destination_live_metadata(
        &mut self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<EvalGcStressBoundaryMinorGcExistingDestinationLiveMetadataCommitDryRun, EvalHeapError>
    {
        let (live_metadata, object_body_and_generation_write_report) = self
            .gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata_inner(
                promotion_policy,
                bases,
                true,
            )?;
        Ok(
            EvalGcStressBoundaryMinorGcExistingDestinationLiveMetadataCommitDryRun::new(
                live_metadata,
                object_body_and_generation_write_report,
            ),
        )
    }

    /// Runs the existing-destination boundary commit bridge end to end.
    ///
    /// This composes
    /// [`Self::gc_stress_boundary_minor_gc_commit_dry_run_with_existing_destination_live_metadata`]
    /// with
    /// [`Self::apply_gc_stress_boundary_minor_gc_live_existing_destination_commit`]
    /// without exposing a caller interleaving point between metadata
    /// installation and live reference publication. The first phase derives the
    /// boundary dry run, validates installable metadata, and preflights paired
    /// destination body/generation writes for already-bound destination records
    /// before any metadata mutation. The second phase validates installed
    /// forwarding metadata, remembered-set publication, card-table state, roots,
    /// fields, and destination body/generation staging before committing
    /// existing destination bodies/generations, supported heap fields, and the
    /// outcome-owned root.
    ///
    /// This remains a narrow GC-stress bridge for existing destination records.
    /// It does not allocate synthetic destinations, reserve semispace storage,
    /// mutate active evaluator frames or import caches, update JIT stack maps,
    /// write ABI forwarding headers, or invoke Tier B.
    /// It is not an all-or-nothing transaction across both phases: if the first
    /// phase installs forwarding cells, outcome-owned metadata, remembered-set
    /// state, or card-table state and the second phase later returns an error,
    /// those first-phase mutations remain installed. The second phase still
    /// keeps its own validation-before-live-reference-mutation contract.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the metadata dry run or existing-destination
    /// preflight fails, if live metadata cannot be installed, or if the
    /// subsequent existing-destination live commit rejects installed metadata,
    /// roots, heap fields, remembered-set/card-table state, or paired
    /// body/generation writes. Errors from the subsequent live commit are
    /// returned after the metadata phase has already installed its side effects.
    pub fn gc_stress_boundary_minor_gc_commit_dry_run_with_existing_destination_live_commit(
        &mut self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
    ) -> Result<EvalGcStressBoundaryMinorGcExistingDestinationLiveCommit, EvalHeapError> {
        let live_metadata = self
            .gc_stress_boundary_minor_gc_commit_dry_run_with_existing_destination_live_metadata(
                promotion_policy,
                bases,
            )?;
        let live_commit =
            self.apply_gc_stress_boundary_minor_gc_live_existing_destination_commit()?;
        Ok(
            EvalGcStressBoundaryMinorGcExistingDestinationLiveCommit::new(
                live_metadata,
                live_commit,
            ),
        )
    }

    fn gc_stress_boundary_minor_gc_commit_dry_run_with_live_metadata_inner(
        &mut self,
        promotion_policy: MinorGcPromotionPolicy,
        bases: MinorGcDestinationBases,
        preflight_existing_destinations: bool,
    ) -> Result<
        (
            EvalGcStressBoundaryMinorGcLiveMetadataCommitDryRun,
            AllocationCollectorPollObjectBodyAndGenerationWriteReport,
        ),
        EvalHeapError,
    > {
        let dry_run = self.gc_stress_boundary_minor_gc_commit_dry_run(promotion_policy, bases)?;
        let forwarding_slots =
            boundary_minor_gc_merged_forwarding_slots(dry_run.commit_applications())?;
        let object_bytes =
            boundary_minor_gc_merged_destination_object_bytes(dry_run.commit_applications())?;
        let destination_storage_install_report =
            live_destination_storage_install_report(&object_bytes);
        self.gc_stress_boundary_minor_gc_destination_storage
            .can_install(destination_storage_install_report)?;
        let object_generations =
            boundary_minor_gc_live_object_generations_from_objects(&object_bytes)?;
        let object_generation_install_report =
            live_object_generation_install_report(&object_generations);
        self.gc_stress_boundary_minor_gc_object_generations
            .can_install(object_generation_install_report)?;
        let forwarding_destination_objects = if object_bytes.is_empty() {
            self.gc_stress_boundary_minor_gc_destination_storage
                .object_bytes()
        } else {
            object_bytes.as_slice()
        };
        let _forwarding_destination_bindings =
            boundary_minor_gc_forwarding_destination_bindings_from_heap_and_slots(
                &self.heap,
                &forwarding_slots,
                forwarding_destination_objects,
            )?;
        let forwarding_destination_bindings =
            boundary_minor_gc_forwarding_destination_bindings_from_slots(
                &forwarding_slots,
                &object_bytes,
            )?;
        let forwarding_destination_binding_install_report =
            live_forwarding_destination_binding_install_report(&forwarding_destination_bindings);
        self.gc_stress_boundary_minor_gc_forwarding_destination_bindings
            .can_install(forwarding_destination_binding_install_report)?;
        let writebacks =
            clone_boundary_reference_writeback_applications(dry_run.reference_writebacks())?;
        let reference_writeback_install_report =
            live_reference_writeback_install_report(&writebacks);
        self.gc_stress_boundary_minor_gc_reference_writebacks
            .can_install(reference_writeback_install_report)?;
        let root_writeback_destination_bindings =
            boundary_minor_gc_root_writeback_destination_bindings_from_applications(
                &writebacks,
                &object_bytes,
            )?;
        let heap_field_writeback_destination_bindings =
            boundary_minor_gc_heap_field_writeback_destination_bindings_from_applications_for_heap(
                &self.heap,
                &writebacks,
                &object_bytes,
            )?;
        let writeback_destination_binding_install_report =
            live_writeback_destination_binding_install_report(
                &root_writeback_destination_bindings,
                &heap_field_writeback_destination_bindings,
            );
        self.gc_stress_boundary_minor_gc_writeback_destination_bindings
            .can_install(writeback_destination_binding_install_report)?;
        let remembered_set = boundary_minor_gc_merged_remembered_set(
            dry_run.commit_applications(),
            self.thunk_resolve_remembered_set.epoch(),
        )?;
        let writeback_expected_remembered_set = remembered_set
            .as_ref()
            .map(clone_boundary_remembered_set)
            .transpose()?;
        let object_body_and_generation_write_report = if preflight_existing_destinations {
            let object_body_plan =
                boundary_minor_gc_object_body_generation_preflight_plan_from_generations(
                    &object_generations,
                )?;
            self.heap
                .validate_collector_poll_minor_gc_object_body_and_generation_writes(
                    &object_body_plan,
                )?
        } else {
            AllocationCollectorPollObjectBodyAndGenerationWriteReport::default()
        };

        let forwarding_install_report = self
            .heap
            .install_collector_poll_minor_gc_forwarding_slots(&forwarding_slots)?;

        self.gc_stress_boundary_minor_gc_destination_storage
            .install_prevalidated(object_bytes, destination_storage_install_report);
        self.gc_stress_boundary_minor_gc_forwarding_destination_bindings
            .install_prevalidated(
                forwarding_destination_bindings,
                forwarding_destination_binding_install_report,
            );
        self.gc_stress_boundary_minor_gc_object_generations
            .install_prevalidated(object_generations, object_generation_install_report);
        self.gc_stress_boundary_minor_gc_reference_writebacks
            .install_prevalidated(writebacks, reference_writeback_install_report);
        self.gc_stress_boundary_minor_gc_writeback_destination_bindings
            .install_prevalidated(
                root_writeback_destination_bindings,
                heap_field_writeback_destination_bindings,
                writeback_expected_remembered_set,
                writeback_destination_binding_install_report,
            );
        let remembered_set_published = remembered_set.is_some();
        let card_table_clear_report = if let Some(remembered_set) = remembered_set {
            self.thunk_resolve_remembered_set = remembered_set;
            self.thunk_resolve_card_table.clear_dirty_cards()
        } else {
            GcCardTableClearReport::default()
        };

        Ok((
            EvalGcStressBoundaryMinorGcLiveMetadataCommitDryRun::new(
                dry_run,
                forwarding_install_report,
                forwarding_destination_binding_install_report,
                destination_storage_install_report,
                object_generation_install_report,
                reference_writeback_install_report,
                writeback_destination_binding_install_report,
                remembered_set_published,
                card_table_clear_report,
            ),
            object_body_and_generation_write_report,
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
    /// install forwarding pointers, mutate heap-record object generations, reserve
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
/// Fields without an implementation yet stay present and zero so downstream
/// tracing consumers can rely on stable field names while later slices add GC,
/// promotions, deopts, and early-cutoff cache behavior.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvalStats {
    pub(crate) thunks_forced: u64,
    pub(crate) thunks_allocated: u64,
    pub(crate) thunks_elided: u64,
    pub(crate) binding_assembly_elisions: u64,
    /// Thunks allocated with single-entry storage (no update, no blackhole,
    /// no parallel payload cell) under the C-8 frame-local proof.
    pub(crate) single_entry_thunks_allocated: u64,
    /// Forces served by the single-entry direct-evaluation path.
    pub(crate) single_entry_thunks_forced: u64,
    pub(crate) thunk_cache_hits: u64,
    pub(crate) inline_cache_hits: u64,
    pub(crate) inline_cache_misses: u64,
    pub(crate) shape_transitions: u64,
    pub(crate) gc_bytes: u64,
    pub(crate) gc_pause_us: u64,
    /// Forced thunks whose captures were shed by `AOS_NIX_GC=sweep`.
    pub(crate) thunks_shed: u64,
    /// Tier-B quiescent sweep cycles performed.
    pub(crate) gc_sweeps: u64,
    /// Worker heap records retired across all Tier-B sweep cycles.
    pub(crate) gc_records_swept: u64,
    /// Quiescent-sweep requests declined because the evaluator was not quiescent.
    pub(crate) gc_sweeps_skipped_nonquiescent: u64,
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
    pub(crate) root_cutoffs: u64,
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
    pub(crate) heap_tier_b_admission_worker_records: u64,
    pub(crate) heap_tier_b_admission_permanent_shared_records: u64,
    pub(crate) heap_tier_b_admission_generation_rewrites: u64,
    pub(crate) values_allocated: u64,
    pub(crate) attrsets_built: u64,
    pub(crate) attrs_entries_total: u64,
    pub(crate) function_calls: u64,
    pub(crate) hashcons_attempts: u64,
    pub(crate) hashcons_hits: u64,
    pub(crate) symbols_interned: u64,
    pub(crate) imports_evaluated: u64,
    pub(crate) tier1_promoted: u64,
    pub(crate) tier1_dispatched: u64,
    pub(crate) tier1_deopted: u64,
    pub(crate) tier1_blacklisted: u64,
    pub(crate) tier2_promoted: u64,
    pub(crate) tier2_dispatched: u64,
    pub(crate) tier2_deopted: u64,
    pub(crate) tier2_blacklisted: u64,
    pub(crate) memo_l0_hits: u64,
    pub(crate) memo_l0_misses: u64,
    pub(crate) memo_l0_admissions: u64,
    pub(crate) memo_l0_declines: u64,
    pub(crate) memo_l1_hits: u64,
    pub(crate) memo_l1_misses: u64,
    pub(crate) memo_l1_admissions: u64,
    pub(crate) memo_l1_declines: u64,
    pub(crate) memo_l2_secondary_hits: u64,
    pub(crate) memo_l2_secondary_misses: u64,
    pub(crate) memo_l2_promotions: u64,
    pub(crate) memo_l2_reval_failures: u64,
    pub(crate) memo_net_hits: u64,
    pub(crate) memo_net_misses: u64,
    pub(crate) memo_net_errors: u64,
    pub(crate) memo_net_reval_failures: u64,
    pub(crate) memo_economics: MemoEconomicsStats,
    /// Flat-value campaign work-volume counters (RFC-0007 doc 30 FV-0).
    pub(crate) campaign: CampaignCounters,
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

    /// Returns the number of elided thunks whose bodies were evaluated
    /// directly into their slots during order-sensitive binding assembly
    /// under the analysis' per-frame assembly proof (a subset of
    /// [`Self::thunks_elided`]).
    pub const fn binding_assembly_elisions(&self) -> u64 {
        self.binding_assembly_elisions
    }

    /// Returns the number of thunks allocated with single-entry storage.
    ///
    /// Single-entry thunks skip the update write-back, the blackhole
    /// transition, and the parallel payload cell; they are admitted only
    /// under the C-8 frame-local once-entered proof.
    pub const fn single_entry_thunks_allocated(&self) -> u64 {
        self.single_entry_thunks_allocated
    }

    /// Returns the number of forces served by the single-entry direct path.
    pub const fn single_entry_thunks_forced(&self) -> u64 {
        self.single_entry_thunks_forced
    }

    /// Returns the number of already-forced thunk cell reuses.
    pub const fn thunk_cache_hits(&self) -> u64 {
        self.thunk_cache_hits
    }

    /// Returns the number of inline-cache hits reported by active evaluator tiers.
    pub const fn inline_cache_hits(&self) -> u64 {
        self.inline_cache_hits
    }

    /// Returns the number of inline-cache misses reported by active evaluator tiers.
    pub const fn inline_cache_misses(&self) -> u64 {
        self.inline_cache_misses
    }

    /// Returns the number of object-shape transition edges observed by active tiers.
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

    /// Returns forced thunks whose captures were shed by `AOS_NIX_GC=sweep`.
    pub const fn thunks_shed(&self) -> u64 {
        self.thunks_shed
    }

    /// Returns Tier-B quiescent sweep cycles performed.
    pub const fn gc_sweeps(&self) -> u64 {
        self.gc_sweeps
    }

    /// Returns worker heap records retired across all Tier-B sweep cycles.
    pub const fn gc_records_swept(&self) -> u64 {
        self.gc_records_swept
    }

    /// Returns quiescent-sweep requests declined for lack of quiescence.
    pub const fn gc_sweeps_skipped_nonquiescent(&self) -> u64 {
        self.gc_sweeps_skipped_nonquiescent
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

    /// Returns the number of root-level early cutoffs served without evaluation.
    ///
    /// A root cutoff answers an entire `instantiate(file, attr)` request from a
    /// durable root record after revalidating its transitive impure inputs,
    /// skipping parse, lowering, and evaluation. This counter is one for a
    /// closure re-emitted from such a record and zero for a normal evaluation.
    pub const fn root_cutoffs(&self) -> u64 {
        self.root_cutoffs
    }

    /// Returns evaluator counters describing a root-level early cutoff.
    ///
    /// The returned stats carry a single [`Self::root_cutoffs`] and are
    /// otherwise zero, reflecting that no thunks were forced, no heap was
    /// allocated, and no cache probes were performed because the closure was
    /// re-emitted from a durable root record without evaluation.
    #[must_use]
    pub fn for_root_cutoff() -> Self {
        Self {
            root_cutoffs: 1,
            ..Self::default()
        }
    }

    /// Returns records served from a secondary L2 disk location.
    pub const fn memo_l2_secondary_hits(&self) -> u64 {
        self.memo_l2_secondary_hits
    }

    /// Returns probes that consulted secondaries and missed on every disk location.
    pub const fn memo_l2_secondary_misses(&self) -> u64 {
        self.memo_l2_secondary_misses
    }

    /// Returns records copied into the primary location after a slower-tier hit.
    pub const fn memo_l2_promotions(&self) -> u64 {
        self.memo_l2_promotions
    }

    /// Returns disk-tier records rejected by impure-input slice revalidation.
    pub const fn memo_l2_reval_failures(&self) -> u64 {
        self.memo_l2_reval_failures
    }

    /// Returns records fetched, validated, and accepted from the network tier.
    pub const fn memo_net_hits(&self) -> u64 {
        self.memo_net_hits
    }

    /// Returns network probes answered with "no such record".
    pub const fn memo_net_misses(&self) -> u64 {
        self.memo_net_misses
    }

    /// Returns network probes that failed at the transport or validation layer.
    pub const fn memo_net_errors(&self) -> u64 {
        self.memo_net_errors
    }

    /// Returns network records rejected by local impure-input revalidation.
    pub const fn memo_net_reval_failures(&self) -> u64 {
        self.memo_net_reval_failures
    }

    /// Folds durable-tier memo events observed outside the evaluator into
    /// these counters.
    ///
    /// The root-cutoff fast path answers without constructing an evaluator,
    /// so its L2/L3 probe outcomes arrive as a [`MemoTierEvents`] snapshot
    /// after the fact. Every field is combined with saturating addition.
    pub fn merge_memo_tier_events(&mut self, events: &MemoTierEvents) {
        let MemoTierEvents {
            l2_secondary_hits,
            l2_secondary_misses,
            l2_promotions,
            l2_reval_failures,
            net_hits,
            net_misses,
            net_errors,
            net_reval_failures,
        } = *events;
        self.memo_l2_secondary_hits = self.memo_l2_secondary_hits.saturating_add(l2_secondary_hits);
        self.memo_l2_secondary_misses = self
            .memo_l2_secondary_misses
            .saturating_add(l2_secondary_misses);
        self.memo_l2_promotions = self.memo_l2_promotions.saturating_add(l2_promotions);
        self.memo_l2_reval_failures = self
            .memo_l2_reval_failures
            .saturating_add(l2_reval_failures);
        self.memo_net_hits = self.memo_net_hits.saturating_add(net_hits);
        self.memo_net_misses = self.memo_net_misses.saturating_add(net_misses);
        self.memo_net_errors = self.memo_net_errors.saturating_add(net_errors);
        self.memo_net_reval_failures = self
            .memo_net_reval_failures
            .saturating_add(net_reval_failures);
    }

    /// Accumulates another evaluator's counters into this one.
    ///
    /// Parallel evaluation keeps per-worker [`EvalStats`] and merges them into
    /// one report after all workers join. Every field is combined with
    /// saturating addition: event counters sum naturally, and the heap gauge
    /// fields (`heap_*`/`permanent_heap_*`) become the total across all worker
    /// heaps, which is the meaningful resident-footprint figure for one shared
    /// evaluation. The destructuring is exhaustive so a newly added counter
    /// cannot be silently dropped from the merge.
    pub fn merge_from(&mut self, other: &Self) {
        let Self {
            thunks_forced,
            thunks_allocated,
            thunks_elided,
            binding_assembly_elisions,
            single_entry_thunks_allocated,
            single_entry_thunks_forced,
            thunk_cache_hits,
            inline_cache_hits,
            inline_cache_misses,
            shape_transitions,
            gc_bytes,
            gc_pause_us,
            thunks_shed,
            gc_sweeps,
            gc_records_swept,
            gc_sweeps_skipped_nonquiescent,
            tier_promotions,
            deopts,
            force_cache_hits,
            force_cache_misses,
            force_cache_memoization_admits,
            force_cache_memoization_bypasses,
            force_cache_materialization_materializes,
            force_cache_materialization_keeps_in_memory,
            source_thunk_region_plan_decisions,
            source_thunk_region_plan_lexical_subregion_decisions,
            source_thunk_region_plan_conservative_fallbacks,
            cache_hits,
            cache_misses,
            early_cutoffs,
            root_cutoffs,
            derivation_aterm_path_reuses,
            static_derivation_output_path_reuses,
            derivation_hash_calculations,
            derivation_text_path_calculations,
            heap_chunks,
            heap_reserved_bytes,
            heap_mapped_bytes,
            heap_used_bytes,
            permanent_heap_chunks,
            permanent_heap_reserved_bytes,
            permanent_heap_mapped_bytes,
            permanent_heap_used_bytes,
            heap_tier_b_admission_worker_records,
            heap_tier_b_admission_permanent_shared_records,
            heap_tier_b_admission_generation_rewrites,
            values_allocated,
            attrsets_built,
            attrs_entries_total,
            function_calls,
            hashcons_attempts,
            hashcons_hits,
            symbols_interned,
            imports_evaluated,
            tier1_promoted,
            tier1_dispatched,
            tier1_deopted,
            tier1_blacklisted,
            tier2_promoted,
            tier2_dispatched,
            tier2_deopted,
            tier2_blacklisted,
            memo_l0_hits,
            memo_l0_misses,
            memo_l0_admissions,
            memo_l0_declines,
            memo_l1_hits,
            memo_l1_misses,
            memo_l1_admissions,
            memo_l1_declines,
            memo_l2_secondary_hits,
            memo_l2_secondary_misses,
            memo_l2_promotions,
            memo_l2_reval_failures,
            memo_net_hits,
            memo_net_misses,
            memo_net_errors,
            memo_net_reval_failures,
            memo_economics,
            campaign,
        } = *other;
        self.thunks_forced = self.thunks_forced.saturating_add(thunks_forced);
        self.thunks_allocated = self.thunks_allocated.saturating_add(thunks_allocated);
        self.thunks_elided = self.thunks_elided.saturating_add(thunks_elided);
        self.binding_assembly_elisions = self
            .binding_assembly_elisions
            .saturating_add(binding_assembly_elisions);
        self.single_entry_thunks_allocated = self
            .single_entry_thunks_allocated
            .saturating_add(single_entry_thunks_allocated);
        self.single_entry_thunks_forced = self
            .single_entry_thunks_forced
            .saturating_add(single_entry_thunks_forced);
        self.thunk_cache_hits = self.thunk_cache_hits.saturating_add(thunk_cache_hits);
        self.inline_cache_hits = self.inline_cache_hits.saturating_add(inline_cache_hits);
        self.inline_cache_misses = self.inline_cache_misses.saturating_add(inline_cache_misses);
        self.shape_transitions = self.shape_transitions.saturating_add(shape_transitions);
        self.gc_bytes = self.gc_bytes.saturating_add(gc_bytes);
        self.gc_pause_us = self.gc_pause_us.saturating_add(gc_pause_us);
        self.thunks_shed = self.thunks_shed.saturating_add(thunks_shed);
        self.gc_sweeps = self.gc_sweeps.saturating_add(gc_sweeps);
        self.gc_records_swept = self.gc_records_swept.saturating_add(gc_records_swept);
        self.gc_sweeps_skipped_nonquiescent = self
            .gc_sweeps_skipped_nonquiescent
            .saturating_add(gc_sweeps_skipped_nonquiescent);
        self.tier_promotions = self.tier_promotions.saturating_add(tier_promotions);
        self.deopts = self.deopts.saturating_add(deopts);
        self.force_cache_hits = self.force_cache_hits.saturating_add(force_cache_hits);
        self.force_cache_misses = self.force_cache_misses.saturating_add(force_cache_misses);
        self.force_cache_memoization_admits = self
            .force_cache_memoization_admits
            .saturating_add(force_cache_memoization_admits);
        self.force_cache_memoization_bypasses = self
            .force_cache_memoization_bypasses
            .saturating_add(force_cache_memoization_bypasses);
        self.force_cache_materialization_materializes = self
            .force_cache_materialization_materializes
            .saturating_add(force_cache_materialization_materializes);
        self.force_cache_materialization_keeps_in_memory = self
            .force_cache_materialization_keeps_in_memory
            .saturating_add(force_cache_materialization_keeps_in_memory);
        self.source_thunk_region_plan_decisions = self
            .source_thunk_region_plan_decisions
            .saturating_add(source_thunk_region_plan_decisions);
        self.source_thunk_region_plan_lexical_subregion_decisions = self
            .source_thunk_region_plan_lexical_subregion_decisions
            .saturating_add(source_thunk_region_plan_lexical_subregion_decisions);
        self.source_thunk_region_plan_conservative_fallbacks = self
            .source_thunk_region_plan_conservative_fallbacks
            .saturating_add(source_thunk_region_plan_conservative_fallbacks);
        self.cache_hits = self.cache_hits.saturating_add(cache_hits);
        self.cache_misses = self.cache_misses.saturating_add(cache_misses);
        self.early_cutoffs = self.early_cutoffs.saturating_add(early_cutoffs);
        self.root_cutoffs = self.root_cutoffs.saturating_add(root_cutoffs);
        self.derivation_aterm_path_reuses = self
            .derivation_aterm_path_reuses
            .saturating_add(derivation_aterm_path_reuses);
        self.static_derivation_output_path_reuses = self
            .static_derivation_output_path_reuses
            .saturating_add(static_derivation_output_path_reuses);
        self.derivation_hash_calculations = self
            .derivation_hash_calculations
            .saturating_add(derivation_hash_calculations);
        self.derivation_text_path_calculations = self
            .derivation_text_path_calculations
            .saturating_add(derivation_text_path_calculations);
        self.heap_chunks = self.heap_chunks.saturating_add(heap_chunks);
        self.heap_reserved_bytes = self.heap_reserved_bytes.saturating_add(heap_reserved_bytes);
        self.heap_mapped_bytes = self.heap_mapped_bytes.saturating_add(heap_mapped_bytes);
        self.heap_used_bytes = self.heap_used_bytes.saturating_add(heap_used_bytes);
        self.permanent_heap_chunks = self
            .permanent_heap_chunks
            .saturating_add(permanent_heap_chunks);
        self.permanent_heap_reserved_bytes = self
            .permanent_heap_reserved_bytes
            .saturating_add(permanent_heap_reserved_bytes);
        self.permanent_heap_mapped_bytes = self
            .permanent_heap_mapped_bytes
            .saturating_add(permanent_heap_mapped_bytes);
        self.permanent_heap_used_bytes = self
            .permanent_heap_used_bytes
            .saturating_add(permanent_heap_used_bytes);
        self.heap_tier_b_admission_worker_records = self
            .heap_tier_b_admission_worker_records
            .saturating_add(heap_tier_b_admission_worker_records);
        self.heap_tier_b_admission_permanent_shared_records = self
            .heap_tier_b_admission_permanent_shared_records
            .saturating_add(heap_tier_b_admission_permanent_shared_records);
        self.heap_tier_b_admission_generation_rewrites = self
            .heap_tier_b_admission_generation_rewrites
            .saturating_add(heap_tier_b_admission_generation_rewrites);
        self.values_allocated = self.values_allocated.saturating_add(values_allocated);
        self.attrsets_built = self.attrsets_built.saturating_add(attrsets_built);
        self.attrs_entries_total = self.attrs_entries_total.saturating_add(attrs_entries_total);
        self.function_calls = self.function_calls.saturating_add(function_calls);
        self.hashcons_attempts = self.hashcons_attempts.saturating_add(hashcons_attempts);
        self.hashcons_hits = self.hashcons_hits.saturating_add(hashcons_hits);
        self.symbols_interned = self.symbols_interned.saturating_add(symbols_interned);
        self.imports_evaluated = self.imports_evaluated.saturating_add(imports_evaluated);
        self.tier1_promoted = self.tier1_promoted.saturating_add(tier1_promoted);
        self.tier1_dispatched = self.tier1_dispatched.saturating_add(tier1_dispatched);
        self.tier1_deopted = self.tier1_deopted.saturating_add(tier1_deopted);
        self.tier1_blacklisted = self.tier1_blacklisted.saturating_add(tier1_blacklisted);
        self.tier2_promoted = self.tier2_promoted.saturating_add(tier2_promoted);
        self.tier2_dispatched = self.tier2_dispatched.saturating_add(tier2_dispatched);
        self.tier2_deopted = self.tier2_deopted.saturating_add(tier2_deopted);
        self.tier2_blacklisted = self.tier2_blacklisted.saturating_add(tier2_blacklisted);
        self.memo_l0_hits = self.memo_l0_hits.saturating_add(memo_l0_hits);
        self.memo_l0_misses = self.memo_l0_misses.saturating_add(memo_l0_misses);
        self.memo_l0_admissions = self.memo_l0_admissions.saturating_add(memo_l0_admissions);
        self.memo_l0_declines = self.memo_l0_declines.saturating_add(memo_l0_declines);
        self.memo_l1_hits = self.memo_l1_hits.saturating_add(memo_l1_hits);
        self.memo_l1_misses = self.memo_l1_misses.saturating_add(memo_l1_misses);
        self.memo_l1_admissions = self.memo_l1_admissions.saturating_add(memo_l1_admissions);
        self.memo_l1_declines = self.memo_l1_declines.saturating_add(memo_l1_declines);
        self.memo_economics = self.memo_economics.merged(memo_economics);
        self.merge_memo_tier_events(&MemoTierEvents {
            l2_secondary_hits: memo_l2_secondary_hits,
            l2_secondary_misses: memo_l2_secondary_misses,
            l2_promotions: memo_l2_promotions,
            l2_reval_failures: memo_l2_reval_failures,
            net_hits: memo_net_hits,
            net_misses: memo_net_misses,
            net_errors: memo_net_errors,
            net_reval_failures: memo_net_reval_failures,
        });
        self.campaign = self.campaign.merged(campaign);
    }

    /// Returns the flat-value campaign work-volume counters (doc 30 FV-0).
    pub const fn campaign(&self) -> CampaignCounters {
        self.campaign
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

    /// Returns worker-domain heap records counted by the latest Tier-B admission.
    pub const fn heap_tier_b_admission_worker_records(&self) -> u64 {
        self.heap_tier_b_admission_worker_records
    }

    /// Returns permanent-shared heap records counted by the latest Tier-B admission.
    pub const fn heap_tier_b_admission_permanent_shared_records(&self) -> u64 {
        self.heap_tier_b_admission_permanent_shared_records
    }

    /// Returns heap-record generation metadata rewrites from the latest Tier-B admission.
    pub const fn heap_tier_b_admission_generation_rewrites(&self) -> u64 {
        self.heap_tier_b_admission_generation_rewrites
    }

    /// Returns the number of typed-value heap records allocated.
    ///
    /// Counts string, path, list, attribute-set, lambda, builtin, and thunk
    /// records that materialized a new allocation. Hash-cons reuse is excluded,
    /// so this is the dedup-reduced boxed-value analog of C++ Nix's `nrValues`.
    pub const fn values_allocated(&self) -> u64 {
        self.values_allocated
    }

    /// Returns the number of attribute-set constructions requested.
    ///
    /// Includes requests satisfied by a hash-cons hit, matching the accounting
    /// of C++ Nix's `nrAttrsets`.
    pub const fn attrsets_built(&self) -> u64 {
        self.attrsets_built
    }

    /// Returns the total attribute entries summed over every attribute-set
    /// construction, the analog of C++ Nix's `nrAttrsInAttrsets`.
    pub const fn attrs_entries_total(&self) -> u64 {
        self.attrs_entries_total
    }

    /// Returns the number of value-level function applications performed.
    ///
    /// Counts every lambda and builtin application routed through the central
    /// apply path, the analog of C++ Nix's `nrFunctionCalls`. Builtins inlined
    /// as dedicated IR nodes are evaluated directly and are not counted here.
    pub const fn function_calls(&self) -> u64 {
        self.function_calls
    }

    /// Returns the number of structural-hash lookups against the hash-cons tables.
    pub const fn hashcons_attempts(&self) -> u64 {
        self.hashcons_attempts
    }

    /// Returns the number of hash-cons lookups that reused a canonical value.
    pub const fn hashcons_hits(&self) -> u64 {
        self.hashcons_hits
    }

    /// Returns the number of distinct symbols interned by the evaluation.
    ///
    /// This is a gauge of the final symbol-table size, the analog of the symbol
    /// count C++ Nix reports under `symbols`.
    pub const fn symbols_interned(&self) -> u64 {
        self.symbols_interned
    }

    /// Returns the number of imported files that were evaluated.
    ///
    /// Counts import-cache misses: an import whose target was evaluated rather
    /// than served from the per-evaluation import cache. A value below the total
    /// number of `import` expressions demonstrates the import cache working.
    pub const fn imports_evaluated(&self) -> u64 {
        self.imports_evaluated
    }

    /// Returns the number of thunks promoted to tier-1 native code during force.
    pub const fn tier1_promoted(&self) -> u64 {
        self.tier1_promoted
    }

    /// Returns the number of thunk forces served by dispatching tier-1 native code.
    pub const fn tier1_dispatched(&self) -> u64 {
        self.tier1_dispatched
    }

    /// Returns the number of tier-1 dispatch attempts that deoptimized to the tree walk.
    pub const fn tier1_deopted(&self) -> u64 {
        self.tier1_deopted
    }

    /// Returns the number of def-sites blacklisted after a failed tier-1 lowering.
    pub const fn tier1_blacklisted(&self) -> u64 {
        self.tier1_blacklisted
    }

    /// Returns the number of lambda def-sites promoted to tier-2 native code.
    pub const fn tier2_promoted(&self) -> u64 {
        self.tier2_promoted
    }

    /// Returns the number of lambda applications served by tier-2 native code.
    ///
    /// Each dispatch covers one *boundary* application; direct native
    /// self-calls inside a compiled recursion are not individually counted.
    pub const fn tier2_dispatched(&self) -> u64 {
        self.tier2_dispatched
    }

    /// Returns the number of tier-2 dispatch attempts that deoptimized to the
    /// interpreted call.
    pub const fn tier2_deopted(&self) -> u64 {
        self.tier2_deopted
    }

    /// Returns the number of lambda def-sites blacklisted after a failed tier-2
    /// lowering.
    pub const fn tier2_blacklisted(&self) -> u64 {
        self.tier2_blacklisted
    }

    /// Returns L0 content-memo hits (replayed instead of evaluated).
    pub const fn memo_l0_hits(&self) -> u64 {
        self.memo_l0_hits
    }

    /// Returns L0 content-memo probe misses (including failed revalidations).
    pub const fn memo_l0_misses(&self) -> u64 {
        self.memo_l0_misses
    }

    /// Returns entries admitted into the L0 content memo.
    pub const fn memo_l0_admissions(&self) -> u64 {
        self.memo_l0_admissions
    }

    /// Returns L0 content-memo eligibility and record declines.
    pub const fn memo_l0_declines(&self) -> u64 {
        self.memo_l0_declines
    }

    /// Returns L1 (in-process shared) content-memo hits.
    pub const fn memo_l1_hits(&self) -> u64 {
        self.memo_l1_hits
    }

    /// Returns L1 content-memo probe misses (including failed revalidations).
    pub const fn memo_l1_misses(&self) -> u64 {
        self.memo_l1_misses
    }

    /// Returns entries published into the L1 content memo.
    pub const fn memo_l1_admissions(&self) -> u64 {
        self.memo_l1_admissions
    }

    /// Returns L1 content-memo eligibility and record declines.
    pub const fn memo_l1_declines(&self) -> u64 {
        self.memo_l1_declines
    }

    /// Returns opt-in content-memo economics counters and timings.
    pub const fn memo_economics(&self) -> MemoEconomicsStats {
        self.memo_economics
    }

    pub(in crate::eval::tree_walk) fn record_heap_tier_b_admission(
        &mut self,
        report: EvalHeapTierBAdmissionReport,
    ) {
        self.heap_tier_b_admission_worker_records = report.worker_records() as u64;
        self.heap_tier_b_admission_permanent_shared_records =
            report.permanent_shared_records() as u64;
        self.heap_tier_b_admission_generation_rewrites = report.generation_rewrites() as u64;
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
