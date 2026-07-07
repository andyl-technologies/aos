//! Allocation, lookup, and cons-table machinery for the [`EvalHeap`] arena.

use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};

use xxhash_rust::xxh3::Xxh3;

use crate::heap::{
    ArenaMemoryAdviceReport, GcHeapAddress, HeapMemoryBudget, HeapMemoryBudgetResponse,
    HeapMemorySample, MemoryAdviceKind, MemoryAdviceOutcome, ProcessResidentMemorySample,
    ProcessResidentMemorySource, RegionPlan, advise_cold_heap_object_allocation,
    advise_evict_heap_object_allocation,
};

use super::*;

static NEXT_HEAP_REGION_OWNER: AtomicU64 = AtomicU64::new(1);

/// A whole-heap high-water memory-budget decision.
///
/// `EvalHeap` owns a worker allocation domain and a permanent shared domain, so
/// this decision records both accounting snapshots alongside the single sample
/// and resident-byte source classified by the shared budget policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvalHeapMemoryBudgetDecision {
    budget: HeapMemoryBudget,
    sample: HeapMemorySample,
    resident_source: EvalHeapResidentMemorySource,
    worker_stats: ArenaStats,
    permanent_stats: ArenaStats,
    response: HeapMemoryBudgetResponse,
}

impl EvalHeapMemoryBudgetDecision {
    const fn new(
        budget: HeapMemoryBudget,
        sample: HeapMemorySample,
        resident_source: EvalHeapResidentMemorySource,
        worker_stats: ArenaStats,
        permanent_stats: ArenaStats,
    ) -> Self {
        Self {
            budget,
            sample,
            resident_source,
            worker_stats,
            permanent_stats,
            response: budget.classify(sample),
        }
    }

    /// Returns the budget used to classify memory pressure.
    pub const fn budget(self) -> HeapMemoryBudget {
        self.budget
    }

    /// Returns the whole-heap memory sample classified by the budget policy.
    pub const fn sample(self) -> HeapMemorySample {
        self.sample
    }

    /// Returns the source used for the resident byte count in the sample.
    pub const fn resident_source(self) -> EvalHeapResidentMemorySource {
        self.resident_source
    }

    /// Returns worker-domain arena accounting captured for this decision.
    pub const fn worker_stats(self) -> ArenaStats {
        self.worker_stats
    }

    /// Returns permanent-shared arena accounting captured for this decision.
    pub const fn permanent_stats(self) -> ArenaStats {
        self.permanent_stats
    }

    /// Returns the high-water budget response selected for the whole heap.
    pub const fn response(self) -> HeapMemoryBudgetResponse {
        self.response
    }

    /// Returns whether the response asks runtime code to do more than continue.
    pub const fn requires_runtime_action(self) -> bool {
        match self.response {
            HeapMemoryBudgetResponse::ContinueTierA { .. } => false,
            HeapMemoryBudgetResponse::SpillCold { .. }
            | HeapMemoryBudgetResponse::InstallTierB { .. } => true,
        }
    }

    /// Returns whether the response asks the runtime to install Tier B.
    pub const fn requests_tier_b(self) -> bool {
        matches!(self.response, HeapMemoryBudgetResponse::InstallTierB { .. })
    }
}

/// The resident-byte source used for a heap memory-budget decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvalHeapResidentMemorySource {
    /// The decision used worker plus permanent arena mapped bytes.
    ArenaMappedBytes,
    /// The decision used a live process resident-set sample.
    ProcessResidentSet(ProcessResidentMemorySource),
}

/// The resident-byte sampling mode for automatic heap budget polls.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EvalHeapResidentMemoryMode {
    /// Use worker plus permanent arena mapped bytes.
    #[default]
    ArenaMappedBytes,
    /// Try a live process resident-set sample, falling back to arena mapped bytes.
    ProcessResidentSetWithArenaFallback,
}

/// Memory-advice reports for both evaluator heap allocation domains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvalHeapMemoryAdviceReport {
    kind: MemoryAdviceKind,
    worker: ArenaMemoryAdviceReport,
    permanent: ArenaMemoryAdviceReport,
}

impl EvalHeapMemoryAdviceReport {
    const fn new(
        kind: MemoryAdviceKind,
        worker: ArenaMemoryAdviceReport,
        permanent: ArenaMemoryAdviceReport,
    ) -> Self {
        Self {
            kind,
            worker,
            permanent,
        }
    }

    /// Returns the advice kind requested for both allocation domains.
    pub const fn kind(self) -> MemoryAdviceKind {
        self.kind
    }

    /// Returns the worker-domain arena advice report.
    pub const fn worker(self) -> ArenaMemoryAdviceReport {
        self.worker
    }

    /// Returns the permanent-shared arena advice report.
    pub const fn permanent(self) -> ArenaMemoryAdviceReport {
        self.permanent
    }

    /// Returns how many arena chunks were considered across both domains.
    pub const fn chunks(self) -> usize {
        self.worker.chunks().saturating_add(self.permanent.chunks())
    }

    /// Returns the total unused-tail bytes passed to the advice shim.
    pub const fn requested_bytes(self) -> usize {
        self.worker
            .requested_bytes()
            .saturating_add(self.permanent.requested_bytes())
    }

    /// Returns how many chunk-tail advice calls the operating system accepted.
    pub const fn applied(self) -> usize {
        self.worker
            .applied()
            .saturating_add(self.permanent.applied())
    }

    /// Returns how many chunk-tail advice calls had no platform lowering.
    pub const fn unsupported(self) -> usize {
        self.worker
            .unsupported()
            .saturating_add(self.permanent.unsupported())
    }

    /// Returns how many chunk tails contained no complete page to advise.
    pub const fn empty_ranges(self) -> usize {
        self.worker
            .empty_ranges()
            .saturating_add(self.permanent.empty_ranges())
    }

    /// Returns how many chunk-tail advice calls the platform rejected.
    pub const fn rejected(self) -> usize {
        self.worker
            .rejected()
            .saturating_add(self.permanent.rejected())
    }
}

/// Memory-advice report for cold permanent hash-consed heap records.
///
/// This report is advisory metadata only. A successful advice call does not
/// evict values from the evaluator heap or install CA-store handles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvalHeapColdHashConsedAdviceReport {
    kind: MemoryAdviceKind,
    min_idle_epochs: u64,
    records: usize,
    requested_bytes: usize,
    applied: usize,
    unsupported: usize,
    empty: usize,
    rejected: usize,
}

impl EvalHeapColdHashConsedAdviceReport {
    const fn new(kind: MemoryAdviceKind, min_idle_epochs: u64) -> Self {
        Self {
            kind,
            min_idle_epochs,
            records: 0,
            requested_bytes: 0,
            applied: 0,
            unsupported: 0,
            empty: 0,
            rejected: 0,
        }
    }

    fn record(&mut self, requested_bytes: usize, outcome: MemoryAdviceOutcome) {
        self.records = self.records.saturating_add(1);
        self.requested_bytes = self.requested_bytes.saturating_add(requested_bytes);
        match outcome {
            MemoryAdviceOutcome::Applied { .. } => {
                self.applied = self.applied.saturating_add(1);
            }
            MemoryAdviceOutcome::Unsupported { .. } => {
                self.unsupported = self.unsupported.saturating_add(1);
            }
            MemoryAdviceOutcome::EmptyRange { .. } => {
                self.empty = self.empty.saturating_add(1);
            }
            MemoryAdviceOutcome::Rejected { .. } => {
                self.rejected = self.rejected.saturating_add(1);
            }
        }
    }

    /// Returns the advice kind requested for each cold hash-consed record.
    pub const fn kind(self) -> MemoryAdviceKind {
        self.kind
    }

    /// Returns the idle-epoch threshold used to select records.
    pub const fn min_idle_epochs(self) -> u64 {
        self.min_idle_epochs
    }

    /// Returns how many cold hash-consed records were considered.
    pub const fn records(self) -> usize {
        self.records
    }

    /// Returns the logical bytes passed to the advice shim.
    pub const fn requested_bytes(self) -> usize {
        self.requested_bytes
    }

    /// Returns how many record advice calls the operating system accepted.
    pub const fn applied(self) -> usize {
        self.applied
    }

    /// Returns how many record advice calls had no platform lowering.
    pub const fn unsupported(self) -> usize {
        self.unsupported
    }

    /// Returns how many record ranges contained no complete page to advise.
    pub const fn empty_ranges(self) -> usize {
        self.empty
    }

    /// Returns how many record advice calls the platform rejected.
    pub const fn rejected(self) -> usize {
        self.rejected
    }
}

/// Memory-advice reports for all currently implemented cheap heap hints.
///
/// This combines destructive advice over unused arena tails with
/// non-destructive cold advice over idle hash-consed records. It is an explicit
/// helper for future budget policy; automatic budget actions still account only
/// for implemented reclaim capacity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvalHeapCheapMemoryAdviceReport {
    unused_tails: EvalHeapMemoryAdviceReport,
    cold_hash_consed: EvalHeapColdHashConsedAdviceReport,
}

impl EvalHeapCheapMemoryAdviceReport {
    const fn new(
        unused_tails: EvalHeapMemoryAdviceReport,
        cold_hash_consed: EvalHeapColdHashConsedAdviceReport,
    ) -> Self {
        Self {
            unused_tails,
            cold_hash_consed,
        }
    }

    /// Returns the unused arena-tail advice report.
    pub const fn unused_tails(self) -> EvalHeapMemoryAdviceReport {
        self.unused_tails
    }

    /// Returns the cold hash-consed record advice report.
    pub const fn cold_hash_consed(self) -> EvalHeapColdHashConsedAdviceReport {
        self.cold_hash_consed
    }
}

/// The budget-policy action currently executable by [`EvalHeap`].
///
/// This action only covers the cheap arena-tail advice that is implemented
/// today. CA-store spill, cold hash-cons page selection, and Tier-B collector
/// installation remain separate future steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvalHeapMemoryBudgetAction {
    /// The heap stayed below the derived soft limit and no reclaim work ran.
    ContinueTierA {
        /// The budget decision that selected this action.
        decision: EvalHeapMemoryBudgetDecision,
    },
    /// The heap advised unused chunk tails and remains in Tier A.
    AdviseUnusedTails {
        /// The budget decision that selected this action.
        decision: EvalHeapMemoryBudgetDecision,
        /// The worker/permanent advice report produced by this action.
        report: EvalHeapMemoryAdviceReport,
    },
    /// Unused-tail advice ran, but Tier B is still required by the classifier.
    RequestTierB {
        /// The budget decision that selected this action.
        decision: EvalHeapMemoryBudgetDecision,
        /// The worker/permanent advice report produced before requesting Tier B.
        report: EvalHeapMemoryAdviceReport,
    },
}

impl EvalHeapMemoryBudgetAction {
    /// Returns the budget decision that selected this action.
    pub const fn decision(self) -> EvalHeapMemoryBudgetDecision {
        match self {
            Self::ContinueTierA { decision }
            | Self::AdviseUnusedTails { decision, .. }
            | Self::RequestTierB { decision, .. } => decision,
        }
    }

    /// Returns the operating-system advice report produced by this action.
    pub const fn advice_report(self) -> Option<EvalHeapMemoryAdviceReport> {
        match self {
            Self::ContinueTierA { .. } => None,
            Self::AdviseUnusedTails { report, .. } | Self::RequestTierB { report, .. } => {
                Some(report)
            }
        }
    }

    /// Returns whether the action reports that Tier B is still needed.
    pub const fn requests_tier_b(self) -> bool {
        matches!(self, Self::RequestTierB { .. })
    }
}

/// One typed heap record considered during Tier-B admission planning.
///
/// The record keeps both the current generation and the generation that a
/// cross-tier flip would assign. It is read-only planning metadata and does not
/// mutate the heap record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvalHeapTierBAdmissionRecord {
    address: GcHeapAddress,
    allocation_domain: HeapAllocationDomain,
    current_generation: HeapGeneration,
    admitted_generation: HeapGeneration,
}

impl EvalHeapTierBAdmissionRecord {
    const fn new(
        address: GcHeapAddress,
        allocation_domain: HeapAllocationDomain,
        current_generation: HeapGeneration,
        admitted_generation: HeapGeneration,
    ) -> Self {
        Self {
            address,
            allocation_domain,
            current_generation,
            admitted_generation,
        }
    }

    /// Returns the heap address of the typed record.
    pub const fn address(self) -> GcHeapAddress {
        self.address
    }

    /// Returns the allocation domain that currently owns the record.
    pub const fn allocation_domain(self) -> HeapAllocationDomain {
        self.allocation_domain
    }

    /// Returns the generation currently recorded on the heap record.
    pub const fn current_generation(self) -> HeapGeneration {
        self.current_generation
    }

    /// Returns the generation Tier-B admission would assign to the record.
    pub const fn admitted_generation(self) -> HeapGeneration {
        self.admitted_generation
    }

    /// Returns whether admission would rewrite the record's generation metadata.
    pub fn needs_generation_rewrite(self) -> bool {
        self.current_generation != self.admitted_generation
    }
}

/// Read-only heap-record plan for admitting a Tier-A heap into Tier B.
///
/// The plan treats worker-domain records as future old-generation records and
/// preserves permanent-shared records as permanent. It deliberately does not
/// install a collector, reserve semispace storage, switch allocators, rewrite
/// heap records, or relocate values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvalHeapTierBAdmissionPlan {
    worker_stats: ArenaStats,
    permanent_stats: ArenaStats,
    worker_records: usize,
    permanent_shared_records: usize,
    records: Vec<EvalHeapTierBAdmissionRecord>,
}

impl EvalHeapTierBAdmissionPlan {
    const fn new(
        worker_stats: ArenaStats,
        permanent_stats: ArenaStats,
        worker_records: usize,
        permanent_shared_records: usize,
        records: Vec<EvalHeapTierBAdmissionRecord>,
    ) -> Self {
        Self {
            worker_stats,
            permanent_stats,
            worker_records,
            permanent_shared_records,
            records,
        }
    }

    /// Returns worker-domain arena accounting captured by the plan.
    pub const fn worker_stats(&self) -> ArenaStats {
        self.worker_stats
    }

    /// Returns permanent-shared arena accounting captured by the plan.
    pub const fn permanent_stats(&self) -> ArenaStats {
        self.permanent_stats
    }

    /// Returns the number of worker-domain records in the plan.
    pub const fn worker_records(&self) -> usize {
        self.worker_records
    }

    /// Returns the number of permanent-shared records in the plan.
    pub const fn permanent_shared_records(&self) -> usize {
        self.permanent_shared_records
    }

    /// Returns admission metadata for all typed heap records in heap-record order.
    pub fn records(&self) -> &[EvalHeapTierBAdmissionRecord] {
        &self.records
    }

    /// Returns the number of typed heap records in the plan.
    pub fn record_count(&self) -> usize {
        self.records.len()
    }
}

/// Result of applying a Tier-B admission plan to heap-record metadata.
///
/// The report counts only generation metadata updates on existing typed heap
/// records. Applying admission does not move objects, change allocation
/// domains, reserve semispace storage, or install a collector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvalHeapTierBAdmissionReport {
    worker_records: usize,
    permanent_shared_records: usize,
    generation_rewrites: usize,
}

impl EvalHeapTierBAdmissionReport {
    const fn new(
        worker_records: usize,
        permanent_shared_records: usize,
        generation_rewrites: usize,
    ) -> Self {
        Self {
            worker_records,
            permanent_shared_records,
            generation_rewrites,
        }
    }

    /// Returns the number of worker-domain records admitted as old generation.
    pub const fn worker_records(self) -> usize {
        self.worker_records
    }

    /// Returns the number of permanent-shared records preserved as permanent.
    pub const fn permanent_shared_records(self) -> usize {
        self.permanent_shared_records
    }

    /// Returns the number of heap-record generation fields rewritten.
    pub const fn generation_rewrites(self) -> usize {
        self.generation_rewrites
    }
}

/// An opt-in cold-aware budget plan with optional advice telemetry.
///
/// This is planning metadata for the future spill path. Its decision can credit
/// logical cold hash-consed bytes as future CA-store spill capacity, while the
/// optional advice report records only the cheap operating-system hints the
/// oracle can issue today. Hash-consed cold/pageout advice preserves typed heap
/// values; it does not prove that resident bytes were reclaimed, install
/// CA-store spill handles, or rematerialize values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvalHeapCheapMemoryBudgetPlan {
    decision: EvalHeapMemoryBudgetDecision,
    cheap_advice_report: Option<EvalHeapCheapMemoryAdviceReport>,
}

impl EvalHeapCheapMemoryBudgetPlan {
    const fn new(
        decision: EvalHeapMemoryBudgetDecision,
        cheap_advice_report: Option<EvalHeapCheapMemoryAdviceReport>,
    ) -> Self {
        Self {
            decision,
            cheap_advice_report,
        }
    }

    /// Returns the cold-aware budget decision selected by the planner.
    pub const fn decision(self) -> EvalHeapMemoryBudgetDecision {
        self.decision
    }

    /// Returns the cheap memory-advice report produced while planning.
    ///
    /// A report means the classifier asked for reclaim and the oracle issued
    /// the cheap hints it can issue today. It is not evidence that cold
    /// hash-consed bytes were actually spilled or reclaimed.
    pub const fn cheap_advice_report(self) -> Option<EvalHeapCheapMemoryAdviceReport> {
        self.cheap_advice_report
    }
}

impl EvalHeap {
    /// Creates an empty evaluator heap.
    ///
    /// # Panics
    ///
    /// Panics if the process exhausts all evaluator heap region-owner ids.
    pub fn new() -> Self {
        Self::with_worker_allocator(RuntimeAllocator::tier_a_one_shot())
    }

    /// Creates an empty evaluator heap backed by the current thread's Tier-A arena.
    ///
    /// The heap still reports the [`RuntimeAllocatorTier::TierAOneShot`] tier,
    /// but worker storage comes from [`crate::heap::arena::ThreadLocalBumpArena`]
    /// through the same `aos_alloc_*` dispatch table. This is an opt-in
    /// per-worker precursor for the final CLI-wide Tier-A default.
    ///
    /// # Panics
    ///
    /// Panics if the process exhausts all evaluator heap region-owner ids, if
    /// the current thread already has an active thread-local runtime allocator,
    /// if the allocator owner-token counter is exhausted, or if the current
    /// thread's arena is already mutably borrowed.
    pub fn new_thread_local_tier_a() -> Self {
        Self::with_worker_allocator(RuntimeAllocator::tier_a_thread_local_empty())
    }

    fn with_worker_allocator(allocator: RuntimeAllocator) -> Self {
        Self {
            allocator,
            permanent_allocator: PermanentSharedAllocator::new(),
            region_owner: next_heap_region_owner(),
            worker_allocator_epoch: 0,
            worker_region_epoch: 0,
            next_worker_region_mark: 1,
            worker_region_mark_stack: Vec::new(),
            access_epoch: Cell::new(0),
            memory_budget: None,
            resident_memory_mode: EvalHeapResidentMemoryMode::ArenaMappedBytes,
            memory_budget_poll_count: 0,
            last_memory_budget_action: None,
            records: HeapRecordTable::new(),
            string_cons: HashConsTable::new(),
            path_cons: HashConsTable::new(),
            list_cons: HashConsTable::new(),
            attrs_cons: HashConsTable::new(),
            alloc_counters: EvalHeapAllocationCounters::default(),
        }
    }

    /// Creates an empty evaluator heap with an explicit first arena chunk size.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Arena`] if the requested chunk size is invalid
    /// or overflows while being rounded to the arena word size.
    ///
    /// # Panics
    ///
    /// Panics if the process exhausts all evaluator heap region-owner ids.
    pub fn with_initial_chunk_bytes(chunk_bytes: usize) -> Result<Self, EvalHeapError> {
        Ok(Self {
            allocator: RuntimeAllocator::tier_a_with_initial_chunk_bytes(chunk_bytes)
                .map_err(EvalHeapError::Arena)?,
            permanent_allocator: PermanentSharedAllocator::with_initial_chunk_bytes(chunk_bytes)
                .map_err(EvalHeapError::Arena)?,
            region_owner: next_heap_region_owner(),
            worker_allocator_epoch: 0,
            worker_region_epoch: 0,
            next_worker_region_mark: 1,
            worker_region_mark_stack: Vec::new(),
            access_epoch: Cell::new(0),
            memory_budget: None,
            resident_memory_mode: EvalHeapResidentMemoryMode::ArenaMappedBytes,
            memory_budget_poll_count: 0,
            last_memory_budget_action: None,
            records: HeapRecordTable::new(),
            string_cons: HashConsTable::new(),
            path_cons: HashConsTable::new(),
            list_cons: HashConsTable::new(),
            attrs_cons: HashConsTable::new(),
            alloc_counters: EvalHeapAllocationCounters::default(),
        })
    }

    /// Returns the configured automatic heap memory budget, if any.
    pub const fn memory_budget(&self) -> Option<HeapMemoryBudget> {
        self.memory_budget
    }

    /// Installs a heap memory budget for later allocation safepoints.
    ///
    /// Successful heap-object allocations classify whole-heap mapped bytes
    /// against this budget and run the currently implemented unused-tail advice
    /// action when the budget policy asks for reclaim.
    pub fn set_memory_budget(&mut self, budget: HeapMemoryBudget) {
        self.memory_budget = Some(budget);
        self.last_memory_budget_action = None;
    }

    /// Clears automatic heap memory-budget polling.
    pub fn clear_memory_budget(&mut self) {
        self.memory_budget = None;
        self.last_memory_budget_action = None;
    }

    /// Returns the resident-memory sampling mode for automatic budget polls.
    pub const fn resident_memory_mode(&self) -> EvalHeapResidentMemoryMode {
        self.resident_memory_mode
    }

    /// Replaces the resident-memory sampling mode for later budget polls.
    pub fn set_resident_memory_mode(&mut self, mode: EvalHeapResidentMemoryMode) {
        self.resident_memory_mode = mode;
        self.last_memory_budget_action = None;
    }

    /// Returns how many successful heap allocations polled the configured budget.
    pub const fn memory_budget_poll_count(&self) -> u64 {
        self.memory_budget_poll_count
    }

    /// Returns the most recent automatic memory-budget action.
    pub const fn last_memory_budget_action(&self) -> Option<EvalHeapMemoryBudgetAction> {
        self.last_memory_budget_action
    }

    /// Builds a read-only Tier-B admission plan for the current heap records.
    ///
    /// The plan captures current worker/permanent arena accounting and assigns
    /// future generation metadata from allocation domains: worker records become
    /// old-generation records, while permanent-shared records remain permanent.
    /// It does not mutate heap records or allocator state.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::RecordAllocationFailed`] if the record plan
    /// buffer cannot be reserved. Returns [`EvalHeapError::GenerationalGc`] if
    /// a registered heap pointer cannot be represented as a GC heap address.
    pub fn plan_tier_b_admission(&self) -> Result<EvalHeapTierBAdmissionPlan, EvalHeapError> {
        let mut records = Vec::new();
        records.try_reserve(self.records.len()).map_err(|_| {
            EvalHeapError::RecordAllocationFailed {
                records: self.records.len(),
            }
        })?;

        let mut worker_records = 0usize;
        let mut permanent_shared_records = 0usize;
        for record in &self.records {
            match record.allocation_domain {
                HeapAllocationDomain::Worker => {
                    worker_records = worker_records.saturating_add(1);
                }
                HeapAllocationDomain::PermanentShared => {
                    permanent_shared_records = permanent_shared_records.saturating_add(1);
                }
            }
            records.push(EvalHeapTierBAdmissionRecord::new(
                gc_address_for_heap_record(record)?,
                record.allocation_domain,
                record.generation,
                tier_b_admitted_generation_for_allocation_domain(record.allocation_domain),
            ));
        }

        Ok(EvalHeapTierBAdmissionPlan::new(
            self.arena_stats(),
            self.permanent_arena_stats(),
            worker_records,
            permanent_shared_records,
            records,
        ))
    }

    /// Applies a Tier-B admission plan to existing heap-record generations.
    ///
    /// The method validates that current heap accounting and typed heap records
    /// still match `plan`, then rewrites only generation metadata: worker-domain
    /// records become old-generation records and permanent-shared records remain
    /// permanent. Allocation domains, object bodies, heap handles, allocator
    /// storage, remembered sets, and card tables are not changed.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if `plan` no longer matches the current heap's
    /// arena accounting, record count, record order, allocation domains, or
    /// pre-admission generations.
    pub fn apply_tier_b_admission_plan(
        &mut self,
        plan: &EvalHeapTierBAdmissionPlan,
    ) -> Result<EvalHeapTierBAdmissionReport, EvalHeapError> {
        self.validate_tier_b_admission_plan(plan)?;

        let mut generation_rewrites = 0usize;
        for record in &mut self.records {
            let admitted_generation =
                tier_b_admitted_generation_for_allocation_domain(record.allocation_domain);
            if record.generation != admitted_generation {
                record.generation = admitted_generation;
                generation_rewrites = generation_rewrites.saturating_add(1);
            }
        }

        Ok(EvalHeapTierBAdmissionReport::new(
            plan.worker_records,
            plan.permanent_shared_records,
            generation_rewrites,
        ))
    }

    /// Returns the current heap record access epoch.
    pub fn access_epoch(&self) -> u64 {
        self.access_epoch.get()
    }

    /// Returns current runtime allocator accounting.
    pub fn arena_stats(&self) -> ArenaStats {
        self.allocator.stats()
    }

    /// Returns current permanent shared allocation accounting.
    pub fn permanent_arena_stats(&self) -> ArenaStats {
        self.permanent_allocator.stats()
    }

    /// Returns the typed-value allocation work counters for this heap.
    ///
    /// The counters describe how many heap records were pushed, how many
    /// attribute sets were constructed, and how effective hash-consing was, so
    /// a native evaluation can be compared work-for-work against C++ Nix's
    /// `NIX_SHOW_STATS` output.
    pub(crate) const fn allocation_counters(&self) -> EvalHeapAllocationCounters {
        self.alloc_counters
    }

    /// Captures the current worker-domain heap position for lexical region pop.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::WorkerRegionMarkLengthOverflow`] if the mark
    /// stack length overflows, [`EvalHeapError::WorkerRegionMarkAllocationFailed`]
    /// if the stack cannot reserve another marker, or
    /// [`EvalHeapError::WorkerRegionMarkIdExhausted`] if the per-heap marker id
    /// space is exhausted.
    pub fn worker_region_mark(&mut self) -> Result<EvalHeapWorkerRegionMark, EvalHeapError> {
        let marks = self
            .worker_region_mark_stack
            .len()
            .checked_add(1)
            .ok_or(EvalHeapError::WorkerRegionMarkLengthOverflow)?;
        self.worker_region_mark_stack
            .try_reserve_exact(1)
            .map_err(|_| EvalHeapError::WorkerRegionMarkAllocationFailed { marks })?;
        let mark_id = self.next_worker_region_mark;
        self.next_worker_region_mark = self
            .next_worker_region_mark
            .checked_add(1)
            .ok_or(EvalHeapError::WorkerRegionMarkIdExhausted)?;
        self.worker_region_mark_stack.push(mark_id);

        Ok(EvalHeapWorkerRegionMark::new(
            self.allocator.region_mark(),
            self.region_owner,
            self.worker_allocator_epoch,
            mark_id,
            self.records.len(),
        ))
    }

    #[cfg(test)]
    pub(crate) fn active_worker_region_marks_for_test(&self) -> usize {
        self.worker_region_mark_stack.len()
    }

    /// Reclaims worker-domain allocations above `mark` when no retained record
    /// points into that region.
    ///
    /// This is the typed side-table admission boundary for future lexical region
    /// inference. The suffix above `mark` must contain only worker-domain
    /// records, and precise edges from retained records must not target any
    /// suffix record. On success the method rewinds the worker arena, restores
    /// worker allocation-safepoint accounting to the marker, removes the suffix
    /// records from the typed side table, and clears cached memory-budget
    /// action telemetry. Reclaimed raw handles are invalid after the pop; a
    /// later bump allocation may reuse the same address for a new typed record.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::WorkerRegionPopStaleMark`] if `mark` cannot
    /// describe this heap's current typed record prefix. Returns
    /// [`EvalHeapError::WorkerRegionPopNonWorkerRecords`] if permanent records
    /// were allocated above the marker. Returns
    /// [`EvalHeapError::WorkerRegionPopRetainedEdge`] if a retained record still
    /// references a record above the marker. Returns [`EvalHeapError::Arena`] if
    /// the lower-level arena marker is invalid.
    ///
    /// # Panics
    ///
    /// Panics if the process exhausts all evaluator heap region-owner ids while
    /// rotating an overflowed worker-region epoch.
    pub fn pop_worker_region_if_disconnected(
        &mut self,
        mark: EvalHeapWorkerRegionMark,
    ) -> Result<EvalHeapWorkerRegionPopReport, EvalHeapError> {
        let reclaimed_records = self.validate_worker_region_pop(mark)?;
        let arena_report = self
            .allocator
            .pop_caller_validated_region(mark.allocator, reclaimed_records)
            .map_err(EvalHeapError::Arena)?;
        self.records.truncate(mark.records);
        let _ = self.worker_region_mark_stack.pop();
        self.advance_worker_region_epoch();
        self.last_memory_budget_action = None;
        Ok(EvalHeapWorkerRegionPopReport::new(
            arena_report,
            reclaimed_records,
            self.records.len(),
        ))
    }

    /// Retires a worker lexical-region marker without reclaiming its suffix.
    ///
    /// The marker must be the current innermost worker-region marker for this
    /// heap. The operation removes only the marker bookkeeping; allocations,
    /// typed records, safepoints, and memory-budget telemetry remain unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::WorkerRegionPopStaleMark`] if `mark` cannot
    /// describe this heap's current typed record prefix or is not the innermost
    /// active worker-region marker.
    pub fn cancel_worker_region_mark(
        &mut self,
        mark: EvalHeapWorkerRegionMark,
    ) -> Result<(), EvalHeapError> {
        self.validate_worker_region_mark_is_innermost(mark)?;
        let _ = self.worker_region_mark_stack.pop();
        Ok(())
    }

    /// Reclaims a worker lexical region when a region plan permits early pop.
    ///
    /// Plans that do not permit early pop retire `mark` with
    /// [`Self::cancel_worker_region_mark`] and return `Ok(None)` without
    /// reclaiming allocations. Plans that permit early pop use
    /// [`Self::pop_worker_region_if_disconnected`], so the existing typed
    /// side-table validation remains the reclamation safety boundary.
    ///
    /// # Errors
    ///
    /// When `plan` permits early pop, returns the same errors as
    /// [`Self::pop_worker_region_if_disconnected`].
    /// When `plan` does not permit early pop, returns the same stale-marker
    /// errors as [`Self::cancel_worker_region_mark`].
    ///
    /// # Panics
    ///
    /// When `plan` permits early pop, panics if the process exhausts all
    /// evaluator heap region-owner ids while rotating an overflowed worker
    /// region epoch.
    pub fn pop_worker_region_if_plan_permits(
        &mut self,
        mark: EvalHeapWorkerRegionMark,
        plan: RegionPlan,
    ) -> Result<Option<EvalHeapWorkerRegionPopReport>, EvalHeapError> {
        if !plan.permits_early_pop() {
            self.cancel_worker_region_mark(mark)?;
            return Ok(None);
        }

        self.pop_worker_region_if_disconnected(mark).map(Some)
    }

    /// Drops the worker-domain arena when no worker heap records remain live.
    ///
    /// Permanent-shared records, their cons tables, and permanent arena
    /// accounting are left intact. This is the safe admission boundary for a
    /// future per-worker arena reset: worker-domain handles must first be absent
    /// from the evaluator side table.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::WorkerResetLiveRecords`] when one or more
    /// worker-domain records are still registered in this heap.
    ///
    /// # Panics
    ///
    /// Panics if the process exhausts all evaluator heap region-owner ids while
    /// rotating an overflowed worker allocator or region epoch.
    pub fn reset_worker_allocator_if_idle(
        &mut self,
    ) -> Result<EvalHeapWorkerResetReport, EvalHeapError> {
        let live_worker_records = self
            .records
            .iter()
            .filter(|record| record.allocation_domain == HeapAllocationDomain::Worker)
            .count();
        if live_worker_records != 0 {
            return Err(EvalHeapError::WorkerResetLiveRecords {
                records: live_worker_records,
            });
        }

        let permanent_stats = self.permanent_arena_stats();
        let dropped_worker_stats = self.allocator.reset_to_empty();
        let worker_stats_after = self.arena_stats();
        self.worker_region_mark_stack.clear();
        self.advance_worker_allocator_epoch();
        self.advance_worker_region_epoch();
        self.last_memory_budget_action = None;
        Ok(EvalHeapWorkerResetReport::new(
            dropped_worker_stats,
            worker_stats_after,
            permanent_stats,
        ))
    }

    /// Builds a high-water budget sample for both heap allocation domains.
    ///
    /// This deterministic helper uses the saturating sum of worker and
    /// permanent mapped arena bytes as the resident-memory proxy. The caller
    /// supplies cheap-reclaim estimates for dead arena pages and cold
    /// hash-consed values.
    pub fn memory_budget_sample(
        &self,
        dead_arena_bytes: usize,
        cold_hash_consed_bytes: usize,
    ) -> HeapMemorySample {
        whole_heap_memory_budget_sample(
            self.arena_stats(),
            self.permanent_arena_stats(),
            dead_arena_bytes,
            cold_hash_consed_bytes,
        )
    }

    /// Classifies the whole heap against a high-water memory budget.
    pub fn classify_memory_budget(
        &self,
        budget: HeapMemoryBudget,
        dead_arena_bytes: usize,
        cold_hash_consed_bytes: usize,
    ) -> EvalHeapMemoryBudgetDecision {
        let worker_stats = self.arena_stats();
        let permanent_stats = self.permanent_arena_stats();
        let sample = whole_heap_memory_budget_sample(
            worker_stats,
            permanent_stats,
            dead_arena_bytes,
            cold_hash_consed_bytes,
        );
        EvalHeapMemoryBudgetDecision::new(
            budget,
            sample,
            EvalHeapResidentMemorySource::ArenaMappedBytes,
            worker_stats,
            permanent_stats,
        )
    }

    /// Returns cold hash-consed bytes using the supplied idle-epoch threshold.
    ///
    /// This is a logical-size estimate over permanent shared, structurally
    /// interned records. It does not evict, page out, or rematerialize values.
    pub fn cold_hash_consed_bytes(&self, min_idle_epochs: u64) -> usize {
        let current_epoch = self.access_epoch();
        self.records.iter().fold(0usize, |bytes, record| {
            if !Self::is_cold_hash_consed_record(record, current_epoch, min_idle_epochs) {
                return bytes;
            }
            bytes.saturating_add(record.layout.size_bytes)
        })
    }

    /// Returns cold hash-consed values selected by the idle-epoch policy.
    ///
    /// The snapshot is a non-destructive bridge for future CA-store spill work:
    /// it reconstructs checked [`Value`] words from permanent shared,
    /// structurally interned records without refreshing their access epochs,
    /// evicting resident objects, installing content-hash handles, or replaying
    /// spilled values.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if the snapshot vector cannot be reserved or a
    /// selected record cannot be represented as a checked heap value.
    pub fn cold_hash_consed_values(
        &self,
        min_idle_epochs: u64,
    ) -> Result<Vec<EvalHeapColdHashConsedValue>, EvalHeapError> {
        let current_epoch = self.access_epoch();
        let values = self
            .records
            .iter()
            .filter(|record| {
                Self::is_cold_hash_consed_record(record, current_epoch, min_idle_epochs)
            })
            .count();
        let mut snapshot = Vec::new();
        snapshot
            .try_reserve_exact(values)
            .map_err(|_| EvalHeapError::RecordAllocationFailed { records: values })?;
        for record in &self.records {
            if !Self::is_cold_hash_consed_record(record, current_epoch, min_idle_epochs) {
                continue;
            }
            let idle_epochs = Self::cold_hash_consed_record_idle_epochs(record, current_epoch);
            snapshot.push(EvalHeapColdHashConsedValue::new(
                Self::value_for_record(record)?,
                record.layout.size_bytes,
                idle_epochs,
            ));
        }
        Ok(snapshot)
    }

    /// Classifies the whole heap using current cold hash-consed byte estimates.
    ///
    /// This helper feeds cold-value capacity into the budget classifier for the
    /// future CA-store spill path. It does not execute spill or page eviction.
    pub fn classify_memory_budget_with_cold_hash_consed_estimate(
        &self,
        budget: HeapMemoryBudget,
        dead_arena_bytes: usize,
        min_idle_epochs: u64,
    ) -> EvalHeapMemoryBudgetDecision {
        self.classify_memory_budget(
            budget,
            dead_arena_bytes,
            self.cold_hash_consed_bytes(min_idle_epochs),
        )
    }

    /// Advises cold permanent hash-consed record pages to the operating system.
    ///
    /// This uses non-destructive [`MemoryAdviceKind::Cold`] hints over record
    /// byte ranges selected by the same idle-epoch policy as
    /// [`Self::cold_hash_consed_bytes`]. The advice shim trims each record range
    /// to complete contained pages before making a platform call. This does not
    /// evict values from the heap, install CA-store handles, or rematerialize
    /// values on demand.
    pub fn advise_cold_hash_consed_values(
        &self,
        min_idle_epochs: u64,
    ) -> EvalHeapColdHashConsedAdviceReport {
        self.advise_hash_consed_values(
            MemoryAdviceKind::Cold,
            min_idle_epochs,
            advise_cold_heap_object_allocation,
        )
    }

    /// Advises cold permanent hash-consed record pages for OS eviction.
    ///
    /// This uses non-destructive [`MemoryAdviceKind::Evict`] hints over record
    /// byte ranges selected by the same idle-epoch policy as
    /// [`Self::cold_hash_consed_bytes`]. On Linux this lowers to
    /// `MADV_PAGEOUT` after full-page trimming. This does not evict values from
    /// the typed heap, install CA-store handles, or rematerialize values on
    /// demand.
    pub fn advise_evict_hash_consed_values(
        &self,
        min_idle_epochs: u64,
    ) -> EvalHeapColdHashConsedAdviceReport {
        self.advise_hash_consed_values(
            MemoryAdviceKind::Evict,
            min_idle_epochs,
            advise_evict_heap_object_allocation,
        )
    }

    fn advise_hash_consed_values(
        &self,
        kind: MemoryAdviceKind,
        min_idle_epochs: u64,
        mut advise: impl FnMut(NonNull<HeapObject>, usize) -> MemoryAdviceOutcome,
    ) -> EvalHeapColdHashConsedAdviceReport {
        let current_epoch = self.access_epoch();
        let mut report = EvalHeapColdHashConsedAdviceReport::new(kind, min_idle_epochs);
        for record in &self.records {
            if !Self::is_cold_hash_consed_record(record, current_epoch, min_idle_epochs) {
                continue;
            }
            report.record(
                record.layout.size_bytes,
                advise(record.ptr, record.layout.size_bytes),
            );
        }
        report
    }

    /// Advises unused bytes at the end of both heap allocation domains.
    ///
    /// This forwards to each underlying arena's unused-tail advice hook and does
    /// not select dead regions, spill hash-consed values, or install a collector.
    pub fn advise_unused_tails(&self, kind: MemoryAdviceKind) -> EvalHeapMemoryAdviceReport {
        EvalHeapMemoryAdviceReport::new(
            kind,
            self.allocator.advise_unused_tail(kind),
            self.permanent_allocator.advise_unused_tail(kind),
        )
    }

    /// Advises all cheap heap ranges currently implemented by the oracle heap.
    ///
    /// Unused arena tails receive destructive [`MemoryAdviceKind::Dead`] advice
    /// because no live allocation has reached them. Cold hash-consed records
    /// receive non-destructive [`MemoryAdviceKind::Cold`] advice through
    /// [`Self::advise_cold_hash_consed_values`]. This method does not classify
    /// a memory budget, credit cold reclaim capacity, request Tier B, or execute
    /// CA-store spill.
    pub fn advise_cheap_memory_ranges(
        &self,
        min_idle_epochs: u64,
    ) -> EvalHeapCheapMemoryAdviceReport {
        EvalHeapCheapMemoryAdviceReport::new(
            self.advise_unused_tails(MemoryAdviceKind::Dead),
            self.advise_cold_hash_consed_values(min_idle_epochs),
        )
    }

    /// Returns whole-heap unused-tail bytes this platform can lower to page advice.
    pub fn supported_unused_tail_advice_bytes(&self) -> usize {
        self.allocator
            .supported_unused_tail_advice_bytes()
            .saturating_add(
                self.permanent_allocator
                    .supported_unused_tail_advice_bytes(),
            )
    }

    /// Classifies memory pressure and applies the currently implemented cheap
    /// reclaim action.
    ///
    /// The method estimates dead arena bytes from unused worker/permanent arena
    /// tails that the active advice shim can lower, samples resident bytes from
    /// the configured resident-memory mode, classifies the whole heap with no
    /// cold hash-cons reclaim estimate, and applies destructive dead-page advice
    /// to unused tails when the classifier asks for reclaim. It does not spill
    /// cold hash-consed values or install Tier B; those states are reflected in
    /// the returned action for future runtime dispatch.
    pub fn respond_to_memory_budget_with_unused_tail_advice(
        &self,
        budget: HeapMemoryBudget,
    ) -> EvalHeapMemoryBudgetAction {
        let worker_stats = self.arena_stats();
        let permanent_stats = self.permanent_arena_stats();
        let dead_arena_bytes = self.supported_unused_tail_advice_bytes();
        let (resident_bytes, resident_source) =
            self.memory_budget_resident_bytes(worker_stats, permanent_stats);
        let sample = HeapMemorySample::new(resident_bytes, dead_arena_bytes, 0);
        let decision = EvalHeapMemoryBudgetDecision::new(
            budget,
            sample,
            resident_source,
            worker_stats,
            permanent_stats,
        );
        match decision.response() {
            HeapMemoryBudgetResponse::ContinueTierA { .. } => {
                EvalHeapMemoryBudgetAction::ContinueTierA { decision }
            }
            HeapMemoryBudgetResponse::SpillCold { .. } => {
                let report = self.advise_unused_tails(MemoryAdviceKind::Dead);
                EvalHeapMemoryBudgetAction::AdviseUnusedTails { decision, report }
            }
            HeapMemoryBudgetResponse::InstallTierB { .. } => {
                let report = self.advise_unused_tails(MemoryAdviceKind::Dead);
                EvalHeapMemoryBudgetAction::RequestTierB { decision, report }
            }
        }
    }

    /// Builds a cold-aware budget plan and applies cheap advice for telemetry.
    ///
    /// The method estimates dead arena bytes from supported unused
    /// worker/permanent arena tails, estimates cold permanent hash-consed bytes
    /// with `min_idle_epochs`, samples resident bytes from the configured
    /// resident-memory mode, and classifies the whole heap with both reclaim
    /// estimates. When the classifier asks for reclaim, it records the cheap
    /// hints available today by applying destructive dead-page advice to unused
    /// tails and non-destructive pageout advice to selected hash-consed records.
    /// The returned decision can model future CA-store spill capacity, but the
    /// advice report is not proof that cold hash-consed resident bytes were
    /// reclaimed. Automatic allocation-safepoint polling keeps using
    /// [`Self::respond_to_memory_budget_with_unused_tail_advice`].
    pub fn plan_memory_budget_with_cheap_memory_advice(
        &self,
        budget: HeapMemoryBudget,
        min_idle_epochs: u64,
    ) -> EvalHeapCheapMemoryBudgetPlan {
        let worker_stats = self.arena_stats();
        let permanent_stats = self.permanent_arena_stats();
        let dead_arena_bytes = self.supported_unused_tail_advice_bytes();
        let cold_hash_consed_bytes = self.cold_hash_consed_bytes(min_idle_epochs);
        let (resident_bytes, resident_source) =
            self.memory_budget_resident_bytes(worker_stats, permanent_stats);
        let sample =
            HeapMemorySample::new(resident_bytes, dead_arena_bytes, cold_hash_consed_bytes);
        let decision = EvalHeapMemoryBudgetDecision::new(
            budget,
            sample,
            resident_source,
            worker_stats,
            permanent_stats,
        );
        let cheap_advice_report = match decision.response() {
            HeapMemoryBudgetResponse::ContinueTierA { .. } => None,
            HeapMemoryBudgetResponse::SpillCold { .. }
            | HeapMemoryBudgetResponse::InstallTierB { .. } => {
                Some(EvalHeapCheapMemoryAdviceReport::new(
                    self.advise_unused_tails(MemoryAdviceKind::Dead),
                    self.advise_evict_hash_consed_values(min_idle_epochs),
                ))
            }
        };
        EvalHeapCheapMemoryBudgetPlan::new(decision, cheap_advice_report)
    }

    fn poll_memory_budget_after_allocation(&mut self) {
        let Some(budget) = self.memory_budget else {
            return;
        };
        self.memory_budget_poll_count = self.memory_budget_poll_count.saturating_add(1);
        self.last_memory_budget_action =
            Some(self.respond_to_memory_budget_with_unused_tail_advice(budget));
    }

    fn memory_budget_resident_bytes(
        &self,
        worker_stats: ArenaStats,
        permanent_stats: ArenaStats,
    ) -> (usize, EvalHeapResidentMemorySource) {
        let mapped_bytes = worker_stats
            .mapped_bytes
            .saturating_add(permanent_stats.mapped_bytes);
        match self.resident_memory_mode {
            EvalHeapResidentMemoryMode::ArenaMappedBytes => {
                (mapped_bytes, EvalHeapResidentMemorySource::ArenaMappedBytes)
            }
            EvalHeapResidentMemoryMode::ProcessResidentSetWithArenaFallback => {
                match ProcessResidentMemorySample::current() {
                    Ok(Some(sample)) => (
                        sample.resident_bytes(),
                        EvalHeapResidentMemorySource::ProcessResidentSet(sample.source()),
                    ),
                    Ok(None) | Err(_) => {
                        (mapped_bytes, EvalHeapResidentMemorySource::ArenaMappedBytes)
                    }
                }
            }
        }
    }

    /// Installs one GC-stress polling policy for both worker and permanent
    /// allocation domains.
    pub fn set_gc_stress_policy(&mut self, policy: GcStressPolicy) {
        self.allocator.set_gc_stress_policy(policy);
        self.permanent_allocator.set_gc_stress_policy(policy);
    }

    /// Returns the worker allocation-domain GC-stress polling policy.
    pub const fn allocator_gc_stress_policy(&self) -> GcStressPolicy {
        self.allocator.gc_stress_policy()
    }

    /// Returns the permanent allocation-domain GC-stress polling policy.
    pub const fn permanent_allocator_gc_stress_policy(&self) -> GcStressPolicy {
        self.permanent_allocator.gc_stress_policy()
    }

    /// Returns allocation-safepoint accounting for worker-domain allocations.
    pub const fn allocation_safepoints(&self) -> AllocationSafepointState {
        self.allocator.allocation_safepoints()
    }

    /// Returns allocation-safepoint accounting for permanent shared
    /// allocations.
    pub const fn permanent_allocation_safepoints(&self) -> AllocationSafepointState {
        self.permanent_allocator.allocation_safepoints()
    }

    /// Returns the runtime allocation tier backing this heap.
    pub fn allocator_tier(&self) -> RuntimeAllocatorTier {
        self.allocator.tier()
    }

    /// Returns whether worker allocations use the current thread's Tier-A arena.
    pub fn uses_thread_local_tier_a(&self) -> bool {
        self.allocator.uses_thread_local_tier_a()
    }

    /// Returns the runtime allocation tier backing permanent shared values.
    pub fn permanent_allocator_tier(&self) -> RuntimeAllocatorTier {
        self.permanent_allocator.tier()
    }

    /// Returns the allocation domain that owns `value`'s typed heap record.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not an evaluator heap
    /// value. Returns [`EvalHeapError::UnknownPointer`] if the heap handle does
    /// not belong to this heap. Returns [`EvalHeapError::RecordTypeMismatch`]
    /// if the handle belongs to this heap but references another typed record.
    pub fn allocation_domain(&self, value: Value) -> Result<HeapAllocationDomain, EvalHeapError> {
        let (tag, ptr) = any_value_heap_ptr(value)?;
        let record = self.record_or_unknown(tag, ptr)?;
        let actual = record.object.tag();
        if actual == tag {
            Ok(record.allocation_domain)
        } else {
            Err(EvalHeapError::record_type_mismatch(tag, actual, ptr))
        }
    }

    /// Returns the heap generation that currently owns `value`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not an evaluator heap
    /// value. Returns [`EvalHeapError::UnknownPointer`] if the heap handle does
    /// not belong to this heap. Returns [`EvalHeapError::RecordTypeMismatch`]
    /// if the handle belongs to this heap but references another typed record.
    pub fn generation(&self, value: Value) -> Result<HeapGeneration, EvalHeapError> {
        let (tag, ptr) = any_value_heap_ptr(value)?;
        let record = self.record_or_unknown(tag, ptr)?;
        let actual = record.object.tag();
        if actual == tag {
            Ok(record.generation)
        } else {
            Err(EvalHeapError::record_type_mismatch(tag, actual, ptr))
        }
    }

    /// Replaces a heap record's allocation domain in evaluator tests.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not an evaluator heap
    /// value. Returns [`EvalHeapError::UnknownPointer`] if the heap handle does
    /// not belong to this heap. Returns [`EvalHeapError::RecordTypeMismatch`]
    /// if the handle belongs to this heap but references another typed record.
    #[cfg(test)]
    pub(crate) fn set_allocation_domain_for_test(
        &mut self,
        value: Value,
        domain: HeapAllocationDomain,
    ) -> Result<(), EvalHeapError> {
        let (tag, ptr) = any_value_heap_ptr(value)?;
        let address = ptr.as_ptr() as usize;
        let record = self
            .records
            .iter_mut()
            .find(|record| record.ptr.as_ptr() as usize == address)
            .ok_or_else(|| EvalHeapError::unknown(tag, ptr))?;
        let actual = record.object.tag();
        if actual != tag {
            return Err(EvalHeapError::record_type_mismatch(tag, actual, ptr));
        }
        record.allocation_domain = domain;
        record.generation = initial_generation_for_allocation_domain(domain);
        Ok(())
    }

    /// Returns the number of typed objects registered in this heap.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns whether this heap contains no typed objects.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn test_record_value(&self, index: usize) -> Option<Result<Value, EvalHeapError>> {
        self.records.get(index).map(Self::value_for_record)
    }

    #[cfg(test)]
    pub(crate) fn test_record_values(
        &self,
    ) -> impl Iterator<Item = Result<Value, EvalHeapError>> + '_ {
        self.records.iter().map(Self::value_for_record)
    }

    /// Allocates a Nix string object and returns its opaque runtime value.
    ///
    /// The returned value is only meaningful while this [`EvalHeap`] remains
    /// alive. Use [`EvalHeap::get_string`] to recover the typed string.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if record or cons-table storage cannot be
    /// reserved, if the runtime allocator cannot reserve a string handle, or if
    /// the resulting handle violates the runtime value alignment contract.
    pub fn alloc_string(&mut self, string: NixString) -> Result<Value, EvalHeapError> {
        let hash = string.structural_hash_xxh3();
        let cons_slot = match self.admit_string_cons(hash, &string)? {
            HashConsReservation::Existing(value) => {
                self.alloc_counters.note_hashcons(true);
                self.touch_reusable_value(value)?;
                return Ok(value);
            }
            HashConsReservation::Vacant(slot) => {
                self.alloc_counters.note_hashcons(false);
                slot
            }
        };
        let allocation = match self
            .permanent_allocator
            .aos_alloc_string(string.len())
            .map_err(EvalHeapError::Arena)
        {
            Ok(allocation) => allocation,
            Err(error) => {
                self.cancel_string_cons_slot(cons_slot);
                return Err(error);
            }
        };
        let value = match Value::string(allocation.ptr).map_err(EvalHeapError::Value) {
            Ok(value) => value,
            Err(error) => {
                self.cancel_string_cons_slot(cons_slot);
                return Err(error);
            }
        };
        let last_touch_epoch = Cell::new(self.next_access_epoch());
        self.records.push(HeapRecord {
            ptr: allocation.ptr,
            layout: HeapRecordLayout::from_allocation(allocation),
            structural_hash: Some(hash),
            allocation_domain: HeapAllocationDomain::PermanentShared,
            generation: initial_generation_for_allocation_domain(
                HeapAllocationDomain::PermanentShared,
            ),
            minor_gc_forwarding: Cell::new(None),
            last_touch_epoch,
            object: HeapObjectValue::String(string),
        });
        self.push_string_cons_value(cons_slot, value);
        self.alloc_counters.note_value_allocated();
        self.poll_memory_budget_after_allocation();
        Ok(value)
    }

    /// Allocates a Nix path object and returns its opaque runtime value.
    ///
    /// The returned value is only meaningful while this [`EvalHeap`] remains
    /// alive. Use [`EvalHeap::get_path`] to recover the typed path bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if record or cons-table storage cannot be
    /// reserved, if the runtime allocator cannot reserve a path handle, or if
    /// the resulting handle violates the runtime value alignment contract.
    pub fn alloc_path(&mut self, path: NixString) -> Result<Value, EvalHeapError> {
        let hash = path.structural_hash_xxh3();
        let cons_slot = match self.admit_path_cons(hash, &path)? {
            HashConsReservation::Existing(value) => {
                self.alloc_counters.note_hashcons(true);
                self.touch_reusable_value(value)?;
                return Ok(value);
            }
            HashConsReservation::Vacant(slot) => {
                self.alloc_counters.note_hashcons(false);
                slot
            }
        };
        let allocation = match self
            .permanent_allocator
            .aos_alloc_string(path.len())
            .map_err(EvalHeapError::Arena)
        {
            Ok(allocation) => allocation,
            Err(error) => {
                self.cancel_path_cons_slot(cons_slot);
                return Err(error);
            }
        };
        let value = match Value::path(allocation.ptr).map_err(EvalHeapError::Value) {
            Ok(value) => value,
            Err(error) => {
                self.cancel_path_cons_slot(cons_slot);
                return Err(error);
            }
        };
        let last_touch_epoch = Cell::new(self.next_access_epoch());
        self.records.push(HeapRecord {
            ptr: allocation.ptr,
            layout: HeapRecordLayout::from_allocation(allocation),
            structural_hash: Some(hash),
            allocation_domain: HeapAllocationDomain::PermanentShared,
            generation: initial_generation_for_allocation_domain(
                HeapAllocationDomain::PermanentShared,
            ),
            minor_gc_forwarding: Cell::new(None),
            last_touch_epoch,
            object: HeapObjectValue::Path(path),
        });
        self.push_path_cons_value(cons_slot, value);
        self.alloc_counters.note_value_allocated();
        self.poll_memory_budget_after_allocation();
        Ok(value)
    }

    /// Allocates a Nix list object and returns its opaque runtime value.
    ///
    /// The returned value is only meaningful while this [`EvalHeap`] remains
    /// alive. Use [`EvalHeap::get_list`] to recover the typed list.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if record or cons-table storage cannot be
    /// reserved, if the runtime allocator cannot reserve a list handle, or if
    /// the resulting handle violates the runtime value alignment contract.
    pub fn alloc_list(&mut self, list: NixList) -> Result<Value, EvalHeapError> {
        let hash = list_structural_hash(&list);
        let cons_slot = match self.admit_list_cons(hash, &list)? {
            HashConsReservation::Existing(value) => {
                self.alloc_counters.note_hashcons(true);
                self.touch_reusable_value(value)?;
                return Ok(value);
            }
            HashConsReservation::Vacant(slot) => {
                self.alloc_counters.note_hashcons(false);
                slot
            }
        };
        let allocation = match self
            .permanent_allocator
            .aos_alloc_list(list.len())
            .map_err(EvalHeapError::Arena)
        {
            Ok(allocation) => allocation,
            Err(error) => {
                self.cancel_list_cons_slot(cons_slot);
                return Err(error);
            }
        };
        let value = match Value::list(allocation.ptr).map_err(EvalHeapError::Value) {
            Ok(value) => value,
            Err(error) => {
                self.cancel_list_cons_slot(cons_slot);
                return Err(error);
            }
        };
        let last_touch_epoch = Cell::new(self.next_access_epoch());
        self.records.push(HeapRecord {
            ptr: allocation.ptr,
            layout: HeapRecordLayout::from_allocation(allocation),
            structural_hash: Some(hash),
            allocation_domain: HeapAllocationDomain::PermanentShared,
            generation: initial_generation_for_allocation_domain(
                HeapAllocationDomain::PermanentShared,
            ),
            minor_gc_forwarding: Cell::new(None),
            last_touch_epoch,
            object: HeapObjectValue::List(list),
        });
        self.push_list_cons_value(cons_slot, value);
        self.alloc_counters.note_value_allocated();
        self.poll_memory_budget_after_allocation();
        Ok(value)
    }

    /// Allocates an attribute-set object and returns its opaque runtime value.
    ///
    /// The returned value is only meaningful while this [`EvalHeap`] remains
    /// alive. Use [`EvalHeap::get_attrs`] to recover the typed attrset.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if record or cons-table storage cannot be
    /// reserved, if the attrset length cannot fit the runtime slot count, if
    /// the runtime allocator cannot reserve an attrset handle, or if the
    /// resulting handle violates the runtime value alignment contract.
    pub fn alloc_attrs(&mut self, shape: u32, attrs: FlatAttrs) -> Result<Value, EvalHeapError> {
        self.alloc_attrs_with_repr_metadata(shape, AttrSetReprKind::Flat, attrs)
    }

    /// Allocates an attribute-set object with explicit representation metadata.
    ///
    /// The active object payload remains [`FlatAttrs`]. The `repr` argument is
    /// persisted with the heap record so policy-aware attrset operations can
    /// observe the representation selected for this value while existing flat
    /// consumers keep using [`EvalHeap::get_attrs`].
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if record or cons-table storage cannot be
    /// reserved, if the attrset length cannot fit the runtime slot count, if
    /// the runtime allocator cannot reserve an attrset handle, or if the
    /// resulting handle violates the runtime value alignment contract.
    pub fn alloc_attrs_with_repr_metadata(
        &mut self,
        shape: u32,
        repr: AttrSetReprKind,
        attrs: FlatAttrs,
    ) -> Result<Value, EvalHeapError> {
        self.alloc_attrs_with_projected_shape_metadata(shape, repr, None, attrs)
    }

    /// Allocates an attribute-set value with representation and shape metadata.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if record or cons-table storage cannot be
    /// reserved, if the attrset length cannot fit the runtime slot count, if
    /// the runtime allocator cannot reserve an attrset handle, or if the
    /// resulting handle violates the runtime value alignment contract.
    pub fn alloc_attrs_with_projected_shape_metadata(
        &mut self,
        shape: u32,
        repr: AttrSetReprKind,
        projected_shape: Option<ShapeId>,
        attrs: FlatAttrs,
    ) -> Result<Value, EvalHeapError> {
        self.alloc_counters.note_attrs_built(attrs.len());
        let metadata = match projected_shape {
            Some(projected_shape) => {
                EvalHeapAttrsMetadata::with_projected_shape(shape, repr, projected_shape)
            }
            None => EvalHeapAttrsMetadata::new(shape, repr),
        };
        let hash = attrs_structural_hash(metadata, &attrs);
        let slots = u32::try_from(attrs.len())
            .map_err(|_| EvalHeapError::Arena(ArenaError::SizeOverflow))?;
        let cons_slot = match self.admit_attrs_cons(hash, metadata, &attrs)? {
            HashConsReservation::Existing(value) => {
                self.alloc_counters.note_hashcons(true);
                self.touch_reusable_value(value)?;
                return Ok(value);
            }
            HashConsReservation::Vacant(slot) => {
                self.alloc_counters.note_hashcons(false);
                slot
            }
        };
        let allocation = match self
            .permanent_allocator
            .aos_alloc_attrs(shape, slots)
            .map_err(EvalHeapError::Arena)
        {
            Ok(allocation) => allocation,
            Err(error) => {
                self.cancel_attrs_cons_slot(cons_slot);
                return Err(error);
            }
        };
        let value = match Value::attrs(allocation.ptr).map_err(EvalHeapError::Value) {
            Ok(value) => value,
            Err(error) => {
                self.cancel_attrs_cons_slot(cons_slot);
                return Err(error);
            }
        };
        let last_touch_epoch = Cell::new(self.next_access_epoch());
        self.records.push(HeapRecord {
            ptr: allocation.ptr,
            layout: HeapRecordLayout::from_allocation(allocation),
            structural_hash: Some(hash),
            allocation_domain: HeapAllocationDomain::PermanentShared,
            generation: initial_generation_for_allocation_domain(
                HeapAllocationDomain::PermanentShared,
            ),
            minor_gc_forwarding: Cell::new(None),
            last_touch_epoch,
            object: HeapObjectValue::Attrs { metadata, attrs },
        });
        self.push_attrs_cons_value(cons_slot, value);
        self.alloc_counters.note_value_allocated();
        self.poll_memory_budget_after_allocation();
        Ok(value)
    }

    /// Allocates a lambda closure object and returns its opaque runtime value.
    ///
    /// The returned value is only meaningful while this [`EvalHeap`] remains
    /// alive. Use [`EvalHeap::get_lambda`] to recover the typed closure.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if record storage cannot be reserved, if the
    /// runtime allocator cannot reserve a lambda handle, or if the resulting
    /// handle violates the runtime value alignment contract.
    pub fn alloc_lambda(&mut self, lambda: EvalLambda) -> Result<Value, EvalHeapError> {
        self.reserve_record_slot()?;
        let allocation = self
            .allocator
            .aos_alloc_lambda()
            .map_err(EvalHeapError::Arena)?;
        let value = Value::lambda(allocation.ptr).map_err(EvalHeapError::Value)?;
        let last_touch_epoch = Cell::new(self.next_access_epoch());
        self.records.push(HeapRecord {
            ptr: allocation.ptr,
            layout: HeapRecordLayout::from_allocation(allocation),
            structural_hash: None,
            allocation_domain: HeapAllocationDomain::Worker,
            generation: initial_generation_for_allocation_domain(HeapAllocationDomain::Worker),
            minor_gc_forwarding: Cell::new(None),
            last_touch_epoch,
            object: HeapObjectValue::Lambda(Rc::new(lambda)),
        });
        self.alloc_counters.note_value_allocated();
        self.poll_memory_budget_after_allocation();
        Ok(value)
    }

    /// Allocates a builtin function object and returns its opaque runtime value.
    ///
    /// The returned value is only meaningful while this [`EvalHeap`] remains
    /// alive. Use [`EvalHeap::get_primop`] to recover the typed builtin record.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if record storage cannot be reserved, if the
    /// runtime allocator cannot reserve a builtin handle, or if the resulting
    /// handle violates the runtime value alignment contract.
    pub fn alloc_primop(&mut self, primop: EvalPrimOp) -> Result<Value, EvalHeapError> {
        self.reserve_record_slot()?;
        let allocation = self
            .allocator
            .aos_alloc_raw(PRIMOP_HANDLE_BYTES, PRIMOP_HANDLE_ALIGN, PRIMOP_TYPE_TAG)
            .map_err(EvalHeapError::Arena)?;
        let value = Value::primop(allocation.ptr).map_err(EvalHeapError::Value)?;
        let last_touch_epoch = Cell::new(self.next_access_epoch());
        self.records.push(HeapRecord {
            ptr: allocation.ptr,
            layout: HeapRecordLayout::from_allocation(allocation),
            structural_hash: None,
            allocation_domain: HeapAllocationDomain::Worker,
            generation: initial_generation_for_allocation_domain(HeapAllocationDomain::Worker),
            minor_gc_forwarding: Cell::new(None),
            last_touch_epoch,
            object: HeapObjectValue::Primop(Rc::new(primop)),
        });
        self.alloc_counters.note_value_allocated();
        self.poll_memory_budget_after_allocation();
        Ok(value)
    }

    /// Allocates a suspended thunk object and returns its opaque runtime value.
    ///
    /// The returned value is only meaningful while this [`EvalHeap`] remains
    /// alive. Use [`EvalHeap::get_thunk`] to recover the typed thunk record.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if record storage cannot be reserved, if the
    /// runtime allocator cannot reserve a thunk handle, or if the resulting
    /// handle violates the runtime value alignment contract.
    pub fn alloc_thunk(&mut self, thunk: EvalThunk) -> Result<Value, EvalHeapError> {
        self.reserve_record_slot()?;
        let allocation = self
            .allocator
            .aos_alloc_thunk()
            .map_err(EvalHeapError::Arena)?;
        let value = Value::thunk(allocation.ptr).map_err(EvalHeapError::Value)?;
        let last_touch_epoch = Cell::new(self.next_access_epoch());
        self.records.push(HeapRecord {
            ptr: allocation.ptr,
            layout: HeapRecordLayout::from_allocation(allocation),
            structural_hash: None,
            allocation_domain: HeapAllocationDomain::Worker,
            generation: initial_generation_for_allocation_domain(HeapAllocationDomain::Worker),
            minor_gc_forwarding: Cell::new(None),
            last_touch_epoch,
            object: HeapObjectValue::Thunk(Rc::new(thunk)),
        });
        self.alloc_counters.note_value_allocated();
        self.poll_memory_budget_after_allocation();
        Ok(value)
    }

    /// Allocates a worker-domain placeholder record for a reserved minor-GC destination.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError`] if `tag` is not a worker-domain record type that
    /// can be copied by the current reservation bridge, if record storage cannot
    /// be reserved, if the runtime allocator fails, or if the allocated handle
    /// cannot be represented as a typed evaluator value.
    pub(super) fn alloc_minor_gc_destination_worker_record(
        &mut self,
        source: GcHeapAddress,
        tag: ValueTag,
    ) -> Result<Value, EvalHeapError> {
        if !matches!(tag, ValueTag::Lambda | ValueTag::Primop | ValueTag::Thunk) {
            return Err(
                EvalHeapError::CollectorPollMinorGcDestinationReservationUnsupported {
                    source_address: source,
                    tag,
                },
            );
        }

        self.reserve_record_slot()?;
        let allocation = match tag {
            ValueTag::Lambda => self
                .allocator
                .aos_alloc_lambda()
                .map_err(EvalHeapError::Arena)?,
            ValueTag::Primop => self
                .allocator
                .aos_alloc_raw(PRIMOP_HANDLE_BYTES, PRIMOP_HANDLE_ALIGN, PRIMOP_TYPE_TAG)
                .map_err(EvalHeapError::Arena)?,
            ValueTag::Thunk => self
                .allocator
                .aos_alloc_thunk()
                .map_err(EvalHeapError::Arena)?,
            tag => {
                return Err(
                    EvalHeapError::CollectorPollMinorGcDestinationReservationUnsupported {
                        source_address: source,
                        tag,
                    },
                );
            }
        };
        let (value, object) = match tag {
            ValueTag::Lambda => (
                Value::lambda(allocation.ptr),
                HeapObjectValue::Lambda(Rc::new(EvalLambda::new(
                    IrId::new(0),
                    IrId::new(0),
                    FrameId::new(0),
                    EvalEnv::default(),
                ))),
            ),
            ValueTag::Primop => (
                Value::primop(allocation.ptr),
                HeapObjectValue::Primop(Rc::new(EvalPrimOp::new(Symbol::new(0)))),
            ),
            ValueTag::Thunk => (
                Value::thunk(allocation.ptr),
                HeapObjectValue::Thunk(Rc::new(EvalThunk::new(IrId::new(0)))),
            ),
            tag => {
                return Err(
                    EvalHeapError::CollectorPollMinorGcDestinationReservationUnsupported {
                        source_address: source,
                        tag,
                    },
                );
            }
        };
        let value = value.map_err(EvalHeapError::Value)?;
        let last_touch_epoch = Cell::new(self.next_access_epoch());
        self.records.push(HeapRecord {
            ptr: allocation.ptr,
            layout: HeapRecordLayout::from_allocation(allocation),
            structural_hash: None,
            allocation_domain: HeapAllocationDomain::Worker,
            generation: initial_generation_for_allocation_domain(HeapAllocationDomain::Worker),
            minor_gc_forwarding: Cell::new(None),
            last_touch_epoch,
            object,
        });
        self.poll_memory_budget_after_allocation();
        Ok(value)
    }

    /// Returns the cached canonical value hash for a reusable heap value.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not a string, path, list,
    /// or attrset. Returns [`EvalHeapError::UnknownPointer`] if the heap handle
    /// does not belong to this heap. Returns
    /// [`EvalHeapError::RecordTypeMismatch`] if the handle belongs to this heap
    /// but references a different typed record.
    pub(crate) fn cached_value_hash(
        &self,
        value: Value,
    ) -> Result<Option<ValueHash>, EvalHeapError> {
        let address = self.record_for_value(value)?.ptr.as_ptr() as usize;
        Ok(self.records.cold_value_hash(address))
    }

    /// Stores the canonical value hash for a reusable heap value.
    ///
    /// Repeated writes of the same hash are accepted, but a different hash for
    /// the same immutable heap record is rejected and leaves the cached hash
    /// unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not a string, path, list,
    /// or attrset. Returns [`EvalHeapError::UnknownPointer`] if the heap handle
    /// does not belong to this heap. Returns
    /// [`EvalHeapError::RecordTypeMismatch`] if the handle belongs to this heap
    /// but references a different typed record. Returns
    /// [`EvalHeapError::ValueHashMismatch`] if the record already carries a
    /// different canonical value hash.
    pub(crate) fn cache_value_hash(
        &self,
        value: Value,
        hash: ValueHash,
    ) -> Result<HeapValueHashCacheUpdate, EvalHeapError> {
        let address = self.record_for_value(value)?.ptr.as_ptr() as usize;
        match self.records.cold_value_hash(address) {
            Some(existing) if existing == hash => Ok(HeapValueHashCacheUpdate::AlreadyPresent),
            Some(existing) => Err(EvalHeapError::ValueHashMismatch {
                existing,
                attempted: hash,
            }),
            None => {
                self.records.set_cold_value_hash(address, Some(hash));
                Ok(HeapValueHashCacheUpdate::Inserted)
            }
        }
    }

    /// Returns the cached force-capture value hash for a reusable heap value.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not a string, path, list,
    /// or attrset. Returns [`EvalHeapError::UnknownPointer`] if the heap handle
    /// does not belong to this heap. Returns
    /// [`EvalHeapError::RecordTypeMismatch`] if the handle belongs to this heap
    /// but references a different typed record.
    pub(crate) fn cached_captured_value_hash(
        &self,
        value: Value,
    ) -> Result<Option<ValueHash>, EvalHeapError> {
        let address = self.record_for_value(value)?.ptr.as_ptr() as usize;
        Ok(self.records.cold_captured_value_hash(address))
    }

    /// Stores the force-capture value hash for a reusable heap value.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not a string, path, list,
    /// or attrset. Returns [`EvalHeapError::UnknownPointer`] if the heap handle
    /// does not belong to this heap. Returns
    /// [`EvalHeapError::RecordTypeMismatch`] if the handle belongs to this heap
    /// but references a different typed record.
    pub(crate) fn cache_captured_value_hash(
        &self,
        value: Value,
        hash: ValueHash,
    ) -> Result<(), EvalHeapError> {
        let address = self.record_for_value(value)?.ptr.as_ptr() as usize;
        self.records
            .set_cold_captured_value_hash(address, Some(hash));
        Ok(())
    }

    /// Returns the string object referenced by `value`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not a string value.
    /// Returns [`EvalHeapError::UnknownPointer`] if the string handle does not
    /// belong to this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if
    /// the handle belongs to this heap but references a non-string record.
    pub fn get_string(&self, value: Value) -> Result<&NixString, EvalHeapError> {
        let ptr = value.as_string_ptr().map_err(EvalHeapError::Value)?;
        self.get_string_ptr(ptr)
    }

    /// Returns the string object referenced by an opaque heap pointer.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if `ptr` does not belong to
    /// this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if `ptr`
    /// belongs to this heap but references a non-string record.
    pub fn get_string_ptr(&self, ptr: NonNull<HeapObject>) -> Result<&NixString, EvalHeapError> {
        let record = self.record_or_unknown(ValueTag::String, ptr)?;
        match &record.object {
            HeapObjectValue::String(string) => {
                self.touch_record(record);
                Ok(string)
            }
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::String,
                object.tag(),
                ptr,
            )),
        }
    }

    /// Returns the path object referenced by `value`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not a path value.
    /// Returns [`EvalHeapError::UnknownPointer`] if the path handle does not
    /// belong to this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if
    /// the handle belongs to this heap but references a non-path record.
    pub fn get_path(&self, value: Value) -> Result<&NixString, EvalHeapError> {
        let ptr = value.as_path_ptr().map_err(EvalHeapError::Value)?;
        self.get_path_ptr(ptr)
    }

    /// Returns the path object referenced by an opaque heap pointer.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if `ptr` does not belong to
    /// this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if `ptr`
    /// belongs to this heap but references a non-path record.
    pub fn get_path_ptr(&self, ptr: NonNull<HeapObject>) -> Result<&NixString, EvalHeapError> {
        let record = self.record_or_unknown(ValueTag::Path, ptr)?;
        match &record.object {
            HeapObjectValue::Path(path) => {
                self.touch_record(record);
                Ok(path)
            }
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::Path,
                object.tag(),
                ptr,
            )),
        }
    }

    /// Returns the list object referenced by `value`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not a list value.
    /// Returns [`EvalHeapError::UnknownPointer`] if the list handle does not
    /// belong to this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if
    /// the handle belongs to this heap but references a non-list record.
    pub fn get_list(&self, value: Value) -> Result<&NixList, EvalHeapError> {
        let ptr = value.as_list_ptr().map_err(EvalHeapError::Value)?;
        self.get_list_ptr(ptr)
    }

    /// Returns the list object referenced by an opaque heap pointer.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if `ptr` does not belong to
    /// this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if `ptr`
    /// belongs to this heap but references a non-list record.
    pub fn get_list_ptr(&self, ptr: NonNull<HeapObject>) -> Result<&NixList, EvalHeapError> {
        let record = self.record_or_unknown(ValueTag::List, ptr)?;
        match &record.object {
            HeapObjectValue::List(list) => {
                self.touch_record(record);
                Ok(list)
            }
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::List,
                object.tag(),
                ptr,
            )),
        }
    }

    /// Returns the attribute-set object referenced by `value`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not an attrset value.
    /// Returns [`EvalHeapError::UnknownPointer`] if the attrset handle does not
    /// belong to this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if
    /// the handle belongs to this heap but references a non-attrset record.
    pub fn get_attrs(&self, value: Value) -> Result<&FlatAttrs, EvalHeapError> {
        let ptr = value.as_attrs_ptr().map_err(EvalHeapError::Value)?;
        self.get_attrs_ptr(ptr)
    }

    /// Returns the attribute-set object referenced by an opaque heap pointer.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if `ptr` does not belong to
    /// this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if `ptr`
    /// belongs to this heap but references a non-attrset record.
    pub fn get_attrs_ptr(&self, ptr: NonNull<HeapObject>) -> Result<&FlatAttrs, EvalHeapError> {
        let record = self.record_or_unknown(ValueTag::Attrs, ptr)?;
        match &record.object {
            HeapObjectValue::Attrs { attrs, .. } => {
                self.touch_record(record);
                Ok(attrs)
            }
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::Attrs,
                object.tag(),
                ptr,
            )),
        }
    }

    /// Returns metadata for the attribute-set object referenced by `value`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not an attrset value.
    /// Returns [`EvalHeapError::UnknownPointer`] if the attrset handle does not
    /// belong to this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if
    /// the handle belongs to this heap but references a non-attrset record.
    pub fn get_attrs_metadata(&self, value: Value) -> Result<EvalHeapAttrsMetadata, EvalHeapError> {
        let ptr = value.as_attrs_ptr().map_err(EvalHeapError::Value)?;
        self.get_attrs_metadata_ptr(ptr)
    }

    /// Returns metadata for the attrset referenced by an opaque heap pointer.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if `ptr` does not belong to
    /// this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if `ptr`
    /// belongs to this heap but references a non-attrset record.
    pub fn get_attrs_metadata_ptr(
        &self,
        ptr: NonNull<HeapObject>,
    ) -> Result<EvalHeapAttrsMetadata, EvalHeapError> {
        let record = self.record_or_unknown(ValueTag::Attrs, ptr)?;
        match &record.object {
            HeapObjectValue::Attrs { metadata, .. } => {
                self.touch_record(record);
                Ok(*metadata)
            }
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::Attrs,
                object.tag(),
                ptr,
            )),
        }
    }

    /// Returns the lambda closure object referenced by `value`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not a lambda value.
    /// Returns [`EvalHeapError::UnknownPointer`] if the lambda handle does not
    /// belong to this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if
    /// the handle belongs to this heap but references a non-lambda record.
    pub fn get_lambda(&self, value: Value) -> Result<&EvalLambda, EvalHeapError> {
        let ptr = value.as_lambda_ptr().map_err(EvalHeapError::Value)?;
        self.get_lambda_ptr(ptr)
    }

    /// Returns the lambda closure object referenced by an opaque heap pointer.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if `ptr` does not belong to
    /// this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if `ptr`
    /// belongs to this heap but references a non-lambda record.
    pub fn get_lambda_ptr(&self, ptr: NonNull<HeapObject>) -> Result<&EvalLambda, EvalHeapError> {
        let record = self.record_or_unknown(ValueTag::Lambda, ptr)?;
        match &record.object {
            HeapObjectValue::Lambda(lambda) => {
                self.touch_record(record);
                Ok(lambda.as_ref())
            }
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::Lambda,
                object.tag(),
                ptr,
            )),
        }
    }

    /// Returns the builtin record referenced by `value`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not a builtin value.
    /// Returns [`EvalHeapError::UnknownPointer`] if the builtin handle does not
    /// belong to this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if
    /// the handle belongs to this heap but references a non-builtin record.
    pub fn get_primop(&self, value: Value) -> Result<&EvalPrimOp, EvalHeapError> {
        let ptr = value.as_primop_ptr().map_err(EvalHeapError::Value)?;
        self.get_primop_ptr(ptr)
    }

    /// Returns the builtin record referenced by an opaque heap pointer.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if `ptr` does not belong to
    /// this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if `ptr`
    /// belongs to this heap but references a non-builtin record.
    pub fn get_primop_ptr(&self, ptr: NonNull<HeapObject>) -> Result<&EvalPrimOp, EvalHeapError> {
        let record = self.record_or_unknown(ValueTag::Primop, ptr)?;
        match &record.object {
            HeapObjectValue::Primop(primop) => {
                self.touch_record(record);
                Ok(primop.as_ref())
            }
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::Primop,
                object.tag(),
                ptr,
            )),
        }
    }

    /// Returns the suspended thunk object referenced by `value`.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::Value`] if `value` is not a thunk value.
    /// Returns [`EvalHeapError::UnknownPointer`] if the thunk handle does not
    /// belong to this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if
    /// the handle belongs to this heap but references a non-thunk record.
    pub fn get_thunk(&self, value: Value) -> Result<&EvalThunk, EvalHeapError> {
        let ptr = value.as_thunk_ptr().map_err(EvalHeapError::Value)?;
        self.get_thunk_ptr(ptr)
    }

    /// Returns the suspended thunk object referenced by an opaque heap pointer.
    ///
    /// # Errors
    ///
    /// Returns [`EvalHeapError::UnknownPointer`] if `ptr` does not belong to
    /// this heap. Returns [`EvalHeapError::RecordTypeMismatch`] if `ptr`
    /// belongs to this heap but references a non-thunk record.
    pub fn get_thunk_ptr(&self, ptr: NonNull<HeapObject>) -> Result<&EvalThunk, EvalHeapError> {
        let record = self.record_or_unknown(ValueTag::Thunk, ptr)?;
        match &record.object {
            HeapObjectValue::Thunk(thunk) => {
                self.touch_record(record);
                Ok(thunk.as_ref())
            }
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::Thunk,
                object.tag(),
                ptr,
            )),
        }
    }

    /// Clones the thunk handle so forcing can release the heap borrow before
    /// re-entering evaluation.
    pub(crate) fn clone_thunk(&self, value: Value) -> Result<Rc<EvalThunk>, EvalHeapError> {
        let ptr = value.as_thunk_ptr().map_err(EvalHeapError::Value)?;
        let record = self.record_or_unknown(ValueTag::Thunk, ptr)?;
        match &record.object {
            HeapObjectValue::Thunk(thunk) => {
                self.touch_record(record);
                Ok(Rc::clone(thunk))
            }
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::Thunk,
                object.tag(),
                ptr,
            )),
        }
    }

    /// Clones the lambda handle so application can release the heap borrow
    /// before evaluating the body.
    pub(crate) fn clone_lambda(&self, value: Value) -> Result<Rc<EvalLambda>, EvalHeapError> {
        let ptr = value.as_lambda_ptr().map_err(EvalHeapError::Value)?;
        let record = self.record_or_unknown(ValueTag::Lambda, ptr)?;
        match &record.object {
            HeapObjectValue::Lambda(lambda) => {
                self.touch_record(record);
                Ok(Rc::clone(lambda))
            }
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::Lambda,
                object.tag(),
                ptr,
            )),
        }
    }

    /// Clones the builtin handle so application can release the heap borrow
    /// before forcing captured arguments.
    pub(crate) fn clone_primop(&self, value: Value) -> Result<Rc<EvalPrimOp>, EvalHeapError> {
        let ptr = value.as_primop_ptr().map_err(EvalHeapError::Value)?;
        let record = self.record_or_unknown(ValueTag::Primop, ptr)?;
        match &record.object {
            HeapObjectValue::Primop(primop) => {
                self.touch_record(record);
                Ok(Rc::clone(primop))
            }
            object => Err(EvalHeapError::record_type_mismatch(
                ValueTag::Primop,
                object.tag(),
                ptr,
            )),
        }
    }

    fn reserve_record_slot(&mut self) -> Result<(), EvalHeapError> {
        let records = self
            .records
            .len()
            .checked_add(1)
            .ok_or(EvalHeapError::RecordLengthOverflow)?;
        self.records
            .try_reserve_exact(1)
            .map_err(|_| EvalHeapError::RecordAllocationFailed { records })
    }

    fn admit_string_cons(
        &mut self,
        hash: HotXxh3Hash,
        string: &NixString,
    ) -> Result<HashConsReservation<HotXxh3Hash, Value>, EvalHeapError> {
        let existing = {
            let records = &self.records;
            self.string_cons
                .try_find(&hash, |value| {
                    let value = *value;
                    let ptr = value.as_string_ptr().map_err(EvalHeapError::Value)?;
                    let record = records
                        .find(ptr)
                        .ok_or_else(|| EvalHeapError::unknown(ValueTag::String, ptr))?;
                    let same_hash = record.structural_hash == Some(hash);
                    let same_string = matches!(
                        &record.object,
                        HeapObjectValue::String(candidate) if candidate == string
                    );
                    Ok::<bool, EvalHeapError>(same_hash && same_string)
                })?
                .copied()
        };
        if let Some(value) = existing {
            return Ok(HashConsReservation::Existing(value));
        }
        self.reserve_record_slot()?;
        Ok(HashConsReservation::Vacant(
            self.string_cons
                .reserve_slot(hash)
                .map_err(EvalHeapError::from)?,
        ))
    }

    fn admit_path_cons(
        &mut self,
        hash: HotXxh3Hash,
        path: &NixString,
    ) -> Result<HashConsReservation<HotXxh3Hash, Value>, EvalHeapError> {
        let existing = {
            let records = &self.records;
            self.path_cons
                .try_find(&hash, |value| {
                    let value = *value;
                    let ptr = value.as_path_ptr().map_err(EvalHeapError::Value)?;
                    let record = records
                        .find(ptr)
                        .ok_or_else(|| EvalHeapError::unknown(ValueTag::Path, ptr))?;
                    let same_hash = record.structural_hash == Some(hash);
                    let same_path = matches!(
                        &record.object,
                        HeapObjectValue::Path(candidate) if candidate == path
                    );
                    Ok::<bool, EvalHeapError>(same_hash && same_path)
                })?
                .copied()
        };
        if let Some(value) = existing {
            return Ok(HashConsReservation::Existing(value));
        }
        self.reserve_record_slot()?;
        Ok(HashConsReservation::Vacant(
            self.path_cons
                .reserve_slot(hash)
                .map_err(EvalHeapError::from)?,
        ))
    }

    fn admit_list_cons(
        &mut self,
        hash: HotXxh3Hash,
        list: &NixList,
    ) -> Result<HashConsReservation<HotXxh3Hash, Value>, EvalHeapError> {
        let existing = {
            let records = &self.records;
            self.list_cons
                .try_find(&hash, |value| {
                    let value = *value;
                    let ptr = value.as_list_ptr().map_err(EvalHeapError::Value)?;
                    let record = records
                        .find(ptr)
                        .ok_or_else(|| EvalHeapError::unknown(ValueTag::List, ptr))?;
                    let same_hash = record.structural_hash == Some(hash);
                    let same_list = matches!(
                        &record.object,
                        HeapObjectValue::List(candidate) if candidate.raw_eq(list)
                    );
                    Ok::<bool, EvalHeapError>(same_hash && same_list)
                })?
                .copied()
        };
        if let Some(value) = existing {
            return Ok(HashConsReservation::Existing(value));
        }
        self.reserve_record_slot()?;
        Ok(HashConsReservation::Vacant(
            self.list_cons
                .reserve_slot(hash)
                .map_err(EvalHeapError::from)?,
        ))
    }

    fn admit_attrs_cons(
        &mut self,
        hash: HotXxh3Hash,
        metadata: EvalHeapAttrsMetadata,
        attrs: &FlatAttrs,
    ) -> Result<HashConsReservation<HotXxh3Hash, Value>, EvalHeapError> {
        let existing = {
            let records = &self.records;
            self.attrs_cons
                .try_find(&hash, |value| {
                    let value = *value;
                    let ptr = value.as_attrs_ptr().map_err(EvalHeapError::Value)?;
                    let record = records
                        .find(ptr)
                        .ok_or_else(|| EvalHeapError::unknown(ValueTag::Attrs, ptr))?;
                    let same_hash = record.structural_hash == Some(hash);
                    let same_attrs = matches!(
                        &record.object,
                        HeapObjectValue::Attrs {
                            metadata: candidate_metadata,
                            attrs: candidate_attrs,
                        } if *candidate_metadata == metadata && candidate_attrs.raw_eq(attrs)
                    );
                    Ok::<bool, EvalHeapError>(same_hash && same_attrs)
                })?
                .copied()
        };
        if let Some(value) = existing {
            return Ok(HashConsReservation::Existing(value));
        }
        self.reserve_record_slot()?;
        Ok(HashConsReservation::Vacant(
            self.attrs_cons
                .reserve_slot(hash)
                .map_err(EvalHeapError::from)?,
        ))
    }

    fn push_string_cons_value(&mut self, slot: HashConsSlot<HotXxh3Hash>, value: Value) {
        let pushed = self.string_cons.push_reserved(slot, value);
        debug_assert!(
            pushed,
            "cons-table slot should be reserved before allocation"
        );
    }

    fn push_path_cons_value(&mut self, slot: HashConsSlot<HotXxh3Hash>, value: Value) {
        let pushed = self.path_cons.push_reserved(slot, value);
        debug_assert!(
            pushed,
            "cons-table slot should be reserved before allocation"
        );
    }

    fn push_attrs_cons_value(&mut self, slot: HashConsSlot<HotXxh3Hash>, value: Value) {
        let pushed = self.attrs_cons.push_reserved(slot, value);
        debug_assert!(
            pushed,
            "cons-table slot should be reserved before allocation"
        );
    }

    fn push_list_cons_value(&mut self, slot: HashConsSlot<HotXxh3Hash>, value: Value) {
        let pushed = self.list_cons.push_reserved(slot, value);
        debug_assert!(
            pushed,
            "cons-table slot should be reserved before allocation"
        );
    }

    fn cancel_string_cons_slot(&mut self, slot: HashConsSlot<HotXxh3Hash>) {
        let canceled = self.string_cons.cancel_reserved(slot);
        debug_assert!(
            canceled,
            "cons-table slot should be reserved before cancellation"
        );
    }

    fn cancel_path_cons_slot(&mut self, slot: HashConsSlot<HotXxh3Hash>) {
        let canceled = self.path_cons.cancel_reserved(slot);
        debug_assert!(
            canceled,
            "cons-table slot should be reserved before cancellation"
        );
    }

    fn cancel_attrs_cons_slot(&mut self, slot: HashConsSlot<HotXxh3Hash>) {
        let canceled = self.attrs_cons.cancel_reserved(slot);
        debug_assert!(
            canceled,
            "cons-table slot should be reserved before cancellation"
        );
    }

    fn cancel_list_cons_slot(&mut self, slot: HashConsSlot<HotXxh3Hash>) {
        let canceled = self.list_cons.cancel_reserved(slot);
        debug_assert!(
            canceled,
            "cons-table slot should be reserved before cancellation"
        );
    }

    /// Linearly resolves `ptr` within an arbitrary record sub-slice.
    ///
    /// Whole-table resolution goes through the address-keyed index on
    /// [`super::HeapRecordTable`] and is `O(1)`; this scan is reserved for the
    /// bounded reclaimed-record sub-slice examined during a worker-region pop,
    /// whose length is the popped region size rather than the monotonic record
    /// count, so a scan is acceptable there.
    fn record_in(records: &[HeapRecord], ptr: NonNull<HeapObject>) -> Option<&HeapRecord> {
        let address = ptr.as_ptr() as usize;
        records
            .iter()
            .find(|record| record.ptr.as_ptr() as usize == address)
    }

    fn record_for_value(&self, value: Value) -> Result<&HeapRecord, EvalHeapError> {
        let (tag, ptr) = value_heap_ptr(value)?;
        let record = self.record_or_unknown(tag, ptr)?;
        let actual = record.object.tag();
        if actual == tag {
            self.touch_record(record);
            Ok(record)
        } else {
            Err(EvalHeapError::record_type_mismatch(tag, actual, ptr))
        }
    }

    fn touch_reusable_value(&self, value: Value) -> Result<(), EvalHeapError> {
        self.record_for_value(value)?;
        Ok(())
    }

    fn validate_worker_region_pop(
        &self,
        mark: EvalHeapWorkerRegionMark,
    ) -> Result<usize, EvalHeapError> {
        self.validate_worker_region_mark_is_innermost(mark)?;

        let reclaimed = self.records.len() - mark.records;
        let reclaimed_records = &self.records[mark.records..];
        let non_worker_records = reclaimed_records
            .iter()
            .filter(|record| record.allocation_domain != HeapAllocationDomain::Worker)
            .count();
        if non_worker_records != 0 {
            return Err(EvalHeapError::WorkerRegionPopNonWorkerRecords {
                records: non_worker_records,
            });
        }

        for record in &self.records[..mark.records] {
            let source_address = gc_address_for_heap_record(record)?;
            for edge in self.scan_record_edges(record)? {
                let (_tag, target_ptr) = any_value_heap_ptr(edge.value())?;
                if Self::record_in(reclaimed_records, target_ptr).is_some() {
                    return Err(EvalHeapError::WorkerRegionPopRetainedEdge {
                        source_address,
                        edge_source: edge.source().clone(),
                        target_address: GcHeapAddress::new(target_ptr.as_ptr() as usize)
                            .map_err(EvalHeapError::GenerationalGc)?,
                    });
                }
            }
        }

        Ok(reclaimed)
    }

    fn validate_tier_b_admission_plan(
        &self,
        plan: &EvalHeapTierBAdmissionPlan,
    ) -> Result<(), EvalHeapError> {
        let worker_stats = self.arena_stats();
        if worker_stats != plan.worker_stats {
            return Err(EvalHeapError::TierBAdmissionStaleArenaStats {
                domain: "worker",
                expected: plan.worker_stats,
                actual: worker_stats,
            });
        }

        let permanent_stats = self.permanent_arena_stats();
        if permanent_stats != plan.permanent_stats {
            return Err(EvalHeapError::TierBAdmissionStaleArenaStats {
                domain: "permanent-shared",
                expected: plan.permanent_stats,
                actual: permanent_stats,
            });
        }

        if self.records.len() != plan.records.len() {
            return Err(EvalHeapError::TierBAdmissionStaleRecordCount {
                expected_records: plan.records.len(),
                actual_records: self.records.len(),
            });
        }

        for (index, (record, planned)) in self.records.iter().zip(plan.records.iter()).enumerate() {
            let address = gc_address_for_heap_record(record)?;
            if address != planned.address {
                return Err(EvalHeapError::TierBAdmissionStaleRecordAddress {
                    index,
                    expected: planned.address,
                    actual: address,
                });
            }
            if record.allocation_domain != planned.allocation_domain {
                return Err(EvalHeapError::TierBAdmissionStaleRecordDomain {
                    index,
                    address,
                    expected: planned.allocation_domain,
                    actual: record.allocation_domain,
                });
            }
            if record.generation != planned.current_generation {
                return Err(EvalHeapError::TierBAdmissionStaleRecordGeneration {
                    index,
                    address,
                    expected: planned.current_generation,
                    actual: record.generation,
                });
            }
        }

        Ok(())
    }

    fn validate_worker_region_mark_is_innermost(
        &self,
        mark: EvalHeapWorkerRegionMark,
    ) -> Result<(), EvalHeapError> {
        if mark.owner != self.region_owner {
            return Err(EvalHeapError::WorkerRegionPopStaleMark {
                reason: "marker was captured from another heap",
                marker_records: mark.records,
                current_records: self.records.len(),
            });
        }
        if mark.allocator_epoch != self.worker_allocator_epoch {
            return Err(EvalHeapError::WorkerRegionPopStaleMark {
                reason: "worker allocator epoch changed",
                marker_records: mark.records,
                current_records: self.records.len(),
            });
        }
        if self.worker_region_mark_stack.last().copied() != Some(mark.mark_id) {
            return Err(EvalHeapError::WorkerRegionPopStaleMark {
                reason: "worker region mark is not innermost",
                marker_records: mark.records,
                current_records: self.records.len(),
            });
        }
        if mark.records > self.records.len() {
            return Err(EvalHeapError::WorkerRegionPopStaleMark {
                reason: "marker record prefix exceeds current records",
                marker_records: mark.records,
                current_records: self.records.len(),
            });
        }

        Ok(())
    }

    fn touch_record(&self, record: &HeapRecord) {
        record.last_touch_epoch.set(self.next_access_epoch());
    }

    fn value_for_record(record: &HeapRecord) -> Result<Value, EvalHeapError> {
        Ok(Value::heap(record.object.tag(), record.ptr)?)
    }

    pub(super) fn advance_worker_region_epoch(&mut self) {
        if let Some(next) = self.worker_region_epoch.checked_add(1) {
            self.worker_region_epoch = next;
        } else {
            self.rotate_region_owner();
        }
    }

    pub(super) fn advance_worker_allocator_epoch(&mut self) {
        if let Some(next) = self.worker_allocator_epoch.checked_add(1) {
            self.worker_allocator_epoch = next;
        } else {
            self.rotate_region_owner();
        }
    }

    fn rotate_region_owner(&mut self) {
        self.region_owner = next_heap_region_owner();
        self.worker_allocator_epoch = 0;
        self.worker_region_epoch = 0;
        self.worker_region_mark_stack.clear();
    }

    fn next_access_epoch(&self) -> u64 {
        let next_epoch = self.access_epoch.get().saturating_add(1);
        self.access_epoch.set(next_epoch);
        next_epoch
    }

    fn is_cold_hash_consed_record(
        record: &HeapRecord,
        current_epoch: u64,
        min_idle_epochs: u64,
    ) -> bool {
        if record.allocation_domain != HeapAllocationDomain::PermanentShared
            || record.structural_hash.is_none()
        {
            return false;
        }
        let idle_epochs = current_epoch.saturating_sub(record.last_touch_epoch.get());
        idle_epochs >= min_idle_epochs
    }

    fn cold_hash_consed_record_idle_epochs(record: &HeapRecord, current_epoch: u64) -> u64 {
        current_epoch.saturating_sub(record.last_touch_epoch.get())
    }

    pub(super) fn record_or_unknown(
        &self,
        tag: ValueTag,
        ptr: NonNull<HeapObject>,
    ) -> Result<&HeapRecord, EvalHeapError> {
        self.records
            .find(ptr)
            .ok_or_else(|| EvalHeapError::unknown(tag, ptr))
    }
}

fn value_heap_ptr(value: Value) -> Result<(ValueTag, NonNull<HeapObject>), EvalHeapError> {
    match value.tag() {
        ValueTag::String => Ok((
            ValueTag::String,
            value.as_string_ptr().map_err(EvalHeapError::Value)?,
        )),
        ValueTag::Path => Ok((
            ValueTag::Path,
            value.as_path_ptr().map_err(EvalHeapError::Value)?,
        )),
        ValueTag::List => Ok((
            ValueTag::List,
            value.as_list_ptr().map_err(EvalHeapError::Value)?,
        )),
        ValueTag::Attrs => Ok((
            ValueTag::Attrs,
            value.as_attrs_ptr().map_err(EvalHeapError::Value)?,
        )),
        actual => Err(EvalHeapError::Value(ValueError::Type {
            expected: "string, path, list, or attrs",
            actual,
        })),
    }
}

fn any_value_heap_ptr(value: Value) -> Result<(ValueTag, NonNull<HeapObject>), EvalHeapError> {
    match value.tag() {
        ValueTag::String => Ok((
            ValueTag::String,
            value.as_string_ptr().map_err(EvalHeapError::Value)?,
        )),
        ValueTag::Path => Ok((
            ValueTag::Path,
            value.as_path_ptr().map_err(EvalHeapError::Value)?,
        )),
        ValueTag::List => Ok((
            ValueTag::List,
            value.as_list_ptr().map_err(EvalHeapError::Value)?,
        )),
        ValueTag::Attrs => Ok((
            ValueTag::Attrs,
            value.as_attrs_ptr().map_err(EvalHeapError::Value)?,
        )),
        ValueTag::Lambda => Ok((
            ValueTag::Lambda,
            value.as_lambda_ptr().map_err(EvalHeapError::Value)?,
        )),
        ValueTag::Primop => Ok((
            ValueTag::Primop,
            value.as_primop_ptr().map_err(EvalHeapError::Value)?,
        )),
        ValueTag::Thunk => Ok((
            ValueTag::Thunk,
            value.as_thunk_ptr().map_err(EvalHeapError::Value)?,
        )),
        actual => Err(EvalHeapError::Value(ValueError::Type {
            expected: "evaluator heap value",
            actual,
        })),
    }
}

fn gc_address_for_heap_record(record: &HeapRecord) -> Result<GcHeapAddress, EvalHeapError> {
    GcHeapAddress::new(record.ptr.as_ptr() as usize).map_err(EvalHeapError::GenerationalGc)
}

const fn tier_b_admitted_generation_for_allocation_domain(
    allocation_domain: HeapAllocationDomain,
) -> HeapGeneration {
    match allocation_domain {
        HeapAllocationDomain::Worker => HeapGeneration::Old,
        HeapAllocationDomain::PermanentShared => HeapGeneration::Permanent,
    }
}

fn next_heap_region_owner() -> u64 {
    let mut current = NEXT_HEAP_REGION_OWNER.load(Ordering::Relaxed);
    loop {
        if current == 0 || current == u64::MAX {
            panic!("evaluator heap region-owner id space exhausted");
        }
        let next = current + 1;
        match NEXT_HEAP_REGION_OWNER.compare_exchange_weak(
            current,
            next,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(owner) => return owner,
            Err(observed) => current = observed,
        }
    }
}

const fn whole_heap_memory_budget_sample(
    worker_stats: ArenaStats,
    permanent_stats: ArenaStats,
    dead_arena_bytes: usize,
    cold_hash_consed_bytes: usize,
) -> HeapMemorySample {
    HeapMemorySample::new(
        worker_stats
            .mapped_bytes
            .saturating_add(permanent_stats.mapped_bytes),
        dead_arena_bytes,
        cold_hash_consed_bytes,
    )
}

fn list_structural_hash(list: &NixList) -> HotXxh3Hash {
    let mut hasher = Xxh3::new();
    ValueTag::List.hash(&mut hasher);
    list.len().hash(&mut hasher);
    for value in list {
        value.tag().hash(&mut hasher);
        value.payload_bits().hash(&mut hasher);
    }
    HotXxh3Hash::from_xxh3(hasher.finish())
}

fn attrs_structural_hash(metadata: EvalHeapAttrsMetadata, attrs: &FlatAttrs) -> HotXxh3Hash {
    let mut hasher = Xxh3::new();
    ValueTag::Attrs.hash(&mut hasher);
    metadata.hash(&mut hasher);
    attrs.len().hash(&mut hasher);
    attrs.source_order().hash(&mut hasher);
    attrs.iteration_order().hash(&mut hasher);
    for entry in attrs.entries_by_symbol() {
        entry.key.hash(&mut hasher);
        entry.value.tag().hash(&mut hasher);
        entry.value.payload_bits().hash(&mut hasher);
        match entry.position {
            Some(position) => {
                true.hash(&mut hasher);
                position.module.hash(&mut hasher);
                position.span.hash(&mut hasher);
            }
            None => false.hash(&mut hasher),
        }
    }
    HotXxh3Hash::from_xxh3(hasher.finish())
}
