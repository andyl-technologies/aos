//! Memory-budget, advice, and Tier-B admission report types for the
//! evaluator heap. Moved verbatim from `heap/arena.rs` under the RFC-0007 §2
//! file-size cap; the parent re-exports every public path.

use super::*;

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
    pub(super) const fn new(
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
    pub(super) const fn new(
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
    pub(super) const fn new(kind: MemoryAdviceKind, min_idle_epochs: u64) -> Self {
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

    pub(super) fn record(&mut self, requested_bytes: usize, outcome: MemoryAdviceOutcome) {
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
    pub(super) const fn new(
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
    // Fields are `pub(super)`: the parent's plan validation reads them
    // directly (pre-split private access, made module-explicit by the §2
    // relocation).
    pub(super) address: GcHeapAddress,
    pub(super) allocation_domain: HeapAllocationDomain,
    pub(super) current_generation: HeapGeneration,
    admitted_generation: HeapGeneration,
}

impl EvalHeapTierBAdmissionRecord {
    pub(super) const fn new(
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
    // Fields are `pub(super)`: the parent's plan-validation and the
    // governance sibling's apply/report methods read them directly (the
    // pre-split private access, made module-explicit by the §2 relocation).
    pub(super) worker_stats: ArenaStats,
    pub(super) permanent_stats: ArenaStats,
    pub(super) worker_records: usize,
    pub(super) permanent_shared_records: usize,
    pub(super) records: Vec<EvalHeapTierBAdmissionRecord>,
}

impl EvalHeapTierBAdmissionPlan {
    pub(super) const fn new(
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
    pub(super) const fn new(
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
    pub(super) const fn new(
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
