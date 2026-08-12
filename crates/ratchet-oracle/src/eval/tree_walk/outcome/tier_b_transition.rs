//! Tier-B transition request, preflight, and admission-plan types (split from outcome.rs for the §2 cap).

use super::*;

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
