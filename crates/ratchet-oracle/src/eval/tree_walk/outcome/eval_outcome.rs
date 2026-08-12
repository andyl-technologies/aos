//! The evaluation outcome: final value, heap, statistics, traces, and reports.

use super::*;

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
