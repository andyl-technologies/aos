//! Memory governance methods: budget installation and classification,
//! resident-memory modes, Tier-B admission planning, memory advice, worker
//! region marks/pops, and allocator resets. Moved verbatim from
//! `heap/arena.rs`'s `impl EvalHeap` under the RFC-0007 §2 file-size cap
//! (impl reopened; method bodies unchanged).

use super::*;

impl EvalHeap {
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
            if record.is_retired() {
                continue;
            }
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
            if record.is_retired() {
                continue;
            }
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
    ///
    /// Includes the flat worker-closure store's arena (doc 30 FV-3): flat
    /// closures are worker-domain values, so their bytes stay in the worker
    /// columns of every budget decision and statistics surface.
    pub fn arena_stats(&self) -> ArenaStats {
        merged_arena_stats(self.allocator.stats(), self.flat_closures.arena_stats())
    }

    /// Returns current permanent shared allocation accounting.
    ///
    /// Includes the shared flat arena's low permanent lane exactly once; the
    /// high closure lane remains in [`Self::arena_stats`].
    pub fn permanent_arena_stats(&self) -> ArenaStats {
        merged_arena_stats(
            self.permanent_allocator.stats(),
            self.flat_arena.permanent_stats(),
        )
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
    /// space is exhausted. Returns
    /// [`EvalHeapError::TypedThunkHeadsRegionUnsupported`] while typed thunk
    /// heads are enabled because their permanent identities cannot participate
    /// in worker-region rewind.
    pub fn worker_region_mark(&mut self) -> Result<EvalHeapWorkerRegionMark, EvalHeapError> {
        if self.typed_apply_thunk_heads_enabled
            || cfg!(feature = "active_packed_thunk_probe") && {
                #[cfg(feature = "active_packed_thunk_probe")]
                {
                    self.active_packed_thunks.is_configured()
                }
                #[cfg(not(feature = "active_packed_thunk_probe"))]
                {
                    false
                }
            }
        {
            return Err(EvalHeapError::TypedThunkHeadsRegionUnsupported);
        }
        let marks = self
            .worker_region_mark_stack
            .len()
            .checked_add(1)
            .ok_or(EvalHeapError::WorkerRegionMarkLengthOverflow)?;
        self.worker_region_mark_stack
            .try_reserve_exact(1)
            .map_err(|_| EvalHeapError::WorkerRegionMarkAllocationFailed { marks })?;
        // The worker closure store always owns its arena (region pops require
        // it), so its region mark cannot fail; surface the impossible case as
        // a mark-allocation failure before any marker state changes.
        let flat_closures_mark = self
            .flat_closures
            .region_mark()
            .map_err(|error| match error {
                crate::heap::flat::FlatObjectError::Arena(source) => EvalHeapError::Arena(source),
                _ => EvalHeapError::WorkerRegionMarkAllocationFailed { marks },
            })?;
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
            flat_closures_mark,
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
        // Flat worker closures above the marker were validated unreferenced
        // together with the record suffix; drop their payloads and rewind the
        // flat store's arena (doc 30 FV-3). The pop cannot fail here: the
        // marker was structurally validated against both the registry and the
        // store's arena before any state changed.
        let flat_report = self
            .flat_closures
            .pop_region(mark.flat_closures)
            .map_err(|error| match error {
                crate::heap::flat::FlatObjectError::Arena(source) => EvalHeapError::Arena(source),
                _ => EvalHeapError::WorkerRegionPopStaleMark {
                    reason: "flat closure region mark does not match the store",
                    marker_records: mark.records.saturating_add(mark.flat_closures.entries()),
                    current_records: self.records.len().saturating_add(self.flat_closures.len()),
                },
            })?;
        self.records.truncate(mark.records);
        let _ = self.worker_region_mark_stack.pop();
        self.advance_worker_region_epoch();
        self.last_memory_budget_action = None;
        Ok(EvalHeapWorkerRegionPopReport::new(
            arena_report.merged(flat_report.arena_report()),
            flat_report,
            reclaimed_records.saturating_add(flat_report.popped_entries()),
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
            .filter(|record| {
                record.allocation_domain == HeapAllocationDomain::Worker && !record.is_retired()
            })
            .count()
            .saturating_add(self.live_flat_closures());
        if live_worker_records != 0 {
            return Err(EvalHeapError::WorkerResetLiveRecords {
                records: live_worker_records,
            });
        }

        let permanent_stats = self.permanent_arena_stats();
        // Replace the provably idle flat closure store with the worker arena.
        let dropped_flat_store = std::mem::take(&mut self.flat_closures);
        let dropped_flat_closures = dropped_flat_store.arena_stats();
        drop(dropped_flat_store);
        self.flat_closures = serial_flat_closure_store(&self.flat_arena);
        let dropped_worker_stats =
            merged_arena_stats(self.allocator.reset_to_empty(), dropped_flat_closures);
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
        let record_bytes = self.records.iter().fold(0usize, |bytes, record| {
            if !Self::is_cold_hash_consed_record(record, current_epoch, min_idle_epochs) {
                return bytes;
            }
            bytes.saturating_add(record.layout.size_bytes)
        });
        let flat_bytes = self.flat.iter().fold(record_bytes, |bytes, entry| {
            let idle = current_epoch.saturating_sub(entry.object().last_touch_epoch());
            if idle < min_idle_epochs {
                return bytes;
            }
            bytes.saturating_add(entry.size_bytes())
        });
        let flat_bytes = self.flat_lists.iter().fold(flat_bytes, |bytes, entry| {
            let idle = current_epoch.saturating_sub(entry.object().last_touch_epoch());
            if idle < min_idle_epochs {
                return bytes;
            }
            bytes.saturating_add(entry.size_bytes())
        });
        self.flat_attrs.iter().fold(flat_bytes, |bytes, entry| {
            let idle = current_epoch.saturating_sub(entry.object().last_touch_epoch());
            if idle < min_idle_epochs {
                return bytes;
            }
            bytes.saturating_add(entry.size_bytes())
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
        let is_cold_flat = |entry: &crate::heap::flat::FlatStoredObject<'_, NixString>| {
            current_epoch.saturating_sub(entry.object().last_touch_epoch()) >= min_idle_epochs
        };
        let is_cold_flat_list = |entry: &crate::heap::flat::FlatStoredObject<'_, NixList>| {
            current_epoch.saturating_sub(entry.object().last_touch_epoch()) >= min_idle_epochs
        };
        let is_cold_flat_attrs =
            |entry: &crate::heap::flat::FlatStoredObject<'_, FlatAttrsPayload>| {
                current_epoch.saturating_sub(entry.object().last_touch_epoch()) >= min_idle_epochs
            };
        let values = self
            .records
            .iter()
            .filter(|record| {
                Self::is_cold_hash_consed_record(record, current_epoch, min_idle_epochs)
            })
            .count()
            .saturating_add(self.flat.iter().filter(is_cold_flat).count())
            .saturating_add(self.flat_lists.iter().filter(is_cold_flat_list).count())
            .saturating_add(self.flat_attrs.iter().filter(is_cold_flat_attrs).count());
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
        for entry in self.flat.iter() {
            if !is_cold_flat(&entry) {
                continue;
            }
            let idle_epochs = current_epoch.saturating_sub(entry.object().last_touch_epoch());
            let tag = flat_values::value_tag_for_flat_kind(entry.object().kind());
            snapshot.push(EvalHeapColdHashConsedValue::new(
                Value::heap(tag, entry.ptr())?,
                entry.size_bytes(),
                idle_epochs,
            ));
        }
        for entry in self.flat_lists.iter() {
            if !is_cold_flat_list(&entry) {
                continue;
            }
            let idle_epochs = current_epoch.saturating_sub(entry.object().last_touch_epoch());
            snapshot.push(EvalHeapColdHashConsedValue::new(
                Value::heap(ValueTag::List, entry.ptr())?,
                entry.size_bytes(),
                idle_epochs,
            ));
        }
        for entry in self.flat_attrs.iter() {
            if !is_cold_flat_attrs(&entry) {
                continue;
            }
            let idle_epochs = current_epoch.saturating_sub(entry.object().last_touch_epoch());
            snapshot.push(EvalHeapColdHashConsedValue::new(
                Value::heap(ValueTag::Attrs, entry.ptr())?,
                entry.size_bytes(),
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
        for entry in self.flat.iter() {
            let idle = current_epoch.saturating_sub(entry.object().last_touch_epoch());
            if idle < min_idle_epochs {
                continue;
            }
            report.record(entry.size_bytes(), advise(entry.ptr(), entry.size_bytes()));
        }
        for entry in self.flat_lists.iter() {
            let idle = current_epoch.saturating_sub(entry.object().last_touch_epoch());
            if idle < min_idle_epochs {
                continue;
            }
            report.record(entry.size_bytes(), advise(entry.ptr(), entry.size_bytes()));
        }
        for entry in self.flat_attrs.iter() {
            let idle = current_epoch.saturating_sub(entry.object().last_touch_epoch());
            if idle < min_idle_epochs {
                continue;
            }
            report.record(entry.size_bytes(), advise(entry.ptr(), entry.size_bytes()));
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
            self.allocator
                .advise_unused_tail(kind)
                .merged(self.flat_closures.advise_unused_tail(kind)),
            self.permanent_allocator
                .advise_unused_tail(kind)
                .merged(self.flat_arena.advise_unused_tail(kind)),
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
            .saturating_add(self.flat_arena.supported_unused_tail_advice_bytes())
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

    // Visibility widened from the pre-split `pub(super)` (then = the heap
    // module) to keep the same audience after the §2 relocation.
    pub(in crate::eval::heap) fn poll_memory_budget_after_allocation(&mut self) {
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
            .saturating_add(permanent_stats.mapped_bytes)
            .saturating_add(
                self.shared
                    .as_ref()
                    .map_or(0, |shared| shared.arena().published_payload_bytes()),
            );
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
        // The GC-stress proving ground relocates young *record-table*
        // objects (the Tier-B B2 scaffolding), so heaps under stress keep
        // allocating worker closures as records (doc 30 FV-3 placement
        // decision; see `flat_values::closures`).
        if !policy.is_disabled() {
            self.worker_closure_placement = WorkerClosurePlacement::Record;
        }
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
}
