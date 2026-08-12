//! Evaluator-heap unit tests, part 3 of 16 (RFC-0007 §2 split, #9).
//!
//! Move-only item-boundary split of the `tests.rs` inline body; each
//! test keeps its `#[cfg]`/doc prefix. No test changed.

#![allow(unused_imports)]

use super::super::*;
use super::*;

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn tier_b_admission_application_rejects_stale_worker_stats_before_mutation() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let worker = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("worker thunk allocates");
    let plan = heap
        .plan_tier_b_admission()
        .expect("admission planning succeeds");
    let expected_stats = plan.worker_stats();

    heap.alloc_thunk(EvalThunk::new(IrId::new(2)))
        .expect("second worker thunk allocates");
    let actual_stats = heap.arena_stats();
    let error = heap
        .apply_tier_b_admission_plan(&plan)
        .expect_err("stale worker accounting is rejected");

    assert_eq!(
        error,
        EvalHeapError::TierBAdmissionStaleArenaStats {
            domain: "worker",
            expected: expected_stats,
            actual: actual_stats,
        }
    );
    assert_eq!(heap_generation(&heap, worker), HeapGeneration::Young);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn tier_b_admission_application_rejects_stale_record_generation_before_mutation() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    // FV-3: this fixture exercises the Tier-B B2 record-relocation
    // scaffolding, which operates on record-table worker objects.
    heap.use_record_worker_closures_for_gc_scaffolding();
    let first = heap
        .alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("first worker thunk allocates");
    let second = heap
        .alloc_thunk(EvalThunk::new(IrId::new(2)))
        .expect("second worker thunk allocates");
    let plan = heap
        .plan_tier_b_admission()
        .expect("admission planning succeeds");
    set_heap_generation(&mut heap, second, HeapGeneration::Old);

    let error = heap
        .apply_tier_b_admission_plan(&plan)
        .expect_err("stale generation is rejected");

    assert_eq!(
        error,
        EvalHeapError::TierBAdmissionStaleRecordGeneration {
            index: 1,
            address: gc_address(second),
            expected: HeapGeneration::Young,
            actual: HeapGeneration::Old,
        }
    );
    assert_eq!(heap_generation(&heap, first), HeapGeneration::Young);
    assert_eq!(heap_generation(&heap, second), HeapGeneration::Old);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn cold_hash_consed_estimate_flows_into_opt_in_budget_classification() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(65536).expect("heap creates");
    let string = heap
        .alloc_string(NixString::from_bytes(b"spillable".to_vec()))
        .expect("string allocates");
    let string_size = record_layout_size(&heap, string);

    heap.alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("thunk allocates");

    let worker_stats = heap.arena_stats();
    let permanent_stats = heap.permanent_arena_stats();
    let resident_bytes = worker_stats
        .mapped_bytes
        .checked_add(permanent_stats.mapped_bytes)
        .expect("resident bytes fit");
    let budget = HeapMemoryBudget::new(resident_bytes).expect("budget is non-zero");
    let decision = heap.classify_memory_budget_with_cold_hash_consed_estimate(budget, 13, 1);

    assert_eq!(
        decision.sample(),
        HeapMemorySample::new(resident_bytes, 13, string_size)
    );
    assert_eq!(
        decision.resident_source(),
        EvalHeapResidentMemorySource::ArenaMappedBytes
    );
    assert_eq!(decision.worker_stats(), worker_stats);
    assert_eq!(decision.permanent_stats(), permanent_stats);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn whole_heap_unused_tail_advice_reports_both_allocation_domains() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(65536).expect("heap creates");
    heap.alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("worker thunk allocates");
    heap.alloc_string(NixString::from_bytes(b"permanent".to_vec()))
        .expect("permanent string allocates");
    let worker_stats = heap.arena_stats();
    let permanent_stats = heap.permanent_arena_stats();

    let report = heap.advise_unused_tails(MemoryAdviceKind::Dead);

    assert_eq!(report.kind(), MemoryAdviceKind::Dead);
    assert_eq!(report.worker().kind(), MemoryAdviceKind::Dead);
    assert_eq!(report.permanent().kind(), MemoryAdviceKind::Dead);
    assert_eq!(report.worker().chunks(), 1);
    assert_eq!(report.permanent().chunks(), 1);
    assert_eq!(report.chunks(), 2);
    assert_eq!(
        report.requested_bytes(),
        report.worker().requested_bytes() + report.permanent().requested_bytes()
    );
    assert_eq!(
        report.requested_bytes(),
        (worker_stats.mapped_bytes - worker_stats.used_bytes)
            + (permanent_stats.mapped_bytes - permanent_stats.used_bytes)
    );
    assert_eq!(
        report.applied() + report.unsupported() + report.empty_ranges() + report.rejected(),
        2
    );
    assert_eq!(heap.arena_stats(), worker_stats);
    assert_eq!(heap.permanent_arena_stats(), permanent_stats);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn memory_budget_action_continues_without_advice_below_soft_limit() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(65536).expect("heap creates");
    heap.alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("worker thunk allocates");
    heap.alloc_string(NixString::from_bytes(b"permanent".to_vec()))
        .expect("permanent string allocates");
    let resident_bytes = heap
        .arena_stats()
        .mapped_bytes
        .checked_add(heap.permanent_arena_stats().mapped_bytes)
        .expect("resident bytes fit");
    let budget = HeapMemoryBudget::new(resident_bytes.checked_mul(2).expect("budget doubles"))
        .expect("budget is non-zero");

    let action = heap.respond_to_memory_budget_with_unused_tail_advice(budget);

    assert!(matches!(
        action,
        EvalHeapMemoryBudgetAction::ContinueTierA { .. }
    ));
    assert_eq!(action.advice_report(), None);
    assert!(!action.requests_tier_b());
    assert_eq!(
        action.decision().response(),
        HeapMemoryBudgetResponse::ContinueTierA {
            headroom_bytes: budget.soft_limit_bytes() - resident_bytes,
            projected_resident_bytes: resident_bytes,
        }
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn memory_budget_action_does_not_credit_subpage_or_unsupported_tail_advice() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    heap.alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("worker thunk allocates");
    heap.alloc_string(NixString::from_bytes(b"permanent".to_vec()))
        .expect("permanent string allocates");
    let worker_stats = heap.arena_stats();
    let permanent_stats = heap.permanent_arena_stats();
    let resident_bytes = worker_stats
        .mapped_bytes
        .checked_add(permanent_stats.mapped_bytes)
        .expect("resident bytes fit");
    let unused_tail_bytes = (worker_stats.mapped_bytes - worker_stats.used_bytes)
        + (permanent_stats.mapped_bytes - permanent_stats.used_bytes);
    assert_eq!(heap.supported_unused_tail_advice_bytes(), 0);
    let budget = HeapMemoryBudget::new(resident_bytes).expect("budget is non-zero");

    let action = heap.respond_to_memory_budget_with_unused_tail_advice(budget);

    let EvalHeapMemoryBudgetAction::AdviseUnusedTails { decision, report } = action else {
        panic!("near-budget response should still attempt unused-tail advice");
    };
    assert_eq!(decision.sample().dead_arena_bytes(), 0);
    assert_eq!(decision.sample().cold_hash_consed_bytes(), 0);
    assert_eq!(
        decision.response(),
        HeapMemoryBudgetResponse::SpillCold {
            desired_reclaim_bytes: resident_bytes - budget.soft_limit_bytes(),
            available_reclaim_bytes: 0,
            projected_resident_bytes: resident_bytes,
        }
    );
    assert_eq!(action.advice_report(), Some(report));
    assert_eq!(report.requested_bytes(), unused_tail_bytes);
    assert_eq!(
        report.applied() + report.unsupported() + report.empty_ranges() + report.rejected(),
        2
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn cheap_memory_budget_plan_credits_cold_hash_consed_estimate_as_planning_metadata() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let string = heap
        .alloc_string(NixString::from_bytes(b"spillable".to_vec()))
        .expect("permanent string allocates");
    let cold_hash_consed_bytes = record_layout_size(&heap, string);
    let permanent_stats = heap.permanent_arena_stats();
    let resident_bytes = heap
        .arena_stats()
        .mapped_bytes
        .checked_add(permanent_stats.mapped_bytes)
        .expect("resident bytes fit");
    assert_eq!(heap.supported_unused_tail_advice_bytes(), 0);
    assert!(resident_bytes > cold_hash_consed_bytes);
    let budget =
        HeapMemoryBudget::new(resident_bytes - cold_hash_consed_bytes).expect("budget is non-zero");

    let unused_tail_action = heap.respond_to_memory_budget_with_unused_tail_advice(budget);
    assert!(matches!(
        unused_tail_action,
        EvalHeapMemoryBudgetAction::RequestTierB { .. }
    ));
    assert_eq!(
        unused_tail_action
            .decision()
            .sample()
            .cold_hash_consed_bytes(),
        0
    );

    let plan = heap.plan_memory_budget_with_cheap_memory_advice(budget, 0);

    let decision = plan.decision();
    let report = plan
        .cheap_advice_report()
        .expect("cold-aware spill planning records cheap advice telemetry");
    assert_eq!(
        decision.sample(),
        HeapMemorySample::new(resident_bytes, 0, cold_hash_consed_bytes)
    );
    assert_eq!(
        decision.response(),
        HeapMemoryBudgetResponse::SpillCold {
            desired_reclaim_bytes: resident_bytes - budget.soft_limit_bytes(),
            available_reclaim_bytes: cold_hash_consed_bytes,
            projected_resident_bytes: budget.max_resident_bytes(),
        }
    );
    assert_eq!(report.unused_tails().kind(), MemoryAdviceKind::Dead);
    assert_eq!(report.cold_hash_consed().kind(), MemoryAdviceKind::Evict);
    assert_eq!(report.cold_hash_consed().min_idle_epochs(), 0);
    assert_eq!(report.cold_hash_consed().records(), 1);
    assert_eq!(
        report.cold_hash_consed().requested_bytes(),
        cold_hash_consed_bytes
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn cheap_memory_budget_plan_uses_pageout_advice_before_tier_b_request() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(65536).expect("heap creates");
    let string = heap
        .alloc_string(NixString::from_bytes(b"tier-b-pageout".to_vec()))
        .expect("permanent string allocates");
    let cold_hash_consed_bytes = record_layout_size(&heap, string);
    heap.alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("worker thunk allocates");
    let worker_stats = heap.arena_stats();
    let permanent_stats = heap.permanent_arena_stats();
    let resident_bytes = worker_stats
        .mapped_bytes
        .checked_add(permanent_stats.mapped_bytes)
        .expect("resident bytes fit");
    let supported_tail_advice_bytes = heap.supported_unused_tail_advice_bytes();
    let budget = HeapMemoryBudget::new(1).expect("budget is non-zero");

    let plan = heap.plan_memory_budget_with_cheap_memory_advice(budget, 0);

    let decision = plan.decision();
    let report = plan
        .cheap_advice_report()
        .expect("tier-b budget planning records advice telemetry");
    let desired_reclaim_bytes = resident_bytes - budget.soft_limit_bytes();
    let available_reclaim_bytes = supported_tail_advice_bytes + cold_hash_consed_bytes;
    let projected_resident_bytes = resident_bytes - available_reclaim_bytes;
    assert_eq!(
        decision.response(),
        HeapMemoryBudgetResponse::InstallTierB {
            desired_reclaim_bytes,
            available_reclaim_bytes,
            projected_resident_bytes,
            over_budget_bytes: projected_resident_bytes - budget.max_resident_bytes(),
        }
    );
    assert_eq!(report.unused_tails().kind(), MemoryAdviceKind::Dead);
    assert_eq!(report.cold_hash_consed().kind(), MemoryAdviceKind::Evict);
    assert_eq!(report.cold_hash_consed().records(), 1);
    assert_eq!(
        report.cold_hash_consed().requested_bytes(),
        cold_hash_consed_bytes
    );
    assert_eq!(
        heap.cold_hash_consed_bytes(0),
        cold_hash_consed_bytes,
        "pageout advice preserves typed heap records"
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn cheap_memory_budget_plan_continues_without_advice_below_soft_limit() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    heap.alloc_string(NixString::from_bytes(b"cold-but-under-budget".to_vec()))
        .expect("permanent string allocates");
    let resident_bytes = heap
        .arena_stats()
        .mapped_bytes
        .checked_add(heap.permanent_arena_stats().mapped_bytes)
        .expect("resident bytes fit");
    let budget = HeapMemoryBudget::new(resident_bytes.checked_mul(2).expect("budget doubles"))
        .expect("budget is non-zero");

    let plan = heap.plan_memory_budget_with_cheap_memory_advice(budget, 0);

    assert_eq!(plan.cheap_advice_report(), None);
    assert_eq!(
        plan.decision().response(),
        HeapMemoryBudgetResponse::ContinueTierA {
            headroom_bytes: budget.soft_limit_bytes() - resident_bytes,
            projected_resident_bytes: resident_bytes,
        }
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn memory_budget_action_advises_unused_tails_for_spill_response() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(65536).expect("heap creates");
    heap.alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("worker thunk allocates");
    heap.alloc_string(NixString::from_bytes(b"permanent".to_vec()))
        .expect("permanent string allocates");
    let worker_stats = heap.arena_stats();
    let permanent_stats = heap.permanent_arena_stats();
    let resident_bytes = worker_stats
        .mapped_bytes
        .checked_add(permanent_stats.mapped_bytes)
        .expect("resident bytes fit");
    let unused_tail_bytes = (worker_stats.mapped_bytes - worker_stats.used_bytes)
        + (permanent_stats.mapped_bytes - permanent_stats.used_bytes);
    let supported_tail_advice_bytes = heap.supported_unused_tail_advice_bytes();
    let budget = HeapMemoryBudget::new(resident_bytes).expect("budget is non-zero");

    let action = heap.respond_to_memory_budget_with_unused_tail_advice(budget);

    let EvalHeapMemoryBudgetAction::AdviseUnusedTails { decision, report } = action else {
        panic!("spill response should advise unused tails");
    };
    assert_eq!(
        decision.sample().dead_arena_bytes(),
        supported_tail_advice_bytes
    );
    assert_eq!(decision.sample().cold_hash_consed_bytes(), 0);
    let desired_reclaim_bytes = resident_bytes - budget.soft_limit_bytes();
    let reclaim_bytes = desired_reclaim_bytes.min(supported_tail_advice_bytes);
    assert_eq!(
        decision.response(),
        HeapMemoryBudgetResponse::SpillCold {
            desired_reclaim_bytes,
            available_reclaim_bytes: supported_tail_advice_bytes,
            projected_resident_bytes: resident_bytes - reclaim_bytes,
        }
    );
    assert_eq!(action.advice_report(), Some(report));
    assert!(!action.requests_tier_b());
    assert_eq!(report.kind(), MemoryAdviceKind::Dead);
    assert_eq!(report.chunks(), 2);
    assert_eq!(report.requested_bytes(), unused_tail_bytes);
    assert!(supported_tail_advice_bytes <= report.requested_bytes());
    assert_eq!(
        report.applied() + report.unsupported() + report.empty_ranges() + report.rejected(),
        2
    );
    assert_eq!(heap.arena_stats(), worker_stats);
    assert_eq!(heap.permanent_arena_stats(), permanent_stats);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn memory_budget_action_advises_unused_tails_before_tier_b_request() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(65536).expect("heap creates");
    heap.alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("worker thunk allocates");
    heap.alloc_string(NixString::from_bytes(b"permanent".to_vec()))
        .expect("permanent string allocates");
    let worker_stats = heap.arena_stats();
    let permanent_stats = heap.permanent_arena_stats();
    let resident_bytes = worker_stats
        .mapped_bytes
        .checked_add(permanent_stats.mapped_bytes)
        .expect("resident bytes fit");
    let unused_tail_bytes = (worker_stats.mapped_bytes - worker_stats.used_bytes)
        + (permanent_stats.mapped_bytes - permanent_stats.used_bytes);
    let supported_tail_advice_bytes = heap.supported_unused_tail_advice_bytes();
    let budget = HeapMemoryBudget::new(1).expect("budget is non-zero");

    let action = heap.respond_to_memory_budget_with_unused_tail_advice(budget);

    let EvalHeapMemoryBudgetAction::RequestTierB { decision, report } = action else {
        panic!("over-budget response should request Tier B");
    };
    assert_eq!(
        decision.sample().dead_arena_bytes(),
        supported_tail_advice_bytes
    );
    assert_eq!(decision.sample().cold_hash_consed_bytes(), 0);
    let desired_reclaim_bytes = resident_bytes - budget.soft_limit_bytes();
    let reclaim_bytes = desired_reclaim_bytes.min(supported_tail_advice_bytes);
    let projected_resident_bytes = resident_bytes - reclaim_bytes;
    assert_eq!(
        decision.response(),
        HeapMemoryBudgetResponse::InstallTierB {
            desired_reclaim_bytes,
            available_reclaim_bytes: supported_tail_advice_bytes,
            projected_resident_bytes,
            over_budget_bytes: projected_resident_bytes - budget.max_resident_bytes(),
        }
    );
    assert_eq!(action.advice_report(), Some(report));
    assert!(action.requests_tier_b());
    assert_eq!(report.kind(), MemoryAdviceKind::Dead);
    assert_eq!(report.chunks(), 2);
    assert_eq!(report.requested_bytes(), unused_tail_bytes);
    assert!(supported_tail_advice_bytes <= report.requested_bytes());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn configured_heap_memory_budget_polls_successful_allocations() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(65536).expect("heap creates");
    let budget = HeapMemoryBudget::new(1).expect("budget is non-zero");

    heap.set_memory_budget(budget);

    assert_eq!(heap.memory_budget(), Some(budget));
    assert_eq!(
        heap.resident_memory_mode(),
        EvalHeapResidentMemoryMode::ArenaMappedBytes
    );
    assert_eq!(heap.memory_budget_poll_count(), 0);
    assert_eq!(heap.last_memory_budget_action(), None);

    heap.alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("worker thunk allocates");

    assert_eq!(heap.memory_budget_poll_count(), 1);
    let action = heap
        .last_memory_budget_action()
        .expect("configured budget polls after allocation");
    assert_eq!(action.decision().budget(), budget);
    assert_eq!(
        action.decision().resident_source(),
        EvalHeapResidentMemorySource::ArenaMappedBytes
    );
    assert_eq!(action.decision().worker_stats(), heap.arena_stats());
    assert_eq!(
        action.decision().permanent_stats(),
        heap.permanent_arena_stats()
    );
    assert!(action.requests_tier_b());

    heap.set_memory_budget(budget);
    assert_eq!(
        heap.last_memory_budget_action(),
        None,
        "reconfiguring the budget clears stale action metadata"
    );
    let first = heap
        .alloc_string(NixString::from_bytes(b"shared".to_vec()))
        .expect("first permanent string allocates");
    assert_eq!(heap.memory_budget_poll_count(), 2);
    let string_action = heap
        .last_memory_budget_action()
        .expect("permanent allocation records an action");
    assert_eq!(
        string_action.decision().sample().cold_hash_consed_bytes(),
        0,
        "automatic polling stays on the conservative unused-tail response"
    );
    let second = heap
        .alloc_string(NixString::from_bytes(b"shared".to_vec()))
        .expect("matching permanent string reuses the consed value");
    assert!(first.raw_eq(second));
    assert_eq!(
        heap.memory_budget_poll_count(),
        2,
        "hash-cons reuse is not an allocation safepoint"
    );

    heap.clear_memory_budget();
    assert_eq!(heap.memory_budget(), None);
    assert_eq!(heap.last_memory_budget_action(), None);
    heap.alloc_lambda(EvalLambda::new(
        IrId::new(2),
        IrId::new(3),
        FrameId::new(0),
        EvalEnv::default(),
    ))
    .expect("lambda allocates with budget polling disabled");
    assert_eq!(heap.memory_budget_poll_count(), 2);
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn process_resident_memory_mode_reports_live_or_mapped_source() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(65536).expect("heap creates");
    let budget = HeapMemoryBudget::new(1).expect("budget is non-zero");

    heap.set_memory_budget(budget);
    heap.set_resident_memory_mode(EvalHeapResidentMemoryMode::ProcessResidentSetWithArenaFallback);
    heap.alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("worker thunk allocates");

    assert_eq!(
        heap.resident_memory_mode(),
        EvalHeapResidentMemoryMode::ProcessResidentSetWithArenaFallback
    );
    let action = heap
        .last_memory_budget_action()
        .expect("configured budget polls after allocation");
    match action.decision().resident_source() {
        EvalHeapResidentMemorySource::ArenaMappedBytes => {}
        EvalHeapResidentMemorySource::ProcessResidentSet(source) => {
            assert!(matches!(
                source,
                ProcessResidentMemorySource::LinuxProcSelfStatm
                    | ProcessResidentMemorySource::DarwinMachTaskBasicInfo
            ));
        }
    }
    assert!(action.requests_tier_b());
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn multiple_string_values_keep_distinct_heap_records() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let first = heap
        .alloc_string(NixString::from_bytes(b"first".to_vec()))
        .expect("first string allocates");
    let second = heap
        .alloc_string(NixString::from_bytes(b"second".to_vec()))
        .expect("second string allocates");

    assert_ne!(first.payload_bits(), second.payload_bits());
    assert_eq!(heap.len(), 2);
    assert_eq!(
        heap.get_string(first).expect("first exists").bytes(),
        b"first"
    );
    assert_eq!(
        heap.get_string(second).expect("second exists").bytes(),
        b"second"
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn identical_string_values_reuse_heap_record() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(128).expect("heap creates");
    let first = heap
        .alloc_string(NixString::from_bytes(
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-pkg".to_vec(),
        ))
        .expect("first string allocates");
    let second = heap
        .alloc_string(NixString::from_bytes(
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-pkg".to_vec(),
        ))
        .expect("second string allocates");

    assert!(first.raw_eq(second));
    assert_eq!(heap.len(), 1);
    assert_eq!(
        heap.get_string(second)
            .expect("second string exists")
            .bytes(),
        b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-pkg"
    );
    assert_eq!(heap.arena_stats(), ArenaStats::default());
    assert_eq!(heap.permanent_arena_stats().chunks, 1);
    assert_eq!(
        allocation_domain(&heap, second),
        HeapAllocationDomain::PermanentShared
    );
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn hash_consed_heap_records_share_cached_captured_value_hashes() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(256).expect("heap creates");
    let first = heap
        .alloc_string(NixString::from_bytes(
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-pkg".to_vec(),
        ))
        .expect("first string allocates");
    let second = heap
        .alloc_string(NixString::from_bytes(
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-pkg".to_vec(),
        ))
        .expect("second string allocates");
    let list = heap
        .alloc_list(NixList::new(vec![Value::int(1), Value::bool(true)]))
        .expect("list allocates");
    let hash = ValueHash::from_canonical_value_hash(crate::cache::DurableBlake3Hash::for_bytes(
        b"captured string",
    ));

    assert!(first.raw_eq(second));
    assert_eq!(heap.cached_captured_value_hash(first), Ok(None));
    assert_eq!(heap.cached_captured_value_hash(second), Ok(None));

    heap.cache_captured_value_hash(first, hash)
        .expect("captured hash caches");

    assert_eq!(heap.cached_captured_value_hash(first), Ok(Some(hash)));
    assert_eq!(heap.cached_captured_value_hash(second), Ok(Some(hash)));
    assert_eq!(heap.cached_captured_value_hash(list), Ok(None));
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn hash_consed_heap_records_share_cached_value_hashes() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(256).expect("heap creates");
    let first = heap
        .alloc_string(NixString::from_bytes(
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-pkg".to_vec(),
        ))
        .expect("first string allocates");
    let second = heap
        .alloc_string(NixString::from_bytes(
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-pkg".to_vec(),
        ))
        .expect("second string allocates");
    let list = heap
        .alloc_list(NixList::new(vec![Value::int(1), Value::bool(true)]))
        .expect("list allocates");
    let hash = ValueHash::from_context_free_string_bytes(
        b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-pkg",
    );

    assert!(first.raw_eq(second));
    assert_eq!(heap.cached_value_hash(first), Ok(None));
    assert_eq!(heap.cached_value_hash(second), Ok(None));

    assert_eq!(
        heap.cache_value_hash(first, hash)
            .expect("value hash caches"),
        HeapValueHashCacheUpdate::Inserted
    );

    assert_eq!(heap.cached_value_hash(first), Ok(Some(hash)));
    assert_eq!(heap.cached_value_hash(second), Ok(Some(hash)));
    assert_eq!(heap.cached_value_hash(list), Ok(None));

    assert_eq!(
        heap.cache_value_hash(second, hash)
            .expect("alias accepts same value hash"),
        HeapValueHashCacheUpdate::AlreadyPresent
    );
    let other_hash = ValueHash::from_context_free_string_bytes(b"other");
    assert_eq!(
        heap.cache_value_hash(second, other_hash),
        Err(EvalHeapError::ValueHashMismatch {
            existing: hash,
            attempted: other_hash,
        })
    );
    assert_eq!(heap.cached_value_hash(first), Ok(Some(hash)));
    assert_eq!(heap.cached_value_hash(second), Ok(Some(hash)));
}

// Reconciled for the Candidate-C 8-byte carrier: this test forces a non-
// reservation heap geometry (GC-stress record placement / chunked / fake
// pointer) or reads a boxed wide scalar context-free — both unavailable under
// the single-reservation Candidate-C carrier. Real eval is covered by the
// byte-parity battery (cutover plan sections 2, 3.6).
#[cfg(not(feature = "candidate_c_value"))]
#[test]
fn cached_value_hash_lookups_refresh_cold_hash_consed_touch_epoch() {
    let mut heap = EvalHeap::with_initial_chunk_bytes(65536).expect("heap creates");
    // Consumes last-touch epochs, stamped only under epoch tracking (RFC-0007
    // §P1 ledger lever 5).
    heap.set_epoch_tracking_enabled(true);
    let value = heap
        .alloc_string(NixString::from_bytes(b"cache-key".to_vec()))
        .expect("string allocates");
    let string_size = record_layout_size(&heap, value);

    heap.alloc_thunk(EvalThunk::new(IrId::new(1)))
        .expect("thunk allocates");

    assert_eq!(heap.cold_hash_consed_bytes(1), string_size);
    assert_eq!(heap.cached_value_hash(value), Ok(None));
    assert_eq!(heap.cold_hash_consed_bytes(1), 0);

    heap.alloc_thunk(EvalThunk::new(IrId::new(2)))
        .expect("second thunk allocates");

    assert_eq!(heap.cold_hash_consed_bytes(1), string_size);
    assert_eq!(
        heap.cache_value_hash(
            value,
            ValueHash::from_context_free_string_bytes(b"cache-key")
        )
        .expect("value hash caches"),
        HeapValueHashCacheUpdate::Inserted
    );
    assert_eq!(heap.cold_hash_consed_bytes(1), 0);
}
