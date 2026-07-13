//! Tree-walk safepoint root-set tests.

// Many tests here are gated off under the Candidate-C variant (they force a
// GC-stress record placement outside the single reservation), leaving their
// shared helpers unused on that carrier only; the baseline still uses them.
#![cfg_attr(feature = "candidate_c_value", allow(dead_code))]

use super::*;
use crate::compile::IrId;
use crate::eval::heap::{
    AllocationCollectorPollDirectHeapFieldWrite, AllocationCollectorPollObjectByteCopyPlan,
    AllocationCollectorPollObjectByteCopyRequest, AllocationCollectorPollObjectGenerationWritePlan,
    AllocationCollectorPollRootWritebackPlan, AllocationCollectorPollScan, EvalRoot,
    EvalRootSource, EvalThunk, HeapAllocationDomain, HeapEdgeSource, InternedRootTable,
};
use crate::eval::tree_walk::safepoint_roots::TreeWalkSafepointRootWritebackError;
use crate::heap::{
    GcCardTable, GcHeapAddress, GenerationalGcError, GenerationalGcTier, HeapGeneration,
    MinorGcDestinationBases, MinorGcForwardingSlot, MinorGcPromotionPolicy, MinorGcSurvivorAction,
    RememberedEdge, RememberedSet, ResolvedValueGeneration,
};
use crate::list::NixList;
use crate::runtime::alloc::{
    AllocationCollectorPoll, AllocationGcPollReason, GcStressPolicy, RuntimeAllocationEntryPoint,
    RuntimeAllocatorTier,
};
use std::path::PathBuf;


mod support;
mod part_1;
mod part_2;
mod part_3;
mod part_4;
mod part_5;
mod part_6;
mod part_7;
mod part_8;
mod part_9;
mod part_10;
mod part_11;
mod part_12;
mod part_13;
mod part_14;
mod part_15;
pub(crate) use support::*;

fn tree_walk_with_periodic_poll_before_single_young_reservation()
-> (TreeWalk, AllocationCollectorPoll, [Value; 1]) {
    let ir = lower("x: x");
    let mut evaluator = TreeWalk::new(&ir);
    // FV-3: this fixture drives collector-poll minor-GC plan application,
    // which relocates record-table worker objects (scaffolding placement).
    evaluator
        .heap
        .use_record_worker_closures_for_gc_scaffolding();
    let retained = evaluator
        .heap
        .alloc_lambda(EvalLambda::new(
            IrId::new(1),
            IrId::new(1),
            FrameId::new(0),
            EvalEnv::default(),
        ))
        .expect("retained lambda allocates");
    let mark = evaluator
        .heap
        .worker_region_mark()
        .expect("worker mark records");
    let temporary_source = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(2)))
        .expect("temporary source thunk allocates");
    let generation_plan =
        AllocationCollectorPollObjectGenerationWritePlan::from_requests_for_test(vec![
            AllocationCollectorPollObjectByteCopyRequest::for_test(
                gc_address(temporary_source),
                gc_address(retained),
                MinorGcSurvivorAction::PromoteToOld,
                HeapGeneration::Old,
                1,
                1,
            ),
        ])
        .expect("test generation plan builds");
    evaluator
        .heap
        .apply_collector_poll_minor_gc_object_generation_writes(&generation_plan)
        .expect("retained object can be marked old for test setup");
    evaluator
        .heap
        .pop_worker_region_if_disconnected(mark)
        .expect("temporary source is disconnected");
    assert_eq!(
        evaluator
            .heap()
            .generation(retained)
            .expect("retained object remains heap-bound"),
        HeapGeneration::Old
    );

    evaluator
        .heap
        .set_gc_stress_policy(GcStressPolicy::every_n_safepoints(2).expect("period is non-zero"));
    let child = evaluator
        .heap
        .alloc_thunk(EvalThunk::new(IrId::new(3)))
        .expect("polling child thunk allocates");
    let poll = evaluator
        .heap()
        .allocation_safepoints()
        .last_safepoint_collector_poll()
        .expect("second worker allocation requests a periodic poll");
    assert_eq!(
        poll.reason(),
        AllocationGcPollReason::GcStressEveryNSafepoints { period: 2 }
    );

    (evaluator, poll, [child])
}

fn assert_periodic_poll_reserved_application_without_reservation_poll(
    evaluator: &TreeWalk,
    relocated: Value,
    root_writebacks: usize,
) {
    assert_eq!(root_writebacks, 1);
    assert_eq!(
        evaluator
            .heap()
            .allocation_safepoints()
            .last()
            .expect("reservation safepoint records")
            .gc_poll_reason(),
        None
    );
    assert_eq!(
        evaluator
            .heap()
            .allocation_safepoints()
            .last_safepoint_collector_poll(),
        None
    );
    assert_eq!(relocated.tag(), ValueTag::Thunk);
    assert_eq!(
        evaluator
            .heap()
            .generation(relocated)
            .expect("relocated root remains heap-bound"),
        HeapGeneration::Young
    );
}

